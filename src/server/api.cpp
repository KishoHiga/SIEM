#include "server/api.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

#include "core/crypto.hpp"
#include "core/json.hpp"
#include "core/log.hpp"
#include "core/util.hpp"
#include "parse/parsers.hpp"
#include "server/json_out.hpp"

namespace sentinel {

using net::HttpRequest;
using net::HttpResponse;

namespace {

constexpr size_t kMaxEventsPerRequest = 200000;
constexpr int kAuthFailLimit = 20;            // неудачных попыток за минуту
constexpr int64_t kAuthBlockMs = 5 * 60000;   // блокировка IP

std::vector<std::string_view> path_parts(std::string_view path) {
    std::vector<std::string_view> parts;
    for (auto p : split(path, '/'))
        if (!p.empty()) parts.push_back(p);
    return parts;
}

}  // namespace

std::optional<int64_t> parse_time_param(std::string_view v) {
    if (v.empty()) return std::nullopt;
    if (auto n = parse_int(v)) return *n;  // миллисекунды
    return parse_iso8601(v);
}

bool parse_event_query(const HttpRequest& req, EventQuery& q, std::string& error) {
    // служебные параметры (остальные — фильтры по полям)
    static const std::set<std::string> reserved = {"from", "to", "limit", "before_id", "q", "format", "tz", "raw"};
    if (auto t = parse_time_param(req.param("from"))) q.from = *t;
    else if (!req.param("from").empty()) return error = "bad 'from' (ISO-8601 or ms)", false;
    if (auto t = parse_time_param(req.param("to"))) q.to = *t;
    else if (!req.param("to").empty()) return error = "bad 'to' (ISO-8601 or ms)", false;
    if (auto b = parse_uint(req.param("before_id"))) q.before_id = *b;
    q.text = std::string(req.param("q"));
    for (auto& p : req.query) {
        if (reserved.count(p.first) || p.second.empty()) continue;
        q.equals.emplace_back(p.first, p.second);
    }
    return true;
}

bool parse_alert_query(const HttpRequest& req, AlertQuery& q, std::string& error) {
    if (auto t = parse_time_param(req.param("from"))) q.from = *t;
    else if (!req.param("from").empty()) return error = "bad 'from' (ISO-8601 or ms)", false;
    if (auto t = parse_time_param(req.param("to"))) q.to = *t;
    else if (!req.param("to").empty()) return error = "bad 'to' (ISO-8601 or ms)", false;
    if (!req.param("status").empty()) {
        auto s = alert_status_from_name(req.param("status"));
        if (!s) return error = "bad status (new|acknowledged|resolved|false_positive)", false;
        q.status = *s;
    }
    if (!req.param("severity").empty()) {
        auto s = severity_from_name(req.param("severity"));
        if (!s) return error = "bad severity (info|low|medium|high|critical)", false;
        q.min_severity = *s;
    }
    q.rule_id = std::string(req.param("rule"));
    q.src_ip = std::string(req.param("src_ip"));
    if (auto b = parse_uint(req.param("before_id"))) q.before_id = *b;
    return true;
}

Api::Api(const Config& cfg, EventStore& events, AlertStore& alerts, LiveStats& stats, Pipeline& pipeline)
    : events_(events), alerts_(alerts), live_(stats), pipeline_(pipeline), started_ms_(now_ms()) {
    keys_.init(cfg.keys, cfg.keys_file);
    std::string err;
    if (!keys_.reload(err)) log::error("keys: ", err);
    enroll_.set_file(cfg.data_dir + "/enroll_tokens.yaml");
    agents_file_ = cfg.data_dir + "/agents.json";
    tmp_dir_ = cfg.data_dir + "/tmp";
    // недоотправленные выгрузки прошлого запуска
    std::error_code ec;
    std::filesystem::remove_all(tmp_dir_, ec);
}

void Api::set_rules(const std::vector<Rule>& rules) {
    std::lock_guard<std::mutex> lock(rules_mu_);
    rules_list_ = rules;
}

bool Api::auth_blocked(const std::string& ip) {
    std::lock_guard<std::mutex> lock(auth_mu_);
    auto it = auth_fail_.find(ip);
    return it != auth_fail_.end() && it->second.blocked_until > now_ms();
}

void Api::auth_failed(const std::string& ip) {
    std::lock_guard<std::mutex> lock(auth_mu_);
    int64_t now = now_ms();
    if (auth_fail_.size() > 100000) auth_fail_.clear();  // защита памяти
    AuthFail& f = auth_fail_[ip];
    if (now - f.window_start > 60000) {
        f.window_start = now;
        f.count = 0;
    }
    if (++f.count >= kAuthFailLimit) {
        f.blocked_until = now + kAuthBlockMs;
        log::warn("auth: too many failed attempts from ", ip, ", blocked for 5 minutes");
    }
}

namespace {
constexpr int64_t kSessionTtlMs = 12 * 3600 * 1000LL;
constexpr const char* kCookie = "sentinel_session";

std::string cookie_value(std::string_view header, std::string_view name) {
    for (auto part : split(header, ';')) {
        part = trim(part);
        size_t eq = part.find('=');
        if (eq != std::string_view::npos && part.substr(0, eq) == name) return std::string(part.substr(eq + 1));
    }
    return "";
}
}  // namespace

std::optional<ApiKey> Api::session_from_cookie(const HttpRequest& req) {
    std::string id = cookie_value(req.header("cookie"), kCookie);
    if (id.size() != 64) return std::nullopt;
    std::string hash;
    {
        std::lock_guard<std::mutex> lock(sessions_mu_);
        auto it = sessions_.find(id);
        if (it == sessions_.end()) return std::nullopt;
        int64_t now = now_ms();
        if (it->second.expires < now) {
            sessions_.erase(it);
            return std::nullopt;
        }
        it->second.expires = now + kSessionTtlMs;  // скользящее продление
        hash = it->second.key_hash;
    }
    auto k = keys_.find_by_hash(hash);
    if (!k) {  // ключ удалили из keys.yaml — выходим из всех его сессий
        std::lock_guard<std::mutex> lock(sessions_mu_);
        sessions_.erase(id);
    }
    return k;
}

// WebSocket не защищён правилами CORS, поэтому сами проверяем, что страница с нашего адреса.
static bool same_origin(const HttpRequest& req) {
    std::string_view origin = req.header("origin");
    if (origin.empty()) return true;  // не браузер (агент, curl)
    size_t p = origin.find("://");
    if (p == std::string_view::npos) return false;
    return iequals(origin.substr(p + 3), req.header("host"));
}

bool Api::ws_accept(const HttpRequest& req) {
    if (!same_origin(req)) return false;
    std::optional<ApiKey> k = session_from_cookie(req);
    if (!k) {
        std::string_view h = req.header("authorization");
        if (h.size() > 7 && iequals(h.substr(0, 7), "bearer ")) k = keys_.find_by_secret(trim(h.substr(7)));
    }
    return k && role_can_read(k->role);
}

void Api::login(const HttpRequest& req, HttpResponse& resp) {
    if (req.header("x-requested-with") != "sentinel") return resp.error(403, "CSRF check failed: missing X-Requested-With header");
    if (auth_blocked(req.remote_addr)) {
        resp.error(429, "too many failed attempts, try later");
        resp.headers.emplace_back("Retry-After", "300");
        return;
    }
    JValue v;
    std::string err;
    if (!json_parse(req.body, v, err) || !v.is_object() || !v.get("key") || !v.get("key")->is_string())
        return resp.error(400, "expected JSON {\"key\": \"...\"}");
    auto k = keys_.find_by_secret(trim(v.get("key")->s));
    if (!k) {
        auth_failed(req.remote_addr);
        return resp.error(401, "invalid key");
    }
    if (!role_can_read(k->role)) return resp.error(403, "this key can only send logs, use a read/analyst/admin key");
    std::string id = random_hex(32);
    {
        std::lock_guard<std::mutex> lock(sessions_mu_);
        int64_t now = now_ms();
        if (sessions_.size() > 1000)
            for (auto it = sessions_.begin(); it != sessions_.end();)
                it = it->second.expires < now ? sessions_.erase(it) : std::next(it);
        if (sessions_.size() > 10000) return resp.error(503, "too many sessions");
        sessions_[id] = Session{k->sha256, now + kSessionTtlMs};
    }
    log::info("login: '", k->name, "' (", role_name(k->role), ") from ", req.remote_addr);
    std::string cookie = std::string(kCookie) + "=" + id + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" +
                         std::to_string(kSessionTtlMs / 1000) + (req.tls ? "; Secure" : "");
    resp.headers.emplace_back("Set-Cookie", cookie);
    std::string b;
    JsonWriter(b).begin_object().kv("name", k->name).kv("role", role_name(k->role)).end_object();
    resp.json(200, std::move(b));
}

void Api::logout(const HttpRequest& req, HttpResponse& resp) {
    if (req.header("x-requested-with") != "sentinel") return resp.error(403, "CSRF check failed: missing X-Requested-With header");
    std::string id = cookie_value(req.header("cookie"), kCookie);
    {
        std::lock_guard<std::mutex> lock(sessions_mu_);
        sessions_.erase(id);
    }
    resp.headers.emplace_back("Set-Cookie", std::string(kCookie) + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    resp.json(200, "{\"ok\":true}");
}

void Api::create_enroll_token(const HttpRequest& req, HttpResponse& resp) {
    JValue v;
    std::string err;
    int64_t ttl_h = 24, uses = 1;
    std::string label;
    if (!req.body.empty()) {
        if (!json_parse(req.body, v, err) || !v.is_object()) return resp.error(400, "expected JSON object");
        if (auto* t = v.get("ttl_hours"); t && t->is_number()) ttl_h = std::clamp<int64_t>(t->i, 1, 24 * 30);
        if (auto* u = v.get("uses"); u && u->is_number()) uses = std::clamp<int64_t>(u->i, 1, 1000);
        if (auto* l = v.get("label"); l && l->is_string()) label = l->s.substr(0, 100);
    }
    std::string token;
    if (!enroll_.create(ttl_h * 3600000, int(uses), label, token, err)) {
        log::error("enroll-token: ", err);
        return resp.error(500, "cannot create token");
    }
    std::string cmd = "sentinel-agent enroll --server " + agent_url_ + " --token " + token;
    if (!agent_pin_.empty()) cmd += " --pin " + agent_pin_;
    std::string b;
    JsonWriter(b)
        .begin_object()
        .kv("token", token)
        .kv("expires", format_iso8601(now_ms() + ttl_h * 3600000))
        .kv("uses", uses)
        .kv("server", agent_url_)
        .kv("pin", agent_pin_)
        .kv("command", cmd)
        .end_object();
    resp.json(201, std::move(b));
}

std::optional<ApiKey> Api::authenticate(const HttpRequest& req, HttpResponse& resp, bool& via_cookie) {
    via_cookie = false;
    if (req.header("authorization").empty() && req.header("x-api-key").empty()) {
        if (auto s = session_from_cookie(req)) {
            via_cookie = true;
            return s;
        }
    }
    if (auth_blocked(req.remote_addr)) {
        resp.error(429, "too many failed authentication attempts, try later");
        resp.headers.emplace_back("Retry-After", "300");
        return std::nullopt;
    }
    std::string_view token = req.header("x-api-key");
    if (token.empty()) {
        std::string_view h = req.header("authorization");
        if (h.size() > 7 && iequals(h.substr(0, 7), "bearer ")) token = trim(h.substr(7));
    }
    if (auto k = keys_.find_by_secret(token)) return k;
    auth_failed(req.remote_addr);
    resp.error(401, "missing or invalid API key");
    resp.headers.emplace_back("WWW-Authenticate", "Bearer");
    return std::nullopt;
}

void Api::enroll(const HttpRequest& req, HttpResponse& resp) {
    if (auth_blocked(req.remote_addr)) {
        resp.error(429, "too many failed attempts, try later");
        resp.headers.emplace_back("Retry-After", "300");
        return;
    }
    JValue v;
    std::string err;
    if (!json_parse(req.body, v, err) || !v.is_object()) return resp.error(400, "expected JSON {\"token\": ..., \"host\": ...}");
    const JValue* tok = v.get("token");
    const JValue* host = v.get("host");
    if (!tok || !tok->is_string()) return resp.error(400, "missing 'token'");
    auto r = enroll_.consume(tok->s);
    if (r != EnrollStore::Result::Ok) {
        auth_failed(req.remote_addr);
        return resp.error(403, r == EnrollStore::Result::Expired ? "enroll token expired or already used"
                                                                 : "invalid enroll token");
    }
    // Имя ключа из имени хоста (только безопасные символы)
    std::string base = "agent-";
    std::string h = host && host->is_string() ? host->s : std::string("host");
    for (char c : h) {
        if (is_alpha(c) || is_digit(c) || c == '-' || c == '.' || c == '_') base.push_back(to_lower_ascii(c));
        if (base.size() > 60) break;
    }
    if (base == "agent-") base += "host";
    std::string name = base;
    for (int i = 2; keys_.has_name(name); ++i) name = base + "-" + std::to_string(i);
    std::string secret;
    if (!keys_.add(name, Role::Ingest, secret, err)) {
        log::error("enroll: cannot create key: ", err);
        return resp.error(500, "cannot create key");
    }
    log::info("enroll: agent '", name, "' connected from ", req.remote_addr);
    std::string b;
    JsonWriter(b).begin_object().kv("key", secret).kv("name", name).kv("role", "ingest").end_object();
    resp.json(201, std::move(b));
}

void Api::touch_agent(const ApiKey& key, const HttpRequest& req, size_t events) {
    std::lock_guard<std::mutex> lock(agents_mu_);
    if (agents_.size() > 10000 && !agents_.count(key.name)) return;
    AgentInfo& a = agents_[key.name];
    int64_t now = now_ms();
    if (a.first_seen == 0) a.first_seen = now;
    a.last_seen = now;
    a.events += events;
    ++a.requests;
    a.remote_addr = req.remote_addr;
    if (auto h = req.header("x-sentinel-host"); !h.empty()) a.host = std::string(h.substr(0, 200));
    if (auto ver = req.header("x-sentinel-agent"); !ver.empty()) a.version = std::string(ver.substr(0, 100));
    if (auto fw = req.header("x-sentinel-firewall"); !fw.empty()) a.firewall = std::string(fw.substr(0, 300));
    agents_dirty_ = true;
}

void Api::agents(HttpResponse& resp) {
    std::string b;
    JsonWriter w(b);
    const int64_t now = now_ms();
    w.begin_object().key("agents").begin_array();
    {
        std::lock_guard<std::mutex> lock(agents_mu_);
        for (auto& kv : agents_) {
            const AgentInfo& a = kv.second;
            w.begin_object();
            w.kv("key_name", kv.first).kv("host", a.host).kv("agent", a.version).kv("remote_addr", a.remote_addr);
            w.kv("first_seen", format_iso8601(a.first_seen)).kv("last_seen", format_iso8601(a.last_seen));
            w.kv("seconds_since_last", (now - a.last_seen) / 1000);
            w.kv("online", now - a.last_seen < 120000);
            w.kv("events", a.events).kv("requests", a.requests);
            w.kv("firewall", a.firewall);
            if (a.blocks_synced) w.kv("blocks_synced", format_iso8601(a.blocks_synced));
            w.end_object();
        }
    }
    w.end_array().end_object();
    resp.json(200, std::move(b));
}

void Api::handle(const HttpRequest& req, HttpResponse& resp) {
    auto parts = path_parts(req.path);
    if (parts.empty() || (parts[0] != "api" && parts[0] != "health")) {
        if (web_ && web_->serve(req, resp)) return;  // панель
        resp.error(404, "not found");
        return;
    }
    if (parts.size() == 1 && parts[0] == "health") {
        std::string b;
        JsonWriter(b).begin_object().kv("status", "ok").kv("version", "0.6.0").end_object();
        resp.json(200, std::move(b));
        return;
    }
    if (parts.size() < 3 || parts[0] != "api" || parts[1] != "v1") {
        resp.error(404, "not found");
        return;
    }
    if (parts.size() == 3 && parts[2] == "enroll") {
        if (req.method != "POST") return resp.error(405, "use POST");
        return enroll(req, resp);
    }
    if (parts.size() == 3 && parts[2] == "login") {
        if (req.method != "POST") return resp.error(405, "use POST");
        return login(req, resp);
    }
    if (parts.size() == 3 && parts[2] == "logout") {
        if (req.method != "POST") return resp.error(405, "use POST");
        return logout(req, resp);
    }
    bool via_cookie = false;
    const std::optional<ApiKey> key = authenticate(req, resp, via_cookie);
    if (!key) return;
    // Cookie браузер шлёт сам — изменяющие запросы требуют заголовок, который чужой сайт поставить не может.
    if (via_cookie && req.method != "GET" && req.header("x-requested-with") != "sentinel")
        return resp.error(403, "CSRF check failed: missing X-Requested-With header");
    const std::string_view res = parts[2];
    const bool get = req.method == "GET";
    const bool post = req.method == "POST";

    auto need = [&](bool allowed) {
        if (!allowed) resp.error(403, std::string("role '") + role_name(key->role) + "' is not allowed here");
        return allowed;
    };
    auto parse_id = [&](std::string_view s, uint64_t& id) {
        auto v = parse_uint(s);
        if (!v) {
            resp.error(400, "bad id");
            return false;
        }
        id = *v;
        return true;
    };

    if (res == "ingest" && parts.size() == 3) {
        if (!post) return resp.error(405, "use POST");
        if (need(role_can_ingest(key->role))) ingest(req, resp, *key);
        return;
    }
    if (res == "me" && parts.size() == 3 && get) {
        std::string b;
        JsonWriter(b)
            .begin_object()
            .kv("name", key->name)
            .kv("role", role_name(key->role))
            .kv("can_change_alerts", role_can_change_alerts(key->role))
            .kv("is_admin", key->role == Role::Admin)
            .end_object();
        resp.json(200, std::move(b));
        return;
    }
    if (res == "enroll-tokens" && parts.size() == 3) {
        if (!post) return resp.error(405, "use POST");
        if (need(key->role == Role::Admin)) create_enroll_token(req, resp);
        return;
    }
    if (res == "agent" && parts.size() == 4 && parts[3] == "blocks") {
        if (!get) return resp.error(405, "use GET");
        if (need(role_can_ingest(key->role))) agent_blocks(req, resp, *key);
        return;
    }
    if (res == "whoami" && parts.size() == 3 && get) {
        std::string b;
        JsonWriter(b).begin_object().kv("name", key->name).kv("role", role_name(key->role)).end_object();
        resp.json(200, std::move(b));
        return;
    }
    if (!need(role_can_read(key->role))) return;

    if (res == "events") {
        if (parts.size() == 3 && get) return list_events(req, resp);
        uint64_t id = 0;
        if (parts.size() == 4 && get && parse_id(parts[3], id)) return get_event(id, resp);
        if (resp.status == 400) return;
    } else if (res == "alerts") {
        if (parts.size() == 3 && get) return list_alerts(req, resp);
        uint64_t id = 0;
        if (parts.size() >= 4 && !parse_id(parts[3], id)) return;
        if (parts.size() == 4 && get) return get_alert(id, resp);
        if (parts.size() == 5 && parts[4] == "status" && post) {
            if (need(role_can_change_alerts(key->role))) set_alert_status(id, req, resp);
            return;
        }
    } else if (res == "stats" && parts.size() == 3 && get) {
        return stats(req, resp);
    } else if (res == "rules") {
        return rules_route(req, resp, *key, parts);
    } else if (res == "ip" && parts.size() == 4 && get) {
        return ip_card(net::url_decode_component(parts[3], false), req, resp);
    } else if (res == "incidents") {
        return incidents_route(req, resp, *key, parts);
    } else if (res == "export" && parts.size() == 4 && get) {
        return export_data(parts[3], req, resp);
    } else if (res == "report" && parts.size() == 3 && get) {
        return report(req, resp);
    } else if (res == "report" && parts.size() == 4 && parts[3] == "send") {
        if (!post) return resp.error(405, "use POST");
        if (need(key->role == Role::Admin)) report_send(req, resp, *key);
        return;
    } else if (res == "threat" && parts.size() == 3 && get) {
        return threat_status(resp);
    } else if (res == "agents" && parts.size() == 3 && get) {
        return agents(resp);
    } else if (res == "blocks" && parts.size() == 3) {
        if (get) return list_blocks(req, resp);
        if (!need(role_can_change_alerts(key->role))) return;
        if (post) return add_block(req, resp, *key);
        if (req.method == "DELETE") return remove_block(req, resp, *key);
        return resp.error(405, "use GET, POST or DELETE");
    } else if (res == "notify" && parts.size() == 3 && get) {
        return notify_status(resp);
    } else if (res == "notify" && parts.size() == 4 && parts[3] == "test") {
        if (!post) return resp.error(405, "use POST");
        if (need(key->role == Role::Admin)) notify_test(resp, *key);
        return;
    }
    resp.error(404, "not found");
}

void Api::ingest(const HttpRequest& req, HttpResponse& resp, const ApiKey& key) {
    ParseContext ctx;
    ctx.now_ms = now_ms();
    std::string source(req.header("x-sentinel-source"));
    std::string host(req.header("x-sentinel-host"));
    ctx.source_hint = source;
    ctx.host_hint = host;
    if (auto tz = parse_int(req.header("x-sentinel-tz"))) ctx.tz_offset_minutes = int(*tz);
    LogFormat fmt = log_format_from_name(req.header("x-sentinel-format"));

    std::string ctype = to_lower(req.header("content-type"));
    if (size_t semi = ctype.find(';'); semi != std::string::npos) ctype = std::string(trim(ctype.substr(0, semi)));

    std::vector<Event> batch;
    auto add_json_object = [&](const JValue& obj) {
        Event ev;
        ev.received = ctx.now_ms;
        event_from_json(obj, ctx, ev);
        json_write_value(ev[Field::Raw], obj);
        enrich_event(ev);
        if (ev[Field::Host].empty()) ev[Field::Host] = host;
        if (ev.ts == 0) ev.ts = ev.received;
        batch.push_back(std::move(ev));
    };

    if (ctype == "application/json") {
        JValue v;
        std::string err;
        if (!json_parse(req.body, v, err)) return resp.error(400, "invalid JSON: " + err);
        if (v.is_object()) {
            add_json_object(v);
        } else if (v.is_array()) {
            if (v.arr.size() > kMaxEventsPerRequest) return resp.error(413, "too many events in one request");
            for (auto& item : v.arr) {
                if (item.is_object()) {
                    add_json_object(item);
                } else if (item.is_string()) {
                    Event ev;
                    if (parse_line(item.s, fmt, ctx, ev)) batch.push_back(std::move(ev));
                } else {
                    return resp.error(400, "array items must be objects or strings");
                }
            }
        } else {
            return resp.error(400, "expected JSON object or array");
        }
    } else {
        // text/plain, application/x-ndjson и прочее: построчно
        LogFormat lf = ctype == "application/x-ndjson" ? LogFormat::Json : fmt;
        std::string_view body = req.body;
        size_t start = 0;
        while (start < body.size()) {
            size_t nl = body.find('\n', start);
            if (nl == std::string_view::npos) nl = body.size();
            std::string_view line = body.substr(start, nl - start);
            start = nl + 1;
            Event ev;
            if (parse_line(line, lf, ctx, ev)) {
                batch.push_back(std::move(ev));
                if (batch.size() > kMaxEventsPerRequest) return resp.error(413, "too many lines in one request");
            }
        }
    }
    size_t n = batch.size();
    touch_agent(key, req, n);
    if (enricher_) enricher_->enrich(batch);
    if (!pipeline_.submit(std::move(batch))) {
        resp.error(503, "server is busy, retry later");
        resp.headers.emplace_back("Retry-After", "1");
        return;
    }
    std::string b;
    JsonWriter(b).begin_object().kv("accepted", n).end_object();
    resp.json(202, std::move(b));
}

void Api::list_events(const HttpRequest& req, HttpResponse& resp) {
    EventQuery q;
    std::string err;
    if (!parse_event_query(req, q, err)) return resp.error(400, err);
    q.limit = 100;
    if (auto l = parse_uint(req.param("limit"))) q.limit = size_t(std::min<uint64_t>(*l, 1000));
    auto events = events_.query(q);
    std::string b;
    b.reserve(events.size() * 600);
    JsonWriter w(b);
    w.begin_object().key("events").begin_array();
    for (auto& e : events) write_event(w, e);
    w.end_array();
    w.key("next_before_id");
    if (events.size() == q.limit && !events.empty()) w.value(events.back().id);
    else w.null();
    w.end_object();
    resp.json(200, std::move(b));
}

void Api::get_event(uint64_t id, HttpResponse& resp) {
    auto e = events_.get(id);
    if (!e) return resp.error(404, "event not found");
    std::string b;
    JsonWriter w(b);
    write_event(w, *e);
    resp.json(200, std::move(b));
}

void Api::list_alerts(const HttpRequest& req, HttpResponse& resp) {
    AlertQuery q;
    std::string err;
    if (!parse_alert_query(req, q, err)) return resp.error(400, err);
    if (auto l = parse_uint(req.param("limit"))) q.limit = size_t(std::min<uint64_t>(*l, 1000));
    auto alerts = alerts_.query(q);
    std::string b;
    JsonWriter w(b);
    w.begin_object().key("alerts").begin_array();
    for (auto& a : alerts) write_alert(w, a, incident_of(a.id));
    w.end_array();
    w.key("next_before_id");
    if (alerts.size() == q.limit && !alerts.empty()) w.value(alerts.back().id);
    else w.null();
    w.end_object();
    resp.json(200, std::move(b));
}

void Api::get_alert(uint64_t id, HttpResponse& resp) {
    auto a = alerts_.get(id);
    if (!a) return resp.error(404, "alert not found");
    std::string b;
    JsonWriter w(b);
    w.begin_object().key("alert");
    write_alert(w, *a, incident_of(a->id));
    w.key("events").begin_array();
    for (uint64_t eid : a->event_ids)
        if (auto e = events_.get(eid)) write_event(w, *e);
    w.end_array().end_object();
    resp.json(200, std::move(b));
}

void Api::set_alert_status(uint64_t id, const HttpRequest& req, HttpResponse& resp) {
    JValue v;
    std::string err;
    if (!json_parse(req.body, v, err) || !v.is_object()) return resp.error(400, "expected JSON {\"status\": ...}");
    const JValue* s = v.get("status");
    if (!s || !s->is_string()) return resp.error(400, "missing 'status'");
    auto st = alert_status_from_name(s->s);
    if (!st) return resp.error(400, "bad status (new|acknowledged|resolved|false_positive)");
    if (!alerts_.set_status(id, *st)) return resp.error(404, "alert not found");
    std::string b;
    JsonWriter(b).begin_object().kv("id", id).kv("status", alert_status_name(*st)).end_object();
    resp.json(200, std::move(b));
}

void Api::stats(const HttpRequest& req, HttpResponse& resp) {
    const int64_t now = now_ms();
    int minutes = 60;
    if (auto m = parse_int(req.param("minutes"))) minutes = int(std::clamp<int64_t>(*m, 1, 1440));
    auto snap = live_.snapshot(now, minutes, 10);
    auto counts = alerts_.counts(now - 86400000LL);
    auto st = events_.stats();
    auto ps = pipeline_.stats();

    std::string b;
    JsonWriter w(b);
    w.begin_object();
    w.kv("uptime_sec", (now - started_ms_) / 1000);
    w.kv("events_since_start", snap.events_total);
    w.kv("events_24h", snap.events_24h);
    w.kv("events_per_sec", snap.events_per_sec_1m);
    w.kv("alerts_24h", counts.total);
    w.kv("alerts_open_24h", counts.by_status[size_t(AlertStatus::New)] + counts.by_status[size_t(AlertStatus::Acknowledged)]);
    w.key("alerts_by_severity_24h").begin_object();
    for (int s = 0; s <= int(Severity::Critical); ++s) w.kv(severity_name(Severity(s)), counts.by_severity[s]);
    w.end_object();
    w.key("alerts_by_status_24h").begin_object();
    for (int s = 0; s <= int(AlertStatus::FalsePositive); ++s) w.kv(alert_status_name(AlertStatus(s)), counts.by_status[s]);
    w.end_object();
    if (incidents_) {
        auto ic = incidents_->counts();
        w.key("incidents").begin_object();
        w.kv("active", ic.active).kv("unassigned", ic.unassigned);
        w.key("by_severity").begin_object();
        for (int s = 0; s <= int(Severity::Critical); ++s) w.kv(severity_name(Severity(s)), ic.by_severity[s]);
        w.end_object().end_object();
    }
    w.key("timeline").begin_array();
    for (size_t i = 0; i < snap.events_per_minute.size(); ++i) {
        w.begin_object();
        w.kv("t", format_iso8601(snap.events_per_minute[i].first));
        w.kv("events", snap.events_per_minute[i].second);
        w.kv("alerts", snap.alerts_per_minute[i].second);
        w.end_object();
    }
    w.end_array();
    auto list = [&](const char* name, const char* k, const std::vector<std::pair<std::string, uint64_t>>& v) {
        w.key(name).begin_array();
        for (auto& p : v) w.begin_object().kv(k, p.first).kv("count", p.second).end_object();
        w.end_array();
    };
    w.key("top_ips").begin_array();
    for (auto& p : snap.top_ips) {
        w.begin_object().kv("ip", p.first).kv("count", p.second);
        if (enricher_) {
            IpReport r = enricher_->lookup(p.first);
            if (!r.country.empty()) w.kv("country", r.country);
            if (!r.lists.empty()) w.kv("listed", true);
        }
        w.end_object();
    }
    w.end_array();
    list("top_sources", "source", snap.top_sources);
    list("by_type", "type", snap.by_type);
    list("top_countries", "country", snap.top_countries);
    w.key("storage").begin_object();
    w.kv("events", st.events).kv("segments", st.segments).kv("bytes_on_disk", st.bytes_on_disk);
    w.kv("compression_ratio", st.bytes_on_disk ? double(st.raw_bytes) / double(st.bytes_on_disk) : 0.0);
    w.kv("pending", st.pending).kv("corrupt_blocks", st.corrupt_blocks);
    w.end_object();
    w.key("pipeline").begin_object();
    w.kv("accepted", ps.accepted).kv("rejected", ps.rejected).kv("queued", ps.queued);
    w.kv("alerts_emitted", ps.engine.alerts).kv("alerts_suppressed", ps.engine.suppressed);
    w.kv("detection_state_keys", ps.engine.state_keys);
    w.kv("detect_threads", ps.detect_threads).kv("global_thread", ps.global_thread);
    w.kv("sharded_rules", ps.sharded_rules).kv("global_rules", ps.global_rules);
    w.key("shard_events").begin_array();
    for (auto v : ps.shard_events) w.value(v);
    w.end_array();
    w.end_object();
    w.end_object();
    resp.json(200, std::move(b));
}


// ---------------- Реагирование: блокировки и уведомления ----------------

void write_block(JsonWriter& w, const Block& b) {
    w.begin_object();
    w.kv("ip", b.ip).kv("reason", b.reason).kv("rule_id", b.rule_id).kv("alert_id", b.alert_id).kv("by", b.by);
    w.kv("created", format_iso8601(b.created));
    w.key("expires");
    if (b.expires) w.value(format_iso8601(b.expires));
    else w.null();
    w.kv("hits", b.hits);
    w.end_object();
}

void Api::list_blocks(const HttpRequest& req, HttpResponse& resp) {
    if (!blocks_) return resp.error(503, "blocking is not configured");
    if (req.has_param("ip")) {
        auto b = blocks_->find(std::string(req.param("ip")));
        std::string out;
        JsonWriter w(out);
        w.begin_object().kv("blocked", b.has_value());
        if (b) {
            w.key("block");
            write_block(w, *b);
        }
        w.end_object();
        return resp.json(200, std::move(out));
    }
    auto list = blocks_->list();
    std::sort(list.begin(), list.end(), [](const Block& a, const Block& b) { return a.created > b.created; });
    auto pol = blocks_->policy();
    auto st = blocks_->stats();
    std::string out;
    JsonWriter w(out);
    w.begin_object().kv("version", blocks_->version());
    w.key("policy").begin_object();
    w.kv("auto_block", pol.enabled).kv("min_severity", severity_name(pol.min_severity));
    w.kv("duration_seconds", pol.duration_ms / 1000).kv("block_private", pol.block_private);
    w.kv("max_per_minute", pol.max_per_minute);
    w.key("rules").begin_array();
    for (auto& r : pol.rules) w.value(r);
    w.end_array().key("allowlist").begin_array();
    for (auto& c : pol.allowlist) w.value(format_cidr(c));
    w.end_array().end_object();
    w.key("stats").begin_object();
    w.kv("active", st.active).kv("auto_added", st.auto_added).kv("manual_added", st.manual_added);
    w.kv("skipped_allowlist", st.skipped_allowlist).kv("skipped_private", st.skipped_private);
    w.kv("skipped_limit", st.skipped_limit).kv("expired", st.expired);
    w.end_object();
    w.key("blocks").begin_array();
    for (auto& b : list) write_block(w, b);
    w.end_array().end_object();
    resp.json(200, std::move(out));
}

void Api::add_block(const HttpRequest& req, HttpResponse& resp, const ApiKey& key) {
    if (!blocks_) return resp.error(503, "blocking is not configured");
    JValue v;
    std::string err;
    if (!json_parse(req.body, v, err) || !v.is_object() || !v.get("ip") || !v.get("ip")->is_string())
        return resp.error(400, "expected JSON {\"ip\": \"1.2.3.4\", \"duration\": \"1h\", \"reason\": \"...\"}");
    int64_t duration = 0;  // по умолчанию бессрочно
    if (const JValue* d = v.get("duration")) {
        if (d->is_number()) duration = d->i * 1000;
        else if (d->is_string()) {
            auto ms = parse_duration_ms(d->s);
            if (!ms) return resp.error(400, "bad duration (examples: 30m, 1h, 7d, 0 = permanent)");
            duration = *ms;
        }
    }
    std::string reason;
    if (auto* r = v.get("reason"); r && r->is_string()) reason = r->s.substr(0, 300);
    Block b;
    auto r = blocks_->add_manual(std::string(trim(v.get("ip")->s)), duration, reason, key.name, &b);
    if (r != BlockList::Result::Added && r != BlockList::Result::Extended && r != BlockList::Result::Unchanged)
        return resp.error(r == BlockList::Result::Full ? 409 : 400, BlockList::result_text(r));
    std::string out;
    JsonWriter w(out);
    w.begin_object().kv("result", BlockList::result_text(r)).key("block");
    write_block(w, b);
    w.end_object();
    resp.json(r == BlockList::Result::Added ? 201 : 200, std::move(out));
}

void Api::remove_block(const HttpRequest& req, HttpResponse& resp, const ApiKey& key) {
    if (!blocks_) return resp.error(503, "blocking is not configured");
    std::string ip(req.param("ip"));
    if (ip.empty()) return resp.error(400, "missing ?ip=");
    if (!blocks_->remove(ip)) return resp.error(404, "this address is not blocked");
    log::info("blocks: ", ip, " unblocked by ", key.name);
    resp.json(200, "{\"ok\":true}");
}

void Api::agent_blocks(const HttpRequest& req, HttpResponse& resp, const ApiKey& key) {
    touch_agent(key, req, 0);
    {
        std::lock_guard<std::mutex> lock(agents_mu_);
        agents_[key.name].blocks_synced = now_ms();
    }
    // Без ?version= агент ещё ничего не применял — всегда отдаём полный список (даже пустой),
    // чтобы он убрал старые правила, оставшиеся от прошлого запуска.
    auto have = parse_uint(req.param("version"));
    uint64_t ver = blocks_ ? blocks_->version() : 0;
    bool changed = !have || *have != ver;
    std::string out;
    JsonWriter w(out);
    w.begin_object().kv("version", ver).kv("changed", changed);
    if (changed) {
        w.key("blocks").begin_array();
        if (blocks_)
            for (auto& b : blocks_->list()) w.value(b.ip);
        w.end_array();
    }
    w.end_object();
    resp.json(200, std::move(out));
}

void Api::notify_status(HttpResponse& resp) {
    std::string out;
    JsonWriter w(out);
    w.begin_object();
    if (!notifier_) {
        w.kv("enabled", false).key("channels").begin_array().end_array().end_object();
        return resp.json(200, std::move(out));
    }
    auto st = notifier_->stats();
    w.kv("enabled", st.enabled).kv("min_severity", severity_name(st.min_severity)).kv("mode", st.mode);
    w.kv("queued", st.queued).kv("suppressed", st.suppressed).kv("dropped", st.dropped).kv("digests", st.digests);
    w.key("channels").begin_array();
    for (auto& c : st.channels) {
        w.begin_object().kv("name", c.name).kv("target", c.target).kv("sent", c.sent).kv("failed", c.failed);
        w.key("last_ok");
        if (c.last_ok) w.value(format_iso8601(c.last_ok));
        else w.null();
        w.key("last_error_at");
        if (c.last_error_at) w.value(format_iso8601(c.last_error_at));
        else w.null();
        w.kv("last_error", c.last_error).end_object();
    }
    w.end_array().end_object();
    resp.json(200, std::move(out));
}

void Api::notify_test(HttpResponse& resp, const ApiKey& key) {
    if (!notifier_ || !notifier_->stats().enabled)
        return resp.error(409, "no notification channels configured (see 'notify:' in sentinel.yaml)");
    auto results = notifier_->send_test(key.name);
    std::string out;
    JsonWriter w(out);
    w.begin_object().key("results").begin_array();
    for (auto& r : results) w.begin_object().kv("name", r.name).kv("ok", r.ok).kv("error", r.error).end_object();
    w.end_array().end_object();
    resp.json(200, std::move(out));
}

// ---------------- Список серверов на диске ----------------

void Api::load_agents() {
    std::ifstream in(agents_file_, std::ios::binary);
    if (!in) return;
    std::stringstream ss;
    ss << in.rdbuf();
    JValue v;
    std::string err;
    if (!json_parse(ss.str(), v, err) || !v.get("agents") || !v.get("agents")->is_array()) {
        log::warn("agents: cannot read ", agents_file_, ": ", err);
        return;
    }
    std::lock_guard<std::mutex> lock(agents_mu_);
    for (auto& o : v.get("agents")->arr) {
        auto str = [&](const char* k) {
            auto* x = o.get(k);
            return x && x->is_string() ? x->s : std::string();
        };
        auto num = [&](const char* k) -> int64_t {
            auto* x = o.get(k);
            return x && x->is_number() ? x->i : 0;
        };
        std::string name = str("key_name");
        if (name.empty()) continue;
        AgentInfo a;
        a.host = str("host");
        a.version = str("agent");
        a.remote_addr = str("remote_addr");
        a.firewall = str("firewall");
        a.first_seen = num("first_seen_ms");
        a.last_seen = num("last_seen_ms");
        a.events = uint64_t(num("events"));
        a.requests = uint64_t(num("requests"));
        a.blocks_synced = num("blocks_synced_ms");
        agents_[name] = a;
    }
}

void Api::save_agents() {
    std::string out;
    {
        std::lock_guard<std::mutex> lock(agents_mu_);
        if (!agents_dirty_) return;
        agents_dirty_ = false;
        JsonWriter w(out);
        w.begin_object().key("agents").begin_array();
        for (auto& kv : agents_) {
            const AgentInfo& a = kv.second;
            w.begin_object().kv("key_name", kv.first).kv("host", a.host).kv("agent", a.version);
            w.kv("remote_addr", a.remote_addr).kv("firewall", a.firewall);
            w.kv("first_seen_ms", a.first_seen).kv("last_seen_ms", a.last_seen).kv("events", a.events);
            w.kv("requests", a.requests).kv("blocks_synced_ms", a.blocks_synced).end_object();
        }
        w.end_array().end_object();
    }
    std::string tmp = agents_file_ + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        f << out;
        if (!f) return;
    }
    std::error_code ec;
    std::filesystem::rename(tmp, agents_file_, ec);
    if (ec) {
        std::filesystem::remove(agents_file_, ec);
        std::filesystem::rename(tmp, agents_file_, ec);
    }
}

}  // namespace sentinel
