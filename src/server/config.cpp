#include "server/config.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "core/crypto.hpp"
#include "core/util.hpp"
#include "core/yaml.hpp"

namespace fs = std::filesystem;

namespace sentinel {

const char* role_name(Role r) {
    switch (r) {
        case Role::Ingest: return "ingest";
        case Role::Read: return "read";
        case Role::Analyst: return "analyst";
        case Role::Admin: return "admin";
    }
    return "read";
}

bool role_from_name(const std::string& s, Role& out) {
    if (s == "ingest") out = Role::Ingest;
    else if (s == "read") out = Role::Read;
    else if (s == "analyst") out = Role::Analyst;
    else if (s == "admin") out = Role::Admin;
    else return false;
    return true;
}

bool role_can_ingest(Role r) { return r == Role::Ingest || r == Role::Admin; }
bool role_can_read(Role r) { return r != Role::Ingest; }
bool role_can_change_alerts(Role r) { return r == Role::Analyst || r == Role::Admin; }

static bool read_file(const std::string& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::stringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

static bool parse_keys(const YNode* list, std::vector<ApiKey>& out, std::string& error) {
    if (!list) return true;
    if (!list->is_seq()) {
        error = "api_keys must be a list";
        return false;
    }
    for (auto& k : list->seq) {
        ApiKey key;
        key.name = k.str("name");
        key.sha256 = to_lower(k.str("sha256"));
        std::string role = k.str("role", "read");
        if (key.name.empty() || key.sha256.size() != 64) {
            error = "api key needs 'name' and 64-hex 'sha256'";
            return false;
        }
        if (!role_from_name(role, key.role)) {
            error = "api key " + key.name + ": bad role '" + role + "' (ingest|read|analyst|admin)";
            return false;
        }
        out.push_back(std::move(key));
    }
    return true;
}

static bool get_severity(const YNode& n, const char* key, Severity& out, std::string& error) {
    std::string v = n.str(key);
    if (v.empty()) return true;
    auto s = severity_from_name(v);
    if (!s) {
        error = std::string(key) + ": bad severity '" + v + "' (info|low|medium|high|critical)";
        return false;
    }
    out = *s;
    return true;
}

static bool get_duration(const YNode& n, const char* key, int64_t& out, std::string& error) {
    std::string v = n.str(key);
    if (v.empty()) return true;
    auto d = parse_duration_ms(v);
    if (!d) {
        error = std::string(key) + ": bad duration '" + v + "' (examples: 30s, 10m, 1h, 7d, 0)";
        return false;
    }
    out = *d;
    return true;
}

static bool no_crlf(const std::string& s) { return s.find_first_of("\r\n") == std::string::npos; }

static bool parse_notify(const YNode* n, Config& cfg, std::string& error) {
    if (!n) return true;
    if (!n->is_map()) {
        error = "notify must be a map";
        return false;
    }
    NotifyConfig& c = cfg.notify;
    if (!get_severity(*n, "min_severity", c.min_severity, error)) return false;
    if (!get_duration(*n, "cooldown", c.cooldown_ms, error)) return false;
    if (!get_duration(*n, "batch", c.batch_ms, error)) return false;
    c.batch_ms = std::clamp<int64_t>(c.batch_ms, 500, 600000);
    c.panel_url = n->str("panel_url");
    c.ca_file = n->str("ca_file");
    c.pin = n->str("pin");
    c.mode = to_lower(n->str("mode", "alerts"));
    if (c.mode != "alerts" && c.mode != "incidents") {
        error = "notify.mode must be alerts | incidents";
        return false;
    }
    if (const YNode* t = n->get("telegram")) {
        c.telegram.bot_token = t->str("bot_token");
        c.telegram.chat_id = t->str("chat_id");
        c.telegram.api_url = t->str("api_url", c.telegram.api_url);
        if (c.telegram.bot_token.empty() != c.telegram.chat_id.empty()) {
            error = "notify.telegram needs both bot_token and chat_id";
            return false;
        }
    }
    if (const YNode* w = n->get("webhook")) {
        c.webhook.url = w->str("url");
        c.webhook.format = to_lower(w->str("format", "json"));
        if (c.webhook.format != "json" && c.webhook.format != "slack" && c.webhook.format != "discord") {
            error = "notify.webhook.format must be json | slack | discord";
            return false;
        }
    }
    if (const YNode* e = n->get("email")) {
        std::string smtp = e->str("smtp");
        size_t colon = smtp.rfind(':');
        if (!smtp.empty()) {
            c.email.host = smtp.substr(0, colon);
            if (colon != std::string::npos) {
                auto p = parse_uint(smtp.substr(colon + 1));
                if (!p || *p == 0 || *p > 65535) {
                    error = "notify.email.smtp must be host:port";
                    return false;
                }
                c.email.port = uint16_t(*p);
            }
        }
        c.email.tls = to_lower(e->str("tls", "auto"));
        if (c.email.tls != "auto" && c.email.tls != "starttls" && c.email.tls != "tls" && c.email.tls != "none") {
            error = "notify.email.tls must be auto | starttls | tls | none";
            return false;
        }
        c.email.username = e->str("username");
        c.email.password = e->str("password");
        c.email.from = e->str("from", c.email.username);
        c.email.to = e->strings("to");
        auto valid_addr = [](const std::string& a) {
            return no_crlf(a) && a.find('@') != std::string::npos && a.find_first_of("<> ,;") == std::string::npos;
        };
        if (!c.email.host.empty()) {
            if (!valid_addr(c.email.from)) {
                error = "notify.email.from must be an e-mail address";
                return false;
            }
            if (c.email.to.empty()) {
                error = "notify.email.to needs at least one address";
                return false;
            }
            for (auto& t : c.email.to)
                if (!valid_addr(t)) {
                    error = "notify.email.to: bad address '" + t + "'";
                    return false;
                }
        }
    }
    return true;
}

static bool parse_response(const YNode* n, Config& cfg, std::string& error) {
    ResponseConfig& r = cfg.response;
    // Белый список по умолчанию пустой: частные сети и так не блокируются автоматически.
    if (!n) return true;
    if (!n->is_map()) {
        error = "response must be a map";
        return false;
    }
    // Поддерживаются оба вида: "auto_block: false" и "auto_block: { enabled: ..., duration: ... }"
    const YNode* sub = n->get("auto_block");
    if (sub && sub->is_scalar()) {
        if (auto b = n->boolean("auto_block")) r.auto_block = *b;
        sub = nullptr;
    }
    if (sub && sub->is_map()) {
        if (auto b = sub->boolean("enabled")) r.auto_block = *b;
    }
    const YNode* ab = (sub && sub->is_map()) ? sub : n;
    if (!get_severity(*ab, "min_severity", r.min_severity, error)) return false;
    if (!get_duration(*ab, "duration", r.duration_ms, error)) return false;
    r.rules = ab->strings("rules");
    if (auto b = ab->boolean("block_private")) r.block_private = *b;
    if (auto m = ab->integer("max_per_minute")) r.max_per_minute = int(std::clamp<int64_t>(*m, 1, 100000));
    std::vector<std::string> allow = n->strings("allowlist");
    if (ab != n)
        for (auto& a : ab->strings("allowlist")) allow.push_back(a);
    for (auto& a : allow) {
        auto c = parse_cidr(a);
        if (!c) {
            error = "response.allowlist: bad address or network '" + a + "'";
            return false;
        }
        r.allowlist.push_back(*c);
    }
    return true;
}

bool load_config(const std::string& path, Config& cfg, std::string& error) {
    std::string text;
    if (path.empty() || !read_file(path, text)) {
        if (!path.empty() && fs::exists(path)) {
            error = "cannot read config " + path;
            return false;
        }
        cfg.keys_file = cfg.data_dir + "/keys.yaml";
        return true;
    }
    cfg.source = path;
    YNode n;
    if (!parse_yaml(text, n, error)) {
        error = path + ": " + error;
        return false;
    }
    if (!n.is_map() && !n.is_null()) {
        error = path + ": config must be a map";
        return false;
    }
    std::string listen = n.str("listen", "127.0.0.1:8080");
    size_t colon = listen.rfind(':');
    if (colon == std::string::npos) {
        error = "listen must be host:port";
        return false;
    }
    cfg.listen_host = listen.substr(0, colon);
    if (cfg.listen_host.size() >= 2 && cfg.listen_host.front() == '[' && cfg.listen_host.back() == ']')
        cfg.listen_host = cfg.listen_host.substr(1, cfg.listen_host.size() - 2);
    auto port = parse_uint(listen.substr(colon + 1));
    if (!port || *port > 65535) {
        error = "bad port in listen";
        return false;
    }
    cfg.listen_port = uint16_t(*port);
    cfg.data_dir = n.str("data_dir", cfg.data_dir);
    cfg.rules_dir = n.str("rules_dir", cfg.rules_dir);
    cfg.keys_file = n.str("keys_file", cfg.data_dir + "/keys.yaml");
    if (auto v = n.integer("retention_days")) cfg.retention_days = int(*v);
    if (auto v = n.integer("workers")) cfg.workers = int(*v);
    if (auto v = n.integer("max_body_mb")) cfg.max_body_mb = size_t(*v);
    if (auto v = n.integer("queue_events")) cfg.queue_events = size_t(*v);
    if (std::string dt = to_lower(n.str("detect_threads")); !dt.empty() && dt != "auto") {
        auto v = parse_int(dt);
        if (!v || *v < 1 || *v > 64) {
            error = "detect_threads must be auto or a number from 1 to 64";
            return false;
        }
        cfg.detect_threads = int(*v);
    }
    if (std::string st = to_lower(n.str("store_threads")); !st.empty() && st != "auto") {
        auto v = parse_int(st);
        if (!v || *v < 0 || *v > 16) {
            error = "store_threads must be auto or a number from 0 to 16";
            return false;
        }
        cfg.store_threads = int(*v);
    }
    if (auto v = n.boolean("fsync")) cfg.fsync = *v;
    cfg.log_level = n.str("log_level", cfg.log_level);
    if (const YNode* tls = n.get("tls")) {
        cfg.tls_cert = tls->str("cert");
        cfg.tls_key = tls->str("key");
        if (cfg.tls_cert.empty() != cfg.tls_key.empty()) {
            error = "tls needs both 'cert' and 'key'";
            return false;
        }
    }
    cfg.public_url = n.str("public_url");
    cfg.web_dir = n.str("web_dir", cfg.web_dir);
    if (!parse_notify(n.get("notify"), cfg, error)) return false;
    if (!parse_response(n.get("response"), cfg, error)) return false;
    cfg.geo_db = n.str("geo_db", cfg.data_dir + "/geo/geo.bin");
    if (const YNode* t = n.get("threat_intel"); t && !t->is_null()) {
        if (!t->is_map()) {
            error = "threat_intel must be a map";
            return false;
        }
        if (!get_duration(*t, "refresh", cfg.threat.refresh_ms, error)) return false;
        cfg.threat.refresh_ms = std::max<int64_t>(cfg.threat.refresh_ms, 60000);
        cfg.threat.ca_file = t->str("ca_file");
        if (const YNode* lists = t->get("lists")) {
            for (auto& l : lists->seq) {
                ThreatListConfig c;
                c.name = l.str("name");
                c.url = l.str("url");
                c.file = l.str("file");
                bool good_name = !c.name.empty() && c.name.size() <= 40;
                for (char ch : c.name) good_name &= is_alnum(ch) || ch == '-' || ch == '_';
                if (!good_name) {
                    error = "threat_intel: each list needs 'name' (letters, digits, - and _)";
                    return false;
                }
                if (c.url.empty() == c.file.empty()) {
                    error = "threat_intel list " + c.name + ": set either 'url' or 'file'";
                    return false;
                }
                if (!c.url.empty() && !starts_with(c.url, "http://") && !starts_with(c.url, "https://")) {
                    error = "threat_intel list " + c.name + ": url must start with http:// or https://";
                    return false;
                }
                for (auto& o : cfg.threat.lists)
                    if (o.name == c.name) {
                        error = "threat_intel: duplicate list name " + c.name;
                        return false;
                    }
                cfg.threat.lists.push_back(std::move(c));
            }
        }
        if (cfg.threat.lists.size() > 64) {
            error = "threat_intel: at most 64 lists";
            return false;
        }
    }
    if (const YNode* inc = n.get("incidents"); inc && !inc->is_null()) {
        if (!inc->is_map()) {
            error = "incidents must be a map";
            return false;
        }
        if (!get_duration(*inc, "window", cfg.incident_window_ms, error)) return false;
        if (cfg.incident_window_ms < 60000 || cfg.incident_window_ms > 30LL * 86400000) {
            error = "incidents.window must be from 1m to 30d";
            return false;
        }
    }
    if (const YNode* rep = n.get("reports"); rep && !rep->is_null()) {
        if (!rep->is_map()) {
            error = "reports must be a map";
            return false;
        }
        const YNode* wk = rep->get("weekly");
        if (wk && wk->is_scalar()) {
            if (auto b = rep->boolean("weekly")) cfg.reports.weekly = *b;
        } else if (wk && wk->is_map()) {
            cfg.reports.weekly = true;
            if (auto b = wk->boolean("enabled")) cfg.reports.weekly = *b;
            std::string day = to_lower(wk->str("day", "monday"));
            static const char* en[] = {"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"};
            static const char* ru[] = {"воскресенье", "понедельник", "вторник", "среда", "четверг", "пятница", "суббота"};
            static const char* sh[] = {"sun", "mon", "tue", "wed", "thu", "fri", "sat"};
            int wd = -1;
            for (int i = 0; i < 7; ++i)
                if (day == en[i] || day == ru[i] || day == sh[i]) wd = i;
            if (wd < 0) {
                error = "reports.weekly.day must be a weekday name (monday, вторник, …)";
                return false;
            }
            cfg.reports.weekday = wd;
            std::string t = wk->str("time", "09:00");
            auto tcolon = t.find(':');
            auto hh = parse_uint(t.substr(0, tcolon));
            auto mm = tcolon == std::string::npos ? std::optional<uint64_t>(0) : parse_uint(t.substr(tcolon + 1));
            if (!hh || !mm || *hh > 23 || *mm > 59) {
                error = "reports.weekly.time must be HH:MM";
                return false;
            }
            cfg.reports.minute_of_day = int(*hh * 60 + *mm);
            cfg.reports.to = wk->strings("to");
            for (auto& a : cfg.reports.to)
                if (!no_crlf(a) || a.find('@') == std::string::npos || a.find_first_of("<> ,;") != std::string::npos) {
                    error = "reports.weekly.to: bad address '" + a + "'";
                    return false;
                }
        }
        if (cfg.reports.weekly && !cfg.notify.email.enabled()) {
            error = "reports.weekly needs notify.email (SMTP server) to send the letter";
            return false;
        }
    }
    if (cfg.retention_days < 1 || cfg.workers < 1 || cfg.workers > 256 || cfg.max_body_mb < 1) {
        error = "bad numeric value in config (retention_days>=1, workers 1..256, max_body_mb>=1)";
        return false;
    }
    return parse_keys(n.get("api_keys"), cfg.keys, error);
}

bool read_keys_file(const std::string& path, std::vector<ApiKey>& out, std::string& error) {
    std::string text;
    if (path.empty() || !read_file(path, text)) return true;  // файла ещё нет
    YNode n;
    if (!parse_yaml(text, n, error)) {
        error = path + ": " + error;
        return false;
    }
    if (n.is_null()) return true;
    const YNode* list = n.is_seq() ? &n : n.get("api_keys");
    if (!parse_keys(list, out, error)) {
        error = path + ": " + error;
        return false;
    }
    return true;
}

bool load_keys_file(Config& cfg, std::string& error) { return read_keys_file(cfg.keys_file, cfg.keys, error); }

bool valid_key_name(const std::string& name) {
    if (name.empty() || name.size() > 100) return false;
    for (char c : name)
        if (!(is_alpha(c) || is_digit(c) || c == '-' || c == '_' || c == '.')) return false;
    return true;
}

bool append_key_file(const std::string& path, const ApiKey& k, std::string& error) {
    std::error_code ec;
    fs::path p(path);
    if (p.has_parent_path()) fs::create_directories(p.parent_path(), ec);
    bool fresh = !fs::exists(p, ec);
    std::ofstream out(path, std::ios::app | std::ios::binary);
    if (!out) {
        error = "cannot write " + path;
        return false;
    }
    if (fresh) out << "# Ключи доступа SentinelCore. Хранятся только SHA-256 хеши.\napi_keys:\n";
    out << "  - name: " << k.name << "\n    role: " << role_name(k.role) << "\n    sha256: " << k.sha256 << "\n";
    out.close();
    if (!out) {
        error = "cannot write " + path;
        return false;
    }
#ifndef _WIN32
    fs::permissions(p, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
#endif
    return true;
}

bool create_key(Config& cfg, const std::string& name, Role role, std::string& secret, std::string& error) {
    if (!valid_key_name(name)) {
        error = "key name may contain only letters, digits, - _ .";
        return false;
    }
    for (auto& k : cfg.keys)
        if (k.name == name) {
            error = "key '" + name + "' already exists";
            return false;
        }
    secret = "snt_" + random_hex(24);
    ApiKey k{name, role, sha256_hex(secret)};
    if (!append_key_file(cfg.keys_file, k, error)) return false;
    cfg.keys.push_back(k);
    return true;
}

std::string agent_server_url(const Config& cfg) {
    if (!cfg.public_url.empty()) return cfg.public_url;
    std::string host = cfg.listen_host;
    if (host == "0.0.0.0" || host == "::" || host.empty()) host = "<адрес-сервера>";
    if (host.find(':') != std::string::npos) host = "[" + host + "]";
    return std::string(cfg.tls_cert.empty() ? "http://" : "https://") + host + ":" + std::to_string(cfg.listen_port);
}

}  // namespace sentinel
