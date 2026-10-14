// SentinelCore — HTTP API: правила (список, текст, сохранение, проверка, пробный запуск, история).
#include <algorithm>

#include "core/json.hpp"
#include "core/log.hpp"
#include "core/util.hpp"
#include "server/api.hpp"
#include "server/json_out.hpp"

namespace sentinel {

using net::HttpRequest;
using net::HttpResponse;

namespace {

void write_rule(JsonWriter& w, const Rule& r) {
    w.kv("id", r.id).kv("name", r.name).kv("description", r.description);
    w.kv("severity", severity_name(r.severity)).kv("type", rule_kind_name(r.kind));
    w.kv("enabled", r.enabled).kv("file", r.file);
    if (r.kind == Rule::Kind::Threshold) {
        w.kv("threshold", r.threshold).kv("window_seconds", r.window_ms / 1000);
        if (r.distinct) w.kv("distinct", r.distinct->name);
    }
    if (r.kind == Rule::Kind::Sequence) w.kv("within_seconds", r.within_ms / 1000).kv("steps", r.steps.size());
    w.key("group_by").begin_array();
    for (auto& g : r.group_by) w.value(g.name);
    w.end_array();
    w.key("tags").begin_array();
    for (auto& t : r.tags) w.value(t);
    w.end_array();
    w.kv("tests", r.tests.match.size() + r.tests.no_match.size());
}

void write_check(JsonWriter& w, const RuleCheck& c) {
    w.kv("ok", c.ok).kv("error", c.error).kv("file", c.file).kv("test_cases", c.test_cases);
    w.key("errors").begin_array();
    for (auto& e : c.errors) w.value(e);
    w.end_array().key("rule_ids").begin_array();
    for (auto& id : c.rule_ids) w.value(id);
    w.end_array().key("test_failures").begin_array();
    for (auto& f : c.test_failures)
        w.begin_object().kv("rule_id", f.rule_id).kv("line", f.line).kv("expected_alert", f.expected_alert).end_object();
    w.end_array();
}

bool body_source(const HttpRequest& req, HttpResponse& resp, JValue& v, std::string& source) {
    std::string err;
    if (!json_parse(req.body, v, err) || !v.is_object()) {
        resp.error(400, "expected JSON object");
        return false;
    }
    const JValue* s = v.get("source");
    if (!s || !s->is_string() || trim(s->s).empty()) {
        resp.error(400, "missing 'source' (rule YAML text)");
        return false;
    }
    source = s->s;
    return true;
}

}  // namespace

void Api::rules(HttpResponse& resp) {
    std::vector<Rule> list;
    std::vector<std::string> errors;
    if (rule_mgr_) {
        list = rule_mgr_->rules();
        errors = rule_mgr_->load_errors();
    } else {
        std::lock_guard<std::mutex> lock(rules_mu_);
        list = rules_list_;
    }
    auto counts = alerts_.counts_by_rule(now_ms() - 24 * 3600 * 1000LL);
    std::string out;
    JsonWriter w(out);
    w.begin_object().key("rules").begin_array();
    for (auto& r : list) {
        w.begin_object();
        write_rule(w, r);
        auto it = counts.find(r.id);
        RuleAlertCount c = it == counts.end() ? RuleAlertCount{} : it->second;
        w.key("alerts_24h").begin_object().kv("total", c.total).kv("open", c.open).kv("false_positive", c.false_positive);
        w.key("last");
        if (c.last) w.value(format_iso8601(c.last));
        else w.null();
        w.end_object();
        w.end_object();
    }
    w.end_array().kv("total", list.size()).kv("editable", rule_mgr_ != nullptr);
    w.key("errors").begin_array();
    for (auto& e : errors) w.value(e);
    w.end_array().end_object();
    resp.json(200, std::move(out));
}

void Api::rules_route(const HttpRequest& req, HttpResponse& resp, const ApiKey& key,
                      const std::vector<std::string_view>& parts) {
    const bool get = req.method == "GET", post = req.method == "POST", put = req.method == "PUT",
               del = req.method == "DELETE";
    const bool admin = key.role == Role::Admin, analyst = role_can_change_alerts(key.role);
    auto deny = [&](const char* who) { resp.error(403, std::string("only ") + who + " can do this"); };

    if (parts.size() == 3) {
        if (get) return rules(resp);
        if (post) {
            if (!admin) return deny("admin");
            return rule_save("", req, resp, key);
        }
        return resp.error(405, "use GET or POST");
    }
    if (!rule_mgr_) return resp.error(503, "rule editing is not available");
    std::string id = net::url_decode_component(parts[3], false);
    if (parts.size() == 4 && (id == "check" || id == "try" || id == "try-history")) {
        if (!post) return resp.error(405, "use POST");
        if (!analyst) return deny("analyst or admin");
        if (id == "check") return rule_check(req, resp);
        return rule_try(req, resp, id == "try-history");
    }
    if (parts.size() == 4) {
        if (get) return rule_get(id, resp);
        if (put) return admin ? rule_save(id, req, resp, key) : deny("admin");
        if (del) return admin ? rule_delete(id, resp, key) : deny("admin");
        return resp.error(405, "use GET, PUT or DELETE");
    }
    if (parts.size() == 5 && parts[4] == "enabled") {
        if (!post) return resp.error(405, "use POST");
        return admin ? rule_enabled(id, req, resp, key) : deny("admin");
    }
    if ((parts.size() == 5 || parts.size() == 6) && parts[4] == "history") {
        if (!get) return resp.error(405, "use GET");
        return rule_history(id, parts.size() == 6 ? net::url_decode_component(parts[5], false) : "", resp);
    }
    resp.error(404, "not found");
}

void Api::rule_get(const std::string& id, HttpResponse& resp) {
    std::string file, text, err;
    if (!rule_mgr_->source(id, file, text, err)) return resp.error(404, err);
    std::string out;
    JsonWriter w(out);
    w.begin_object().kv("file", file).kv("source", text);
    w.key("rule").begin_object();
    std::vector<std::string> same_file;
    for (auto& r : rule_mgr_->rules()) {
        if (r.id == id) {
            write_rule(w, r);
            auto counts = alerts_.counts_by_rule(now_ms() - 24 * 3600 * 1000LL);
            auto it = counts.find(r.id);
            RuleAlertCount c = it == counts.end() ? RuleAlertCount{} : it->second;
            w.key("alerts_24h").begin_object().kv("total", c.total).kv("open", c.open);
            w.kv("false_positive", c.false_positive).key("last");
            if (c.last) w.value(format_iso8601(c.last));
            else w.null();
            w.end_object();
        }
        if (r.file == file) same_file.push_back(r.id);
    }
    w.end_object().key("rules_in_file").begin_array();
    for (auto& s : same_file) w.value(s);
    w.end_array();
    // на это правило ссылаются цепочки
    w.key("used_by").begin_array();
    for (auto& r : rule_mgr_->rules())
        for (auto& st : r.steps)
            if (st.rule_id == id) {
                w.value(r.id);
                break;
            }
    w.end_array();
    w.kv("versions", rule_mgr_->history(id).size()).end_object();
    resp.json(200, std::move(out));
}

void Api::rule_save(const std::string& id, const HttpRequest& req, HttpResponse& resp, const ApiKey& key) {
    if (!rule_mgr_) return resp.error(503, "rule editing is not available");
    JValue v;
    std::string source;
    if (!body_source(req, resp, v, source)) return;
    RuleCheck c = rule_mgr_->save(id, source, key.name);
    std::string out;
    JsonWriter w(out);
    w.begin_object();
    write_check(w, c);
    w.end_object();
    if (!c.ok) return resp.json(c.error == "rule not found" ? 404 : 422, std::move(out));
    resp.json(id.empty() ? 201 : 200, std::move(out));
}

void Api::rule_delete(const std::string& id, HttpResponse& resp, const ApiKey& key) {
    RuleCheck c = rule_mgr_->remove(id, key.name);
    std::string out;
    JsonWriter w(out);
    w.begin_object();
    write_check(w, c);
    w.end_object();
    resp.json(c.ok ? 200 : (c.error == "rule not found" ? 404 : 422), std::move(out));
}

void Api::rule_enabled(const std::string& id, const HttpRequest& req, HttpResponse& resp, const ApiKey& key) {
    JValue v;
    std::string err;
    if (!json_parse(req.body, v, err) || !v.is_object() || !v.get("enabled") || !v.get("enabled")->is_bool())
        return resp.error(400, "expected JSON {\"enabled\": true|false}");
    RuleCheck c = rule_mgr_->set_enabled(id, v.get("enabled")->b, key.name);
    std::string out;
    JsonWriter w(out);
    w.begin_object();
    write_check(w, c);
    w.end_object();
    resp.json(c.ok ? 200 : (c.error == "rule not found" ? 404 : 422), std::move(out));
}

void Api::rule_history(const std::string& id, const std::string& version, HttpResponse& resp) {
    std::string out;
    JsonWriter w(out);
    if (!version.empty()) {
        std::string text;
        if (!rule_mgr_->version_text(id, version, text)) return resp.error(404, "version not found");
        w.begin_object().kv("version", version).kv("source", text).end_object();
        return resp.json(200, std::move(out));
    }
    w.begin_object().key("versions").begin_array();
    for (auto& h : rule_mgr_->history(id))
        w.begin_object().kv("version", h.name).kv("ts", format_iso8601(h.ts)).kv("action", h.action).kv("by", h.by).end_object();
    w.end_array().end_object();
    resp.json(200, std::move(out));
}

void Api::rule_check(const HttpRequest& req, HttpResponse& resp) {
    JValue v;
    std::string source;
    if (!body_source(req, resp, v, source)) return;
    std::string id;
    if (auto* i = v.get("id"); i && i->is_string()) id = i->s;
    RuleCheck c = rule_mgr_->check(id, source);
    std::string out;
    JsonWriter w(out);
    w.begin_object();
    write_check(w, c);
    w.end_object();
    resp.json(200, std::move(out));
}

void Api::rule_try(const HttpRequest& req, HttpResponse& resp, bool history) {
    JValue v;
    std::string source;
    if (!body_source(req, resp, v, source)) return;
    DryRun r;
    if (history) {
        int64_t hours = 24;
        if (auto* h = v.get("hours"); h && h->is_number()) hours = std::clamp<int64_t>(h->i, 1, 24 * 30);
        size_t max_events = 200000;
        if (auto* m = v.get("max_events"); m && m->is_number()) max_events = size_t(std::clamp<int64_t>(m->i, 1000, 2000000));
        std::unique_lock<std::mutex> lock(try_mu_, std::try_to_lock);
        if (!lock.owns_lock()) return resp.error(429, "another check is running, try again in a few seconds");
        int64_t now = now_ms();
        r = rule_mgr_->try_history(source, events_, now - hours * 3600 * 1000, now + 60000, max_events);
    } else {
        std::vector<std::string> lines;
        const JValue* l = v.get("lines");
        if (l && l->is_string()) {
            for (auto s : split(l->s, '\n')) lines.emplace_back(s);
        } else if (l && l->is_array()) {
            for (auto& x : l->arr)
                if (x.is_string()) lines.push_back(x.s);
        }
        if (lines.size() > 5000) return resp.error(413, "too many lines (max 5000)");
        std::string format = "auto";
        if (auto* f = v.get("format"); f && f->is_string()) format = f->s;
        int tz = 0;
        if (auto* t = v.get("tz_minutes"); t && t->is_number()) tz = int(std::clamp<int64_t>(t->i, -14 * 60, 14 * 60));
        r = rule_mgr_->try_lines(source, lines, format, tz);
    }
    std::string out;
    JsonWriter w(out);
    w.begin_object().kv("ok", r.ok).kv("error", r.error);
    w.key("errors").begin_array();
    for (auto& e : r.errors) w.value(e);
    w.end_array();
    w.key("tested").begin_array();
    for (auto& id : r.tested_ids) w.value(id);
    w.end_array().key("helpers").begin_array();
    for (auto& id : r.helper_ids) w.value(id);
    w.end_array();
    w.kv("events", r.events).kv("alerts_total", [&] {
        uint64_t n = 0;
        for (auto& kv : r.alerts_by_rule) n += kv.second;
        return n;
    }());
    w.key("alerts_by_rule").begin_object();
    for (auto& kv : r.alerts_by_rule) w.kv(kv.first, kv.second);
    w.end_object();
    w.kv("distinct_ips", r.distinct_ips).kv("took_ms", r.took_ms).kv("truncated", r.truncated);
    w.key("first_ts");
    if (r.first_ts) w.value(format_iso8601(r.first_ts));
    else w.null();
    w.key("last_ts");
    if (r.last_ts) w.value(format_iso8601(r.last_ts));
    else w.null();
    w.key("alerts").begin_array();
    for (auto& a : r.alerts) write_alert(w, a);
    w.end_array();
    if (!history) {
        w.key("lines").begin_array();
        for (auto& l : r.lines) {
            w.begin_object().kv("index", l.index).kv("parsed", l.parsed);
            if (l.parsed) {
                w.key("event");
                write_event(w, l.event);
            }
            w.key("alerts").begin_array();
            for (auto i : l.alerts) w.value(i);
            w.end_array().end_object();
        }
        w.end_array();
        w.key("tests").begin_object().kv("cases", r.tests.cases).key("failures").begin_array();
        for (auto& f : r.tests.failures)
            w.begin_object().kv("rule_id", f.rule_id).kv("line", f.line).kv("expected_alert", f.expected_alert).end_object();
        w.end_array().end_object();
    }
    w.end_object();
    resp.json(200, std::move(out));
}

}  // namespace sentinel
