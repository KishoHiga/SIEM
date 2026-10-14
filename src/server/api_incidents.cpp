// SentinelCore — HTTP API: инциденты (алерты одной атаки в одной карточке).
#include <algorithm>

#include "core/json.hpp"
#include "core/util.hpp"
#include "server/api.hpp"
#include "server/json_out.hpp"

namespace sentinel {

using net::HttpRequest;
using net::HttpResponse;

void write_incident(JsonWriter& w, const Incident& i, bool full) {
    w.begin_object();
    w.kv("id", i.id);
    w.kv("title", i.title());
    w.kv("key", i.key);
    w.kv("src_ip", i.src_ip).kv("user", i.user).kv("host", i.host);
    w.kv("severity", severity_name(i.severity));
    w.kv("status", incident_status_name(i.status));
    w.kv("active", i.active());
    w.kv("assignee", i.assignee);
    w.kv("created", format_iso8601(i.created));
    w.kv("updated", format_iso8601(i.updated));
    w.kv("first_alert", i.first_alert ? format_iso8601(i.first_alert) : std::string());
    w.kv("last_alert", i.last_alert ? format_iso8601(i.last_alert) : std::string());
    w.kv("alert_count", i.alert_count);
    w.kv("notes_count", uint64_t(i.notes.size()));
    if (i.merged_into) w.kv("merged_into", i.merged_into);
    w.key("rules").begin_array();
    for (auto& r : i.rules)
        w.begin_object()
            .kv("rule_id", r.rule_id)
            .kv("rule_name", r.rule_name)
            .kv("severity", severity_name(r.severity))
            .kv("count", r.count)
            .end_object();
    w.end_array();
    w.key("hosts").begin_array();
    for (auto& h : i.hosts) w.value(h);
    w.end_array();
    w.key("users").begin_array();
    for (auto& u : i.users) w.value(u);
    w.end_array();
    if (full) {
        w.key("notes").begin_array();
        for (auto& n : i.notes)
            w.begin_object().kv("id", n.id).kv("ts", format_iso8601(n.ts)).kv("by", n.by).kv("text", n.text).end_object();
        w.end_array();
        w.key("history").begin_array();
        for (auto& h : i.history)
            w.begin_object()
                .kv("ts", format_iso8601(h.ts))
                .kv("by", h.by)
                .kv("kind", h.kind)
                .kv("value", h.value)
                .end_object();
        w.end_array();
    }
    w.end_object();
}

namespace {

// Что делать с алертами инцидента при смене его статуса.
std::optional<AlertStatus> alert_status_for(IncidentStatus s) {
    switch (s) {
        case IncidentStatus::InProgress: return AlertStatus::Acknowledged;
        case IncidentStatus::Resolved: return AlertStatus::Resolved;
        case IncidentStatus::FalsePositive: return AlertStatus::FalsePositive;
        default: return std::nullopt;
    }
}

}  // namespace

void Api::incidents_route(const HttpRequest& req, HttpResponse& resp, const ApiKey& key,
                          const std::vector<std::string_view>& parts) {
    if (!incidents_) return resp.error(503, "incidents are not enabled");
    if (parts.size() == 3) {
        if (req.method != "GET") return resp.error(405, "use GET");
        return list_incidents(req, resp);
    }
    auto id = parse_uint(parts[3]);
    if (!id) return resp.error(400, "bad id");
    if (parts.size() == 4) {
        if (req.method != "GET") return resp.error(405, "use GET");
        return get_incident(*id, resp);
    }
    if (parts.size() == 5) {
        if (req.method != "POST") return resp.error(405, "use POST");
        if (!role_can_change_alerts(key.role))
            return resp.error(403, std::string("role '") + role_name(key.role) + "' is not allowed here");
        return incident_action(*id, parts[4], req, resp, key);
    }
    resp.error(404, "not found");
}

bool parse_incident_query(const HttpRequest& req, IncidentQuery& q, std::string& error) {
    if (!req.param("status").empty()) {
        auto s = incident_status_from_name(req.param("status"));
        if (!s) return error = "bad status (open|in_progress|resolved|false_positive)", false;
        q.status = *s;
    }
    std::string_view act = req.param("active");
    q.active_only = act == "1" || act == "true";
    if (!req.param("severity").empty()) {
        auto s = severity_from_name(req.param("severity"));
        if (!s) return error = "bad severity (info|low|medium|high|critical)", false;
        q.min_severity = *s;
    }
    q.text = std::string(trim(req.param("q")));
    q.assignee = std::string(req.param("assignee"));
    if (auto b = parse_uint(req.param("before_id"))) q.before_id = *b;
    return true;
}

void Api::list_incidents(const HttpRequest& req, HttpResponse& resp) {
    IncidentQuery q;
    std::string perr;
    if (!parse_incident_query(req, q, perr)) return resp.error(400, perr);
    if (auto l = parse_uint(req.param("limit"))) q.limit = size_t(std::clamp<uint64_t>(*l, 1, 500));
    auto list = incidents_->list(q);
    auto counts = incidents_->counts();
    std::string b;
    JsonWriter w(b);
    w.begin_object().key("incidents").begin_array();
    for (auto& i : list) write_incident(w, i, false);
    w.end_array();
    w.key("next_before_id");
    if (list.size() == q.limit && !list.empty()) w.value(list.back().id);
    else w.null();
    w.kv("active", counts.active).kv("unassigned", counts.unassigned);
    w.end_object();
    resp.json(200, std::move(b));
}

void Api::get_incident(uint64_t id, HttpResponse& resp) {
    auto inc = incidents_->get(id);
    if (!inc) return resp.error(404, "incident not found");
    std::string b;
    JsonWriter w(b);
    w.begin_object().key("incident");
    write_incident(w, *inc, true);
    // алерты — свежие первыми (не больше 300; старые остаются в разделе «Алерты»)
    w.key("alerts").begin_array();
    size_t shown = 0;
    for (auto it = inc->alert_ids.rbegin(); it != inc->alert_ids.rend() && shown < 300; ++it) {
        if (auto a = alerts_.get(*it)) {
            write_alert(w, *a, id);
            ++shown;
        }
    }
    w.end_array();
    w.kv("alerts_shown", uint64_t(shown));
    if (!inc->src_ip.empty()) {
        w.key("ip").begin_object();
        IpReport r;
        if (enricher_) r = enricher_->lookup(inc->src_ip);
        w.kv("ip", inc->src_ip).kv("internal", r.internal);
        w.kv("country", r.country).kv("city", r.city).kv("org", r.org);
        w.kv("asn", r.asn);
        w.key("lists").begin_array();
        for (auto& l : r.lists) w.value(l);
        w.end_array();
        w.key("block");
        std::optional<Block> blk;
        if (blocks_) blk = blocks_->find(inc->src_ip);
        if (blk) write_block(w, *blk);
        else w.null();
        w.end_object();
    }
    w.end_object();
    resp.json(200, std::move(b));
}

void Api::incident_action(uint64_t id, std::string_view action, const HttpRequest& req, HttpResponse& resp,
                          const ApiKey& key) {
    JValue v;
    std::string err;
    if (!json_parse(req.body.empty() ? std::string_view("{}") : std::string_view(req.body), v, err) || !v.is_object())
        return resp.error(400, "expected a JSON object");
    auto str = [&](const char* k) -> const std::string* {
        const JValue* x = v.get(k);
        return x && x->is_string() ? &x->s : nullptr;
    };
    bool ok = false;
    uint64_t alerts_changed = 0;
    if (action == "status") {
        const std::string* s = str("status");
        if (!s) return resp.error(400, "missing 'status'");
        auto st = incident_status_from_name(*s);
        if (!st) return resp.error(400, "bad status (open|in_progress|resolved|false_positive)");
        auto before = incidents_->get(id);
        if (!before) return resp.error(404, "incident not found");
        ok = incidents_->set_status(id, *st, key.name, err);
        // алерты инцидента получают соответствующий статус (по умолчанию — да)
        const JValue* ca = v.get("close_alerts");
        bool close_alerts = !(ca && ca->is_bool() && !ca->b);
        if (ok && close_alerts)
            if (auto ast = alert_status_for(*st)) {
                for (uint64_t aid : before->alert_ids) {
                    auto a = alerts_.get(aid);
                    if (!a || a->status == *ast) continue;
                    // «в работе» не трогает уже закрытые алерты
                    if (*ast == AlertStatus::Acknowledged && a->status != AlertStatus::New) continue;
                    if (alerts_.set_status(aid, *ast)) ++alerts_changed;
                }
            }
    } else if (action == "assign") {
        const std::string* s = str("assignee");
        if (!s) return resp.error(400, "missing 'assignee'");
        std::string who = *s == "me" ? key.name : std::string(trim(*s));
        if (!who.empty() && !valid_key_name(who)) return resp.error(400, "bad assignee name");
        ok = incidents_->assign(id, who, key.name, err);
    } else if (action == "notes") {
        const std::string* s = str("text");
        std::string text = s ? std::string(trim(*s)) : std::string();
        if (text.empty()) return resp.error(400, "missing 'text'");
        if (text.size() > 10000) return resp.error(400, "note is too long (max 10000 bytes)");
        ok = incidents_->add_note(id, key.name, text, err);
    } else if (action == "merge") {
        const JValue* into = v.get("into");
        uint64_t dst = 0;
        if (into && into->is_number() && into->is_int && into->i >= 1) dst = uint64_t(into->i);
        else if (into && into->is_string())
            if (auto p = parse_uint(into->s)) dst = *p;
        if (!dst) return resp.error(400, "missing 'into' (incident number)");
        ok = incidents_->merge(id, dst, key.name, err);
    } else {
        return resp.error(404, "not found");
    }
    if (!ok) return resp.error(err == "incident not found" ? 404 : 409, err);
    auto inc = incidents_->get(id);
    std::string b;
    JsonWriter w(b);
    w.begin_object().key("incident");
    if (inc) write_incident(w, *inc, true);
    else w.null();
    w.kv("alerts_changed", alerts_changed);
    w.end_object();
    resp.json(200, std::move(b));
}

}  // namespace sentinel
