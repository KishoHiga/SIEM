#include "server/json_out.hpp"

#include "core/util.hpp"

namespace sentinel {

void write_event(JsonWriter& w, const Event& e) {
    w.begin_object();
    w.kv("id", e.id);
    w.kv("ts", format_iso8601(e.ts));
    w.kv("ts_ms", e.ts);
    w.kv("received", format_iso8601(e.received));
    for (size_t i = 0; i < kFieldCount; ++i) {
        if (e.f[i].empty()) continue;
        w.kv(field_name(Field(i)), e.f[i]);
    }
    if (!e.extra.empty()) {
        w.key("extra").begin_object();
        for (auto& kv : e.extra) w.kv(kv.first, kv.second);
        w.end_object();
    }
    w.end_object();
}

void write_alert(JsonWriter& w, const Alert& a, uint64_t incident_id) {
    w.begin_object();
    w.kv("id", a.id);
    w.kv("ts", format_iso8601(a.ts));
    w.kv("created", format_iso8601(a.created));
    w.kv("rule_id", a.rule_id);
    w.kv("rule_name", a.rule_name);
    w.kv("severity", severity_name(a.severity));
    w.kv("status", alert_status_name(a.status));
    w.kv("src_ip", a.src_ip);
    w.kv("user", a.user);
    w.kv("host", a.host);
    w.kv("message", a.message);
    w.kv("count", a.count);
    if (incident_id) w.kv("incident_id", incident_id);
    w.key("event_ids").begin_array();
    for (auto id : a.event_ids) w.value(id);
    w.end_array();
    w.key("fields").begin_object();
    for (auto& kv : a.fields) w.kv(kv.first, kv.second);
    w.end_object();
    w.end_object();
}

void write_event_summary(JsonWriter& w, const Event& e) {
    w.begin_object();
    w.kv("id", e.id);
    w.kv("ts", format_iso8601(e.ts));
    for (Field f : {Field::Source, Field::Type, Field::Host, Field::SrcIp, Field::User, Field::Outcome}) {
        if (!e[f].empty()) w.kv(field_name(f), e[f]);
    }
    const std::string& m = e[Field::Message].empty() ? e[Field::Raw] : e[Field::Message];
    w.kv("message", m.size() > 240 ? m.substr(0, 240) + "..." : m);
    w.end_object();
}

}  // namespace sentinel
