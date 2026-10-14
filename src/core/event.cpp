#include "core/event.hpp"

#include "core/util.hpp"

namespace sentinel {

static const char* kFieldNames[kFieldCount] = {
    "source", "type", "host", "process", "src_ip", "src_port", "dst_ip",
    "dst_port", "proto", "user", "action", "outcome", "http.method", "http.path",
    "http.status", "http.user_agent", "http.referer", "bytes", "message", "raw"};

const char* field_name(Field f) {
    size_t i = size_t(f);
    return i < kFieldCount ? kFieldNames[i] : "?";
}

std::optional<Field> field_from_name(std::string_view name) {
    for (size_t i = 0; i < kFieldCount; ++i)
        if (name == kFieldNames[i]) return Field(i);
    struct Alias {
        const char* name;
        Field f;
    };
    static const Alias aliases[] = {
        {"source_ip", Field::SrcIp},       {"client_ip", Field::SrcIp},       {"ip", Field::SrcIp},
        {"remote_addr", Field::SrcIp},     {"source.ip", Field::SrcIp},       {"src", Field::SrcIp},
        {"source_port", Field::SrcPort},   {"source.port", Field::SrcPort},   {"sport", Field::SrcPort},
        {"dest_ip", Field::DstIp},         {"destination_ip", Field::DstIp},  {"destination.ip", Field::DstIp},
        {"dst", Field::DstIp},             {"dest_port", Field::DstPort},     {"destination_port", Field::DstPort},
        {"destination.port", Field::DstPort}, {"dport", Field::DstPort},      {"protocol", Field::Proto},
        {"username", Field::User},         {"user.name", Field::User},        {"hostname", Field::Host},
        {"host.name", Field::Host},        {"event_type", Field::Type},       {"event.category", Field::Type},
        {"result", Field::Outcome},        {"event.outcome", Field::Outcome}, {"event.action", Field::Action},
        {"method", Field::HttpMethod},     {"http.request.method", Field::HttpMethod},
        {"path", Field::HttpPath},         {"url", Field::HttpPath},          {"uri", Field::HttpPath},
        {"request_uri", Field::HttpPath},  {"url.original", Field::HttpPath},
        {"status_code", Field::HttpStatus}, {"http.response.status_code", Field::HttpStatus},
        {"user_agent", Field::HttpUserAgent}, {"user_agent.original", Field::HttpUserAgent},
        {"http_user_agent", Field::HttpUserAgent}, {"referer", Field::HttpReferer},
        {"referrer", Field::HttpReferer},  {"http.request.referrer", Field::HttpReferer},
        {"bytes_sent", Field::Bytes},      {"body_bytes_sent", Field::Bytes}, {"msg", Field::Message},
        {"program", Field::Process},       {"app", Field::Process},           {"process.name", Field::Process},
        {"raw_data", Field::Raw},          {"event.original", Field::Raw},
    };
    for (auto& a : aliases)
        if (name == a.name) return a.f;
    return std::nullopt;
}

std::string_view Event::get(std::string_view name) const {
    if (auto fld = field_from_name(name)) return f[size_t(*fld)];
    if (starts_with(name, "extra.")) name.remove_prefix(6);
    if (auto* v = extra_get(name)) return *v;
    return {};
}

const std::string* Event::extra_get(std::string_view key) const {
    for (auto& kv : extra)
        if (kv.first == key) return &kv.second;
    return nullptr;
}

void Event::extra_set(std::string_view key, std::string_view value) {
    for (auto& kv : extra) {
        if (kv.first == key) {
            kv.second.assign(value.data(), value.size());
            return;
        }
    }
    extra.emplace_back(std::string(key), std::string(value));
}

void Event::clear() {
    id = 0;
    ts = 0;
    received = 0;
    for (auto& s : f) s.clear();
    extra.clear();
}

const char* severity_name(Severity s) {
    switch (s) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
    }
    return "medium";
}

std::optional<Severity> severity_from_name(std::string_view s) {
    if (iequals(s, "info")) return Severity::Info;
    if (iequals(s, "low")) return Severity::Low;
    if (iequals(s, "medium")) return Severity::Medium;
    if (iequals(s, "high")) return Severity::High;
    if (iequals(s, "critical")) return Severity::Critical;
    return std::nullopt;
}

const char* alert_status_name(AlertStatus s) {
    switch (s) {
        case AlertStatus::New: return "new";
        case AlertStatus::Acknowledged: return "acknowledged";
        case AlertStatus::Resolved: return "resolved";
        case AlertStatus::FalsePositive: return "false_positive";
    }
    return "new";
}

std::optional<AlertStatus> alert_status_from_name(std::string_view s) {
    if (s == "new") return AlertStatus::New;
    if (s == "acknowledged") return AlertStatus::Acknowledged;
    if (s == "resolved") return AlertStatus::Resolved;
    if (s == "false_positive") return AlertStatus::FalsePositive;
    return std::nullopt;
}

}  // namespace sentinel
