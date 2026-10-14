#include "store/codec.hpp"

namespace sentinel {

// Версия формата события: при изменении полей увеличить и поддержать чтение старой.
static constexpr uint8_t kEventFormat = 1;
static constexpr uint8_t kAlertFormat = 1;

void encode_event(const Event& ev, std::string& out) {
    put_u8(out, kEventFormat);
    put_varint(out, ev.id);
    put_svarint(out, ev.ts);
    put_svarint(out, ev.received - ev.ts);
    put_varint(out, kFieldCount);
    for (size_t i = 0; i < kFieldCount; ++i) put_bytes(out, ev.f[i]);
    put_varint(out, ev.extra.size());
    for (auto& kv : ev.extra) {
        put_bytes(out, kv.first);
        put_bytes(out, kv.second);
    }
}

bool decode_event(Reader& r, Event& ev) {
    ev.clear();
    uint8_t fmt = r.u8();
    if (!r.ok() || fmt != kEventFormat) return false;
    ev.id = r.varint();
    ev.ts = r.svarint();
    ev.received = ev.ts + r.svarint();
    uint64_t nf = r.varint();
    if (!r.ok() || nf > 255) return false;
    for (uint64_t i = 0; i < nf; ++i) {
        std::string_view v = r.bytes();
        if (i < kFieldCount) ev.f[i].assign(v.data(), v.size());  // новые поля из будущих версий пропускаем
    }
    uint64_t ne = r.varint();
    if (!r.ok() || ne > 100000) return false;
    ev.extra.reserve(size_t(ne));
    for (uint64_t i = 0; i < ne; ++i) {
        std::string_view k = r.bytes();
        std::string_view v = r.bytes();
        ev.extra.emplace_back(std::string(k), std::string(v));
    }
    return r.ok();
}

void encode_alert(const Alert& a, std::string& out) {
    put_u8(out, kAlertFormat);
    put_varint(out, a.id);
    put_svarint(out, a.ts);
    put_svarint(out, a.created);
    put_bytes(out, a.rule_id);
    put_bytes(out, a.rule_name);
    put_u8(out, uint8_t(a.severity));
    put_u8(out, uint8_t(a.status));
    put_bytes(out, a.src_ip);
    put_bytes(out, a.user);
    put_bytes(out, a.host);
    put_bytes(out, a.message);
    put_varint(out, a.count);
    put_varint(out, a.event_ids.size());
    for (uint64_t id : a.event_ids) put_varint(out, id);
    put_varint(out, a.fields.size());
    for (auto& kv : a.fields) {
        put_bytes(out, kv.first);
        put_bytes(out, kv.second);
    }
}

bool decode_alert(Reader& r, Alert& a) {
    a = Alert{};
    if (r.u8() != kAlertFormat) return false;
    a.id = r.varint();
    a.ts = r.svarint();
    a.created = r.svarint();
    a.rule_id = std::string(r.bytes());
    a.rule_name = std::string(r.bytes());
    uint8_t sev = r.u8(), st = r.u8();
    if (sev > uint8_t(Severity::Critical) || st > uint8_t(AlertStatus::FalsePositive)) return false;
    a.severity = Severity(sev);
    a.status = AlertStatus(st);
    a.src_ip = std::string(r.bytes());
    a.user = std::string(r.bytes());
    a.host = std::string(r.bytes());
    a.message = std::string(r.bytes());
    a.count = r.varint();
    uint64_t n = r.varint();
    if (!r.ok() || n > 100000) return false;
    for (uint64_t i = 0; i < n; ++i) a.event_ids.push_back(r.varint());
    uint64_t nf = r.varint();
    if (!r.ok() || nf > 100000) return false;
    for (uint64_t i = 0; i < nf; ++i) {
        std::string k(r.bytes());
        std::string v(r.bytes());
        a.fields.emplace_back(std::move(k), std::move(v));
    }
    return r.ok();
}

}  // namespace sentinel
