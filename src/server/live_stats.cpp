#include "server/live_stats.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "core/util.hpp"

namespace sentinel {

LiveStats::MinuteBucket& LiveStats::minute(int64_t m) {
    MinuteBucket& b = minutes_[size_t(m % kMinutes)];
    if (b.minute != m) b = MinuteBucket{m, 0, 0};
    return b;
}

static void keep_top(std::unordered_map<std::string, uint64_t>& m, size_t n) {
    if (m.size() <= n) return;
    std::vector<std::pair<std::string, uint64_t>> v(m.begin(), m.end());
    std::partial_sort(v.begin(), v.begin() + long(n), v.end(), [](auto& a, auto& b) { return a.second > b.second; });
    v.resize(n);
    m = std::unordered_map<std::string, uint64_t>(v.begin(), v.end());
}

LiveStats::HourBucket& LiveStats::hour(int64_t h) {
    HourBucket& b = hours_[size_t(h % kHours)];
    if (b.hour != h) {
        b = HourBucket{};
        b.hour = h;
        // начался новый час: часы старше суток сжимаем до самых частых значений
        for (auto& o : hours_) {
            if (o.hour < 0 || o.compact || o.hour > h - kDashHours) continue;
            keep_top(o.ips, kKeepOldHour);
            keep_top(o.sources, kKeepOldHour);
            keep_top(o.types, kKeepOldHour);
            keep_top(o.countries, kKeepOldHour);
            o.compact = true;
        }
    }
    return b;
}

void LiveStats::add_events(const std::vector<Event>& events, int64_t now) {
    std::lock_guard<std::mutex> lock(mu_);
    // Считаем по времени приёма: панель показывает поток данных "сейчас".
    MinuteBucket& mb = minute(now / 60000);
    HourBucket& hb = hour(now / 3600000);
    mb.events += events.size();
    hb.events += events.size();
    total_ += events.size();
    auto bump = [](std::unordered_map<std::string, uint64_t>& m, const std::string& k) {
        if (k.empty()) return;
        auto it = m.find(k);
        if (it != m.end()) {
            ++it->second;
        } else if (m.size() < kMaxKeysPerHour) {
            m.emplace(k, 1);
        }
    };
    for (auto& e : events) {
        bump(hb.ips, e[Field::SrcIp]);
        bump(hb.sources, e[Field::Source]);
        bump(hb.types, e[Field::Type]);
        if (const std::string* c = e.extra_get("geo.country")) bump(hb.countries, *c);
    }
}

void LiveStats::add_alerts(const std::vector<Alert>& alerts, int64_t now) {
    std::lock_guard<std::mutex> lock(mu_);
    minute(now / 60000).alerts += alerts.size();
    hour(now / 3600000).alerts += alerts.size();
}

static std::vector<std::pair<std::string, uint64_t>> top(const std::unordered_map<std::string, uint64_t>& m, size_t n) {
    std::vector<std::pair<std::string, uint64_t>> v(m.begin(), m.end());
    size_t k = std::min(n, v.size());
    std::partial_sort(v.begin(), v.begin() + long(k), v.end(),
                      [](auto& a, auto& b) { return a.second != b.second ? a.second > b.second : a.first < b.first; });
    v.resize(k);
    return v;
}

LiveStats::Snapshot LiveStats::snapshot(int64_t now, int minutes, size_t top_n) const {
    std::lock_guard<std::mutex> lock(mu_);
    Snapshot s;
    s.events_total = total_;
    const int64_t cur_min = now / 60000;
    if (minutes < 1) minutes = 60;
    if (minutes > kMinutes) minutes = kMinutes;
    for (const auto& b : minutes_) {
        if (b.minute < 0 || b.minute <= cur_min - kMinutes) continue;
        s.events_24h += b.events;
        s.alerts_24h += b.alerts;
    }
    for (int64_t m = cur_min - minutes + 1; m <= cur_min; ++m) {
        const MinuteBucket& b = minutes_[size_t(m % kMinutes)];
        bool valid = b.minute == m;
        s.events_per_minute.emplace_back(m * 60000, valid ? b.events : 0);
        s.alerts_per_minute.emplace_back(m * 60000, valid ? b.alerts : 0);
    }
    // скорость за последнюю полную минуту + текущую частично
    {
        const MinuteBucket& prev = minutes_[size_t((cur_min - 1) % kMinutes)];
        const MinuteBucket& cur = minutes_[size_t(cur_min % kMinutes)];
        uint64_t n = (prev.minute == cur_min - 1 ? prev.events : 0) + (cur.minute == cur_min ? cur.events : 0);
        double secs = 60.0 + double(now % 60000) / 1000.0;
        s.events_per_sec_1m = double(n) / secs;
    }
    std::unordered_map<std::string, uint64_t> ips, sources, types, countries;
    const int64_t cur_hour = now / 3600000;
    for (const auto& h : hours_) {
        if (h.hour < 0 || h.hour <= cur_hour - kDashHours) continue;
        for (auto& kv : h.ips) ips[kv.first] += kv.second;
        for (auto& kv : h.sources) sources[kv.first] += kv.second;
        for (auto& kv : h.types) types[kv.first] += kv.second;
        for (auto& kv : h.countries) countries[kv.first] += kv.second;
    }
    s.top_ips = top(ips, top_n);
    s.top_sources = top(sources, top_n);
    s.by_type = top(types, 50);
    s.top_countries = top(countries, top_n);
    return s;
}

LiveStats::Period LiveStats::period(int64_t from, int64_t to, size_t top_n) const {
    std::lock_guard<std::mutex> lock(mu_);
    Period p;
    std::unordered_map<std::string, uint64_t> ips, sources, types, countries;
    const int64_t h0 = from / 3600000, h1 = to / 3600000;
    std::vector<const HourBucket*> hs;
    for (const auto& h : hours_)
        if (h.hour >= 0 && h.hour >= h0 && h.hour <= h1) hs.push_back(&h);
    std::sort(hs.begin(), hs.end(), [](auto* a, auto* b) { return a->hour < b->hour; });
    for (const auto* h : hs) {
        if (!p.data_from) p.data_from = h->hour * 3600000;
        p.events += h->events;
        p.alerts += h->alerts;
        p.hours.push_back({h->hour * 3600000, {h->events, h->alerts}});
        for (auto& kv : h->ips) ips[kv.first] += kv.second;
        for (auto& kv : h->sources) sources[kv.first] += kv.second;
        for (auto& kv : h->types) types[kv.first] += kv.second;
        for (auto& kv : h->countries) countries[kv.first] += kv.second;
    }
    p.top_ips = top(ips, top_n);
    p.top_sources = top(sources, top_n);
    p.by_type = top(types, 50);
    p.top_countries = top(countries, top_n);
    return p;
}

namespace {
constexpr uint32_t kStatsMagic = 0x53544153;   // "SATS" — версия 1 (без стран и часовых счётчиков)
constexpr uint32_t kStatsMagic2 = 0x32544153;  // "SAT2"
constexpr size_t kKeepPerMap = 2000;          // на диск — самые частые ключи каждого часа

void put_map(std::string& out, const std::unordered_map<std::string, uint64_t>& m) {
    std::vector<std::pair<std::string, uint64_t>> v(m.begin(), m.end());
    if (v.size() > kKeepPerMap) {
        std::partial_sort(v.begin(), v.begin() + long(kKeepPerMap), v.end(),
                          [](auto& a, auto& b) { return a.second > b.second; });
        v.resize(kKeepPerMap);
    }
    put_varint(out, v.size());
    for (auto& kv : v) {
        put_bytes(out, kv.first);
        put_varint(out, kv.second);
    }
}

bool get_map(Reader& r, std::unordered_map<std::string, uint64_t>& m) {
    uint64_t n = r.varint();
    if (!r.ok() || n > 100000) return false;
    for (uint64_t i = 0; i < n; ++i) {
        std::string k(r.bytes());
        m[k] = r.varint();
    }
    return r.ok();
}
}  // namespace

bool LiveStats::save(const std::string& path) const {
    std::string body;
    {
        std::lock_guard<std::mutex> lock(mu_);
        put_varint(body, total_);
        size_t valid = 0;
        for (auto& b : minutes_) valid += b.minute >= 0;
        put_varint(body, valid);
        for (auto& b : minutes_) {
            if (b.minute < 0) continue;
            put_varint(body, uint64_t(b.minute));
            put_varint(body, b.events);
            put_varint(body, b.alerts);
        }
        valid = 0;
        for (auto& h : hours_) valid += h.hour >= 0;
        put_varint(body, valid);
        for (auto& h : hours_) {
            if (h.hour < 0) continue;
            put_varint(body, uint64_t(h.hour));
            put_varint(body, h.events);
            put_varint(body, h.alerts);
            put_map(body, h.ips);
            put_map(body, h.sources);
            put_map(body, h.types);
            put_map(body, h.countries);
        }
    }
    std::string out;
    put_u32(out, kStatsMagic2);
    put_u32(out, crc32(body.data(), body.size()));
    out += body;
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        f << out;
        if (!f) return false;
    }
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(path, ec);
        std::filesystem::rename(tmp, path, ec);
    }
    return !ec;
}

bool LiveStats::load(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::stringstream ss;
    ss << in.rdbuf();
    std::string data = ss.str();
    Reader h(data);
    uint32_t magic = h.u32();
    if (magic != kStatsMagic && magic != kStatsMagic2) return false;
    const bool v2 = magic == kStatsMagic2;
    uint32_t crc = h.u32();
    if (!h.ok() || crc != crc32(data.data() + 8, data.size() - 8)) return false;
    Reader r(data.data() + 8, data.size() - 8);
    LiveStats tmp;
    tmp.total_ = r.varint();
    uint64_t n = r.varint();
    if (!r.ok() || n > uint64_t(kMinutes)) return false;
    for (uint64_t i = 0; i < n; ++i) {
        int64_t m = int64_t(r.varint());
        MinuteBucket& b = tmp.minutes_[size_t(m % kMinutes)];
        b.minute = m;
        b.events = r.varint();
        b.alerts = r.varint();
    }
    n = r.varint();
    if (!r.ok() || n > uint64_t(kHours)) return false;
    for (uint64_t i = 0; i < n; ++i) {
        int64_t hr = int64_t(r.varint());
        if (hr < 0) return false;
        HourBucket& b = tmp.hours_[size_t(hr % kHours)];
        b.hour = hr;
        if (v2) {
            b.events = r.varint();
            b.alerts = r.varint();
        }
        if (!get_map(r, b.ips) || !get_map(r, b.sources) || !get_map(r, b.types)) return false;
        if (v2 && !get_map(r, b.countries)) return false;
    }
    if (!r.ok()) return false;
    std::lock_guard<std::mutex> lock(mu_);
    total_ = tmp.total_;
    minutes_ = std::move(tmp.minutes_);
    hours_ = std::move(tmp.hours_);
    return true;
}

}  // namespace sentinel
