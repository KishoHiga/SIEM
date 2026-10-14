#include "enrich/threat.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "core/log.hpp"
#include "core/util.hpp"
#include "net/client.hpp"

namespace fs = std::filesystem;

namespace sentinel {

namespace {

uint32_t v4_of(const IpAddr& ip) {
    return (uint32_t(ip.b[0]) << 24) | (uint32_t(ip.b[1]) << 16) | (uint32_t(ip.b[2]) << 8) | uint32_t(ip.b[3]);
}

std::array<uint8_t, 16> last_of(const Cidr& c) {
    std::array<uint8_t, 16> e = c.net.b;
    int bits = c.net.v6 ? 128 : 32;
    for (int i = c.prefix; i < bits; ++i) e[size_t(i / 8)] |= uint8_t(0x80 >> (i % 8));
    return e;
}

template <class R, class K>
void merge_ranges(std::vector<R>& v) {
    std::sort(v.begin(), v.end(), [](const R& a, const R& b) { return a.start < b.start; });
    std::vector<R> out;
    for (auto& r : v) {
        if (!out.empty() && !(out.back().end < r.start)) {
            if (out.back().end < r.end) out.back().end = r.end;
        } else {
            out.push_back(r);
        }
    }
    v.swap(out);
}

bool read_file(const std::string& p, std::string& out) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return false;
    std::stringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

}  // namespace

std::vector<Cidr> parse_threat_list(std::string_view text, size_t* bad_lines) {
    std::vector<Cidr> out;
    size_t bad = 0;
    for (auto line : split(text, '\n')) {
        std::string_view l = trim(line);
        if (size_t h = l.find_first_of("#;"); h != std::string_view::npos) l = trim(l.substr(0, h));
        if (l.empty()) continue;
        size_t sp = l.find_first_of(" \t,");
        if (sp != std::string_view::npos) l = l.substr(0, sp);
        auto c = parse_cidr(l);
        if (!c) {
            ++bad;
            continue;
        }
        if (c->prefix < (c->net.v6 ? 16 : 8)) {
            ++bad;  // слишком широкая сеть — скорее ошибка списка
            continue;
        }
        out.push_back(*c);
    }
    if (bad_lines) *bad_lines = bad;
    return out;
}

void ThreatSet::add(const std::string& name, const std::vector<Cidr>& entries) {
    if (names_.size() >= 64) return;
    names_.push_back(name);
    counts_.push_back(entries.size());
    std::vector<V4> a;
    std::vector<V6> b;
    for (auto& c : entries) {
        auto e = last_of(c);
        if (!c.net.v6) {
            IpAddr end;
            end.b = e;
            a.push_back({v4_of(c.net), v4_of(end)});
        } else {
            b.push_back({c.net.b, e});
        }
    }
    merge_ranges<V4, uint32_t>(a);
    merge_ranges<V6, std::array<uint8_t, 16>>(b);
    v4_.push_back(std::move(a));
    v6_.push_back(std::move(b));
}

uint64_t ThreatSet::match(const IpAddr& ip) const {
    uint64_t mask = 0;
    for (size_t i = 0; i < names_.size(); ++i) {
        bool hit = false;
        if (!ip.v6) {
            uint32_t x = v4_of(ip);
            const auto& v = v4_[i];
            auto it = std::upper_bound(v.begin(), v.end(), x, [](uint32_t val, const V4& r) { return val < r.start; });
            hit = it != v.begin() && x <= std::prev(it)->end;
        } else {
            const auto& v = v6_[i];
            auto it = std::upper_bound(v.begin(), v.end(), ip.b,
                                       [](const std::array<uint8_t, 16>& val, const V6& r) { return val < r.start; });
            hit = it != v.begin() && !(std::prev(it)->end < ip.b);
        }
        if (hit) mask |= uint64_t(1) << i;
    }
    return mask;
}

std::string ThreatSet::names_of(uint64_t mask) const {
    std::string out;
    for (size_t i = 0; i < names_.size(); ++i)
        if (mask & (uint64_t(1) << i)) {
            if (!out.empty()) out += ',';
            out += names_[i];
        }
    return out;
}

ThreatFeeds::ThreatFeeds(ThreatConfig cfg, std::string cache_dir, OnUpdate on_update)
    : cfg_(std::move(cfg)), cache_dir_(std::move(cache_dir)), on_update_(std::move(on_update)) {
    status_.resize(cfg_.lists.size());
    data_.resize(cfg_.lists.size());
    for (size_t i = 0; i < cfg_.lists.size(); ++i) {
        status_[i].name = cfg_.lists[i].name;
        status_[i].source = cfg_.lists[i].url.empty() ? cfg_.lists[i].file : cfg_.lists[i].url;
    }
}

ThreatFeeds::~ThreatFeeds() { stop(); }

void ThreatFeeds::start() {
    if (cfg_.lists.empty()) return;
    std::error_code ec;
    fs::create_directories(cache_dir_, ec);
    // копии с прошлого запуска — сразу, без ожидания сети
    bool any = false;
    for (size_t i = 0; i < cfg_.lists.size(); ++i) {
        std::string text;
        const auto& l = cfg_.lists[i];
        std::string p = l.url.empty() ? l.file : cache_dir_ + "/" + l.name + ".txt";
        if (!read_file(p, text)) continue;
        auto entries = parse_threat_list(text);
        std::lock_guard<std::mutex> lock(mu_);
        data_[i] = std::move(entries);
        status_[i].entries = data_[i].size();
        status_[i].cached = true;
        any = true;
    }
    if (any) rebuild();
    th_ = std::thread([this] { loop(); });
}

void ThreatFeeds::stop() {
    {
        std::lock_guard<std::mutex> lock(mu_);
        stop_ = true;
    }
    cv_.notify_all();
    if (th_.joinable()) th_.join();
}

bool ThreatFeeds::fetch(size_t i, std::string& text, std::string& error) {
    const auto& l = cfg_.lists[i];
    if (l.url.empty()) {
        if (!read_file(l.file, text)) {
            error = "cannot read " + l.file;
            return false;
        }
        return true;
    }
    net::ClientTlsOptions tls;
    tls.ca_file = cfg_.ca_file;
    net::ClientResponse resp;
    if (!net::http_get(l.url, tls, 60000, resp, error, 64u << 20)) return false;
    if (resp.status != 200) {
        error = "HTTP " + std::to_string(resp.status);
        return false;
    }
    text = std::move(resp.body);
    // копия на диск — для запуска без интернета
    std::error_code dir_ec;
    fs::create_directories(cache_dir_, dir_ec);
    std::string p = cache_dir_ + "/" + l.name + ".txt", tmp = p + ".tmp";
    {
        std::ofstream o(tmp, std::ios::binary | std::ios::trunc);
        o << text;
    }
    std::error_code ec;
    fs::rename(tmp, p, ec);
    return true;
}

bool ThreatFeeds::refresh_all() {
    bool changed = false;
    for (size_t i = 0; i < cfg_.lists.size(); ++i) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (stop_) return changed;
        }
        std::string text, err;
        bool ok = fetch(i, text, err);
        size_t bad = 0;
        std::vector<Cidr> entries;
        if (ok) {
            entries = parse_threat_list(text, &bad);
            if (entries.empty() && !text.empty()) {
                ok = false;
                err = "no addresses in the downloaded list";
            }
        }
        std::lock_guard<std::mutex> lock(mu_);
        auto& st = status_[i];
        st.last_try = now_ms();
        if (!ok) {
            st.last_error = err;
            log::warn("threat: list ", st.name, ": ", err, st.entries ? " (keeping the previous copy)" : "");
            continue;
        }
        st.last_error.clear();
        st.updated = now_ms();
        st.cached = false;
        st.entries = entries.size();
        data_[i] = std::move(entries);
        changed = true;
        log::info("threat: list ", st.name, " loaded, ", st.entries, " entries", bad ? ", skipped lines: " + std::to_string(bad) : "");
    }
    if (changed) rebuild();
    return changed;
}

void ThreatFeeds::rebuild() {
    auto set = std::make_shared<ThreatSet>();
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (size_t i = 0; i < cfg_.lists.size(); ++i)
            if (!data_[i].empty()) set->add(cfg_.lists[i].name, data_[i]);
    }
    if (on_update_) on_update_(set);
}

void ThreatFeeds::loop() {
    while (true) {
        refresh_all();
        std::unique_lock<std::mutex> lock(mu_);
        // при ошибках — повтор через 10 минут, иначе по расписанию
        bool errors = false;
        for (auto& s : status_) errors |= !s.last_error.empty();
        int64_t wait = errors ? std::min<int64_t>(cfg_.refresh_ms, 600000) : cfg_.refresh_ms;
        cv_.wait_for(lock, std::chrono::milliseconds(wait), [&] { return stop_; });
        if (stop_) return;
    }
}

std::vector<ThreatListStatus> ThreatFeeds::status() const {
    std::lock_guard<std::mutex> lock(mu_);
    return status_;
}

}  // namespace sentinel
