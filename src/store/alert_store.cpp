#include "store/alert_store.hpp"

#include <algorithm>
#include <filesystem>

#include "core/log.hpp"
#include "core/util.hpp"
#include "store/codec.hpp"

namespace fs = std::filesystem;

namespace sentinel {

namespace {
constexpr uint8_t kRecAlert = 1;
constexpr uint8_t kRecStatus = 2;
constexpr uint32_t kMaxRecord = 16u << 20;
}  // namespace

// Формат записи: [u32 длина][u32 CRC(тип+данные)][u8 тип][данные]
bool AlertStore::append_record(uint8_t type, const std::string& payload) {
    std::string rec;
    rec.reserve(payload.size() + 9);
    std::string body;
    body.push_back(char(type));
    body += payload;
    put_u32(rec, uint32_t(body.size()));
    put_u32(rec, crc32(body.data(), body.size()));
    rec += body;
    return file_.write(rec.data(), rec.size()) && file_.flush();
}

bool AlertStore::open(const std::string& dir, int64_t retention_ms, std::string& error) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    path_ = dir + "/alerts.log";
    retention_ms_ = retention_ms;
    alerts_.clear();
    index_.clear();
    uint64_t good_end = 0;
    size_t records = 0;
    if (fs::exists(path_, ec)) {
        File f;
        if (!f.open(path_, "rb")) {
            error = "cannot read " + path_;
            return false;
        }
        uint64_t size = f.size();
        uint64_t off = 0;
        std::string body;
        while (off + 8 <= size) {
            char hdr[8];
            if (!f.seek(off) || !f.read(hdr, 8)) break;
            Reader hr(hdr, 8);
            uint32_t len = hr.u32(), crc = hr.u32();
            if (len == 0 || len > kMaxRecord || off + 8 + len > size) break;
            body.resize(len);
            if (!f.read(body.data(), len) || crc32(body.data(), len) != crc) break;
            Reader r(body.data() + 1, len - 1);
            if (uint8_t(body[0]) == kRecAlert) {
                Alert a;
                if (!decode_alert(r, a)) break;
                index_[a.id] = alerts_.size();
                next_id_ = std::max(next_id_, a.id + 1);
                alerts_.push_back(std::move(a));
            } else if (uint8_t(body[0]) == kRecStatus) {
                uint64_t id = r.varint();
                uint8_t st = r.u8();
                if (!r.ok() || st > uint8_t(AlertStatus::FalsePositive)) break;
                auto it = index_.find(id);
                if (it != index_.end()) alerts_[it->second].status = AlertStatus(st);
            } else {
                break;
            }
            ++records;
            off += 8 + len;
            good_end = off;
        }
        f.close();
        if (good_end != size) {
            log::warn("alerts: truncating damaged tail of ", path_, " at ", good_end);
            fs::resize_file(path_, good_end, ec);
        }
    }
    // Срок хранения
    const int64_t cutoff = now_ms() - retention_ms_;
    size_t before = alerts_.size();
    alerts_.erase(std::remove_if(alerts_.begin(), alerts_.end(), [&](const Alert& a) { return a.created < cutoff; }),
                  alerts_.end());
    index_.clear();
    for (size_t i = 0; i < alerts_.size(); ++i) index_[alerts_[i].id] = i;
    if (before != alerts_.size() || records > alerts_.size() * 2 + 1000) rewrite_compacted();
    if (!file_.open(path_, "ab")) {
        error = "cannot open " + path_ + " for writing";
        return false;
    }
    log::info("alerts: loaded ", alerts_.size(), " alerts");
    return true;
}

void AlertStore::rewrite_compacted() {
    std::string tmp = path_ + ".tmp";
    {
        File out;
        if (!out.open(tmp, "wb")) return;
        file_.close();
        for (auto& a : alerts_) {
            std::string payload;
            encode_alert(a, payload);
            std::string body;
            body.push_back(char(kRecAlert));
            body += payload;
            std::string rec;
            put_u32(rec, uint32_t(body.size()));
            put_u32(rec, crc32(body.data(), body.size()));
            rec += body;
            if (!out.write(rec.data(), rec.size())) return;
        }
        out.sync();
    }
    std::error_code ec;
    fs::rename(tmp, path_, ec);
    if (ec) {
        // Windows: rename поверх существующего может не сработать
        fs::remove(path_, ec);
        fs::rename(tmp, path_, ec);
    }
}

void AlertStore::close() {
    std::lock_guard<std::mutex> lock(mu_);
    file_.sync();
    file_.close();
}

void AlertStore::add(std::vector<Alert>& alerts) {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& a : alerts) {
        a.id = next_id_++;
        if (a.created == 0) a.created = now_ms();
        std::string payload;
        encode_alert(a, payload);
        if (!append_record(kRecAlert, payload)) log::error("alerts: write failed for alert ", a.id);
        index_[a.id] = alerts_.size();
        alerts_.push_back(a);
    }
    file_.sync();
    // Срок хранения в памяти (раз в много добавлений)
    if (alerts_.size() > 100000 && (next_id_ % 1024) == 0) {
        const int64_t cutoff = now_ms() - retention_ms_;
        size_t n = 0;
        while (n < alerts_.size() && alerts_[n].created < cutoff) ++n;
        if (n) {
            alerts_.erase(alerts_.begin(), alerts_.begin() + long(n));
            index_.clear();
            for (size_t i = 0; i < alerts_.size(); ++i) index_[alerts_[i].id] = i;
        }
    }
}

bool AlertStore::set_status(uint64_t id, AlertStatus status) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = index_.find(id);
    if (it == index_.end()) return false;
    std::string payload;
    put_varint(payload, id);
    put_u8(payload, uint8_t(status));
    if (!append_record(kRecStatus, payload)) return false;
    file_.sync();
    alerts_[it->second].status = status;
    return true;
}

std::vector<Alert> AlertStore::query(const AlertQuery& q) const {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<Alert> out;
    const size_t limit = q.limit ? q.limit : 100;
    for (auto it = alerts_.rbegin(); it != alerts_.rend() && out.size() < limit; ++it) {
        const Alert& a = *it;
        if (q.before_id && a.id >= q.before_id) continue;
        if (a.ts < q.from || a.ts > q.to) continue;
        if (q.status && a.status != *q.status) continue;
        if (q.min_severity && a.severity < *q.min_severity) continue;
        if (!q.rule_id.empty() && a.rule_id != q.rule_id) continue;
        if (!q.src_ip.empty() && a.src_ip != q.src_ip) continue;
        out.push_back(a);
    }
    return out;
}

std::optional<Alert> AlertStore::get(uint64_t id) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = index_.find(id);
    if (it == index_.end()) return std::nullopt;
    return alerts_[it->second];
}

AlertCounts AlertStore::counts(int64_t since_ms) const {
    std::lock_guard<std::mutex> lock(mu_);
    AlertCounts c;
    for (auto it = alerts_.rbegin(); it != alerts_.rend(); ++it) {
        if (it->created < since_ms) break;
        ++c.total;
        ++c.by_severity[size_t(it->severity)];
        ++c.by_status[size_t(it->status)];
    }
    return c;
}

std::unordered_map<std::string, RuleAlertCount> AlertStore::counts_by_rule(int64_t since_ms) const {
    std::lock_guard<std::mutex> lock(mu_);
    std::unordered_map<std::string, RuleAlertCount> out;
    for (auto it = alerts_.rbegin(); it != alerts_.rend(); ++it) {
        if (it->created < since_ms) break;
        RuleAlertCount& c = out[it->rule_id];
        ++c.total;
        if (it->status == AlertStatus::New || it->status == AlertStatus::Acknowledged) ++c.open;
        if (it->status == AlertStatus::FalsePositive) ++c.false_positive;
        if (it->created > c.last) c.last = it->created;
    }
    return out;
}

uint64_t AlertStore::max_id() const {
    std::lock_guard<std::mutex> lock(mu_);
    return next_id_ - 1;
}

}  // namespace sentinel
