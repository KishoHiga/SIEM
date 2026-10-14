#include "store/incident_store.hpp"

#include <algorithm>
#include <filesystem>

#include "core/log.hpp"
#include "core/util.hpp"

namespace fs = std::filesystem;

namespace sentinel {

namespace {

constexpr uint8_t kCreate = 1, kAlert = 2, kStatus = 3, kAssign = 4, kNote = 5, kMerge = 6, kSnapshot = 7;
constexpr uint32_t kMaxRecord = 16u << 20;
constexpr size_t kMaxDistinct = 20;
constexpr size_t kMaxNotes = 500;

void push_distinct(std::vector<std::string>& v, const std::string& s) {
    if (s.empty() || v.size() >= kMaxDistinct) return;
    if (std::find(v.begin(), v.end(), s) == v.end()) v.push_back(s);
}

std::string incident_key(const Alert& a) {
    if (!a.src_ip.empty()) return "ip:" + a.src_ip;
    if (!a.user.empty()) return "user:" + a.user + "@" + a.host;
    return "rule:" + a.rule_id + "@" + a.host;
}

void encode_snapshot(const Incident& i, std::string& out) {
    put_varint(out, i.id);
    put_bytes(out, i.key);
    put_bytes(out, i.src_ip);
    put_bytes(out, i.user);
    put_bytes(out, i.host);
    put_u8(out, uint8_t(i.severity));
    put_u8(out, uint8_t(i.status));
    put_bytes(out, i.assignee);
    put_svarint(out, i.created);
    put_svarint(out, i.updated);
    put_svarint(out, i.first_alert);
    put_svarint(out, i.last_alert);
    put_varint(out, i.alert_count);
    put_varint(out, i.merged_into);
    put_varint(out, i.alert_ids.size());
    uint64_t prev = 0;
    for (auto id : i.alert_ids) {
        put_varint(out, id - prev);  // по возрастанию — разницы маленькие
        prev = id;
    }
    put_varint(out, i.rules.size());
    for (auto& r : i.rules) {
        put_bytes(out, r.rule_id);
        put_bytes(out, r.rule_name);
        put_u8(out, uint8_t(r.severity));
        put_varint(out, r.count);
    }
    put_varint(out, i.hosts.size());
    for (auto& h : i.hosts) put_bytes(out, h);
    put_varint(out, i.users.size());
    for (auto& u : i.users) put_bytes(out, u);
    put_varint(out, i.notes.size());
    for (auto& n : i.notes) {
        put_varint(out, n.id);
        put_svarint(out, n.ts);
        put_bytes(out, n.by);
        put_bytes(out, n.text);
    }
    put_varint(out, i.history.size());
    for (auto& h : i.history) {
        put_svarint(out, h.ts);
        put_bytes(out, h.by);
        put_bytes(out, h.kind);
        put_bytes(out, h.value);
    }
}

void add_history(Incident& i, int64_t ts, const std::string& by, const char* kind, std::string value) {
    i.history.push_back({ts, by, kind, std::move(value)});
    if (i.history.size() > Incident::kMaxHistory) i.history.erase(i.history.begin());
}

bool decode_snapshot(Reader& r, Incident& i) {
    i.id = r.varint();
    i.key = std::string(r.bytes());
    i.src_ip = std::string(r.bytes());
    i.user = std::string(r.bytes());
    i.host = std::string(r.bytes());
    uint8_t sev = r.u8(), st = r.u8();
    if (sev > 4 || st > 3) return false;
    i.severity = Severity(sev);
    i.status = IncidentStatus(st);
    i.assignee = std::string(r.bytes());
    i.created = r.svarint();
    i.updated = r.svarint();
    i.first_alert = r.svarint();
    i.last_alert = r.svarint();
    i.alert_count = r.varint();
    i.merged_into = r.varint();
    uint64_t n = r.varint();
    if (!r.ok() || n > Incident::kMaxAlertIds) return false;
    uint64_t prev = 0;
    for (uint64_t k = 0; k < n; ++k) {
        prev += r.varint();
        i.alert_ids.push_back(prev);
    }
    n = r.varint();
    if (!r.ok() || n > 10000) return false;
    for (uint64_t k = 0; k < n; ++k) {
        IncidentRule x;
        x.rule_id = std::string(r.bytes());
        x.rule_name = std::string(r.bytes());
        uint8_t s = r.u8();
        if (s > 4) return false;
        x.severity = Severity(s);
        x.count = r.varint();
        i.rules.push_back(std::move(x));
    }
    for (auto* v : {&i.hosts, &i.users}) {
        n = r.varint();
        if (!r.ok() || n > 1000) return false;
        for (uint64_t k = 0; k < n; ++k) v->emplace_back(r.bytes());
    }
    n = r.varint();
    if (!r.ok() || n > 100000) return false;
    for (uint64_t k = 0; k < n; ++k) {
        IncidentNote x;
        x.id = r.varint();
        x.ts = r.svarint();
        x.by = std::string(r.bytes());
        x.text = std::string(r.bytes());
        i.notes.push_back(std::move(x));
    }
    n = r.varint();
    if (!r.ok() || n > 100000) return false;
    for (uint64_t k = 0; k < n; ++k) {
        IncidentChange h;
        h.ts = r.svarint();
        h.by = std::string(r.bytes());
        h.kind = std::string(r.bytes());
        h.value = std::string(r.bytes());
        i.history.push_back(std::move(h));
    }
    return r.ok();
}

}  // namespace

const char* incident_status_name(IncidentStatus s) {
    switch (s) {
        case IncidentStatus::Open: return "open";
        case IncidentStatus::InProgress: return "in_progress";
        case IncidentStatus::Resolved: return "resolved";
        case IncidentStatus::FalsePositive: return "false_positive";
    }
    return "open";
}

std::optional<IncidentStatus> incident_status_from_name(std::string_view s) {
    if (s == "open") return IncidentStatus::Open;
    if (s == "in_progress") return IncidentStatus::InProgress;
    if (s == "resolved") return IncidentStatus::Resolved;
    if (s == "false_positive") return IncidentStatus::FalsePositive;
    return std::nullopt;
}

std::string Incident::title() const {
    std::string main;
    Severity best = Severity::Info;
    for (auto& r : rules)
        if (main.empty() || r.severity > best) {
            main = r.rule_name;
            best = r.severity;
        }
    if (main.empty()) main = "Инцидент";
    if (rules.size() > 1) main += " и ещё " + std::to_string(rules.size() - 1);
    std::string who = !src_ip.empty() ? src_ip : !user.empty() ? user + (host.empty() ? "" : "@" + host) : host;
    if (!who.empty()) main += " · " + who;
    return main;
}

Incident* IncidentStore::find_locked(uint64_t id) {
    auto it = index_.find(id);
    return it == index_.end() ? nullptr : &incidents_[it->second];
}

bool IncidentStore::append(uint8_t type, const std::string& payload) {
    if (!file_.is_open()) return false;
    std::string body;
    body.push_back(char(type));
    body += payload;
    std::string rec;
    put_u32(rec, uint32_t(body.size()));
    put_u32(rec, crc32(body.data(), body.size()));
    rec += body;
    ++records_;
    if (batching_) {
        batch_ += rec;
        return true;
    }
    return file_.write(rec.data(), rec.size()) && file_.flush();
}

void IncidentStore::apply_alert(Incident& inc, uint64_t alert_id, const std::string& rule_id, const std::string& rule_name,
                                Severity sev, int64_t ts, const std::string& host, const std::string& user) {
    ++inc.alert_count;
    inc.alert_ids.push_back(alert_id);
    if (inc.alert_ids.size() > Incident::kMaxAlertIds) inc.alert_ids.erase(inc.alert_ids.begin());
    if (!inc.first_alert || ts < inc.first_alert) inc.first_alert = ts;
    if (ts > inc.last_alert) inc.last_alert = ts;
    if (ts > inc.updated) inc.updated = ts;
    if (sev > inc.severity) inc.severity = sev;
    auto r = std::find_if(inc.rules.begin(), inc.rules.end(), [&](const IncidentRule& x) { return x.rule_id == rule_id; });
    if (r == inc.rules.end()) {
        if (inc.rules.size() < 1000) inc.rules.push_back({rule_id, rule_name, sev, 1});
    } else {
        ++r->count;
        if (sev > r->severity) r->severity = sev;
    }
    push_distinct(inc.hosts, host);
    push_distinct(inc.users, user);
    alert_to_inc_[alert_id] = inc.id;
}

void IncidentStore::status_locked(Incident& inc, IncidentStatus st, const std::string& by, int64_t ts) {
    inc.status = st;
    inc.updated = std::max(inc.updated, ts);
    add_history(inc, ts, by, "status", incident_status_name(st));
}

void IncidentStore::assign_locked(Incident& inc, const std::string& who, const std::string& by, int64_t ts) {
    inc.assignee = who;
    inc.updated = std::max(inc.updated, ts);
    add_history(inc, ts, by, "assign", who);
}

void IncidentStore::merge_locked(Incident& s, Incident& d, const std::string& by, int64_t ts) {
    add_history(s, ts, by, "merged_into", std::to_string(d.id));
    add_history(d, ts, by, "merged_from", std::to_string(s.id));
    for (auto a : s.alert_ids) alert_to_inc_[a] = d.id;
    std::vector<uint64_t> ids = d.alert_ids;
    ids.insert(ids.end(), s.alert_ids.begin(), s.alert_ids.end());
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    if (ids.size() > Incident::kMaxAlertIds) ids.erase(ids.begin(), ids.end() - long(Incident::kMaxAlertIds));
    d.alert_ids = std::move(ids);
    d.alert_count += s.alert_count;
    if (s.severity > d.severity) d.severity = s.severity;
    if (s.first_alert && (!d.first_alert || s.first_alert < d.first_alert)) d.first_alert = s.first_alert;
    d.last_alert = std::max(d.last_alert, s.last_alert);
    for (auto& rr : s.rules) {
        auto it = std::find_if(d.rules.begin(), d.rules.end(), [&](const IncidentRule& x) { return x.rule_id == rr.rule_id; });
        if (it == d.rules.end()) d.rules.push_back(rr);
        else {
            it->count += rr.count;
            it->severity = std::max(it->severity, rr.severity);
        }
    }
    for (auto& h : s.hosts) push_distinct(d.hosts, h);
    for (auto& u : s.users) push_distinct(d.users, u);
    d.updated = std::max(d.updated, ts);
    s.merged_into = d.id;
    s.status = IncidentStatus::Resolved;
    s.updated = std::max(s.updated, ts);
}

bool IncidentStore::open(const std::string& dir, int64_t retention_ms, std::string& error) {
    std::lock_guard<std::mutex> lock(mu_);
    std::error_code ec;
    fs::create_directories(dir, ec);
    path_ = dir + "/incidents.log";
    retention_ms_ = retention_ms;
    incidents_.clear();
    index_.clear();
    by_key_.clear();
    alert_to_inc_.clear();
    size_t records = 0;
    if (fs::exists(path_, ec)) {
        File f;
        if (!f.open(path_, "rb")) {
            error = "cannot read " + path_;
            return false;
        }
        uint64_t size = f.size(), off = 0, good_end = 0;
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
            uint8_t type = uint8_t(body[0]);
            bool ok = true;
            if (type == kCreate || type == kSnapshot) {
                Incident inc;
                if (type == kSnapshot) {
                    ok = decode_snapshot(r, inc);
                } else {
                    inc.id = r.varint();
                    inc.key = std::string(r.bytes());
                    inc.src_ip = std::string(r.bytes());
                    inc.user = std::string(r.bytes());
                    inc.host = std::string(r.bytes());
                    inc.created = inc.updated = r.svarint();
                    ok = r.ok();
                }
                if (ok) {
                    next_id_ = std::max(next_id_, inc.id + 1);
                    for (auto& n : inc.notes) next_note_ = std::max(next_note_, n.id + 1);
                    if (!inc.merged_into)
                        for (auto a : inc.alert_ids) alert_to_inc_[a] = inc.id;
                    if (auto it = index_.find(inc.id); it != index_.end()) incidents_[it->second] = std::move(inc);
                    else {
                        index_[inc.id] = incidents_.size();
                        incidents_.push_back(std::move(inc));
                    }
                }
            } else if (type == kAlert) {
                uint64_t id = r.varint(), aid = r.varint();
                std::string rid(r.bytes()), rname(r.bytes());
                uint8_t sev = r.u8();
                int64_t ts = r.svarint();
                std::string host(r.bytes()), user(r.bytes());
                ok = r.ok() && sev <= 4;
                if (ok)
                    if (Incident* inc = find_locked(id)) apply_alert(*inc, aid, rid, rname, Severity(sev), ts, host, user);
            } else if (type == kStatus) {
                uint64_t id = r.varint();
                uint8_t st = r.u8();
                std::string by(r.bytes());
                int64_t ts = r.svarint();
                ok = r.ok() && st <= 3;
                if (ok)
                    if (Incident* inc = find_locked(id)) status_locked(*inc, IncidentStatus(st), by, ts);
            } else if (type == kAssign) {
                uint64_t id = r.varint();
                std::string who(r.bytes()), by(r.bytes());
                int64_t ts = r.svarint();
                ok = r.ok();
                if (ok)
                    if (Incident* inc = find_locked(id)) assign_locked(*inc, who, by, ts);
            } else if (type == kNote) {
                uint64_t id = r.varint();
                IncidentNote n;
                n.id = r.varint();
                n.ts = r.svarint();
                n.by = std::string(r.bytes());
                n.text = std::string(r.bytes());
                ok = r.ok();
                if (ok) {
                    next_note_ = std::max(next_note_, n.id + 1);
                    if (Incident* inc = find_locked(id)) {
                        inc->updated = std::max(inc->updated, n.ts);
                        inc->notes.push_back(std::move(n));
                    }
                }
            } else if (type == kMerge) {
                uint64_t src = r.varint(), dst = r.varint();
                std::string by(r.bytes());
                int64_t ts = r.svarint();
                ok = r.ok();
                Incident* s = ok ? find_locked(src) : nullptr;
                Incident* d = ok ? find_locked(dst) : nullptr;
                if (s && d) merge_locked(*s, *d, by, ts);
            } else {
                ok = false;
            }
            if (!ok) break;
            ++records;
            off += 8 + len;
            good_end = off;
        }
        f.close();
        if (good_end != size) {
            log::warn("incidents: truncating damaged tail of ", path_, " at ", good_end);
            fs::resize_file(path_, good_end, ec);
        }
    }
    records_ = records;
    prune_locked(true);
    if (!file_.open(path_, "ab")) {
        error = "cannot open " + path_ + " for writing";
        return false;
    }
    log::info("incidents: loaded ", incidents_.size(), " incidents");
    return true;
}

void IncidentStore::prune_locked(bool force_index) {
    // срок хранения: давно не менявшиеся инциденты удаляются
    const int64_t cutoff = now_ms() - retention_ms_;
    size_t before = incidents_.size();
    incidents_.erase(std::remove_if(incidents_.begin(), incidents_.end(), [&](const Incident& i) { return i.updated < cutoff; }),
                     incidents_.end());
    bool removed = before != incidents_.size();
    if (removed || force_index) {
        index_.clear();
        alert_to_inc_.clear();
        by_key_.clear();
        for (size_t k = 0; k < incidents_.size(); ++k) {
            auto& i = incidents_[k];
            index_[i.id] = k;
            if (!i.merged_into)  // алерты влитого инцидента принадлежат тому, в который его влили
                for (auto a : i.alert_ids) alert_to_inc_[a] = i.id;
            if (i.active()) by_key_[i.key] = i.id;  // по возрастанию id — останется самый новый
        }
    }
    if (removed || records_ > incidents_.size() * 50 + 1000) {
        bool was_open = file_.is_open();
        rewrite_compacted();
        records_ = incidents_.size();
        if (was_open) file_.open(path_, "ab");
    }
}

void IncidentStore::maintain() {
    std::lock_guard<std::mutex> lock(mu_);
    prune_locked(false);
}

void IncidentStore::rewrite_compacted() {
    std::string tmp = path_ + ".tmp";
    {
        File out;
        if (!out.open(tmp, "wb")) return;
        file_.close();
        for (auto& i : incidents_) {
            std::string payload;
            encode_snapshot(i, payload);
            std::string body;
            body.push_back(char(kSnapshot));
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
        fs::remove(path_, ec);
        fs::rename(tmp, path_, ec);
    }
}

void IncidentStore::close() {
    std::lock_guard<std::mutex> lock(mu_);
    file_.sync();
    file_.close();
}

std::vector<IncidentNotice> IncidentStore::on_alerts(const std::vector<Alert>& alerts) {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<IncidentNotice> out;
    std::unordered_map<uint64_t, size_t> notice_of;  // инцидент -> позиция в out
    std::unordered_map<uint64_t, Severity> before;   // важность до этой пачки
    batching_ = true;
    batch_.clear();
    for (const Alert& a : alerts) {
        if (a.id == 0) continue;
        const int64_t t = a.created ? a.created : now_ms();
        std::string key = incident_key(a);
        Incident* inc = nullptr;
        if (auto it = by_key_.find(key); it != by_key_.end()) {
            Incident* c = find_locked(it->second);
            if (c && c->active() && t - c->last_alert <= window_ms_) inc = c;
        }
        bool created = false;
        if (!inc) {
            Incident n;
            n.id = next_id_++;
            n.key = key;
            n.src_ip = a.src_ip;
            n.user = a.user;
            n.host = a.host;
            n.created = n.updated = t;
            std::string p;
            put_varint(p, n.id);
            put_bytes(p, n.key);
            put_bytes(p, n.src_ip);
            put_bytes(p, n.user);
            put_bytes(p, n.host);
            put_svarint(p, n.created);
            append(kCreate, p);
            index_[n.id] = incidents_.size();
            incidents_.push_back(std::move(n));
            inc = &incidents_.back();
            by_key_[key] = inc->id;
            created = true;
        }
        if (!before.count(inc->id)) before[inc->id] = created ? Severity::Info : inc->severity;
        std::string p;
        put_varint(p, inc->id);
        put_varint(p, a.id);
        put_bytes(p, a.rule_id);
        put_bytes(p, a.rule_name);
        put_u8(p, uint8_t(a.severity));
        put_svarint(p, t);
        put_bytes(p, a.host);
        put_bytes(p, a.user);
        append(kAlert, p);
        apply_alert(*inc, a.id, a.rule_id, a.rule_name, a.severity, t, a.host, a.user);

        auto nit = notice_of.find(inc->id);
        if (nit == notice_of.end()) {
            notice_of[inc->id] = out.size();
            out.push_back({});
            out.back().is_new = created;
        }
        IncidentNotice& n = out[notice_of[inc->id]];
        n.id = inc->id;
        n.severity = inc->severity;
        n.alert_count = inc->alert_count;
        n.title = inc->title();
        n.alert = a;
        n.escalated = !n.is_new && inc->severity > before[inc->id];
    }
    batching_ = false;
    if (!batch_.empty() && file_.is_open()) {
        if (!file_.write(batch_.data(), batch_.size()) || !file_.flush()) log::warn("incidents: cannot write ", path_);
    }
    batch_.clear();
    return out;
}

std::vector<Incident> IncidentStore::list(const IncidentQuery& q) const {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<Incident> out;
    std::string needle = to_lower(q.text);
    for (auto it = incidents_.rbegin(); it != incidents_.rend() && out.size() < (q.limit ? q.limit : 50); ++it) {
        const Incident& i = *it;
        if (q.before_id && i.id >= q.before_id) continue;
        if (q.status && i.status != *q.status) continue;
        if (q.active_only && !i.active()) continue;
        if (q.min_severity && i.severity < *q.min_severity) continue;
        if (!q.assignee.empty() && (q.assignee == "-" ? !i.assignee.empty() : i.assignee != q.assignee)) continue;
        if (!needle.empty()) {
            std::string hay = to_lower(i.title() + " " + i.src_ip + " " + i.user + " " + i.host);
            for (auto& r : i.rules) hay += " " + to_lower(r.rule_id) + " " + to_lower(r.rule_name);
            if (hay.find(needle) == std::string::npos) continue;
        }
        out.push_back(i);
    }
    return out;
}

std::optional<Incident> IncidentStore::get(uint64_t id) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = index_.find(id);
    if (it == index_.end()) return std::nullopt;
    return incidents_[it->second];
}

uint64_t IncidentStore::incident_of_alert(uint64_t alert_id) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = alert_to_inc_.find(alert_id);
    return it == alert_to_inc_.end() ? 0 : it->second;
}

IncidentCounts IncidentStore::counts() const {
    std::lock_guard<std::mutex> lock(mu_);
    IncidentCounts c;
    for (auto& i : incidents_) {
        if (!i.active()) continue;
        ++c.active;
        if (i.assignee.empty()) ++c.unassigned;
        ++c.by_severity[size_t(i.severity)];
    }
    return c;
}

bool IncidentStore::set_status(uint64_t id, IncidentStatus st, const std::string& by, std::string& error) {
    std::lock_guard<std::mutex> lock(mu_);
    Incident* inc = find_locked(id);
    if (!inc) {
        error = "incident not found";
        return false;
    }
    if (inc->merged_into && (st == IncidentStatus::Open || st == IncidentStatus::InProgress)) {
        error = "incident was merged into #" + std::to_string(inc->merged_into);
        return false;
    }
    const int64_t now = now_ms();
    std::string p;
    put_varint(p, id);
    put_u8(p, uint8_t(st));
    put_bytes(p, by);
    put_svarint(p, now);
    append(kStatus, p);
    status_locked(*inc, st, by, now);
    if (inc->active()) {
        // снова открыт: новые алерты с этого адреса пойдут в него, если нет более нового
        auto it = by_key_.find(inc->key);
        if (it == by_key_.end() || it->second < inc->id) by_key_[inc->key] = inc->id;
    } else if (auto it = by_key_.find(inc->key); it != by_key_.end() && it->second == inc->id) {
        by_key_.erase(it);
    }
    return true;
}

bool IncidentStore::assign(uint64_t id, const std::string& assignee, const std::string& by, std::string& error) {
    std::lock_guard<std::mutex> lock(mu_);
    Incident* inc = find_locked(id);
    if (!inc) {
        error = "incident not found";
        return false;
    }
    const int64_t now = now_ms();
    std::string p;
    put_varint(p, id);
    put_bytes(p, assignee);
    put_bytes(p, by);
    put_svarint(p, now);
    append(kAssign, p);
    assign_locked(*inc, assignee, by, now);
    return true;
}

bool IncidentStore::add_note(uint64_t id, const std::string& by, const std::string& text, std::string& error) {
    std::lock_guard<std::mutex> lock(mu_);
    Incident* inc = find_locked(id);
    if (!inc) {
        error = "incident not found";
        return false;
    }
    if (inc->notes.size() >= kMaxNotes) {
        error = "too many notes";
        return false;
    }
    IncidentNote n;
    n.id = next_note_++;
    n.ts = now_ms();
    n.by = by;
    n.text = text;
    std::string p;
    put_varint(p, id);
    put_varint(p, n.id);
    put_svarint(p, n.ts);
    put_bytes(p, n.by);
    put_bytes(p, n.text);
    append(kNote, p);
    inc->updated = n.ts;
    inc->notes.push_back(std::move(n));
    return true;
}

bool IncidentStore::merge(uint64_t src, uint64_t dst, const std::string& by, std::string& error) {
    std::lock_guard<std::mutex> lock(mu_);
    if (src == dst) {
        error = "cannot merge an incident into itself";
        return false;
    }
    Incident* s = find_locked(src);
    Incident* d = find_locked(dst);
    if (!s || !d) {
        error = "incident not found";
        return false;
    }
    if (s->merged_into) {
        error = "incident #" + std::to_string(src) + " is already merged";
        return false;
    }
    if (d->merged_into) {
        error = "incident #" + std::to_string(dst) + " was merged into #" + std::to_string(d->merged_into);
        return false;
    }
    const int64_t now = now_ms();
    std::string p;
    put_varint(p, src);
    put_varint(p, dst);
    put_bytes(p, by);
    put_svarint(p, now);
    append(kMerge, p);
    merge_locked(*s, *d, by, now);
    if (auto it = by_key_.find(s->key); it != by_key_.end() && it->second == s->id) {
        by_key_.erase(it);
        if (d->active() && !by_key_.count(s->key)) by_key_[s->key] = d->id;  // новые алерты того адреса — в общий
    }
    return true;
}

}  // namespace sentinel
