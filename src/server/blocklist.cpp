#include "server/blocklist.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "core/json.hpp"
#include "core/log.hpp"
#include "core/util.hpp"

namespace fs = std::filesystem;

namespace sentinel {

namespace {

bool overlaps(const Cidr& a, const Cidr& b) {
    if (a.net.v6 != b.net.v6) return false;
    return a.contains(b.net) || b.contains(a.net);
}

// Адреса, которые нельзя блокировать даже вручную: это сломало бы сам сервер.
bool unblockable(const Cidr& c) {
    static const Cidr never[] = {*parse_cidr("0.0.0.0/8"), *parse_cidr("127.0.0.0/8"), *parse_cidr("224.0.0.0/3"),
                                 *parse_cidr("::/128"),    *parse_cidr("::1/128"),     *parse_cidr("ff00::/8")};
    for (auto& n : never)
        if (overlaps(n, c)) return true;
    return c.prefix < (c.net.v6 ? 16 : 8);  // слишком большая подсеть — почти наверняка ошибка
}

}  // namespace

const char* BlockList::result_text(Result r) {
    switch (r) {
        case Result::Added: return "added";
        case Result::Extended: return "extended";
        case Result::Unchanged: return "unchanged";
        case Result::Invalid: return "invalid address or network (or a range that must not be blocked)";
        case Result::Allowlisted: return "address is in the allowlist";
        case Result::Private: return "private or special address";
        case Result::Limit: return "auto-block rate limit reached";
        case Result::Full: return "block list is full";
    }
    return "?";
}

bool BlockList::open(const std::string& path, std::string& error) {
    std::lock_guard<std::mutex> lock(mu_);
    path_ = path;
    blocks_.clear();
    if (path_.empty()) return true;
    std::ifstream in(path_, std::ios::binary);
    if (!in) return true;  // ещё нет файла
    std::stringstream ss;
    ss << in.rdbuf();
    JValue v;
    if (!json_parse(ss.str(), v, error) || !v.is_object()) {
        error = path_ + ": damaged block list (" + error + ")";
        return false;
    }
    if (auto* ver = v.get("version"); ver && ver->is_number()) version_ = uint64_t(ver->i) + 1;
    if (auto* arr = v.get("blocks"); arr && arr->is_array()) {
        for (auto& o : arr->arr) {
            auto str = [&](const char* k) {
                auto* x = o.get(k);
                return x && x->is_string() ? x->s : std::string();
            };
            auto num = [&](const char* k) -> int64_t {
                auto* x = o.get(k);
                return x && x->is_number() ? x->i : 0;
            };
            auto c = parse_cidr(str("ip"));
            if (!c) continue;
            Block b;
            b.ip = format_cidr(*c);
            b.reason = str("reason");
            b.rule_id = str("rule_id");
            b.alert_id = uint64_t(num("alert_id"));
            b.by = str("by");
            b.created = num("created_ms");
            b.expires = num("expires_ms");
            b.hits = uint64_t(std::max<int64_t>(1, num("hits")));
            blocks_[b.ip] = b;
        }
    }
    stats_.active = blocks_.size();
    log::info("blocks: loaded ", blocks_.size(), " blocked addresses");
    return true;
}

void BlockList::set_policy(AutoBlockPolicy p) {
    std::lock_guard<std::mutex> lock(mu_);
    policy_ = std::move(p);
}

AutoBlockPolicy BlockList::policy() const {
    std::lock_guard<std::mutex> lock(mu_);
    return policy_;
}

bool BlockList::allowlisted(const Cidr& c) const {
    for (auto& a : policy_.allowlist)
        if (overlaps(a, c)) return true;
    return false;
}

BlockList::Result BlockList::add_locked(const Cidr& c, int64_t duration_ms, const std::string& reason,
                                        const std::string& rule_id, uint64_t alert_id, const std::string& by,
                                        int64_t now, Block* out) {
    const std::string key = format_cidr(c);
    const int64_t expires = duration_ms > 0 ? now + duration_ms : 0;
    auto it = blocks_.find(key);
    if (it != blocks_.end()) {
        Block& b = it->second;
        bool is_auto = by == "auto";
        bool longer = b.expires != 0 && (expires == 0 || expires > b.expires);
        if (is_auto && !longer) {
            if (out) *out = b;
            return Result::Unchanged;
        }
        b.expires = expires;  // автоблокировка только продлевает, ручное действие задаёт срок явно
        ++b.hits;
        if (!is_auto) {
            b.reason = reason;
            b.by = by;
        } else {
            b.alert_id = alert_id;
            b.rule_id = rule_id;
        }
        ++version_;
        dirty_ = true;
        if (out) *out = b;
        return Result::Extended;
    }
    if (blocks_.size() >= kMaxEntries) return Result::Full;
    Block b;
    b.ip = key;
    b.reason = reason;
    b.rule_id = rule_id;
    b.alert_id = alert_id;
    b.by = by;
    b.created = now;
    b.expires = expires;
    blocks_[key] = b;
    ++version_;
    dirty_ = true;
    stats_.active = blocks_.size();
    if (out) *out = b;
    return Result::Added;
}

BlockList::Result BlockList::add_manual(const std::string& ip_or_cidr, int64_t duration_ms, const std::string& reason,
                                        const std::string& by, Block* out) {
    auto c = parse_cidr(ip_or_cidr);
    if (!c || unblockable(*c)) return Result::Invalid;
    std::lock_guard<std::mutex> lock(mu_);
    if (allowlisted(*c)) {
        ++stats_.skipped_allowlist;
        return Result::Allowlisted;
    }
    Result r = add_locked(*c, duration_ms, reason, "", 0, by.empty() ? "manual" : by, now_ms(), out);
    if (r == Result::Added || r == Result::Extended) {
        ++stats_.manual_added;
        log::info("blocks: ", format_cidr(*c), " blocked by ", by, duration_ms ? "" : " (permanently)",
                  reason.empty() ? "" : ": " + reason);
    }
    return r;
}

bool BlockList::remove(const std::string& ip_or_cidr) {
    auto c = parse_cidr(ip_or_cidr);
    if (!c) return false;
    std::lock_guard<std::mutex> lock(mu_);
    if (blocks_.erase(format_cidr(*c)) == 0) return false;
    ++version_;
    dirty_ = true;
    stats_.active = blocks_.size();
    log::info("blocks: ", format_cidr(*c), " unblocked");
    return true;
}

std::vector<Block> BlockList::on_alerts(const std::vector<Alert>& alerts) {
    std::vector<Block> added;
    std::lock_guard<std::mutex> lock(mu_);
    if (!policy_.enabled) return added;
    const int64_t now = now_ms();
    for (const Alert& a : alerts) {
        if (a.src_ip.empty()) continue;
        bool by_rule = std::find(policy_.rules.begin(), policy_.rules.end(), a.rule_id) != policy_.rules.end();
        if (!by_rule && a.severity < policy_.min_severity) continue;
        auto ip = parse_ip(a.src_ip);
        if (!ip) continue;
        Cidr c{*ip, ip->v6 ? 128 : 32};
        if (unblockable(c)) continue;
        if (allowlisted(c)) {
            ++stats_.skipped_allowlist;
            continue;
        }
        if (!policy_.block_private && is_private_or_special(*ip)) {
            ++stats_.skipped_private;
            continue;
        }
        if (now - minute_start_ >= 60000) {
            minute_start_ = now;
            minute_count_ = 0;
        }
        if (minute_count_ >= policy_.max_per_minute) {
            if (stats_.skipped_limit++ % 100 == 0)
                log::warn("blocks: auto-block limit (", policy_.max_per_minute, "/min) reached, skipping ", a.src_ip);
            continue;
        }
        Block b;
        Result r = add_locked(c, policy_.duration_ms, a.rule_name, a.rule_id, a.id, "auto", now, &b);
        if (r == Result::Added || r == Result::Extended) {
            ++minute_count_;
            ++stats_.auto_added;
            added.push_back(b);
            log::info("blocks: auto-blocked ", b.ip, " (alert #", a.id, " ", a.rule_id, ")",
                      b.expires ? " until " + format_iso8601(b.expires) : std::string(" permanently"));
        }
    }
    return added;
}

void BlockList::tick(int64_t now) {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto it = blocks_.begin(); it != blocks_.end();) {
        if (it->second.expires != 0 && it->second.expires <= now) {
            log::info("blocks: ", it->first, " expired");
            it = blocks_.erase(it);
            ++version_;
            ++stats_.expired;
            dirty_ = true;
        } else {
            ++it;
        }
    }
    stats_.active = blocks_.size();
    if (dirty_) save_locked();
}

void BlockList::flush() {
    std::lock_guard<std::mutex> lock(mu_);
    if (dirty_) save_locked();
}

void BlockList::save_locked() {
    dirty_ = false;
    if (path_.empty()) return;
    std::string out;
    JsonWriter w(out);
    w.begin_object().kv("version", version_).key("blocks").begin_array();
    for (auto& kv : blocks_) {
        const Block& b = kv.second;
        w.begin_object().kv("ip", b.ip).kv("reason", b.reason).kv("rule_id", b.rule_id).kv("alert_id", b.alert_id);
        w.kv("by", b.by).kv("created_ms", b.created).kv("expires_ms", b.expires).kv("hits", b.hits).end_object();
    }
    w.end_array().end_object();
    std::error_code ec;
    fs::path p(path_);
    if (p.has_parent_path()) fs::create_directories(p.parent_path(), ec);
    std::string tmp = path_ + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        f << out;
        if (!f) {
            log::error("blocks: cannot write ", tmp);
            dirty_ = true;
            return;
        }
    }
    fs::rename(tmp, path_, ec);
    if (ec) {
        fs::remove(path_, ec);
        fs::rename(tmp, path_, ec);
    }
    if (ec) {
        log::error("blocks: cannot replace ", path_);
        dirty_ = true;
    }
}

std::vector<Block> BlockList::list() const {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<Block> out;
    out.reserve(blocks_.size());
    for (auto& kv : blocks_) out.push_back(kv.second);
    return out;
}

std::optional<Block> BlockList::find(const std::string& ip) const {
    auto c = parse_cidr(ip);
    if (!c) return std::nullopt;
    std::lock_guard<std::mutex> lock(mu_);
    auto it = blocks_.find(format_cidr(*c));
    if (it != blocks_.end()) return it->second;
    for (auto& kv : blocks_) {
        auto bc = parse_cidr(kv.first);
        if (bc && bc->prefix < (bc->net.v6 ? 128 : 32) && bc->contains(c->net)) return kv.second;
    }
    return std::nullopt;
}

uint64_t BlockList::version() const {
    std::lock_guard<std::mutex> lock(mu_);
    return version_;
}

BlockStats BlockList::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    BlockStats s = stats_;
    s.active = blocks_.size();
    return s;
}

}  // namespace sentinel
