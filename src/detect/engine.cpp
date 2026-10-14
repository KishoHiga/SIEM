#include "detect/engine.hpp"

#include <algorithm>

#include "core/log.hpp"
#include "core/util.hpp"
#include "detect/transform.hpp"

namespace sentinel {

namespace {
constexpr size_t kMaxScanBytes = 64 * 1024;   // поле длиннее проверяется по первым 64 КБ
constexpr size_t kMaxIdsPerAlert = 20;
constexpr size_t kMaxValueInAlert = 300;

std::string clip(std::string_view s, size_t n = kMaxValueInAlert) {
    if (s.size() <= n) return std::string(s);
    return std::string(s.substr(0, n)) + "...";
}
}  // namespace

struct DetectionEngine::Group {
    FieldRef field;
    uint32_t transforms = 0;
    rx::MultiMatcher mm;
    uint64_t evaluated_for = 0;
    std::vector<uint8_t> hit;
    std::vector<uint32_t> found;
    std::string text;
};

struct DetectionEngine::Window {
    struct Hit {
        int64_t ts;
        uint64_t id;
    };
    std::deque<Hit> hits;
    std::deque<std::string> vals;  // для distinct: значение для каждого hit
    std::unordered_map<std::string, uint32_t> counts;
    int64_t cooldown_until = 0;

    void pop_front() {
        hits.pop_front();
        if (!vals.empty()) {
            auto it = counts.find(vals.front());
            if (it != counts.end() && --it->second == 0) counts.erase(it);
            vals.pop_front();
        }
    }
};

DetectionEngine::DetectionEngine() = default;
DetectionEngine::~DetectionEngine() = default;

bool DetectionEngine::load(std::vector<Rule> rules, std::string& error) {
    rules_.clear();
    groups_.clear();
    rule_index_.clear();
    for (auto& r : rules)
        if (r.enabled) rules_.push_back(std::move(r));

    std::unordered_map<std::string, size_t> group_by_key;
    auto attach = [&](Condition& c, const Rule& r) -> bool {
        if (c.op != Condition::Op::Regex && c.op != Condition::Op::NotRegex) return true;
        std::string gk = c.field.name + "|" + std::to_string(c.transforms);
        auto it = group_by_key.find(gk);
        size_t gi;
        if (it == group_by_key.end()) {
            auto g = std::make_unique<Group>();
            g->field = c.field;
            g->transforms = c.transforms;
            groups_.push_back(std::move(g));
            gi = groups_.size() - 1;
            group_by_key.emplace(gk, gi);
        } else {
            gi = it->second;
        }
        c.group = int(gi);
        c.pattern_ids.clear();
        for (auto& p : c.values) {
            std::string err;
            int id = groups_[gi]->mm.add(p, &err);
            if (id < 0) {
                error = "rule " + r.id + ": bad regex '" + p + "': " + err;
                return false;
            }
            c.pattern_ids.push_back(uint32_t(id));
        }
        return true;
    };
    auto order = [](std::vector<Condition>& conds) {
        // дешёвые условия первыми, регулярки — последними
        std::stable_sort(conds.begin(), conds.end(), [](const Condition& a, const Condition& b) {
            auto heavy = [](const Condition& c) {
                return c.op == Condition::Op::Regex || c.op == Condition::Op::NotRegex ||
                       c.op == Condition::Op::Contains;
            };
            return !heavy(a) && heavy(b);
        });
    };
    for (auto& r : rules_) {
        order(r.where);
        for (auto& c : r.where)
            if (!attach(c, r)) return false;
        for (auto& s : r.steps) {
            order(s.where);
            for (auto& c : s.where)
                if (!attach(c, r)) return false;
        }
    }
    for (auto& g : groups_) {
        std::string err;
        if (!g->mm.compile(&err)) {
            error = "regex group for field " + g->field.name + ": " + err;
            return false;
        }
        g->hit.assign(g->mm.pattern_count(), 0);
    }
    for (size_t i = 0; i < rules_.size(); ++i) rule_index_[rules_[i].id] = i;
    for (auto& r : rules_) {
        for (auto& s : r.steps) {
            if (!s.rule_id.empty() && !rule_index_.count(s.rule_id)) {
                error = "rule " + r.id + ": step refers to unknown or disabled rule " + s.rule_id;
                return false;
            }
        }
    }
    state_.clear();
    state_.resize(rules_.size());
    return true;
}

void DetectionEngine::reset_state() {
    state_.clear();
    state_.resize(rules_.size());
    latest_ts_ = 0;
}

bool DetectionEngine::group_hit(const Condition& c, const Event& ev) {
    Group& g = *groups_[size_t(c.group)];
    if (g.evaluated_for != seq_no_) {
        std::string_view v = g.field.get(ev);
        if (v.size() > kMaxScanBytes) v = v.substr(0, kMaxScanBytes);
        for (uint32_t id : g.found) g.hit[id] = 0;
        g.found.clear();
        if (g.transforms) {
            apply_transforms(v, g.transforms, g.text);
            g.mm.scan(g.text, g.found);
        } else {
            g.mm.scan(v, g.found);
        }
        for (uint32_t id : g.found) g.hit[id] = 1;
        g.evaluated_for = seq_no_;
    }
    for (uint32_t id : c.pattern_ids)
        if (g.hit[id]) return true;
    return false;
}

bool DetectionEngine::eval_one(const Condition& c, const Event& ev) {
    using Op = Condition::Op;
    switch (c.op) {
        case Op::Regex: return group_hit(c, ev);
        case Op::NotRegex: return !group_hit(c, ev);
        default: break;
    }
    std::string_view v = c.field.get(ev);
    switch (c.op) {
        case Op::In:
            for (auto& x : c.values)
                if (iequals(v, x)) return true;
            return false;
        case Op::NotIn:
            for (auto& x : c.values)
                if (iequals(v, x)) return false;
            return true;
        case Op::Contains: {
            std::string_view hay = v;
            if (c.transforms) {
                apply_transforms(v, c.transforms, scratch_);
                hay = scratch_;
            }
            for (auto& x : c.values)
                if (ifind(hay, x) != std::string_view::npos) return true;
            return false;
        }
        case Op::Exists: return !v.empty();
        case Op::Missing: return v.empty();
        case Op::Gte:
        case Op::Lte:
        case Op::Gt:
        case Op::Lt: {
            auto d = parse_double(v);
            if (!d) return false;
            if (c.op == Op::Gte) return *d >= c.number;
            if (c.op == Op::Lte) return *d <= c.number;
            if (c.op == Op::Gt) return *d > c.number;
            return *d < c.number;
        }
        default: return false;
    }
}

bool DetectionEngine::eval(const std::vector<Condition>& conds, const Event& ev) {
    for (auto& c : conds)
        if (!eval_one(c, ev)) return false;
    return true;
}

bool DetectionEngine::make_key(const Rule& r, const Event& ev, std::string& key) const {
    key.clear();
    for (size_t i = 0; i < r.group_by.size(); ++i) {
        std::string_view v = r.group_by[i].get(ev);
        if (v.empty()) return false;
        if (i) key.push_back('\x1f');
        key.append(v.data(), v.size());
    }
    return true;
}

std::string DetectionEngine::render(const Rule& r, const Event& ev, uint64_t count) const {
    std::string tmpl = r.message;
    if (tmpl.empty()) {
        tmpl = r.name;
        if (!ev[Field::SrcIp].empty()) tmpl += " from {src_ip}";
        if (r.kind == Rule::Kind::Threshold) tmpl += " ({count} events)";
    }
    std::string out;
    out.reserve(tmpl.size() + 64);
    for (size_t i = 0; i < tmpl.size(); ++i) {
        if (tmpl[i] == '{') {
            size_t close = tmpl.find('}', i);
            if (close != std::string::npos && close - i < 64) {
                std::string_view name(tmpl.data() + i + 1, close - i - 1);
                if (name == "count") out += std::to_string(count);
                else if (name == "rule") out += r.name;
                else if (name == "threshold") out += std::to_string(r.threshold);
                else if (name == "window") out += std::to_string(r.window_ms / 1000);
                else out += clip(ev.get(name), 160);
                i = close;
                continue;
            }
        }
        out.push_back(tmpl[i]);
    }
    return out;
}

Alert DetectionEngine::make_alert(const Rule& r, const Event& ev, uint64_t count) const {
    Alert a;
    a.ts = ev.time();
    a.created = now_ms();
    a.rule_id = r.id;
    a.rule_name = r.name;
    a.severity = r.severity;
    a.src_ip = ev[Field::SrcIp];
    a.user = ev[Field::User];
    a.host = ev[Field::Host];
    a.count = count;
    a.message = render(r, ev, count);
    a.fields.emplace_back("rule_type", rule_kind_name(r.kind));
    for (auto& c : r.where) {
        if (c.op == Condition::Op::Regex || c.op == Condition::Op::Contains) {
            std::string_view v = c.field.get(ev);
            if (!v.empty()) a.fields.emplace_back(c.field.name, clip(v));
        }
    }
    // откуда атакующий и в каких чёрных списках (если события обогащены)
    for (const char* k : {"geo.country", "geo.org", "ti.lists"})
        if (const std::string* v = ev.extra_get(k)) a.fields.emplace_back(k, *v);
    if (r.kind == Rule::Kind::Threshold) {
        a.fields.emplace_back("threshold", std::to_string(r.threshold));
        a.fields.emplace_back("window_seconds", std::to_string(r.window_ms / 1000));
        if (r.distinct) a.fields.emplace_back("distinct_field", r.distinct->name);
    }
    return a;
}

bool DetectionEngine::cooldown_pass(size_t ri, const std::string& key, int64_t t, int64_t cd_ms, uint64_t& repeats) {
    repeats = 0;
    if (cd_ms <= 0) return true;
    Cooldown& c = state_[ri].cooldown[key];
    if (t < c.until) {
        ++c.suppressed;
        ++stats_.suppressed;
        return false;
    }
    repeats = c.suppressed;
    c.suppressed = 0;
    c.until = t + cd_ms;
    return true;
}

void DetectionEngine::process(const Event& ev, std::vector<Alert>& out) {
    ++seq_no_;
    ++stats_.events;
    fired_.clear();
    const int64_t t = ev.time();
    if (t > latest_ts_) latest_ts_ = t;
    std::string key;

    for (size_t ri = 0; ri < rules_.size(); ++ri) {
        const Rule& r = rules_[ri];
        if (r.kind == Rule::Kind::Sequence) continue;
        if (!eval(r.where, ev)) continue;
        bool key_ok = make_key(r, ev, key);

        if (r.kind == Rule::Kind::Match) {
            fired_.push_back(ri);
            if (!key_ok) key.clear();
            uint64_t repeats;
            int64_t cd = r.cooldown_ms >= 0 ? r.cooldown_ms : 60000;
            if (cooldown_pass(ri, key, t, cd, repeats)) {
                Alert a = make_alert(r, ev, 1);
                if (repeats) a.fields.emplace_back("repeats_before", std::to_string(repeats));
                a.event_ids.push_back(ev.id);
                out.push_back(std::move(a));
                ++stats_.alerts;
            }
            continue;
        }

        // threshold
        if (!key_ok) continue;
        auto& wp = state_[ri].windows[key];
        if (!wp) wp = std::make_unique<Window>();
        Window& w = *wp;
        w.hits.push_back({t, ev.id});
        if (r.distinct) {
            std::string v(r.distinct->get(ev));
            ++w.counts[v];
            w.vals.push_back(std::move(v));
        }
        const int64_t cutoff = t - r.window_ms;
        while (!w.hits.empty() && w.hits.front().ts < cutoff) w.pop_front();
        // защита памяти: при поиске разных значений храним до 10000 отметок, иначе 2*порог
        const size_t cap = r.distinct ? 10000 : size_t(r.threshold) * 2 + 16;
        while (w.hits.size() > cap) w.pop_front();
        const uint64_t count = r.distinct ? w.counts.size() : w.hits.size();
        if (count >= r.threshold) {
            fired_.push_back(ri);
            if (t >= w.cooldown_until) {
                Alert a = make_alert(r, ev, count);
                size_t n = std::min(w.hits.size(), kMaxIdsPerAlert);
                for (size_t k = w.hits.size() - n; k < w.hits.size(); ++k) a.event_ids.push_back(w.hits[k].id);
                w.cooldown_until = t + (r.cooldown_ms >= 0 ? r.cooldown_ms : r.window_ms);
                out.push_back(std::move(a));
                ++stats_.alerts;
            } else {
                ++stats_.suppressed;
            }
        }
    }

    // Цепочки (после того, как известно, какие правила сработали на этом событии)
    for (size_t ri = 0; ri < rules_.size(); ++ri) {
        const Rule& r = rules_[ri];
        if (r.kind != Rule::Kind::Sequence) continue;
        if (!r.where.empty() && !eval(r.where, ev)) continue;
        if (!make_key(r, ev, key)) continue;
        auto& states = state_[ri].seq;
        auto it = states.find(key);
        if (it != states.end() && t - it->second.start > r.within_ms) {
            states.erase(it);
            it = states.end();
        }
        const size_t cur = it == states.end() ? 0 : it->second.step;
        const Rule::Step& step = r.steps[cur];
        bool ok;
        if (!step.rule_id.empty()) {
            size_t idx = rule_index_[step.rule_id];
            ok = std::find(fired_.begin(), fired_.end(), idx) != fired_.end();
        } else {
            ok = eval(step.where, ev);
        }
        if (!ok) continue;
        if (it == states.end()) it = states.emplace(key, SeqState{0, t, {}}).first;
        SeqState& s = it->second;
        ++s.step;
        if (s.ids.size() < kMaxIdsPerAlert) s.ids.push_back(ev.id);
        if (s.step >= r.steps.size()) {
            fired_.push_back(ri);
            uint64_t repeats;
            int64_t cd = r.cooldown_ms >= 0 ? r.cooldown_ms : r.within_ms;
            if (cooldown_pass(ri, key, t, cd, repeats)) {
                Alert a = make_alert(r, ev, r.steps.size());
                a.event_ids = s.ids;
                a.fields.emplace_back("steps", std::to_string(r.steps.size()));
                out.push_back(std::move(a));
                ++stats_.alerts;
            }
            states.erase(it);
        }
    }

    if ((stats_.events & 8191) == 0) sweep(latest_ts_);
}

void DetectionEngine::sweep(int64_t now) {
    if (latest_ts_ > now) now = latest_ts_;
    for (size_t ri = 0; ri < rules_.size(); ++ri) {
        const Rule& r = rules_[ri];
        RuleState& st = state_[ri];
        for (auto it = st.cooldown.begin(); it != st.cooldown.end();) {
            if (it->second.until < now) it = st.cooldown.erase(it);
            else ++it;
        }
        for (auto it = st.windows.begin(); it != st.windows.end();) {
            Window& w = *it->second;
            const int64_t cutoff = now - r.window_ms;
            while (!w.hits.empty() && w.hits.front().ts < cutoff) w.pop_front();
            if (w.hits.empty() && w.cooldown_until < now) it = st.windows.erase(it);
            else ++it;
        }
        for (auto it = st.seq.begin(); it != st.seq.end();) {
            if (now - it->second.start > r.within_ms) it = st.seq.erase(it);
            else ++it;
        }
        limit_state(ri, now);
    }
}

void DetectionEngine::limit_state(size_t ri, int64_t) {
    RuleState& st = state_[ri];
    auto over = [&](size_t n) { return n > max_keys_; };
    if (over(st.windows.size()) || over(st.cooldown.size()) || over(st.seq.size())) {
        log::warn("detection: rule ", rules_[ri].id, " state exceeded ", max_keys_, " keys, resetting its state");
        if (over(st.windows.size())) st.windows.clear();
        if (over(st.cooldown.size())) st.cooldown.clear();
        if (over(st.seq.size())) st.seq.clear();
    }
}

EngineStats DetectionEngine::stats() const {
    EngineStats s = stats_;
    s.state_keys = 0;
    for (auto& st : state_) s.state_keys += st.cooldown.size() + st.windows.size() + st.seq.size();
    return s;
}

}  // namespace sentinel
