// SentinelCore — HTTP API: карточка IP-адреса и состояние чёрных списков.
#include <algorithm>
#include <map>
#include <unordered_map>
#include <unordered_set>

#include "core/json.hpp"
#include "core/util.hpp"
#include "server/api.hpp"
#include "server/json_out.hpp"

namespace sentinel {

using net::HttpRequest;
using net::HttpResponse;

namespace {

using Counter = std::unordered_map<std::string, uint64_t>;

void write_top(JsonWriter& w, const char* name, const Counter& m, size_t n) {
    std::vector<std::pair<std::string, uint64_t>> v(m.begin(), m.end());
    size_t k = std::min(n, v.size());
    std::partial_sort(v.begin(), v.begin() + long(k), v.end(),
                      [](auto& a, auto& b) { return a.second != b.second ? a.second > b.second : a.first < b.first; });
    v.resize(k);
    w.key(name).begin_array();
    for (auto& p : v) w.begin_object().kv("value", p.first).kv("count", p.second).end_object();
    w.end_array();
}

void bump(Counter& m, std::string_view k) {
    if (k.empty() || m.size() > 20000) return;
    ++m[std::string(k.substr(0, 300))];
}

}  // namespace

void Api::ip_card(const std::string& raw, const HttpRequest& req, HttpResponse& resp) {
    auto ip = parse_ip(trim(raw));
    if (!ip) return resp.error(400, "not an IP address");
    const std::string addr = format_ip(*ip);
    IpReport rep;
    if (enricher_) rep = enricher_->lookup(addr);
    else {
        rep.valid = true;
        rep.ip = addr;
        rep.internal = is_private_or_special(*ip);
    }
    size_t max_events = 20000;
    if (auto m = parse_uint(req.param("max_events"))) max_events = size_t(std::clamp<uint64_t>(*m, 100, 200000));

    // события этого адреса (по bloom-фильтрам читаются только нужные блоки), сначала свежие
    EventQuery q;
    q.equals = {{"src_ip", addr}};
    q.limit = max_events;
    Counter paths, users, hosts, types, actions, agents, statuses, sources;
    std::map<int64_t, uint64_t> by_day;
    int64_t first = 0, last = 0;
    uint64_t failures = 0;
    size_t seen = events_.visit(q, [&](Event&& e) {
        int64_t t = e.time();
        if (!last || t > last) last = t;
        if (!first || t < first) first = t;
        ++by_day[t / 86400000 * 86400000];
        bump(paths, e[Field::HttpPath].substr(0, e[Field::HttpPath].find('?')));
        bump(users, e[Field::User]);
        bump(hosts, e[Field::Host]);
        bump(types, e[Field::Type]);
        bump(sources, e[Field::Source]);
        bump(statuses, e[Field::HttpStatus]);
        bump(agents, e[Field::HttpUserAgent]);
        if (!e[Field::Action].empty()) bump(actions, e[Field::Action] + (e[Field::Outcome].empty() ? "" : ":" + e[Field::Outcome]));
        if (e[Field::Outcome] == "failure") ++failures;
        return true;
    });

    AlertQuery aq;
    aq.src_ip = addr;
    aq.limit = 2000;
    auto alerts = alerts_.query(aq);
    std::unordered_map<std::string, std::pair<std::string, uint64_t>> by_rule;
    for (auto& a : alerts) {
        auto& r = by_rule[a.rule_id];
        r.first = a.rule_name;
        ++r.second;
    }

    std::string out;
    JsonWriter w(out);
    w.begin_object().kv("ip", addr).kv("internal", rep.internal);
    w.kv("country", rep.country).kv("city", rep.city).kv("asn", rep.asn).kv("org", rep.org);
    w.key("lists").begin_array();
    for (auto& l : rep.lists) w.value(l);
    w.end_array();
    bool dbip = false;
    if (enricher_)
        if (auto g = enricher_->geo())
            for (auto& s : g->sources()) dbip |= to_lower(s).find("dbip") != std::string::npos;
    w.kv("geo_available", enricher_ && enricher_->geo() && !enricher_->geo()->empty());
    w.kv("geo_attribution", dbip ? "IP geolocation by DB-IP (db-ip.com)" : "");
    w.key("block");
    std::optional<Block> blk = blocks_ ? blocks_->find(addr) : std::nullopt;
    if (blk) write_block(w, *blk);
    else w.null();

    w.key("events").begin_object().kv("count", seen).kv("capped", seen >= max_events).kv("failures", failures);
    w.key("first_seen");
    if (first) w.value(format_iso8601(first));
    else w.null();
    w.key("last_seen");
    if (last) w.value(format_iso8601(last));
    else w.null();
    w.key("by_day").begin_array();
    for (auto& [d, n] : by_day) w.begin_object().kv("day", format_iso8601(d).substr(0, 10)).kv("count", n).end_object();
    w.end_array();
    write_top(w, "paths", paths, 10);
    write_top(w, "users", users, 10);
    write_top(w, "hosts", hosts, 10);
    write_top(w, "types", types, 10);
    write_top(w, "sources", sources, 10);
    write_top(w, "statuses", statuses, 10);
    write_top(w, "actions", actions, 10);
    write_top(w, "user_agents", agents, 5);
    w.end_object();

    w.key("alerts").begin_object().kv("count", alerts.size()).kv("capped", alerts.size() >= aq.limit);
    std::vector<std::pair<std::string, std::pair<std::string, uint64_t>>> rules(by_rule.begin(), by_rule.end());
    std::sort(rules.begin(), rules.end(), [](auto& a, auto& b) { return a.second.second > b.second.second; });
    w.key("by_rule").begin_array();
    for (auto& r : rules)
        w.begin_object().kv("rule_id", r.first).kv("rule_name", r.second.first).kv("count", r.second.second).end_object();
    w.end_array();
    w.key("recent").begin_array();
    for (size_t i = 0; i < alerts.size() && i < 20; ++i) write_alert(w, alerts[i]);
    w.end_array().end_object();
    w.end_object();
    resp.json(200, std::move(out));
}

void Api::threat_status(HttpResponse& resp) {
    std::string out;
    JsonWriter w(out);
    w.begin_object();
    bool geo = false;
    size_t c = 0, a = 0;
    int64_t built = 0;
    if (enricher_)
        if (auto g = enricher_->geo()) {
            geo = !g->empty();
            c = g->ranges(GeoDb::Country) + g->ranges(GeoDb::City);
            a = g->ranges(GeoDb::Asn);
            built = g->built_at();
        }
    w.key("geo").begin_object().kv("available", geo).kv("country_ranges", c).kv("asn_ranges", a);
    w.key("built");
    if (built) w.value(format_iso8601(built));
    else w.null();
    w.end_object();
    w.key("lists").begin_array();
    if (feeds_)
        for (auto& s : feeds_->status()) {
            w.begin_object().kv("name", s.name).kv("source", s.source).kv("entries", s.entries).kv("cached", s.cached);
            w.key("updated");
            if (s.updated) w.value(format_iso8601(s.updated));
            else w.null();
            w.key("last_try");
            if (s.last_try) w.value(format_iso8601(s.last_try));
            else w.null();
            w.kv("last_error", s.last_error).end_object();
        }
    w.end_array().end_object();
    resp.json(200, std::move(out));
}

}  // namespace sentinel
