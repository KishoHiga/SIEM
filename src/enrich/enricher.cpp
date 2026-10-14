#include "enrich/enricher.hpp"

#include <filesystem>

#include "core/log.hpp"
#include "core/util.hpp"

namespace fs = std::filesystem;

namespace sentinel {

void Enricher::set_geo(std::shared_ptr<const GeoDb> db) {
    std::lock_guard<std::mutex> lock(mu_);
    geo_ = std::move(db);
}

void Enricher::set_threat(std::shared_ptr<const ThreatSet> set) {
    std::lock_guard<std::mutex> lock(mu_);
    threat_ = std::move(set);
}

std::shared_ptr<const GeoDb> Enricher::geo() const {
    std::lock_guard<std::mutex> lock(mu_);
    return geo_;
}

std::shared_ptr<const ThreatSet> Enricher::threat() const {
    std::lock_guard<std::mutex> lock(mu_);
    return threat_;
}

void Enricher::enrich(std::vector<Event>& batch) const {
    std::shared_ptr<const GeoDb> geo;
    std::shared_ptr<const ThreatSet> ti;
    {
        std::lock_guard<std::mutex> lock(mu_);
        geo = geo_;
        ti = threat_;
    }
    if ((!geo || geo->empty()) && (!ti || ti->names().empty())) return;
    // в пачке обычно много событий с одного адреса — запоминаем последний
    std::string last_ip;
    GeoInfo last_geo;
    uint64_t last_mask = 0;
    bool last_ok = false;
    for (auto& ev : batch) {
        const std::string& s = ev[Field::SrcIp];
        if (s.empty()) continue;
        if (s != last_ip) {
            last_ip = s;
            last_ok = false;
            auto ip = parse_ip(s);
            if (ip && !is_private_or_special(*ip)) {
                last_ok = true;
                last_geo = geo ? geo->lookup(*ip) : GeoInfo{};
                last_mask = ti ? ti->match(*ip) : 0;
            }
        }
        if (!last_ok) continue;
        if (!last_geo.country.empty()) ev.extra_set("geo.country", last_geo.country);
        if (!last_geo.city.empty()) ev.extra_set("geo.city", last_geo.city);
        if (!last_geo.asn.empty()) ev.extra_set("geo.asn", last_geo.asn);
        if (!last_geo.org.empty()) ev.extra_set("geo.org", last_geo.org);
        if (last_mask) {
            ev.extra_set("ti.listed", "true");
            ev.extra_set("ti.lists", ti->names_of(last_mask));
        }
    }
}

IpReport Enricher::lookup(const std::string& s) const {
    IpReport r;
    auto ip = parse_ip(trim(s));
    if (!ip) return r;
    r.valid = true;
    r.ip = format_ip(*ip);
    r.internal = is_private_or_special(*ip);
    std::shared_ptr<const GeoDb> geo;
    std::shared_ptr<const ThreatSet> ti;
    {
        std::lock_guard<std::mutex> lock(mu_);
        geo = geo_;
        ti = threat_;
    }
    if (geo) {
        GeoInfo g = geo->lookup(*ip);
        r.country = std::string(g.country);
        r.city = std::string(g.city);
        r.asn = std::string(g.asn);
        r.org = std::string(g.org);
    }
    if (ti) {
        uint64_t m = ti->match(*ip);
        for (size_t i = 0; i < ti->names().size(); ++i)
            if (m & (uint64_t(1) << i)) r.lists.push_back(ti->names()[i]);
    }
    return r;
}

bool Enricher::reload_geo_if_changed(const std::string& path) {
    std::error_code ec;
    if (!fs::exists(path, ec)) return false;
    int64_t stamp = int64_t(fs::last_write_time(path, ec).time_since_epoch().count()) ^ int64_t(fs::file_size(path, ec));
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (stamp == geo_stamp_) return false;
        geo_stamp_ = stamp;
    }
    auto db = std::make_shared<GeoDb>();
    std::string err;
    if (!db->load(path, err)) {
        log::error("geo: ", err);
        return false;
    }
    log::info("geo: loaded ", db->ranges(GeoDb::Country) + db->ranges(GeoDb::City), " country/city and ",
              db->ranges(GeoDb::Asn), " network ranges from ", path);
    set_geo(std::move(db));
    return true;
}

}  // namespace sentinel
