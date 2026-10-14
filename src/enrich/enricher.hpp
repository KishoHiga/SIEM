// SentinelCore — обогащение событий при приёме: страна и сеть по IP источника (geo.*)
// и отметка «адрес из чёрного списка» (ti.*). Базы меняются на лету, без остановки приёма.
#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "core/event.hpp"
#include "enrich/geo.hpp"
#include "enrich/threat.hpp"

namespace sentinel {

struct IpReport {
    bool valid = false;
    bool internal = false;  // частная или служебная сеть
    std::string ip;         // в каноническом виде
    std::string country, city, asn, org;
    std::vector<std::string> lists;  // в каких чёрных списках
};

class Enricher {
public:
    void set_geo(std::shared_ptr<const GeoDb> db);
    void set_threat(std::shared_ptr<const ThreatSet> set);
    std::shared_ptr<const GeoDb> geo() const;
    std::shared_ptr<const ThreatSet> threat() const;

    // Добавить geo.country, geo.city, geo.asn, geo.org, ti.listed, ti.lists к событиям пачки.
    void enrich(std::vector<Event>& batch) const;
    IpReport lookup(const std::string& ip) const;

    // Подхватить новый файл базы (после geo-import), если он изменился. true — загружен.
    bool reload_geo_if_changed(const std::string& path);

private:
    mutable std::mutex mu_;
    std::shared_ptr<const GeoDb> geo_;
    std::shared_ptr<const ThreatSet> threat_;
    int64_t geo_stamp_ = -1;
};

}  // namespace sentinel
