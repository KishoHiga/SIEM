// SentinelCore — страна, сеть (ASN) и город по IP-адресу. Своя база диапазонов:
// отсортированные интервалы и двоичный поиск, IPv4 и IPv6, поиск — доли микросекунды.
//
// Данные берутся из открытых CSV (это данные, а не программы):
//   DB-IP Lite country:  1.0.0.0,1.0.0.255,AU
//   DB-IP Lite ASN:      1.0.0.0,1.0.0.255,13335,"Cloudflare, Inc."
//   DB-IP Lite city:     1.0.0.0,1.0.0.255,OC,AU,Queensland,South Brisbane,-27.47,153.02
//   iptoasn (TSV):       1.0.0.0<TAB>1.0.0.255<TAB>13335<TAB>US<TAB>CLOUDFLARENET
// Команда `sentinel-server geo-import файлы...` переводит их в один файл data/geo/geo.bin.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "core/ip.hpp"

namespace sentinel {

struct GeoInfo {
    std::string_view country;  // ISO-код: RU, US, DE...
    std::string_view city;
    std::string_view asn;      // номер сети: 13335
    std::string_view org;      // владелец сети: Cloudflare, Inc.
    bool any() const { return !country.empty() || !asn.empty() || !city.empty(); }
};

struct GeoImportStats {
    size_t files = 0;
    size_t country_ranges = 0, asn_ranges = 0, city_ranges = 0;
    size_t skipped_lines = 0;
    std::vector<std::string> sources;  // имена файлов
};

class GeoDb {
public:
    enum Kind { Country = 0, Asn = 1, City = 2, kKinds = 3 };

    // CSV/TSV -> двоичный файл. Вид каждого файла определяется по числу колонок.
    static bool import_files(const std::vector<std::string>& inputs, const std::string& out_path, GeoImportStats& st,
                             std::string& error);

    bool load(const std::string& path, std::string& error);
    GeoInfo lookup(const IpAddr& ip) const;
    size_t ranges(Kind k) const { return v4_[k].size() + v6_[k].size(); }
    bool empty() const;
    int64_t built_at() const { return built_at_; }
    const std::vector<std::string>& sources() const { return sources_; }

    // Для тестов и импорта: добавить диапазон (до finish()).
    void add(Kind k, const IpAddr& start, const IpAddr& end, std::string_view value);
    void finish();  // сортировка, устранение пересечений
    std::string serialize() const;

private:
    struct R4 {
        uint32_t start, end, val;
    };
    struct R6 {
        std::array<uint8_t, 16> start, end;
        uint32_t val;
    };
    uint32_t intern(std::string_view s);
    std::string_view value(Kind k, const IpAddr& ip) const;

    std::vector<R4> v4_[kKinds];
    std::vector<R6> v6_[kKinds];
    std::vector<std::string> strings_;
    std::unordered_map<std::string, uint32_t> index_;  // для intern при импорте
    std::vector<std::string> sources_;
    int64_t built_at_ = 0;
};

}  // namespace sentinel
