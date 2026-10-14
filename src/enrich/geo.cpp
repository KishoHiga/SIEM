#include "enrich/geo.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "core/util.hpp"

namespace fs = std::filesystem;

namespace sentinel {

namespace {

constexpr char kMagic[8] = {'S', 'N', 'G', 'E', 'O', 0, 0, 1};

uint32_t v4_of(const IpAddr& ip) {
    return (uint32_t(ip.b[0]) << 24) | (uint32_t(ip.b[1]) << 16) | (uint32_t(ip.b[2]) << 8) | uint32_t(ip.b[3]);
}

// Разбор строки CSV (кавычки "..." с удвоением "") или TSV.
void split_row(std::string_view line, char sep, std::vector<std::string>& out) {
    out.clear();
    std::string cur;
    bool q = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (q) {
            if (c == '"') {
                if (i + 1 < line.size() && line[i + 1] == '"') {
                    cur.push_back('"');
                    ++i;
                } else {
                    q = false;
                }
            } else {
                cur.push_back(c);
            }
        } else if (c == '"' && cur.empty()) {
            q = true;
        } else if (c == sep) {
            out.push_back(std::move(cur));
            cur.clear();
        } else if (c != '\r') {
            cur.push_back(c);
        }
    }
    out.push_back(std::move(cur));
}

}  // namespace

uint32_t GeoDb::intern(std::string_view s) {
    auto it = index_.find(std::string(s));
    if (it != index_.end()) return it->second;
    uint32_t id = uint32_t(strings_.size());
    strings_.emplace_back(s);
    index_.emplace(std::string(s), id);
    return id;
}

void GeoDb::add(Kind k, const IpAddr& start, const IpAddr& end, std::string_view value) {
    if (start.v6 != end.v6 || value.empty()) return;
    uint32_t v = intern(value);
    if (!start.v6) {
        uint32_t a = v4_of(start), b = v4_of(end);
        if (a <= b) v4_[k].push_back({a, b, v});
    } else if (start.b <= end.b) {
        v6_[k].push_back({start.b, end.b, v});
    }
}

void GeoDb::finish() {
    for (int k = 0; k < kKinds; ++k) {
        auto& a = v4_[k];
        std::stable_sort(a.begin(), a.end(), [](const R4& x, const R4& y) { return x.start < y.start; });
        // пересечения: более поздний диапазон обрезает предыдущий
        std::vector<R4> out;
        out.reserve(a.size());
        for (auto& r : a) {
            if (!out.empty() && out.back().end >= r.start) {
                if (out.back().start >= r.start) out.pop_back();
                else out.back().end = r.start - 1;
            }
            out.push_back(r);
        }
        a.swap(out);
        auto& b = v6_[k];
        std::stable_sort(b.begin(), b.end(), [](const R6& x, const R6& y) { return x.start < y.start; });
        std::vector<R6> out6;
        out6.reserve(b.size());
        for (auto& r : b) {
            if (!out6.empty() && out6.back().end >= r.start) {
                if (out6.back().start >= r.start) {
                    out6.pop_back();
                } else {
                    auto e = r.start;  // end = start - 1
                    for (int i = 15; i >= 0; --i) {
                        if (e[size_t(i)]-- != 0) break;
                    }
                    out6.back().end = e;
                }
            }
            out6.push_back(r);
        }
        b.swap(out6);
    }
    index_.clear();
}

bool GeoDb::empty() const {
    for (int k = 0; k < kKinds; ++k)
        if (!v4_[k].empty() || !v6_[k].empty()) return false;
    return true;
}

std::string GeoDb::serialize() const {
    std::string body;
    put_u64(body, uint64_t(built_at_));
    put_varint(body, sources_.size());
    for (auto& s : sources_) put_bytes(body, s);
    put_varint(body, strings_.size());
    for (auto& s : strings_) put_bytes(body, s);
    for (int k = 0; k < kKinds; ++k) {
        put_u32(body, uint32_t(v4_[k].size()));
        for (auto& r : v4_[k]) {
            put_u32(body, r.start);
            put_u32(body, r.end);
            put_u32(body, r.val);
        }
        put_u32(body, uint32_t(v6_[k].size()));
        for (auto& r : v6_[k]) {
            body.append(reinterpret_cast<const char*>(r.start.data()), 16);
            body.append(reinterpret_cast<const char*>(r.end.data()), 16);
            put_u32(body, r.val);
        }
    }
    std::string out(kMagic, 8);
    put_u32(out, crc32(body.data(), body.size()));
    out += body;
    return out;
}

bool GeoDb::load(const std::string& path, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "cannot open " + path;
        return false;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    std::string data = ss.str();
    if (data.size() < 12 || data.compare(0, 8, std::string(kMagic, 8)) != 0) {
        error = path + ": not a SentinelCore geo database (run 'sentinel-server geo-import')";
        return false;
    }
    Reader h(data.data() + 8, 4);
    if (h.u32() != crc32(data.data() + 12, data.size() - 12)) {
        error = path + ": damaged (checksum mismatch)";
        return false;
    }
    Reader r(data.data() + 12, data.size() - 12);
    GeoDb t;
    t.built_at_ = int64_t(r.u64());
    uint64_t n = r.varint();
    for (uint64_t i = 0; i < n && r.ok() && i < 1000; ++i) t.sources_.emplace_back(r.bytes());
    n = r.varint();
    if (!r.ok() || n > 100000000) {
        error = path + ": damaged";
        return false;
    }
    t.strings_.reserve(size_t(n));
    for (uint64_t i = 0; i < n && r.ok(); ++i) t.strings_.emplace_back(r.bytes());
    for (int k = 0; k < kKinds && r.ok(); ++k) {
        uint32_t c4 = r.u32();
        if (!r.ok() || uint64_t(c4) * 12 > r.remaining()) break;
        t.v4_[k].resize(c4);
        for (auto& x : t.v4_[k]) {
            x.start = r.u32();
            x.end = r.u32();
            x.val = r.u32();
        }
        uint32_t c6 = r.u32();
        if (!r.ok() || uint64_t(c6) * 36 > r.remaining()) {
            r.raw(r.remaining() + 1);  // ok() = false
            break;
        }
        t.v6_[k].resize(c6);
        for (auto& x : t.v6_[k]) {
            auto a = r.raw(16), b = r.raw(16);
            if (!r.ok()) break;
            std::copy(a.begin(), a.end(), x.start.begin());
            std::copy(b.begin(), b.end(), x.end.begin());
            x.val = r.u32();
        }
    }
    if (!r.ok()) {
        error = path + ": damaged";
        return false;
    }
    for (int k = 0; k < kKinds; ++k) {
        for (auto& x : t.v4_[k])
            if (x.val >= t.strings_.size()) x.val = 0;
        for (auto& x : t.v6_[k])
            if (x.val >= t.strings_.size()) x.val = 0;
    }
    *this = std::move(t);
    return true;
}

std::string_view GeoDb::value(Kind k, const IpAddr& ip) const {
    if (!ip.v6) {
        const auto& a = v4_[k];
        uint32_t x = v4_of(ip);
        auto it = std::upper_bound(a.begin(), a.end(), x, [](uint32_t v, const R4& r) { return v < r.start; });
        if (it == a.begin()) return {};
        --it;
        if (x > it->end || it->val >= strings_.size()) return {};
        return strings_[it->val];
    }
    const auto& a = v6_[k];
    auto it = std::upper_bound(a.begin(), a.end(), ip.b, [](const std::array<uint8_t, 16>& v, const R6& r) { return v < r.start; });
    if (it == a.begin()) return {};
    --it;
    if (ip.b > it->end || it->val >= strings_.size()) return {};
    return strings_[it->val];
}

GeoInfo GeoDb::lookup(const IpAddr& ip) const {
    GeoInfo g;
    std::string_view c = value(City, ip);
    if (!c.empty()) {
        size_t sep = c.find('\x1f');
        g.country = c.substr(0, sep);
        if (sep != std::string_view::npos) g.city = c.substr(sep + 1);
    }
    if (std::string_view cc = value(Country, ip); !cc.empty()) g.country = cc;
    std::string_view a = value(Asn, ip);
    if (!a.empty()) {
        size_t sep = a.find('\x1f');
        g.asn = a.substr(0, sep);
        if (sep != std::string_view::npos) g.org = a.substr(sep + 1);
    }
    return g;
}

bool GeoDb::import_files(const std::vector<std::string>& inputs, const std::string& out_path, GeoImportStats& st,
                         std::string& error) {
    GeoDb db;
    std::vector<std::string> cols;
    for (auto& path : inputs) {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            error = "cannot open " + path;
            return false;
        }
        ++st.files;
        db.sources_.push_back(fs::path(path).filename().string());
        std::string line;
        char sep = 0;
        size_t good = 0;
        while (std::getline(in, line)) {
            if (line.empty() || line[0] == '#') continue;
            if (!sep) sep = line.find('\t') != std::string::npos ? '\t' : ',';
            split_row(line, sep, cols);
            if (cols.size() < 3) {
                ++st.skipped_lines;
                continue;
            }
            auto a = parse_ip(trim(cols[0])), b = parse_ip(trim(cols[1]));
            if (!a || !b || a->v6 != b->v6) {
                ++st.skipped_lines;  // заголовок или мусор
                continue;
            }
            auto upper = [](std::string s) {
                for (auto& ch : s) ch = char(std::toupper(static_cast<unsigned char>(ch)));
                return s;
            };
            if (sep == '\t' && cols.size() >= 5) {  // iptoasn: asn, страна, владелец
                std::string asn(trim(cols[2]));
                if (asn == "0") continue;  // не анонсируется
                db.add(Asn, *a, *b, asn + '\x1f' + std::string(trim(cols[4])));
                std::string cc = upper(std::string(trim(cols[3])));
                if (cc.size() == 2 && cc != "NONE") db.add(Country, *a, *b, cc);
                ++st.asn_ranges;
            } else if (cols.size() == 3) {
                std::string cc = upper(std::string(trim(cols[2])));
                if (cc.size() != 2 || cc == "ZZ") continue;
                db.add(Country, *a, *b, cc);
                ++st.country_ranges;
            } else if (cols.size() == 4) {
                std::string asn(trim(cols[2]));
                if (asn.empty() || asn == "0") continue;
                db.add(Asn, *a, *b, asn + '\x1f' + std::string(trim(cols[3])));
                ++st.asn_ranges;
            } else {  // city: континент, страна, регион, город, ...
                std::string cc = upper(std::string(trim(cols[3])));
                std::string city = cols.size() > 5 ? std::string(trim(cols[5])) : "";
                if (cc.size() != 2 || cc == "ZZ") continue;
                db.add(City, *a, *b, city.empty() ? cc : cc + '\x1f' + city);
                ++st.city_ranges;
            }
            ++good;
        }
        if (good == 0) {
            error = path + ": no IP ranges found (expected CSV: start_ip,end_ip,country | asn,org | city fields)";
            return false;
        }
    }
    db.finish();
    db.built_at_ = now_ms();
    std::error_code ec;
    if (fs::path(out_path).has_parent_path()) fs::create_directories(fs::path(out_path).parent_path(), ec);
    std::string tmp = out_path + ".tmp";
    {
        std::ofstream o(tmp, std::ios::binary | std::ios::trunc);
        o << db.serialize();
        if (!o) {
            error = "cannot write " + tmp;
            return false;
        }
    }
    fs::rename(tmp, out_path, ec);
    if (ec) {
        fs::remove(out_path, ec);
        fs::rename(tmp, out_path, ec);
    }
    if (ec) {
        error = "cannot write " + out_path;
        return false;
    }
    st.sources = db.sources_;
    return true;
}

}  // namespace sentinel
