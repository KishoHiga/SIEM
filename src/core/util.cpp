#include "core/util.hpp"

#include <chrono>
#include <charconv>
#include <cstdlib>
#include <cstring>

namespace sentinel {

// ---------- Строки ----------

std::string_view trim(std::string_view s) {
    size_t b = 0, e = s.size();
    while (b < e && is_space(s[b])) ++b;
    while (e > b && is_space(s[e - 1])) --e;
    return s.substr(b, e - b);
}

std::string to_lower(std::string_view s) {
    std::string r(s);
    for (char& c : r) c = to_lower_ascii(c);
    return r;
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (to_lower_ascii(a[i]) != to_lower_ascii(b[i])) return false;
    return true;
}

bool starts_with(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

bool ends_with(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}

size_t ifind(std::string_view h, std::string_view n) {
    if (n.empty()) return 0;
    if (n.size() > h.size()) return std::string_view::npos;
    const char first = to_lower_ascii(n[0]);
    for (size_t i = 0; i + n.size() <= h.size(); ++i) {
        if (to_lower_ascii(h[i]) != first) continue;
        size_t j = 1;
        while (j < n.size() && to_lower_ascii(h[i + j]) == to_lower_ascii(n[j])) ++j;
        if (j == n.size()) return i;
    }
    return std::string_view::npos;
}

std::vector<std::string_view> split(std::string_view s, char sep) {
    std::vector<std::string_view> out;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == sep) {
            out.push_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}

std::optional<int64_t> parse_int(std::string_view s) {
    s = trim(s);
    if (!s.empty() && s[0] == '+') s.remove_prefix(1);
    int64_t v = 0;
    auto r = std::from_chars(s.data(), s.data() + s.size(), v);
    if (r.ec != std::errc() || r.ptr != s.data() + s.size() || s.empty()) return std::nullopt;
    return v;
}

std::optional<uint64_t> parse_uint(std::string_view s) {
    s = trim(s);
    uint64_t v = 0;
    auto r = std::from_chars(s.data(), s.data() + s.size(), v);
    if (r.ec != std::errc() || r.ptr != s.data() + s.size() || s.empty()) return std::nullopt;
    return v;
}

std::optional<double> parse_double(std::string_view s) {
    s = trim(s);
    if (s.empty() || s.size() > 64) return std::nullopt;
    char buf[80];
    std::memcpy(buf, s.data(), s.size());
    buf[s.size()] = 0;
    char* end = nullptr;
    double v = std::strtod(buf, &end);
    if (end != buf + s.size()) return std::nullopt;
    return v;
}

std::optional<int64_t> parse_duration_ms(std::string_view s) {
    s = trim(s);
    if (s.empty()) return std::nullopt;
    int64_t mult = 1000;
    char u = s.back();
    if (u == 's') s.remove_suffix(1);
    else if (u == 'm') { mult = 60000; s.remove_suffix(1); }
    else if (u == 'h') { mult = 3600000; s.remove_suffix(1); }
    else if (u == 'd') { mult = 86400000; s.remove_suffix(1); }
    auto n = parse_int(s);
    if (!n || *n < 0 || *n > 100LL * 365 * 86400) return std::nullopt;
    return *n * mult;
}

std::string to_hex(const uint8_t* data, size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string r;
    r.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        r[2 * i] = digits[data[i] >> 4];
        r[2 * i + 1] = digits[data[i] & 15];
    }
    return r;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool from_hex(std::string_view hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int a = hex_val(hex[i]), b = hex_val(hex[i + 1]);
        if (a < 0 || b < 0) return false;
        out.push_back(uint8_t(a * 16 + b));
    }
    return true;
}

// ---------- Время ----------

int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// Алгоритм перевода гражданской даты в номер дня (общеизвестная арифметика эр по 400 лет).
int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = unsigned(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + int64_t(doe) - 719468;
}

void civil_from_days(int64_t z, int64_t& y, unsigned& m, unsigned& d) {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = unsigned(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = int64_t(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    y += (m <= 2);
}

static bool read_digits(std::string_view s, size_t& pos, size_t n, int& out) {
    if (pos + n > s.size()) return false;
    int v = 0;
    for (size_t i = 0; i < n; ++i) {
        char c = s[pos + i];
        if (!is_digit(c)) return false;
        v = v * 10 + (c - '0');
    }
    pos += n;
    out = v;
    return true;
}

std::optional<int64_t> parse_iso8601(std::string_view s) {
    s = trim(s);
    size_t p = 0;
    int Y = 0, M = 0, D = 0, h = 0, mi = 0, sec = 0;
    if (!read_digits(s, p, 4, Y)) return std::nullopt;
    if (p >= s.size() || s[p] != '-') return std::nullopt;
    ++p;
    if (!read_digits(s, p, 2, M)) return std::nullopt;
    if (p >= s.size() || s[p] != '-') return std::nullopt;
    ++p;
    if (!read_digits(s, p, 2, D)) return std::nullopt;
    if (M < 1 || M > 12 || D < 1 || D > 31) return std::nullopt;
    int64_t ms = 0;
    int64_t offset_min = 0;
    if (p < s.size() && (s[p] == 'T' || s[p] == 't' || s[p] == ' ')) {
        ++p;
        if (!read_digits(s, p, 2, h)) return std::nullopt;
        if (p >= s.size() || s[p] != ':') return std::nullopt;
        ++p;
        if (!read_digits(s, p, 2, mi)) return std::nullopt;
        if (p < s.size() && s[p] == ':') {
            ++p;
            if (!read_digits(s, p, 2, sec)) return std::nullopt;
        }
        if (h > 23 || mi > 59 || sec > 60) return std::nullopt;
        if (p < s.size() && (s[p] == '.' || s[p] == ',')) {
            ++p;
            int64_t frac = 0;
            int digits = 0;
            while (p < s.size() && is_digit(s[p])) {
                if (digits < 3) {
                    frac = frac * 10 + (s[p] - '0');
                    ++digits;
                }
                ++p;
            }
            while (digits < 3) {
                frac *= 10;
                ++digits;
            }
            ms = frac;
        }
        if (p < s.size()) {
            if (s[p] == 'Z' || s[p] == 'z') {
                ++p;
            } else if (s[p] == '+' || s[p] == '-') {
                int sign = s[p] == '-' ? -1 : 1;
                ++p;
                int oh = 0, om = 0;
                if (!read_digits(s, p, 2, oh)) return std::nullopt;
                if (p < s.size() && s[p] == ':') ++p;
                if (p < s.size()) {
                    if (!read_digits(s, p, 2, om)) return std::nullopt;
                }
                offset_min = sign * (oh * 60 + om);
            }
        }
    }
    if (p != s.size()) return std::nullopt;
    int64_t days = days_from_civil(Y, unsigned(M), unsigned(D));
    int64_t secs = days * 86400 + h * 3600 + mi * 60 + sec - offset_min * 60;
    return secs * 1000 + ms;
}

std::string format_iso8601(int64_t ms) {
    int64_t secs = ms >= 0 ? ms / 1000 : (ms - 999) / 1000;
    int64_t msec = ms - secs * 1000;
    int64_t days = secs >= 0 ? secs / 86400 : (secs - 86399) / 86400;
    int64_t rem = secs - days * 86400;
    int64_t y;
    unsigned m, d;
    civil_from_days(days, y, m, d);
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04lld-%02u-%02uT%02d:%02d:%02d.%03dZ", (long long)y, m, d,
                  int(rem / 3600), int((rem / 60) % 60), int(rem % 60), int(msec));
    return buf;
}

unsigned month_from_abbr(std::string_view s) {
    static const char* names[] = {"jan", "feb", "mar", "apr", "may", "jun",
                                  "jul", "aug", "sep", "oct", "nov", "dec"};
    if (s.size() != 3) return 0;
    for (unsigned i = 0; i < 12; ++i)
        if (iequals(s, names[i])) return i + 1;
    return 0;
}

// ---------- Хеши ----------

static inline uint64_t mix64(uint64_t x) {
    x ^= x >> 31;
    x *= 0x7fb5d329728ea185ULL;
    x ^= x >> 27;
    x *= 0x81dadef4bc2dd44dULL;
    x ^= x >> 33;
    return x;
}

uint64_t hash64(const void* data, size_t len, uint64_t seed) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t h = seed ^ (uint64_t(len) * 0x9E3779B97F4A7C15ULL);
    while (len >= 8) {
        uint64_t k;
        std::memcpy(&k, p, 8);
        h = mix64(h ^ k) + 0x9E3779B97F4A7C15ULL;
        p += 8;
        len -= 8;
    }
    uint64_t tail = 0;
    for (size_t i = 0; i < len; ++i) tail |= uint64_t(p[i]) << (8 * i);
    return mix64(h ^ tail ^ 0xA0761D6478BD642FULL);
}

static const uint32_t* crc_table() {
    static uint32_t table[256];
    static bool init = [] {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        return true;
    }();
    (void)init;
    return table;
}

uint32_t crc32(const void* data, size_t len, uint32_t crc) {
    const uint32_t* t = crc_table();
    const uint8_t* p = static_cast<const uint8_t*>(data);
    crc = ~crc;
    for (size_t i = 0; i < len; ++i) crc = t[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

// ---------- Двоичная запись ----------

void put_u8(std::string& out, uint8_t v) { out.push_back(char(v)); }
void put_u16(std::string& out, uint16_t v) {
    out.push_back(char(v & 0xFF));
    out.push_back(char(v >> 8));
}
void put_u32(std::string& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(char((v >> (8 * i)) & 0xFF));
}
void put_u64(std::string& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(char((v >> (8 * i)) & 0xFF));
}
void put_varint(std::string& out, uint64_t v) {
    while (v >= 0x80) {
        out.push_back(char((v & 0x7F) | 0x80));
        v >>= 7;
    }
    out.push_back(char(v));
}
void put_svarint(std::string& out, int64_t v) {
    put_varint(out, (uint64_t(v) << 1) ^ uint64_t(v >> 63));
}
void put_bytes(std::string& out, std::string_view s) {
    put_varint(out, s.size());
    out.append(s.data(), s.size());
}

uint8_t Reader::u8() {
    if (end_ - p_ < 1) {
        ok_ = false;
        p_ = end_;
        return 0;
    }
    return uint8_t(*p_++);
}
uint16_t Reader::u16() {
    uint16_t v = u8();
    v |= uint16_t(u8()) << 8;
    return v;
}
uint32_t Reader::u32() {
    if (end_ - p_ < 4) {
        ok_ = false;
        p_ = end_;
        return 0;
    }
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= uint32_t(uint8_t(p_[i])) << (8 * i);
    p_ += 4;
    return v;
}
uint64_t Reader::u64() {
    if (end_ - p_ < 8) {
        ok_ = false;
        p_ = end_;
        return 0;
    }
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= uint64_t(uint8_t(p_[i])) << (8 * i);
    p_ += 8;
    return v;
}
uint64_t Reader::varint() {
    uint64_t v = 0;
    for (int shift = 0; shift < 64; shift += 7) {
        if (p_ >= end_) {
            ok_ = false;
            return 0;
        }
        uint8_t b = uint8_t(*p_++);
        v |= uint64_t(b & 0x7F) << shift;
        if (!(b & 0x80)) return v;
    }
    ok_ = false;
    return 0;
}
int64_t Reader::svarint() {
    uint64_t u = varint();
    return int64_t(u >> 1) ^ -int64_t(u & 1);
}
std::string_view Reader::bytes() {
    uint64_t n = varint();
    return raw(n);
}
std::string_view Reader::raw(size_t n) {
    if (!ok_ || size_t(end_ - p_) < n) {
        ok_ = false;
        p_ = end_;
        return {};
    }
    std::string_view r(p_, n);
    p_ += n;
    return r;
}

}  // namespace sentinel
