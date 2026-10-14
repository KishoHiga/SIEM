#include "core/ip.hpp"

#include <cstdio>
#include <vector>

#include "core/util.hpp"

namespace sentinel {

namespace {

bool parse_v4(std::string_view s, uint8_t out[4]) {
    int part = 0;
    size_t i = 0;
    while (part < 4) {
        if (i >= s.size() || !is_digit(s[i])) return false;
        size_t st = i;
        unsigned v = 0;
        while (i < s.size() && is_digit(s[i])) {
            v = v * 10 + unsigned(s[i] - '0');
            if (v > 255) return false;
            ++i;
        }
        if (i - st > 1 && s[st] == '0') return false;  // 010 — неоднозначно (восьмеричное?)
        out[part++] = uint8_t(v);
        if (part < 4) {
            if (i >= s.size() || s[i] != '.') return false;
            ++i;
        }
    }
    return i == s.size();
}

int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool parse_v6(std::string_view s, uint8_t out[16]) {
    if (s.size() < 2 || s.size() > 45) return false;
    std::vector<uint16_t> head, tail;
    bool seen_gap = false;
    size_t i = 0;
    if (s[0] == ':') {
        if (s[1] != ':') return false;
        seen_gap = true;
        i = 2;
        if (i == s.size()) {
            std::fill(out, out + 16, 0);
            return true;
        }
    }
    bool v4_tail = false;
    uint8_t v4[4];
    while (i < s.size()) {
        auto& groups = seen_gap ? tail : head;
        // встроенный IPv4 в конце
        size_t next_colon = s.find(':', i);
        std::string_view tok = s.substr(i, next_colon == std::string_view::npos ? s.size() - i : next_colon - i);
        if (tok.find('.') != std::string_view::npos) {
            if (next_colon != std::string_view::npos || !parse_v4(tok, v4)) return false;
            v4_tail = true;
            i = s.size();
            break;
        }
        if (tok.empty() || tok.size() > 4) return false;
        unsigned v = 0;
        for (char c : tok) {
            int h = hexv(c);
            if (h < 0) return false;
            v = v * 16 + unsigned(h);
        }
        groups.push_back(uint16_t(v));
        i += tok.size();
        if (i == s.size()) break;
        ++i;  // ':'
        if (i < s.size() && s[i] == ':') {
            if (seen_gap) return false;  // второй "::"
            seen_gap = true;
            ++i;
        } else if (i == s.size()) {
            return false;  // одиночное ':' в конце
        }
    }
    size_t total = head.size() + tail.size() + (v4_tail ? 2 : 0);
    if (seen_gap ? total > 7 : total != 8) return false;
    std::fill(out, out + 16, 0);
    size_t pos = 0;
    for (uint16_t g : head) {
        out[pos++] = uint8_t(g >> 8);
        out[pos++] = uint8_t(g);
    }
    pos = 16 - (tail.size() * 2 + (v4_tail ? 4 : 0));
    for (uint16_t g : tail) {
        out[pos++] = uint8_t(g >> 8);
        out[pos++] = uint8_t(g);
    }
    if (v4_tail)
        for (int k = 0; k < 4; ++k) out[pos++] = v4[k];
    return true;
}

}  // namespace

std::optional<IpAddr> parse_ip(std::string_view s) {
    IpAddr ip;
    if (s.find(':') == std::string_view::npos) {
        if (!parse_v4(s, ip.b.data())) return std::nullopt;
        return ip;
    }
    if (!parse_v6(s, ip.b.data())) return std::nullopt;
    ip.v6 = true;
    // ::ffff:a.b.c.d — это IPv4
    bool mapped = true;
    for (int k = 0; k < 10; ++k) mapped = mapped && ip.b[size_t(k)] == 0;
    if (mapped && ip.b[10] == 0xFF && ip.b[11] == 0xFF) {
        IpAddr v4;
        for (int k = 0; k < 4; ++k) v4.b[size_t(k)] = ip.b[size_t(12 + k)];
        return v4;
    }
    return ip;
}

std::string format_ip(const IpAddr& ip) {
    char buf[64];
    if (!ip.v6) {
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ip.b[0], ip.b[1], ip.b[2], ip.b[3]);
        return buf;
    }
    uint16_t g[8];
    for (int k = 0; k < 8; ++k) g[k] = uint16_t((ip.b[size_t(2 * k)] << 8) | ip.b[size_t(2 * k + 1)]);
    // самая длинная серия нулей длиной >= 2 заменяется на "::"
    int best = -1, best_len = 0;
    for (int k = 0; k < 8;) {
        if (g[k] != 0) {
            ++k;
            continue;
        }
        int st = k;
        while (k < 8 && g[k] == 0) ++k;
        if (k - st > best_len) {
            best = st;
            best_len = k - st;
        }
    }
    if (best_len < 2) best = -1;
    std::string out;
    for (int k = 0; k < 8; ++k) {
        if (k == best) {
            out += "::";
            k += best_len - 1;
            continue;
        }
        if (!out.empty() && out.back() != ':') out.push_back(':');
        std::snprintf(buf, sizeof(buf), "%x", g[k]);
        out += buf;
    }
    return out;
}

bool Cidr::contains(const IpAddr& ip) const {
    if (ip.v6 != net.v6) return false;
    int bits = prefix;
    for (size_t k = 0; bits > 0; ++k, bits -= 8) {
        uint8_t mask = bits >= 8 ? 0xFF : uint8_t(0xFF << (8 - bits));
        if ((ip.b[k] & mask) != (net.b[k] & mask)) return false;
    }
    return true;
}

std::optional<Cidr> parse_cidr(std::string_view s) {
    s = trim(s);
    size_t slash = s.find('/');
    auto ip = parse_ip(s.substr(0, slash));
    if (!ip) return std::nullopt;
    Cidr c;
    c.net = *ip;
    int maxp = ip->v6 ? 128 : 32;
    c.prefix = maxp;
    if (slash != std::string_view::npos) {
        auto p = parse_uint(s.substr(slash + 1));
        if (!p || *p > uint64_t(maxp)) return std::nullopt;
        c.prefix = int(*p);
    }
    // обнулить биты хоста (10.1.2.3/8 -> 10.0.0.0/8)
    int bits = c.prefix;
    for (size_t k = 0; k < 16; ++k, bits -= 8) {
        if (bits >= 8) continue;
        c.net.b[k] &= bits > 0 ? uint8_t(0xFF << (8 - bits)) : 0;
    }
    return c;
}

std::string format_cidr(const Cidr& c) {
    int maxp = c.net.v6 ? 128 : 32;
    std::string s = format_ip(c.net);
    if (c.prefix != maxp) s += "/" + std::to_string(c.prefix);
    return s;
}

bool is_private_or_special(const IpAddr& ip) {
    static const char* ranges[] = {
        "0.0.0.0/8",      "10.0.0.0/8",     "100.64.0.0/10", "127.0.0.0/8",   "169.254.0.0/16", "172.16.0.0/12",
        "192.0.0.0/24",   "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4",   "240.0.0.0/4",    "::/128",
        "::1/128",        "fc00::/7",       "fe80::/10",     "ff00::/8",      "64:ff9b:1::/48",
    };
    static const std::vector<Cidr> parsed = [] {
        std::vector<Cidr> v;
        for (auto r : ranges) v.push_back(*parse_cidr(r));
        return v;
    }();
    for (auto& c : parsed)
        if (c.contains(ip)) return true;
    return false;
}

}  // namespace sentinel
