// SentinelCore — IP-адреса и подсети: строгий разбор IPv4/IPv6, CIDR, частные диапазоны.
// Используется в блокировках: в брандмауэр попадает только то, что прошло этот разбор.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace sentinel {

struct IpAddr {
    bool v6 = false;
    std::array<uint8_t, 16> b{};  // IPv4 — в первых 4 байтах

    bool operator==(const IpAddr& o) const { return v6 == o.v6 && b == o.b; }
    bool operator!=(const IpAddr& o) const { return !(*this == o); }
};

// "1.2.3.4", "2001:db8::1", "::ffff:1.2.3.4" (приводится к IPv4). Ведущие нули в IPv4 запрещены.
std::optional<IpAddr> parse_ip(std::string_view s);
// Канонический вид: IPv4 через точки, IPv6 сжатый в нижнем регистре (RFC 5952).
std::string format_ip(const IpAddr& ip);

struct Cidr {
    IpAddr net;
    int prefix = 32;
    bool contains(const IpAddr& ip) const;
};

// "10.0.0.0/8", "2001:db8::/32" или просто адрес (= /32 или /128).
std::optional<Cidr> parse_cidr(std::string_view s);
std::string format_cidr(const Cidr& c);

// Нельзя блокировать: свои сети, loopback, link-local, multicast, служебные диапазоны.
bool is_private_or_special(const IpAddr& ip);

}  // namespace sentinel
