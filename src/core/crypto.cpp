#include "core/crypto.hpp"

#include <cstring>
#include <random>

#include "core/util.hpp"

namespace sentinel {

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

Sha256::Sha256() {
    static const uint32_t init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::memcpy(h_, init, sizeof(h_));
}

void Sha256::block(const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t(p[4 * i]) << 24) | (uint32_t(p[4 * i + 1]) << 16) | (uint32_t(p[4 * i + 2]) << 8) |
               uint32_t(p[4 * i + 3]);
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
    h_[4] += e;
    h_[5] += f;
    h_[6] += g;
    h_[7] += h;
}

void Sha256::update(const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    total_ += len;
    while (len > 0) {
        size_t take = 64 - buf_len_;
        if (take > len) take = len;
        std::memcpy(buf_ + buf_len_, p, take);
        buf_len_ += take;
        p += take;
        len -= take;
        if (buf_len_ == 64) {
            block(buf_);
            buf_len_ = 0;
        }
    }
}

std::array<uint8_t, 32> Sha256::finish() {
    uint64_t bits = total_ * 8;
    uint8_t pad = 0x80;
    update(&pad, 1);
    uint8_t zero = 0;
    while (buf_len_ != 56) update(&zero, 1);
    uint8_t len_be[8];
    for (int i = 0; i < 8; ++i) len_be[i] = uint8_t(bits >> (56 - 8 * i));
    update(len_be, 8);
    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 8; ++i) {
        out[4 * i] = uint8_t(h_[i] >> 24);
        out[4 * i + 1] = uint8_t(h_[i] >> 16);
        out[4 * i + 2] = uint8_t(h_[i] >> 8);
        out[4 * i + 3] = uint8_t(h_[i]);
    }
    return out;
}

std::string sha256_hex(std::string_view data) {
    Sha256 h;
    h.update(data);
    auto d = h.finish();
    return to_hex(d.data(), d.size());
}

std::array<uint8_t, 20> sha1(std::string_view data) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    std::string msg(data);
    uint64_t bits = uint64_t(data.size()) * 8;
    msg.push_back(char(0x80));
    while (msg.size() % 64 != 56) msg.push_back('\0');
    for (int i = 7; i >= 0; --i) msg.push_back(char((bits >> (8 * i)) & 0xFF));
    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(msg.data() + off + size_t(4 * i));
            w[i] = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
        }
        for (int i = 16; i < 80; ++i) {
            uint32_t x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = (x << 1) | (x >> 31);
        }
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | (~b & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t t = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d;
            d = c;
            c = (b << 30) | (b >> 2);
            b = a;
            a = t;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }
    std::array<uint8_t, 20> out{};
    uint32_t hs[5] = {h0, h1, h2, h3, h4};
    for (int i = 0; i < 5; ++i)
        for (int j = 0; j < 4; ++j) out[size_t(4 * i + j)] = uint8_t(hs[i] >> (24 - 8 * j));
    return out;
}

std::string base64_encode(const uint8_t* d, size_t n) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((n + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 2 < n; i += 3) {
        uint32_t v = (uint32_t(d[i]) << 16) | (uint32_t(d[i + 1]) << 8) | d[i + 2];
        out.push_back(t[v >> 18]);
        out.push_back(t[(v >> 12) & 63]);
        out.push_back(t[(v >> 6) & 63]);
        out.push_back(t[v & 63]);
    }
    if (i + 1 == n) {
        uint32_t v = uint32_t(d[i]) << 16;
        out.push_back(t[v >> 18]);
        out.push_back(t[(v >> 12) & 63]);
        out += "==";
    } else if (i + 2 == n) {
        uint32_t v = (uint32_t(d[i]) << 16) | (uint32_t(d[i + 1]) << 8);
        out.push_back(t[v >> 18]);
        out.push_back(t[(v >> 12) & 63]);
        out.push_back(t[(v >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

bool constant_time_equals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff = diff | uint8_t(a[i] ^ b[i]);
    return diff == 0;
}

std::string random_hex(size_t bytes) {
    std::random_device rd;
    std::string raw;
    raw.reserve(bytes);
    while (raw.size() < bytes) {
        uint32_t v = rd();
        for (int k = 0; k < 4 && raw.size() < bytes; ++k) raw.push_back(char((v >> (8 * k)) & 0xFF));
    }
    return to_hex(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
}

}  // namespace sentinel
