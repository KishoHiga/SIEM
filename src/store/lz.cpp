#include "store/lz.hpp"

#include <cstdint>
#include <cstring>
#include <vector>

namespace sentinel::lz {

namespace {
constexpr int kHashBits = 14;
constexpr size_t kMinMatch = 4;
constexpr size_t kMaxOffset = 65535;
constexpr size_t kTailLiterals = 8;  // последние байты всегда литералы

inline uint32_t read32(const uint8_t* p) {
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}
inline uint32_t hash4(uint32_t v) { return (v * 2654435761u) >> (32 - kHashBits); }

void put_len(std::string& out, size_t len) {
    while (len >= 255) {
        out.push_back(char(255));
        len -= 255;
    }
    out.push_back(char(len));
}
}  // namespace

void compress(std::string_view in_sv, std::string& out) {
    out.clear();
    const uint8_t* in = reinterpret_cast<const uint8_t*>(in_sv.data());
    const size_t n = in_sv.size();
    out.reserve(n / 2 + 16);
    std::vector<uint32_t> table(size_t(1) << kHashBits, 0xFFFFFFFFu);

    size_t anchor = 0;
    size_t ip = 0;
    const size_t limit = n > kTailLiterals + kMinMatch ? n - kTailLiterals : 0;

    auto emit = [&](size_t lit_start, size_t lit_len, size_t offset, size_t match_len) {
        size_t ml = match_len >= kMinMatch ? match_len - kMinMatch : 0;
        uint8_t token = uint8_t((lit_len >= 15 ? 15 : lit_len) << 4) | uint8_t(ml >= 15 ? 15 : ml);
        out.push_back(char(token));
        if (lit_len >= 15) put_len(out, lit_len - 15);
        out.append(reinterpret_cast<const char*>(in + lit_start), lit_len);
        if (match_len >= kMinMatch) {
            out.push_back(char(offset & 0xFF));
            out.push_back(char(offset >> 8));
            if (ml >= 15) put_len(out, ml - 15);
        }
    };

    while (ip < limit) {
        uint32_t seq = read32(in + ip);
        uint32_t h = hash4(seq);
        uint32_t ref = table[h];
        table[h] = uint32_t(ip);
        if (ref != 0xFFFFFFFFu && ip - ref <= kMaxOffset && read32(in + ref) == seq) {
            size_t len = kMinMatch;
            const size_t max_len = n - kTailLiterals - ip;
            while (len < max_len && in[ref + len] == in[ip + len]) ++len;
            emit(anchor, ip - anchor, ip - ref, len);
            // запомним пару позиций внутри совпадения для лучшего сжатия
            if (ip + len >= 2 && ip + len - 2 < limit) table[hash4(read32(in + ip + len - 2))] = uint32_t(ip + len - 2);
            ip += len;
            anchor = ip;
        } else {
            ++ip;
        }
    }
    emit(anchor, n - anchor, 0, 0);
}

bool decompress(std::string_view in_sv, size_t expected, std::string& out) {
    out.clear();
    out.resize(expected);
    const uint8_t* ip = reinterpret_cast<const uint8_t*>(in_sv.data());
    const uint8_t* end = ip + in_sv.size();
    uint8_t* op = reinterpret_cast<uint8_t*>(out.data());
    uint8_t* const ostart = op;
    uint8_t* const oend = op + expected;

    auto read_len = [&](size_t& len) -> bool {
        uint8_t b;
        do {
            if (ip >= end) return false;
            b = *ip++;
            len += b;
            if (len > (size_t(1) << 31)) return false;
        } while (b == 255);
        return true;
    };

    while (ip < end) {
        uint8_t token = *ip++;
        size_t lit = token >> 4;
        if (lit == 15 && !read_len(lit)) return false;
        if (size_t(end - ip) < lit || size_t(oend - op) < lit) return false;
        std::memcpy(op, ip, lit);
        op += lit;
        ip += lit;
        if (ip >= end) break;  // последняя последовательность — только литералы
        if (end - ip < 2) return false;
        size_t offset = size_t(ip[0]) | (size_t(ip[1]) << 8);
        ip += 2;
        size_t ml = token & 15;
        if (ml == 15 && !read_len(ml)) return false;
        ml += kMinMatch;
        if (offset == 0 || offset > size_t(op - ostart) || size_t(oend - op) < ml) return false;
        const uint8_t* src = op - offset;
        if (offset >= ml) {
            std::memcpy(op, src, ml);
            op += ml;
        } else {
            for (size_t k = 0; k < ml; ++k) *op++ = src[k];  // перекрытие — побайтно
        }
    }
    return op == oend;
}

}  // namespace sentinel::lz
