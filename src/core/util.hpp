// SentinelCore — базовые утилиты: строки, числа, время, хеши.
// Только стандартная библиотека C++.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sentinel {

// ---------- Строки ----------

inline bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}
inline bool is_digit(char c) { return c >= '0' && c <= '9'; }
inline bool is_alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
inline bool is_alnum(char c) { return is_alpha(c) || is_digit(c); }
inline char to_lower_ascii(char c) { return (c >= 'A' && c <= 'Z') ? char(c + 32) : c; }

std::string_view trim(std::string_view s);
std::string to_lower(std::string_view s);
bool iequals(std::string_view a, std::string_view b);
bool starts_with(std::string_view s, std::string_view prefix);
bool ends_with(std::string_view s, std::string_view suffix);
// Поиск подстроки без учёта регистра (ASCII). Возвращает npos, если нет.
size_t ifind(std::string_view haystack, std::string_view needle);
std::vector<std::string_view> split(std::string_view s, char sep);

std::optional<int64_t> parse_int(std::string_view s);
std::optional<uint64_t> parse_uint(std::string_view s);
std::optional<double> parse_double(std::string_view s);
// Длительность: "30" (секунды), "30s", "5m", "1h", "7d" -> миллисекунды.
std::optional<int64_t> parse_duration_ms(std::string_view s);

std::string to_hex(const uint8_t* data, size_t n);
bool from_hex(std::string_view hex, std::vector<uint8_t>& out);

// ---------- Время (миллисекунды Unix, UTC) ----------

int64_t now_ms();
// Номер дня от 1970-01-01 по гражданской дате (пролептический григорианский календарь).
int64_t days_from_civil(int64_t y, unsigned m, unsigned d);
void civil_from_days(int64_t z, int64_t& y, unsigned& m, unsigned& d);
// "2026-10-12T13:55:36.123Z", "2026-10-12T13:55:36+03:00", "2026-10-12 13:55:36"
std::optional<int64_t> parse_iso8601(std::string_view s);
std::string format_iso8601(int64_t ms);
// Месяц "Jan".."Dec" -> 1..12, 0 при ошибке
unsigned month_from_abbr(std::string_view s);

// ---------- Хеши ----------

uint64_t hash64(const void* data, size_t len, uint64_t seed = 0);
inline uint64_t hash64(std::string_view s, uint64_t seed = 0) { return hash64(s.data(), s.size(), seed); }

uint32_t crc32(const void* data, size_t len, uint32_t crc = 0);

// ---------- Двоичная запись (little-endian, varint) ----------

void put_u8(std::string& out, uint8_t v);
void put_u16(std::string& out, uint16_t v);
void put_u32(std::string& out, uint32_t v);
void put_u64(std::string& out, uint64_t v);
void put_varint(std::string& out, uint64_t v);
void put_svarint(std::string& out, int64_t v);
void put_bytes(std::string& out, std::string_view s);  // varint длина + байты

// Безопасный читатель: при выходе за границы ok() становится false.
class Reader {
public:
    Reader(const char* data, size_t size) : p_(data), end_(data + size) {}
    explicit Reader(std::string_view s) : Reader(s.data(), s.size()) {}

    bool ok() const { return ok_; }
    bool eof() const { return p_ >= end_; }
    size_t remaining() const { return size_t(end_ - p_); }

    uint8_t u8();
    uint16_t u16();
    uint32_t u32();
    uint64_t u64();
    uint64_t varint();
    int64_t svarint();
    std::string_view bytes();
    std::string_view raw(size_t n);

private:
    const char* p_;
    const char* end_;
    bool ok_ = true;
};

}  // namespace sentinel
