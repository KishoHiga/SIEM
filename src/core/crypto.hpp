// SentinelCore — SHA-256 (FIPS 180-4), сравнение за постоянное время, случайные ключи.
// Используется только для хранения хешей ключей доступа (не для шифрования канала —
// канал шифрует OpenSSL).
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace sentinel {

class Sha256 {
public:
    Sha256();
    void update(const void* data, size_t len);
    void update(std::string_view s) { update(s.data(), s.size()); }
    std::array<uint8_t, 32> finish();

private:
    void block(const uint8_t* p);
    uint32_t h_[8];
    uint8_t buf_[64];
    size_t buf_len_ = 0;
    uint64_t total_ = 0;
};

std::string sha256_hex(std::string_view data);

// SHA-1 (RFC 3174). Нужен ТОЛЬКО для рукопожатия WebSocket (RFC 6455), не для защиты данных.
std::array<uint8_t, 20> sha1(std::string_view data);

// Base64 (RFC 4648)
std::string base64_encode(const uint8_t* data, size_t n);

// Сравнение без раннего выхода (не даёт подобрать значение по времени ответа).
bool constant_time_equals(std::string_view a, std::string_view b);

// Криптостойкие случайные байты из ОС (std::random_device), в hex.
std::string random_hex(size_t bytes);

}  // namespace sentinel
