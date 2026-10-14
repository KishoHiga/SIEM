// SentinelCore — нормализация значений перед поиском шаблонов.
// Атаки прячут в кодировках (%27, &lt;, \x22, /**/), поэтому сначала раскодируем.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace sentinel {

enum Transform : uint32_t {
    T_Unescape = 1u << 0,           // \xHH и \" (так nginx экранирует запрос)
    T_UrlDecode = 1u << 1,          // %XX, %uXXXX, '+' (дважды — против двойного кодирования)
    T_HtmlDecode = 1u << 2,         // &lt; &#60; &#x3c; ...
    T_RemoveSqlComments = 1u << 3,  // /* ... */ -> пробел
    T_CompressSpace = 1u << 4,      // серии пробельных символов -> один пробел
    T_Lowercase = 1u << 5,
};

std::optional<uint32_t> transform_from_name(std::string_view name);
std::string transform_names(uint32_t mask);

// Применяет преобразования в фиксированном порядке (как перечислены выше).
void apply_transforms(std::string_view in, uint32_t mask, std::string& out);

std::string url_decode(std::string_view s);
std::string html_decode(std::string_view s);

}  // namespace sentinel
