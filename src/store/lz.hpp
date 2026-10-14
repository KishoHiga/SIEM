// SentinelCore — собственное быстрое LZ-сжатие для блоков хранилища.
//
// Формат последовательности: [токен][доп. длина литералов][литералы][смещение 2 байта][доп. длина совпадения]
// токен: старшие 4 бита — число литералов (15 = продолжение), младшие — длина совпадения-4.
// Последняя последовательность содержит только литералы.
// Логи очень повторяющиеся (одинаковые IP, пути, User-Agent), сжатие обычно 3-6 раз.
#pragma once

#include <string>
#include <string_view>

namespace sentinel::lz {

void compress(std::string_view in, std::string& out);
// false при повреждённых данных или если результат не совпадает по длине с expected_size.
bool decompress(std::string_view in, size_t expected_size, std::string& out);

}  // namespace sentinel::lz
