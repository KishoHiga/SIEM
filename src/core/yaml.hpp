// SentinelCore — собственный парсер подмножества YAML для правил и конфигов.
//
// Поддерживается: словари (key: value), списки (- item), вложенность отступами,
// скаляры (простые, 'одинарные', "двойные" с экранированием), [flow, списки],
// {flow: словари}, комментарии #. Не поддерживается: якоря, теги, | и > блоки.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sentinel {

struct YMember;

struct YNode {
    enum class Kind { Null, Scalar, Seq, Map };
    Kind kind = Kind::Null;
    std::string scalar;
    bool quoted = false;
    std::vector<YNode> seq;
    std::vector<YMember> map;
    int line = 0;

    bool is_null() const { return kind == Kind::Null; }
    bool is_scalar() const { return kind == Kind::Scalar; }
    bool is_seq() const { return kind == Kind::Seq; }
    bool is_map() const { return kind == Kind::Map; }

    const YNode* get(std::string_view key) const;
    // Значение-строка по ключу или def.
    std::string str(std::string_view key, std::string_view def = "") const;
    std::optional<int64_t> integer(std::string_view key) const;
    std::optional<bool> boolean(std::string_view key) const;
    // Скаляр или список скаляров -> вектор строк.
    std::vector<std::string> strings(std::string_view key) const;
    std::vector<std::string> as_strings() const;
};

struct YMember {
    std::string first;
    YNode second;
    YMember() = default;
    YMember(std::string k, YNode v) : first(std::move(k)), second(std::move(v)) {}
};

// Возвращает false и сообщение об ошибке (с номером строки) при неудаче.
bool parse_yaml(std::string_view text, YNode& out, std::string& error);

}  // namespace sentinel
