// SentinelCore — собственный JSON: парсер в дерево и потоковый писатель.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace sentinel {

struct JMember;

class JValue {
public:
    enum class Type : uint8_t { Null, Bool, Number, String, Array, Object };

    Type type = Type::Null;
    bool b = false;
    bool is_int = false;
    int64_t i = 0;
    double d = 0;
    std::string s;
    std::vector<JValue> arr;
    std::vector<JMember> obj;  // пары ключ-значение (порядок сохраняется)

    bool is_null() const { return type == Type::Null; }
    bool is_string() const { return type == Type::String; }
    bool is_number() const { return type == Type::Number; }
    bool is_object() const { return type == Type::Object; }
    bool is_array() const { return type == Type::Array; }
    bool is_bool() const { return type == Type::Bool; }

    const JValue* get(std::string_view key) const;
    // Строковое представление скаляра (числа/булевы в текст). Для объектов/массивов — JSON.
    std::string as_text() const;
};

// Отдельная структура вместо std::pair: pair с ещё не определённым JValue
// не компилируется в libc++ (macOS) и clang.
struct JMember {
    std::string first;
    JValue second;
    JMember() = default;
    JMember(std::string k, JValue v) : first(std::move(k)), second(std::move(v)) {}
};

bool json_parse(std::string_view text, JValue& out, std::string& error);

// Экранирует строку для JSON; некорректный UTF-8 заменяется на U+FFFD.
void json_escape_to(std::string& out, std::string_view s);

class JsonWriter {
public:
    explicit JsonWriter(std::string& out) : out_(out) {}

    JsonWriter& begin_object();
    JsonWriter& end_object();
    JsonWriter& begin_array();
    JsonWriter& end_array();
    JsonWriter& key(std::string_view k);
    JsonWriter& value(std::string_view v);
    JsonWriter& value(const char* v) { return value(std::string_view(v)); }
    JsonWriter& value(const std::string& v) { return value(std::string_view(v)); }
    // Любые целые типы (одинаково на Linux/macOS/Windows, где int64_t/size_t различаются).
    template <class T, std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<T, bool>, int> = 0>
    JsonWriter& value(T v) {
        if constexpr (std::is_signed_v<T>)
            return value_i64(static_cast<int64_t>(v));
        else
            return value_u64(static_cast<uint64_t>(v));
    }
    JsonWriter& value(double v);
    JsonWriter& value(bool v);
    JsonWriter& null();
    // Вставка готового JSON-фрагмента как значения.
    JsonWriter& raw(std::string_view json);

    template <class T>
    JsonWriter& kv(std::string_view k, const T& v) {
        key(k);
        return value(v);
    }

private:
    JsonWriter& value_i64(int64_t v);
    JsonWriter& value_u64(uint64_t v);
    void comma();
    std::string& out_;
    std::vector<bool> first_{true};
    bool after_key_ = false;
};

void json_write_value(std::string& out, const JValue& v);

}  // namespace sentinel
