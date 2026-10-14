// SentinelCore — собственный движок регулярных выражений.
//
// Как работает:
//   шаблон -> дерево разбора -> NFA (конструкция Томпсона) -> ленивый DFA.
// DFA строится по мере надобности и кэшируется, поэтому каждый байт текста
// обрабатывается одним поиском в таблице. Время проверки строго линейное:
// никакого "катастрофического возврата", как в движках с откатом.
//
// MultiMatcher объединяет МНОГО шаблонов в один автомат и за один проход по
// строке сообщает, какие из них нашлись.
//
// Синтаксис: литералы, . [abc] [^a-z] \d \w \s \D \W \S \xHH \n \t \r,
// группы ( ) (?: ), альтернатива |, * + ? {n} {n,} {n,m} (ленивые *? допускаются),
// якоря ^ $, флаги (?i) (?s) (?-i) и (?i: ... ).
// Не поддерживается (намеренно, ради линейного времени): обратные ссылки,
// просмотр вперёд/назад, \b.
//
// Объект MultiMatcher НЕ потокобезопасен (внутри кэш DFA): по одному на поток.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace sentinel::rx {

struct ByteSet {
    uint64_t w[4] = {0, 0, 0, 0};
    void set(uint8_t c) { w[c >> 6] |= uint64_t(1) << (c & 63); }
    bool has(uint8_t c) const { return (w[c >> 6] >> (c & 63)) & 1; }
    void set_range(uint8_t a, uint8_t b) {
        for (unsigned c = a; c <= b; ++c) set(uint8_t(c));
    }
    void invert() {
        for (auto& x : w) x = ~x;
    }
    void merge(const ByteSet& o) {
        for (int i = 0; i < 4; ++i) w[i] |= o.w[i];
    }
    bool operator==(const ByteSet& o) const {
        return w[0] == o.w[0] && w[1] == o.w[1] && w[2] == o.w[2] && w[3] == o.w[3];
    }
};

// Проверка синтаксиса шаблона без компиляции автомата.
bool validate(std::string_view pattern, std::string* error);

class MultiMatcher {
public:
    MultiMatcher();
    ~MultiMatcher();
    MultiMatcher(MultiMatcher&&) noexcept;
    MultiMatcher& operator=(MultiMatcher&&) noexcept;

    // Добавить шаблон. Возвращает его номер (0,1,2...) или -1 при ошибке.
    int add(std::string_view pattern, std::string* error = nullptr);
    // Собрать автомат. После compile() add() вызывать нельзя.
    bool compile(std::string* error = nullptr);

    size_t pattern_count() const;
    bool compiled() const;

    // Найти все совпавшие шаблоны в тексте. Номера (без повторов) пишутся в out.
    // Возвращает true, если хоть один найден.
    bool scan(std::string_view text, std::vector<uint32_t>& out);
    // Есть ли хоть одно совпадение (выход при первом найденном).
    bool any(std::string_view text);

    // Диагностика
    size_t dfa_state_count() const;
    size_t nfa_state_count() const;
    size_t byte_class_count() const;
    uint64_t cache_resets() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Удобная обёртка для одного шаблона.
class Regex {
public:
    Regex() = default;
    bool compile(std::string_view pattern, std::string* error = nullptr);
    bool search(std::string_view text) { return m_.any(text); }

private:
    MultiMatcher m_;
};

}  // namespace sentinel::rx
