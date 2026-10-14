// SentinelCore — правила обнаружения: структура и загрузка из YAML.
//
// Типы правил:
//   match     — алерт на каждое подходящее событие (с подавлением повторов);
//   threshold — N подходящих событий за окно времени (по группе, например по IP),
//               опционально считать РАЗНЫЕ значения поля (distinct);
//   sequence  — цепочка шагов в пределах времени (например, перебор -> успешный вход).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/event.hpp"
#include "core/yaml.hpp"

namespace sentinel {

// Ссылка на поле события: известное поле или дополнительное (extra).
struct FieldRef {
    bool known = true;
    Field field = Field::Message;
    std::string extra;  // имя доп. поля, если known == false
    std::string name;   // как записано в правиле

    std::string_view get(const Event& ev) const {
        if (known) return ev[field];
        const std::string* v = ev.extra_get(extra);
        return v ? std::string_view(*v) : std::string_view();
    }
};

FieldRef make_field_ref(std::string_view name);

struct Condition {
    enum class Op { In, NotIn, Regex, NotRegex, Contains, Exists, Missing, Gte, Lte, Gt, Lt };
    FieldRef field;
    Op op = Op::In;
    std::vector<std::string> values;  // In/NotIn/Contains/Regex(шаблоны)
    double number = 0;
    uint32_t transforms = 0;          // для Regex/Contains
    // заполняется движком при компиляции
    int group = -1;
    std::vector<uint32_t> pattern_ids;
};

struct RuleTests {
    std::vector<std::string> match;     // строки логов, на которые правило ДОЛЖНО сработать
    std::vector<std::string> no_match;  // строки, на которые НЕ должно
    int repeat = 0;                     // сколько раз подать строку (для threshold; 0 = авто)
};

struct Rule {
    enum class Kind { Match, Threshold, Sequence };

    std::string id;
    std::string name;
    std::string description;
    std::string message;  // шаблон текста алерта: {src_ip}, {user}, {count}, {http.path}...
    std::string file;
    Severity severity = Severity::Medium;
    Kind kind = Kind::Match;
    bool enabled = true;
    std::vector<std::string> tags;

    std::vector<Condition> where;
    std::vector<FieldRef> group_by;  // ключ группировки / подавления повторов
    int64_t cooldown_ms = -1;        // -1: по умолчанию (match: 60 с, threshold: окно)

    // threshold
    uint32_t threshold = 0;
    int64_t window_ms = 0;
    std::optional<FieldRef> distinct;

    // sequence
    struct Step {
        std::string rule_id;           // шаг = срабатывание другого правила
        std::vector<Condition> where;  // или шаг = событие с условиями
    };
    std::vector<Step> steps;
    int64_t within_ms = 0;

    RuleTests tests;
};

const char* rule_kind_name(Rule::Kind k);

struct RuleLoadResult {
    std::vector<Rule> rules;
    std::vector<std::string> errors;  // "файл: ошибка"
};

// Разбор одного YAML-документа (одно правило или список правил).
bool parse_rules_yaml(std::string_view text, const std::string& file, std::vector<Rule>& out, std::string& error);
// Загрузить все *.yml / *.yaml из каталога (с проверкой ссылок и регулярок).
RuleLoadResult load_rules_dir(const std::string& dir);
// Проверка набора: уникальность id, ссылки sequence, синтаксис регулярок.
void validate_rules(std::vector<Rule>& rules, std::vector<std::string>& errors);

}  // namespace sentinel
