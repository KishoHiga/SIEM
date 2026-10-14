// SentinelCore — движок обнаружения.
//
// Для каждого события:
//   1) дешёвые условия (равенство полей) проверяются сразу;
//   2) все регулярки, относящиеся к одному полю (с одинаковыми преобразованиями),
//      собраны в ОДИН автомат — поле просматривается один раз на все правила;
//   3) пороговые окна и цепочки хранятся в памяти по ключу (обычно IP).
//
// Не потокобезопасен: один движок обслуживает один поток обработки.
#pragma once

#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/event.hpp"
#include "detect/rules.hpp"
#include "regex/regex.hpp"

namespace sentinel {

struct EngineStats {
    uint64_t events = 0;
    uint64_t alerts = 0;
    uint64_t suppressed = 0;  // повторы, подавленные cooldown
    uint64_t state_keys = 0;  // размер состояния (окна/цепочки)
};

class DetectionEngine {
public:
    DetectionEngine();
    ~DetectionEngine();

    // Компилирует правила. Отключённые (enabled: false) пропускаются.
    bool load(std::vector<Rule> rules, std::string& error);

    // Проверить событие; новые алерты дописываются в out (id = 0, его назначает вызывающий).
    void process(const Event& ev, std::vector<Alert>& out);

    // Удалить устаревшее состояние (вызывать периодически).
    void sweep(int64_t now_ms);
    // Сбросить всё состояние (окна, cooldown, цепочки).
    void reset_state();

    const std::vector<Rule>& rules() const { return rules_; }
    EngineStats stats() const;

    // Ограничение числа ключей состояния на правило (защита памяти).
    void set_max_keys_per_rule(size_t n) { max_keys_ = n; }

private:
    struct Group;
    struct Window;
    struct SeqState {
        size_t step = 0;
        int64_t start = 0;
        std::vector<uint64_t> ids;
    };
    struct Cooldown {
        int64_t until = 0;
        uint64_t suppressed = 0;
    };
    struct RuleState {
        std::unordered_map<std::string, Cooldown> cooldown;
        std::unordered_map<std::string, std::unique_ptr<Window>> windows;
        std::unordered_map<std::string, SeqState> seq;
    };

    bool eval(const std::vector<Condition>& conds, const Event& ev);
    bool eval_one(const Condition& c, const Event& ev);
    bool group_hit(const Condition& c, const Event& ev);
    bool make_key(const Rule& r, const Event& ev, std::string& key) const;
    Alert make_alert(const Rule& r, const Event& ev, uint64_t count) const;
    std::string render(const Rule& r, const Event& ev, uint64_t count) const;
    bool cooldown_pass(size_t ri, const std::string& key, int64_t t, int64_t cd_ms, uint64_t& repeats);
    void limit_state(size_t ri, int64_t now);

    std::vector<Rule> rules_;
    std::vector<RuleState> state_;
    std::vector<std::unique_ptr<Group>> groups_;
    std::unordered_map<std::string, size_t> rule_index_;
    std::vector<size_t> fired_;  // правила, сработавшие на текущем событии
    uint64_t seq_no_ = 0;
    size_t max_keys_ = 200000;
    EngineStats stats_;
    std::string scratch_;
    int64_t latest_ts_ = 0;
};

}  // namespace sentinel
