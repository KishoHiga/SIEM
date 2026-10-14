// SentinelCore — проверка правил на их встроенных примерах (tests: match / no_match).
#pragma once

#include <string>
#include <vector>

#include "detect/rules.hpp"

namespace sentinel {

struct RuleTestFailure {
    std::string rule_id;
    std::string file;
    std::string line;
    bool expected_alert;  // true: ждали алерт, а его нет; false: алерт лишний
};

struct RuleTestReport {
    size_t rules_with_tests = 0;
    size_t cases = 0;
    std::vector<RuleTestFailure> failures;
    std::vector<std::string> errors;
};

// В строке теста "{n}" заменяется номером повтора (для правил с distinct).
RuleTestReport run_rule_tests(const std::vector<Rule>& rules);

}  // namespace sentinel
