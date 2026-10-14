#include "detect/rule_tests.hpp"

#include "core/util.hpp"
#include "detect/engine.hpp"
#include "parse/parsers.hpp"

namespace sentinel {

static std::string subst_n(const std::string& line, int n) {
    std::string out;
    std::string num = std::to_string(n);
    for (size_t i = 0; i < line.size(); ++i) {
        if (line.compare(i, 3, "{n}") == 0) {
            out += num;
            i += 2;
        } else {
            out.push_back(line[i]);
        }
    }
    return out;
}

RuleTestReport run_rule_tests(const std::vector<Rule>& rules) {
    RuleTestReport rep;
    for (const Rule& r : rules) {
        if (r.tests.match.empty() && r.tests.no_match.empty()) continue;
        if (r.kind == Rule::Kind::Sequence) continue;  // цепочки проверяются юнит-тестами
        ++rep.rules_with_tests;
        DetectionEngine eng;
        std::string err;
        Rule copy = r;
        copy.enabled = true;
        copy.cooldown_ms = 0;
        if (!eng.load({copy}, err)) {
            rep.errors.push_back(r.id + ": " + err);
            continue;
        }
        int repeat = r.tests.repeat > 0 ? r.tests.repeat : (r.kind == Rule::Kind::Threshold ? int(r.threshold) : 1);
        auto fires = [&](const std::string& line) {
            eng.reset_state();
            ParseContext ctx;
            ctx.now_ms = parse_iso8601("2026-10-12T12:00:00Z").value();
            std::vector<Alert> alerts;
            bool fired = false;
            for (int k = 0; k < repeat; ++k) {
                Event ev;
                parse_line(subst_n(line, k), LogFormat::Auto, ctx, ev);
                ev.id = uint64_t(k + 1);
                alerts.clear();
                eng.process(ev, alerts);
                for (auto& a : alerts)
                    if (a.rule_id == r.id) fired = true;
            }
            return fired;
        };
        for (auto& line : r.tests.match) {
            ++rep.cases;
            if (!fires(line)) rep.failures.push_back({r.id, r.file, line, true});
        }
        for (auto& line : r.tests.no_match) {
            ++rep.cases;
            if (fires(line)) rep.failures.push_back({r.id, r.file, line, false});
        }
    }
    return rep;
}

}  // namespace sentinel
