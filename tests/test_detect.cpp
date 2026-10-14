#include "core/util.hpp"
#include "detect/engine.hpp"
#include "detect/rule_tests.hpp"
#include "detect/rules.hpp"
#include "detect/transform.hpp"
#include "parse/parsers.hpp"
#include "testing.hpp"

using namespace sentinel;

#ifndef SENTINEL_SOURCE_DIR
#define SENTINEL_SOURCE_DIR "."
#endif

static const std::string kRulesDir = std::string(SENTINEL_SOURCE_DIR) + "/rules";

static Event ev_at(const std::string& line, int64_t ts, uint64_t id) {
    ParseContext ctx;
    ctx.now_ms = ts;
    Event ev;
    parse_line(line, LogFormat::Auto, ctx, ev);
    ev.ts = ts;
    ev.id = id;
    return ev;
}

static int count_rule(const std::vector<Alert>& a, const std::string& id) {
    int n = 0;
    for (auto& x : a)
        if (x.rule_id == id) ++n;
    return n;
}

TEST("transform: decoding") {
    CHECK_EQ(url_decode("a%20b+c%2527"), std::string("a b c'"));
    CHECK_EQ(url_decode("%u003Cscript"), std::string("<script"));
    CHECK_EQ(html_decode("&lt;a&#62;&#x3c;&quot;&amp;x"), std::string("<a><\"&x"));
    std::string out;
    apply_transforms("1/**/UNION/**/SELECT\t\t2", T_RemoveSqlComments | T_CompressSpace | T_Lowercase, out);
    CHECK_EQ(out, std::string("1 union select 2"));
    apply_transforms("GET /a\\x22b", T_Unescape, out);
    CHECK_EQ(out, std::string("GET /a\"b"));
}

TEST("rules: bundled rules load without errors") {
    auto res = load_rules_dir(kRulesDir);
    for (auto& e : res.errors) std::cerr << "  rule error: " << e << "\n";
    CHECK(res.errors.empty());
    CHECK(res.rules.size() >= 15);
    DetectionEngine eng;
    std::string err;
    CHECK(eng.load(res.rules, err));
    if (!err.empty()) std::cerr << "  " << err << "\n";
}

TEST("rules: built-in examples (match / no_match) pass") {
    auto res = load_rules_dir(kRulesDir);
    auto rep = run_rule_tests(res.rules);
    for (auto& e : rep.errors) std::cerr << "  error: " << e << "\n";
    for (auto& f : rep.failures)
        std::cerr << "  " << f.rule_id << (f.expected_alert ? " MISSED: " : " FALSE ALERT: ") << f.line << "\n";
    CHECK(rep.errors.empty());
    CHECK(rep.failures.empty());
    CHECK(rep.cases > 60);
}

TEST("rules: yaml errors are reported clearly") {
    std::vector<Rule> out;
    std::string err;
    CHECK(!parse_rules_yaml("id: X\ntype: threshold\nwhere:\n  type: web\n", "f.yml", out, err));
    CHECK(err.find("threshold") != std::string::npos);
    CHECK(!parse_rules_yaml("id: X\ntype: match\nwher:\n  type: web\n", "f.yml", out, err));
    CHECK(err.find("unknown key") != std::string::npos);
    std::vector<Rule> rules;
    CHECK(parse_rules_yaml("id: X\npatterns: ['(abc']\n", "f.yml", rules, err));
    std::vector<std::string> errors;
    validate_rules(rules, errors);
    CHECK(rules.empty());
    CHECK(errors.size() == 1);
}

TEST("engine: brute force -> success sequence, and successes alone do nothing") {
    auto res = load_rules_dir(kRulesDir);
    DetectionEngine eng;
    std::string err;
    REQUIRE(eng.load(res.rules, err));
    const int64_t t0 = parse_iso8601("2026-10-12T11:00:00Z").value();
    std::vector<Alert> alerts;
    // Шесть УСПЕШНЫХ входов — ни перебора, ни взлома
    for (int i = 0; i < 6; ++i)
        eng.process(ev_at("Oct 12 11:00:00 h sshd[1]: Accepted password for ivan from 10.0.0.5 port 4000 ssh2", t0 + i * 1000, uint64_t(i + 1)), alerts);
    CHECK(alerts.empty());
    // Пять неудачных + успешный
    for (int i = 0; i < 5; ++i)
        eng.process(ev_at("Oct 12 11:00:00 h sshd[1]: Failed password for root from 45.1.1.1 port 4000 ssh2", t0 + 10000 + i * 1000, uint64_t(100 + i)), alerts);
    CHECK_EQ(count_rule(alerts, "AUTH-BRUTE-001"), 1);
    eng.process(ev_at("Oct 12 11:00:00 h sshd[1]: Accepted password for root from 45.1.1.1 port 4000 ssh2", t0 + 20000, 200), alerts);
    REQUIRE(count_rule(alerts, "AUTH-COMPROMISE-001") == 1);
    for (auto& a : alerts) {
        if (a.rule_id != "AUTH-COMPROMISE-001") continue;
        CHECK(a.severity == Severity::Critical);
        CHECK_EQ(a.src_ip, std::string("45.1.1.1"));
        CHECK_EQ(a.user, std::string("root"));
        CHECK(a.event_ids.size() == 2);
        CHECK(a.message.find("root") != std::string::npos);
    }
    // Успех с ДРУГОГО IP цепочку не замыкает
    alerts.clear();
    for (int i = 0; i < 5; ++i)
        eng.process(ev_at("Oct 12 11:00:00 h sshd[1]: Failed password for root from 45.2.2.2 port 4000 ssh2", t0 + 30000 + i, uint64_t(300 + i)), alerts);
    eng.process(ev_at("Oct 12 11:00:00 h sshd[1]: Accepted password for root from 10.9.9.9 port 4000 ssh2", t0 + 31000, 400), alerts);
    CHECK_EQ(count_rule(alerts, "AUTH-COMPROMISE-001"), 0);
}

TEST("engine: threshold window expires") {
    auto res = load_rules_dir(kRulesDir);
    DetectionEngine eng;
    std::string err;
    REQUIRE(eng.load(res.rules, err));
    const int64_t t0 = parse_iso8601("2026-10-12T11:00:00Z").value();
    std::vector<Alert> alerts;
    const char* line = "Oct 12 11:00:00 h sshd[1]: Failed password for root from 45.3.3.3 port 4000 ssh2";
    for (int i = 0; i < 4; ++i) eng.process(ev_at(line, t0 + i * 1000, uint64_t(i + 1)), alerts);
    eng.process(ev_at(line, t0 + 400000, 10), alerts);  // через 400 с — первые 4 вне окна 300 с
    CHECK_EQ(count_rule(alerts, "AUTH-BRUTE-001"), 0);
}

TEST("engine: match cooldown suppresses repeats, then reports them") {
    auto res = load_rules_dir(kRulesDir);
    DetectionEngine eng;
    std::string err;
    REQUIRE(eng.load(res.rules, err));
    const int64_t t0 = parse_iso8601("2026-10-12T11:00:00Z").value();
    const std::string line =
        R"L(203.0.113.9 - - [12/Oct/2026:10:00:00 +0000] "GET /p?id=1%20UNION%20SELECT%201 HTTP/1.1" 200 5 "-" "x")L";
    std::vector<Alert> alerts;
    for (int i = 0; i < 3; ++i) eng.process(ev_at(line, t0 + i * 1000, uint64_t(i + 1)), alerts);
    CHECK_EQ(count_rule(alerts, "WEB-SQLI-001"), 1);
    eng.process(ev_at(line, t0 + 70000, 9), alerts);
    REQUIRE(count_rule(alerts, "WEB-SQLI-001") == 2);
    bool found = false;
    for (auto& f : alerts.back().fields)
        if (f.first == "repeats_before" && f.second == "2") found = true;
    CHECK(found);
    // Другой IP не подавляется
    alerts.clear();
    eng.process(ev_at(R"L(203.0.113.10 - - [12/Oct/2026:10:00:00 +0000] "GET /p?id=1%20UNION%20SELECT%201 HTTP/1.1" 200 5 "-" "x")L", t0 + 71000, 10), alerts);
    CHECK_EQ(count_rule(alerts, "WEB-SQLI-001"), 1);
    CHECK(eng.stats().suppressed >= 2);
}

TEST("engine: state is bounded under many unique IPs") {
    auto res = load_rules_dir(kRulesDir);
    DetectionEngine eng;
    eng.set_max_keys_per_rule(1000);
    std::string err;
    REQUIRE(eng.load(res.rules, err));
    std::vector<Alert> alerts;
    const int64_t t0 = parse_iso8601("2026-10-12T11:00:00Z").value();
    for (int i = 0; i < 20000; ++i) {
        std::string ip = "10." + std::to_string((i >> 16) & 255) + "." + std::to_string((i >> 8) & 255) + "." + std::to_string(i & 255);
        eng.process(ev_at("Oct 12 11:00:00 h sshd[1]: Failed password for root from " + ip + " port 1 ssh2", t0 + i, uint64_t(i + 1)), alerts);
    }
    eng.sweep(t0 + 20000);
    CHECK(eng.stats().state_keys <= 5000);
}
