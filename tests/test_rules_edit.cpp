// Тесты этапа 5: правка правил (проверка, сохранение, история, включение), пробный запуск и API.
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>

#include "core/crypto.hpp"
#include "core/json.hpp"
#include "core/util.hpp"
#include "detect/engine.hpp"
#include "detect/rules.hpp"
#include "net/client.hpp"
#include "net/server.hpp"
#include "parse/parsers.hpp"
#include "server/api.hpp"
#include "server/pipeline.hpp"
#include "server/rule_manager.hpp"
#include "testing.hpp"

using namespace sentinel;
namespace fs = std::filesystem;

#ifndef SENTINEL_SOURCE_DIR
#define SENTINEL_SOURCE_DIR "."
#endif

namespace {

struct RTmp {
    std::string path;
    RTmp() {
        path = (fs::temp_directory_path() / ("sentinel-rules-" + random_hex(6))).string();
        fs::create_directories(path + "/rules");
        for (auto& e : fs::directory_iterator(std::string(SENTINEL_SOURCE_DIR) + "/rules"))
            fs::copy_file(e.path(), path + "/rules/" + e.path().filename().string());
    }
    ~RTmp() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    std::string rules() const { return path + "/rules"; }
};

std::string slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

const char* kNewRule = R"(# Своё правило: вход под root по SSH
id: CUSTOM-ROOT-LOGIN
name: Вход под root
severity: medium
type: match
group_by: [src_ip, user]
where:
  type: auth
  outcome: success
  user: root
message: 'root вошёл с {src_ip}'
tests:
  match:
    - 'Oct 12 11:00:01 web-01 sshd[1]: Accepted password for root from 198.51.100.9 port 5000 ssh2'
  no_match:
    - 'Oct 12 11:00:01 web-01 sshd[1]: Accepted password for ivan from 198.51.100.9 port 5000 ssh2'
)";

std::string json_body(std::initializer_list<std::pair<const char*, std::string>> kv) {
    std::string out;
    JsonWriter w(out);
    w.begin_object();
    for (auto& p : kv) w.kv(p.first, p.second);
    w.end_object();
    return out;
}

}  // namespace

TEST("rules edit: enabled flag is changed in text, comments and layout stay") {
    std::string out;
    std::string single = "# комментарий\nid: A-1\nname: x\nenabled: true   # был включён\nwhere: {type: web}\n";
    REQUIRE(RuleManager::edit_enabled(single, "A-1", false, out));
    CHECK_EQ(out, std::string("# комментарий\nid: A-1\nname: x\nenabled: false\nwhere: {type: web}\n"));
    std::string no_flag = "id: 'A-2'\r\nname: x\r\nwhere: {type: web}\r\n";
    REQUIRE(RuleManager::edit_enabled(no_flag, "A-2", false, out));
    CHECK_EQ(out, std::string("id: 'A-2'\r\nenabled: false\r\nname: x\r\nwhere: {type: web}\r\n"));
    REQUIRE(RuleManager::edit_enabled(no_flag, "A-2", true, out));  // уже включено — без изменений
    CHECK_EQ(out, no_flag);
    std::string list = "- id: L-1\n  name: a\n  where: {type: web}\n- id: L-2\n  name: b\n  enabled: false\n"
                       "  where: {type: auth}\n- id: L-3\n  name: c\n  where: {type: web}\n";
    REQUIRE(RuleManager::edit_enabled(list, "L-2", true, out));
    CHECK(out.find("- id: L-2\n  name: b\n  enabled: true\n") != std::string::npos);
    REQUIRE(RuleManager::edit_enabled(list, "L-1", false, out));
    CHECK(out.find("- id: L-1\n  enabled: false\n  name: a\n") == 0);
    CHECK(out.find("- id: L-3\n  name: c\n") != std::string::npos);  // соседние не тронуты
    std::string wrapped = "rules:\n  - id: W-1\n    name: a\n    where: {type: web}\n";
    REQUIRE(RuleManager::edit_enabled(wrapped, "W-1", false, out));
    CHECK(out.find("  - id: W-1\n    enabled: false\n") != std::string::npos);
    CHECK(!RuleManager::edit_enabled(single, "NOPE", false, out));

    CHECK_EQ(RuleManager::file_name_for("WEB-SQLI-002"), std::string("web_sqli_002.yml"));
    CHECK_EQ(RuleManager::file_name_for("../../etc/passwd"), std::string("etc_passwd.yml"));
    CHECK_EQ(RuleManager::file_name_for("Правило"), std::string("rule.yml"));
}

TEST("rules edit: save checks everything, applies at once, keeps history; enable/disable/delete keep chains valid") {
    RTmp d;
    RuleManager m(d.rules(), d.path + "/history");
    int applied = 0;
    size_t enabled_rules = 0;
    m.set_apply([&](std::unique_ptr<DetectionEngine> e, const std::vector<Rule>&) {
        ++applied;
        enabled_rules = e->rules().size();
    });
    std::string err;
    REQUIRE(m.reload(err));
    CHECK_EQ(applied, 1);
    const size_t base = load_rules_dir(d.rules()).rules.size();  // правила из папки rules проекта
    CHECK_EQ(enabled_rules, base);
    CHECK(!m.reload_if_changed());

    // новое правило
    RuleCheck c = m.save("", kNewRule, "ivan");
    REQUIRE(c.ok);
    CHECK_EQ(c.file, std::string("custom_root_login.yml"));
    CHECK_EQ(c.test_cases, size_t(2));
    CHECK_EQ(applied, 2);
    CHECK_EQ(enabled_rules, base + 1);
    CHECK_EQ(slurp(d.rules() + "/custom_root_login.yml"), std::string(kNewRule));  // комментарий сохранён
    CHECK(!m.reload_if_changed());  // своё сохранение не вызывает второй перезагрузки
    CHECK_EQ(applied, 2);

    // ошибки — файл не меняется
    std::string before = slurp(d.rules() + "/web_xss.yml");
    c = m.save("WEB-XSS-001", "id: WEB-XSS-001\nname: [broken\n", "ivan");
    CHECK(!c.ok);
    CHECK(!c.error.empty());
    c = m.save("WEB-XSS-001", "id: WEB-XSS-001\ntype: match\nwhere: {type: web}\npatterns: ['(unclosed']\n", "ivan");
    CHECK(!c.ok);
    c = m.save("WEB-XSS-001", "id: WEB-SQLI-001\ntype: match\nwhere: {type: web}\n", "ivan");  // id занят
    CHECK(!c.ok);
    CHECK(c.error.find("duplicate") != std::string::npos);
    std::string bad_example = std::string(kNewRule);
    bad_example.replace(bad_example.find("for ivan"), 8, "for root");  // пример no_match теперь срабатывает
    c = m.save("CUSTOM-ROOT-LOGIN", bad_example, "ivan");
    CHECK(!c.ok);
    REQUIRE(c.test_failures.size() == 1u);
    CHECK(!c.test_failures[0].expected_alert);
    CHECK_EQ(slurp(d.rules() + "/web_xss.yml"), before);
    CHECK_EQ(applied, 2);
    c = m.check("", "id: X\nname: y\ntype: threshold\nwhere: {type: web}\n");  // нет threshold
    CHECK(!c.ok);

    // правка существующего
    std::string edited = before;
    edited.replace(edited.find("severity: high"), 14, "severity: critical");
    c = m.save("WEB-XSS-001", edited, "anna");
    REQUIRE(c.ok);
    CHECK_EQ(applied, 3);
    for (auto& r : m.rules())
        if (r.id == "WEB-XSS-001") CHECK(r.severity == Severity::Critical);
    auto hist = m.history("WEB-XSS-001");
    REQUIRE(hist.size() == 2u);  // исходная версия + правка
    CHECK_EQ(hist[0].action, std::string("update"));
    CHECK_EQ(hist[0].by, std::string("anna"));
    CHECK_EQ(hist[1].action, std::string("original"));
    std::string text;
    REQUIRE(m.version_text("WEB-XSS-001", hist[1].name, text));
    CHECK_EQ(text, before);
    CHECK(!m.version_text("WEB-XSS-001", "../../web_sqli.yml", text));

    // выключение правила, на которое ссылается цепочка — нельзя; обычного — можно
    c = m.set_enabled("AUTH-BRUTE-001", false, "ivan");
    CHECK(!c.ok);
    CHECK(c.error.find("AUTH-BRUTE-001") != std::string::npos);
    c = m.set_enabled("WEB-XSS-001", false, "ivan");
    REQUIRE(c.ok);
    CHECK_EQ(enabled_rules, base);
    std::string now = slurp(d.rules() + "/web_xss.yml");
    CHECK(now.find("id: WEB-XSS-001\nenabled: false\n") == 0);
    CHECK(now.find("patterns:\n  - '<script") != std::string::npos);
    REQUIRE(m.set_enabled("WEB-XSS-001", true, "ivan").ok);
    CHECK_EQ(enabled_rules, base + 1);
    CHECK_EQ(m.history("WEB-XSS-001")[0].action, std::string("enable"));

    // удаление
    c = m.remove("AUTH-BRUTE-001", "ivan");  // нужно цепочке
    CHECK(!c.ok);
    CHECK(fs::exists(d.rules() + "/ssh_bruteforce.yml"));
    REQUIRE(m.remove("CUSTOM-ROOT-LOGIN", "ivan").ok);
    CHECK(!fs::exists(d.rules() + "/custom_root_login.yml"));
    CHECK_EQ(enabled_rules, base);
    CHECK(!m.remove("CUSTOM-ROOT-LOGIN", "ivan").ok);  // уже нет
    CHECK(fs::exists(d.path + "/history/custom_root_login.yml"));  // история удалённого осталась

    // правка вручную подхватывается
    { std::ofstream(d.rules() + "/manual.yml") << "id: MANUAL-1\nname: m\ntype: match\nwhere: {type: web}\n"; }
    CHECK(m.reload_if_changed());
    CHECK_EQ(enabled_rules, base + 1);
    // сломанный файл вручную: остальные правила работают, ошибка видна
    { std::ofstream(d.rules() + "/broken.yml") << "id: B\nname: [x\n"; }
    CHECK(m.reload_if_changed());
    CHECK_EQ(enabled_rules, base + 1);
    CHECK_EQ(m.load_errors().size(), size_t(1));
    // а правка другого правила не мешает чужая ошибка
    REQUIRE(m.save("MANUAL-1", "id: MANUAL-1\nname: m2\ntype: match\nwhere: {type: auth}\n", "ivan").ok);
}

TEST("rules edit: dry run on log lines and on stored events") {
    RTmp d;
    RuleManager m(d.rules(), d.path + "/history");
    std::string err;
    REQUIRE(m.reload(err));

    std::vector<std::string> lines;
    for (int i = 0; i < 6; ++i)
        lines.push_back("Oct 12 11:00:0" + std::to_string(i) + " web-01 sshd[1]: Failed password for root from 45.13.0.9 port 1 ssh2");
    lines.push_back("Oct 12 11:00:09 web-01 sshd[1]: Accepted password for root from 45.13.0.9 port 1 ssh2");
    lines.push_back("");
    lines.push_back("garbage that is not a log line {");
    // цепочка без правила-шага в тексте: шаг берётся из рабочих правил
    std::string chain = slurp(d.rules() + "/auth_bruteforce_success.yml");
    DryRun r = m.try_lines(chain, lines, "auto", 180);
    REQUIRE(r.ok);
    CHECK_EQ(r.tested_ids.size(), size_t(1));
    REQUIRE(r.helper_ids.size() == 1u);
    CHECK_EQ(r.helper_ids[0], std::string("AUTH-BRUTE-001"));
    CHECK_EQ(r.alerts_by_rule["AUTH-COMPROMISE-001"], uint64_t(1));
    CHECK_EQ(r.alerts_by_rule["AUTH-BRUTE-001"], uint64_t(1));
    CHECK_EQ(r.lines.size(), size_t(8));  // пустая строка пропущена
    CHECK(r.lines[6].alerts.size() == 1u);
    CHECK_EQ(r.alerts[r.lines[6].alerts[0]].rule_id, std::string("AUTH-COMPROMISE-001"));
    CHECK_EQ(r.distinct_ips, uint64_t(1));

    DryRun bad = m.try_lines("id: Q\nname: q\ntype: match\nwhere: {type: web}\npatterns: ['(x']\n", lines, "auto", 0);
    CHECK(!bad.ok);
    CHECK(!bad.error.empty());

    // на сохранённых событиях
    EventStore store;
    StoreOptions so;
    so.dir = d.path + "/data";
    so.fsync = false;
    REQUIRE(store.open(so, err));
    ParseContext ctx;
    ctx.now_ms = now_ms();
    std::vector<Event> evs;
    for (int i = 0; i < 3000; ++i) {
        Event ev;
        std::string line = std::to_string(i % 2 ? 203 : 198) + ".51.100." + std::to_string(i % 50) +
                           " - - [12/Oct/2026:10:00:00 +0000] \"GET " + (i % 10 == 0 ? "/q?id=1%20UNION%20SELECT%20pass" : "/ok") +
                           " HTTP/1.1\" 200 1 \"-\" \"Mozilla\"";
        REQUIRE(parse_line(line, LogFormat::Auto, ctx, ev));
        ev.ts = ctx.now_ms - 3600 * 1000 + i;  // час назад
        ev.id = uint64_t(i + 1);
        evs.push_back(std::move(ev));
    }
    for (size_t i = 0; i < evs.size(); i += 500) {
        std::vector<Event> b(evs.begin() + long(i), evs.begin() + long(i + 500));
        store.append(b);
    }
    store.flush();
    std::string sqli = slurp(d.rules() + "/web_sqli.yml");
    DryRun h = m.try_history(sqli, store, now_ms() - 2 * 3600 * 1000, now_ms(), 100000);
    REQUIRE(h.ok);
    CHECK_EQ(h.events, uint64_t(3000));
    CHECK(!h.truncated);
    CHECK(h.alerts_by_rule["WEB-SQLI-001"] > 0);
    CHECK(h.alerts.size() <= DryRun::kMaxSample);
    // предел событий: берутся самые свежие
    DryRun lim = m.try_history(sqli, store, now_ms() - 2 * 3600 * 1000, now_ms(), 1200);
    CHECK(lim.truncated);
    CHECK_EQ(lim.events, uint64_t(1200));
    // период без событий
    DryRun empty = m.try_history(sqli, store, now_ms() - 10 * 3600 * 1000, now_ms() - 5 * 3600 * 1000, 1000);
    CHECK(empty.ok);
    CHECK_EQ(empty.events, uint64_t(0));
    store.close();
}

TEST("api: rules editor endpoints, roles, new rule works on live traffic at once") {
    RTmp d;
    Config cfg;
    cfg.data_dir = d.path;
    cfg.keys_file = d.path + "/keys.yaml";
    std::string admin = "admin-secret-1234567890", reader = "reader-secret-1234567890",
                analyst = "analyst-secret-1234567890", ingest = "ingest-secret-1234567890";
    cfg.keys = {{"admin", Role::Admin, sha256_hex(admin)},
                {"viewer", Role::Read, sha256_hex(reader)},
                {"soc", Role::Analyst, sha256_hex(analyst)},
                {"web-01", Role::Ingest, sha256_hex(ingest)}};
    std::string err;
    EventStore events;
    AlertStore alerts;
    StoreOptions so;
    so.dir = d.path;
    so.fsync = false;
    REQUIRE(events.open(so, err));
    REQUIRE(alerts.open(d.path, so.retention_ms, err));
    LiveStats live;
    RuleManager mgr(d.rules(), d.path + "/rules-history");
    std::unique_ptr<DetectionEngine> first;
    mgr.set_apply([&](std::unique_ptr<DetectionEngine> e, const std::vector<Rule>&) { first = std::move(e); });
    REQUIRE(mgr.reload(err));
    Pipeline pipe(events, alerts, live, 100000);
    pipe.set_detect_threads(2);
    std::mutex mu;
    std::vector<std::string> fired;
    pipe.set_on_stored([&](const std::vector<Event>&, const std::vector<Alert>& al) {
        std::lock_guard<std::mutex> lock(mu);
        for (auto& a : al) fired.push_back(a.rule_id);
    });
    pipe.start(std::move(first));
    {
        Api api(cfg, events, alerts, live, pipe);
        api.set_rules(mgr.rules());
        api.set_rule_manager(&mgr);
        mgr.set_apply([&](std::unique_ptr<DetectionEngine> e, const std::vector<Rule>& r) {
            pipe.replace_engine(std::move(e));
            api.set_rules(r);
        });
        net::ServerOptions o;
        o.port = 0;
        o.workers = 2;
        net::HttpServer server(o, [&](const net::HttpRequest& rq, net::HttpResponse& rs) { api.handle(rq, rs); });
        REQUIRE(server.start(err));
        net::Url u;
        net::parse_url("http://127.0.0.1:" + std::to_string(server.port()), u, err);
        net::HttpClient c(u, {});
        auto call = [&](const std::string& method, const std::string& path, const std::string& key,
                        const std::string& body = "", const std::string& ctype = "application/json") {
            net::ClientResponse r;
            if (!c.request(method, path, {{"Authorization", "Bearer " + key}, {"Content-Type", ctype}}, body, r, err))
                r.status = -1;
            return r;
        };
        auto parse = [&](const net::ClientResponse& r) {
            JValue v;
            std::string e;
            json_parse(r.body, v, e);
            return v;
        };

        auto r = call("GET", "/api/v1/rules", reader);
        REQUIRE(r.status == 200);
        JValue v = parse(r);
        const size_t base = load_rules_dir(d.rules()).rules.size();
        CHECK_EQ(v.get("rules")->arr.size(), base);
        CHECK(v.get("editable")->b);
        CHECK(r.body.find("\"alerts_24h\"") != std::string::npos);

        r = call("GET", "/api/v1/rules/WEB-XSS-001", reader);
        REQUIRE(r.status == 200);
        v = parse(r);
        CHECK_EQ(v.get("file")->s, std::string("web_xss.yml"));
        CHECK(v.get("source")->s.find("id: WEB-XSS-001") == 0);
        r = call("GET", "/api/v1/rules/AUTH-BRUTE-001", reader);
        CHECK(r.body.find("\"used_by\":[\"AUTH-COMPROMISE-001\"]") != std::string::npos);
        CHECK_EQ(call("GET", "/api/v1/rules/NOPE", reader).status, 404);
        CHECK_EQ(call("GET", "/api/v1/rules/WEB-XSS-001", ingest).status, 403);

        // права
        std::string body = json_body({{"source", kNewRule}});
        CHECK_EQ(call("POST", "/api/v1/rules/check", reader, body).status, 403);
        CHECK_EQ(call("POST", "/api/v1/rules", analyst, body).status, 403);
        CHECK_EQ(call("PUT", "/api/v1/rules/WEB-XSS-001", analyst, body).status, 403);
        CHECK_EQ(call("DELETE", "/api/v1/rules/WEB-XSS-001", analyst).status, 403);

        r = call("POST", "/api/v1/rules/check", analyst, body);
        REQUIRE(r.status == 200);
        CHECK(parse(r).get("ok")->b);
        r = call("POST", "/api/v1/rules/check", analyst, json_body({{"source", "id: Z\nname: [x\n"}}));
        CHECK(!parse(r).get("ok")->b);

        // пробный запуск на строках
        r = call("POST", "/api/v1/rules/try", analyst,
                 json_body({{"source", kNewRule},
                            {"lines", "Oct 12 11:00:01 web-01 sshd[1]: Accepted password for root from 198.51.100.9 port 5000 ssh2\n"
                                      "Oct 12 11:00:02 web-01 sshd[1]: Accepted password for ivan from 198.51.100.9 port 5000 ssh2"}}));
        REQUIRE(r.status == 200);
        v = parse(r);
        CHECK(v.get("ok")->b);
        CHECK_EQ(v.get("alerts_total")->i, int64_t(1));
        CHECK_EQ(v.get("lines")->arr.size(), size_t(2));
        CHECK_EQ(v.get("lines")->arr[0].get("alerts")->arr.size(), size_t(1));
        CHECK_EQ(v.get("lines")->arr[1].get("event")->get("user")->s, std::string("ivan"));
        CHECK_EQ(v.get("tests")->get("cases")->i, int64_t(2));

        // создать: сразу работает на живом трафике
        r = call("POST", "/api/v1/rules", admin, body);
        REQUIRE(r.status == 201);
        CHECK_EQ(parse(r).get("file")->s, std::string("custom_root_login.yml"));
        CHECK_EQ(call("POST", "/api/v1/rules", admin, body).status, 422);  // такой id уже есть
        // время строки — «сейчас» (UTC), чтобы событие попало в «последние 48 часов» в любой день
        static const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
        std::string iso = format_iso8601(now_ms());  // 2026-10-14T11:02:33.582Z
        std::string stamp = std::string(months[std::stoi(iso.substr(5, 2)) - 1]) + " " + iso.substr(8, 2) + " " +
                            iso.substr(11, 8);
        r = call("POST", "/api/v1/ingest", ingest,
                 stamp + " web-01 sshd[1]: Accepted password for root from 198.51.100.77 port 5000 ssh2\n",
                 "text/plain");
        CHECK_EQ(r.status, 202);
        bool seen = false;
        for (int i = 0; i < 200 && !seen; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            std::lock_guard<std::mutex> lock(mu);
            for (auto& f : fired) seen |= f == "CUSTOM-ROOT-LOGIN";
        }
        CHECK(seen);

        // история на сохранённых событиях (то самое событие)
        r = call("POST", "/api/v1/rules/try-history", analyst, R"({"source":"id: T\nname: t\ntype: match\nwhere: {type: auth}\n","hours":48})");
        REQUIRE(r.status == 200);
        v = parse(r);
        CHECK(v.get("ok")->b);
        CHECK(v.get("events")->i >= 1);

        // правка, ошибка, выключение, история
        std::string changed = kNewRule;
        changed.replace(changed.find("severity: medium"), 16, "severity: high");
        r = call("PUT", "/api/v1/rules/CUSTOM-ROOT-LOGIN", admin, json_body({{"source", changed}}));
        CHECK_EQ(r.status, 200);
        r = call("PUT", "/api/v1/rules/CUSTOM-ROOT-LOGIN", admin, json_body({{"source", "id: CUSTOM-ROOT-LOGIN\nname: [x\n"}}));
        CHECK_EQ(r.status, 422);
        CHECK(!parse(r).get("error")->s.empty());
        CHECK_EQ(call("POST", "/api/v1/rules/AUTH-BRUTE-001/enabled", admin, R"({"enabled":false})").status, 422);
        CHECK_EQ(call("POST", "/api/v1/rules/WEB-XSS-001/enabled", admin, R"({"enabled":false})").status, 200);
        r = call("GET", "/api/v1/rules", reader);
        CHECK(r.body.find("\"id\":\"WEB-XSS-001\"") != std::string::npos);
        v = parse(r);
        for (auto& x : v.get("rules")->arr)
            if (x.get("id")->s == "WEB-XSS-001") CHECK(!x.get("enabled")->b);
        r = call("GET", "/api/v1/rules/CUSTOM-ROOT-LOGIN/history", reader);
        REQUIRE(r.status == 200);
        v = parse(r);
        REQUIRE(v.get("versions")->arr.size() == 2u);  // create + update
        std::string ver = v.get("versions")->arr[1].get("version")->s;
        r = call("GET", "/api/v1/rules/CUSTOM-ROOT-LOGIN/history/" + ver, reader);
        CHECK_EQ(parse(r).get("source")->s, std::string(kNewRule));
        CHECK_EQ(call("GET", "/api/v1/rules/CUSTOM-ROOT-LOGIN/history/..%2F..%2Fkeys.yaml", reader).status, 404);

        CHECK_EQ(call("DELETE", "/api/v1/rules/CUSTOM-ROOT-LOGIN", admin).status, 200);
        CHECK_EQ(call("DELETE", "/api/v1/rules/CUSTOM-ROOT-LOGIN", admin).status, 404);
        CHECK_EQ(parse(call("GET", "/api/v1/rules", reader)).get("rules")->arr.size(), base);
        server.stop();
    }
    pipe.stop();
    events.close();
    alerts.close();
}
