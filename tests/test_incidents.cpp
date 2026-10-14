// Тесты этапа 6Б: инциденты — группировка, статусы, заметки, объединение, журнал, уведомления, API.
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

#include "core/crypto.hpp"
#include "core/json.hpp"
#include "core/util.hpp"
#include "detect/engine.hpp"
#include "detect/rules.hpp"
#include "net/client.hpp"
#include "net/server.hpp"
#include "server/api.hpp"
#include "server/config.hpp"
#include "server/notifier.hpp"
#include "store/incident_store.hpp"
#include "testing.hpp"

using namespace sentinel;
namespace fs = std::filesystem;

namespace {

struct TmpDir {
    std::string path;
    TmpDir() {
        path = (fs::temp_directory_path() / ("sentinel-inc-" + random_hex(6))).string();
        fs::create_directories(path);
    }
    ~TmpDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

Alert alert_at(uint64_t id, const std::string& rule, Severity sev, const std::string& ip, int64_t t,
               const std::string& user = "", const std::string& host = "web-01") {
    Alert a;
    a.id = id;
    a.rule_id = rule;
    a.rule_name = "Правило " + rule;
    a.severity = sev;
    a.src_ip = ip;
    a.user = user;
    a.host = host;
    a.message = "Атака с " + ip;
    a.ts = a.created = t;
    return a;
}

}  // namespace

TEST("incidents: grouping by IP, window, user without IP, severity, notices") {
    TmpDir d;
    IncidentStore s;
    std::string err;
    REQUIRE(s.open(d.path, 90LL * 86400000, err));
    s.set_window(3600000);
    const int64_t t0 = now_ms() - 5 * 3600000;

    auto n = s.on_alerts({alert_at(1, "WEB-SCAN", Severity::Medium, "45.1.1.1", t0),
                          alert_at(2, "WEB-SQLI", Severity::High, "45.1.1.1", t0 + 60000),
                          alert_at(3, "AUTH-BRUTE", Severity::High, "45.2.2.2", t0 + 1000)});
    REQUIRE(n.size() == 2);
    CHECK(n[0].is_new);
    CHECK(!n[0].escalated);
    CHECK_EQ(n[0].alert_count, 2u);
    CHECK(n[0].severity == Severity::High);
    CHECK_EQ(n[0].alert.id, 2u);  // последний алерт
    CHECK(n[0].title.find("Правило WEB-SQLI и ещё 1") != std::string::npos);
    CHECK(n[0].title.find("45.1.1.1") != std::string::npos);
    const uint64_t a = n[0].id, b = n[1].id;
    CHECK(a != b);
    CHECK_EQ(s.incident_of_alert(1), a);
    CHECK_EQ(s.incident_of_alert(3), b);

    // тот же IP через 30 минут — тот же инцидент; рост важности -> escalated
    n = s.on_alerts({alert_at(4, "WEB-RCE", Severity::Critical, "45.1.1.1", t0 + 31 * 60000)});
    REQUIRE(n.size() == 1);
    CHECK_EQ(n[0].id, a);
    CHECK(!n[0].is_new);
    CHECK(n[0].escalated);
    // ещё один того же уровня — без повышения
    n = s.on_alerts({alert_at(5, "WEB-RCE", Severity::Critical, "45.1.1.1", t0 + 40 * 60000)});
    REQUIRE(n.size() == 1);
    CHECK(!n[0].escalated);
    CHECK(!n[0].is_new);

    // атака затихла дольше окна — новый инцидент
    n = s.on_alerts({alert_at(6, "WEB-SCAN", Severity::Low, "45.1.1.1", t0 + 40 * 60000 + 3600000 + 1)});
    REQUIRE(n.size() == 1);
    CHECK(n[0].is_new);
    CHECK(n[0].id != a);

    // без IP — по пользователю на сервере; без пользователя — по правилу на сервере
    n = s.on_alerts({alert_at(7, "AUTH-SUDO", Severity::Medium, "", t0, "ivan", "db-01"),
                     alert_at(8, "AUTH-SUDO2", Severity::Medium, "", t0 + 1, "ivan", "db-01"),
                     alert_at(9, "AUTH-SUDO", Severity::Medium, "", t0 + 2, "ivan", "web-01"),
                     alert_at(10, "FIM-001", Severity::High, "", t0, "", "db-01")});
    REQUIRE(n.size() == 3);
    CHECK_EQ(n[0].alert_count, 2u);

    auto inc = s.get(a);
    REQUIRE(inc.has_value());
    CHECK_EQ(inc->alert_count, 4u);
    CHECK(inc->severity == Severity::Critical);
    CHECK_EQ(inc->rules.size(), size_t(3));
    CHECK_EQ(inc->rules[0].rule_id, std::string("WEB-SCAN"));
    CHECK_EQ(inc->key, std::string("ip:45.1.1.1"));
    CHECK_EQ(inc->first_alert, t0);
    CHECK_EQ(inc->last_alert, t0 + 40 * 60000);
    CHECK(inc->active());

    auto c = s.counts();
    CHECK_EQ(c.active, 6u);
    CHECK_EQ(c.unassigned, 6u);
    CHECK_EQ(c.by_severity[size_t(Severity::Critical)], 1u);
    // алерт без номера пропускается
    CHECK(s.on_alerts({alert_at(0, "X", Severity::High, "1.1.1.1", t0)}).empty());
}

TEST("incidents: status, assign, notes, merge, list filters; survive restart; damaged tail") {
    TmpDir d;
    std::string err;
    const int64_t t0 = now_ms() - 3600000;
    uint64_t a = 0, b = 0, c = 0;
    {
        IncidentStore s;
        REQUIRE(s.open(d.path, 90LL * 86400000, err));
        auto n = s.on_alerts({alert_at(1, "WEB-SQLI", Severity::High, "45.1.1.1", t0),
                              alert_at(2, "AUTH-BRUTE", Severity::Medium, "45.2.2.2", t0),
                              alert_at(3, "WEB-XSS", Severity::Low, "45.3.3.3", t0)});
        REQUIRE(n.size() == 3);
        a = n[0].id, b = n[1].id, c = n[2].id;

        CHECK(s.assign(a, "ivan", "ivan", err));
        CHECK(s.set_status(a, IncidentStatus::InProgress, "ivan", err));
        CHECK(s.add_note(a, "ivan", "Смотрю логи nginx", err));
        CHECK(s.add_note(a, "olga", "Это сканер из списка FireHOL", err));
        CHECK(!s.add_note(999, "x", "y", err));
        CHECK_EQ(err, std::string("incident not found"));

        // объединение: b -> a
        CHECK(!s.merge(a, a, "ivan", err));
        CHECK(s.merge(b, a, "ivan", err));
        CHECK(!s.merge(b, c, "ivan", err));  // уже объединён
        CHECK(!s.set_status(b, IncidentStatus::Open, "ivan", err));  // объединённый не открыть
        CHECK_EQ(s.incident_of_alert(2), a);

        CHECK(s.set_status(c, IncidentStatus::FalsePositive, "olga", err));

        IncidentQuery q;
        q.active_only = true;
        auto l = s.list(q);
        REQUIRE(l.size() == 1);
        CHECK_EQ(l[0].id, a);
        q = {};
        q.assignee = "-";
        CHECK_EQ(s.list(q).size(), size_t(2));
        q = {};
        q.text = "brute";
        l = s.list(q);
        CHECK_EQ(l.size(), size_t(2));  // сам b и a, в который он влит
        q = {};
        q.status = IncidentStatus::FalsePositive;
        CHECK_EQ(s.list(q).size(), size_t(1));
        q = {};
        q.min_severity = Severity::High;
        CHECK_EQ(s.list(q).size(), size_t(1));
        q = {};
        q.limit = 2;
        l = s.list(q);
        REQUIRE(l.size() == 2);
        CHECK_EQ(l[0].id, c);  // новые первыми
        q.before_id = l[1].id;
        CHECK_EQ(s.list(q).size(), size_t(1));
        s.close();
    }
    auto check_state = [&](IncidentStore& s) {
        auto ia = s.get(a);
        REQUIRE(ia.has_value());
        CHECK_EQ(ia->assignee, std::string("ivan"));
        CHECK(ia->status == IncidentStatus::InProgress);
        REQUIRE(ia->notes.size() == 2);
        CHECK_EQ(ia->notes[1].by, std::string("olga"));
        CHECK_EQ(ia->alert_count, 2u);
        CHECK_EQ(ia->rules.size(), size_t(2));
        CHECK(ia->history.size() >= 3);
        CHECK_EQ(ia->history.back().kind, std::string("merged_from"));
        auto ib = s.get(b);
        REQUIRE(ib.has_value());
        CHECK_EQ(ib->merged_into, a);
        CHECK(!ib->active());
        CHECK_EQ(s.incident_of_alert(2), a);
        CHECK(s.get(c)->status == IncidentStatus::FalsePositive);
    };
    {
        IncidentStore s;
        REQUIRE(s.open(d.path, 90LL * 86400000, err));
        check_state(s);
        // новый алерт с адреса a — в тот же активный инцидент; с адреса b (влит в a) — тоже в a
        auto n = s.on_alerts({alert_at(4, "WEB-SQLI", Severity::High, "45.1.1.1", t0 + 60000)});
        REQUIRE(n.size() == 1);
        CHECK_EQ(n[0].id, a);
        s.close();
    }
    // повреждённый хвост журнала отрезается, остальное цело
    {
        std::ofstream f(d.path + "/incidents.log", std::ios::app | std::ios::binary);
        f << "\x10\x00\x00\x00garbage";
    }
    {
        IncidentStore s;
        REQUIRE(s.open(d.path, 90LL * 86400000, err));
        auto ia = s.get(a);
        REQUIRE(ia.has_value());
        CHECK_EQ(ia->alert_count, 3u);
        auto n = s.on_alerts({alert_at(5, "NEW", Severity::Low, "45.9.9.9", t0)});
        REQUIRE(n.size() == 1);
        CHECK(n[0].id > c);  // номера не повторяются
        s.close();
    }
    // после сжатия (срок хранения короткий) старые удаляются, а состояние переживает снимок
    {
        IncidentStore s;
        REQUIRE(s.open(d.path, 90LL * 86400000, err));
        s.maintain();
        s.close();
        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        IncidentStore s2;
        REQUIRE(s2.open(d.path, 1000, err));  // всё старше секунды — удалить
        CHECK(s2.list({}).empty());
        CHECK_EQ(s2.incident_of_alert(1), 0u);
    }
}

TEST("incidents: compaction to snapshots keeps everything") {
    TmpDir d;
    std::string err;
    const int64_t t0 = now_ms() - 3600000;
    {
        IncidentStore s;
        REQUIRE(s.open(d.path, 90LL * 86400000, err));
        // много мелких записей про один инцидент -> сжатие при следующем открытии
        uint64_t id = 0;
        for (uint64_t i = 1; i <= 1500; ++i) {
            auto n = s.on_alerts({alert_at(i, "R" + std::to_string(i % 7), Severity(i % 5), "45.1.1.1", t0 + int64_t(i))});
            id = n[0].id;
        }
        CHECK(s.add_note(id, "ivan", "проверка снимка", err));
        CHECK(s.assign(id, "ivan", "ivan", err));
        s.close();
    }
    auto size_before = fs::file_size(d.path + "/incidents.log");
    IncidentStore s;
    REQUIRE(s.open(d.path, 90LL * 86400000, err));
    CHECK(fs::file_size(d.path + "/incidents.log") < size_before);
    auto l = s.list({});
    REQUIRE(l.size() == 1);
    CHECK_EQ(l[0].alert_count, 1500u);
    CHECK_EQ(l[0].rules.size(), size_t(7));
    CHECK(l[0].severity == Severity::Critical);
    CHECK_EQ(l[0].notes.size(), size_t(1));
    CHECK_EQ(l[0].assignee, std::string("ivan"));
    CHECK_EQ(s.incident_of_alert(1500), l[0].id);
    CHECK_EQ(s.incident_of_alert(1), l[0].id);
    // после снимка журнал дописывается дальше
    auto n = s.on_alerts({alert_at(2000, "R1", Severity::Low, "45.1.1.1", t0 + 5000)});
    CHECK_EQ(n[0].id, l[0].id);
    s.close();
    IncidentStore s2;
    REQUIRE(s2.open(d.path, 90LL * 86400000, err));
    CHECK_EQ(s2.get(l[0].id)->alert_count, 1501u);
}

TEST("incidents: notification texts and incident mode filtering") {
    NotifyConfig c;
    c.panel_url = "https://siem.example.com";
    c.mode = "incidents";
    Notifier n(c);
    Notifier::Item it;
    it.alert = alert_at(42, "WEB-SQLI", Severity::Critical, "203.0.113.5", now_ms());
    it.incident_id = 7;
    it.incident_title = "Правило WEB-SQLI и ещё 2 · 203.0.113.5";
    it.incident_severity = Severity::Critical;
    it.incident_alerts = 12;
    it.incident_new = true;
    std::string text = n.format_text(it, false);
    CHECK(text.find("Новый инцидент #7") != std::string::npos);
    CHECK(text.find("Алертов в инциденте: 12") != std::string::npos);
    CHECK(text.find("https://siem.example.com/incidents/7") != std::string::npos);
    CHECK(n.subject(it).find("Новый инцидент #7 (Критический)") != std::string::npos);
    it.incident_new = false;
    CHECK(n.subject(it).find("стал серьёзнее #7") != std::string::npos);
    std::vector<Notifier::Item> many(5, it);
    for (size_t i = 0; i < many.size(); ++i) many[i].incident_id = 10 + i;
    std::string dg = n.format_digest(many, false);
    CHECK(dg.find("инцидентов: 5") != std::string::npos);
    CHECK(dg.find("#12 ") != std::string::npos);
    CHECK(dg.find("https://siem.example.com/incidents") != std::string::npos);
    CHECK_EQ(n.digest_subject(many), std::string("[Sentinel] Инцидентов: 5"));

    std::string err;
    Config cfg;
    {
        std::string path = (fs::temp_directory_path() / ("sentinel-inc-cfg-" + random_hex(4) + ".yaml")).string();
        std::ofstream(path) << "notify:\n  mode: incidents\nincidents:\n  window: 30m\n";
        CHECK(load_config(path, cfg, err));
        CHECK(cfg.notify.incidents());
        CHECK_EQ(cfg.incident_window_ms, int64_t(30 * 60000));
        std::ofstream(path) << "notify:\n  mode: sometimes\n";
        Config bad;
        CHECK(!load_config(path, bad, err));
        std::ofstream(path) << "incidents:\n  window: 5s\n";
        Config bad2;
        CHECK(!load_config(path, bad2, err));
        fs::remove(path);
    }
}

TEST("api: incidents list, card, status closes alerts, assign me, notes, merge, roles") {
    TmpDir d;
    Config cfg;
    cfg.data_dir = d.path;
    cfg.keys_file = d.path + "/keys.yaml";
    std::string reader = "reader-secret-1234567890", analyst = "analyst-secret-1234567890";
    cfg.keys = {{"viewer", Role::Read, sha256_hex(reader)}, {"soc", Role::Analyst, sha256_hex(analyst)}};
    std::string err;
    EventStore events;
    AlertStore alerts;
    StoreOptions so;
    so.dir = d.path;
    so.fsync = false;
    REQUIRE(events.open(so, err));
    REQUIRE(alerts.open(d.path, so.retention_ms, err));
    IncidentStore incidents;
    REQUIRE(incidents.open(d.path, so.retention_ms, err));
    LiveStats live;
    BlockList blocks;
    REQUIRE(blocks.open(d.path + "/blocks.json", err));
    std::vector<Alert> al = {alert_at(0, "WEB-SQLI", Severity::High, "45.1.1.1", now_ms()),
                             alert_at(0, "WEB-XSS", Severity::Medium, "45.1.1.1", now_ms()),
                             alert_at(0, "AUTH-BRUTE", Severity::Critical, "45.2.2.2", now_ms())};
    alerts.add(al);
    auto notices = incidents.on_alerts(al);
    REQUIRE(notices.size() == 2);
    const uint64_t a = notices[0].id, b = notices[1].id;
    Pipeline pipe(events, alerts, live, 1000);
    {
        Api api(cfg, events, alerts, live, pipe);
        api.set_response(&blocks, nullptr);
        api.set_incidents(&incidents);
        net::ServerOptions o;
        o.port = 0;
        o.workers = 2;
        net::HttpServer server(o, [&](const net::HttpRequest& rq, net::HttpResponse& rs) { api.handle(rq, rs); });
        REQUIRE(server.start(err));
        net::Url u;
        net::parse_url("http://127.0.0.1:" + std::to_string(server.port()), u, err);
        net::HttpClient c(u, {});
        auto call = [&](const std::string& method, const std::string& path, const std::string& key,
                        const std::string& body = "") {
            net::ClientResponse r;
            std::vector<std::pair<std::string, std::string>> h = {{"Authorization", "Bearer " + key},
                                                                  {"Content-Type", "application/json"}};
            if (!c.request(method, path, h, body, r, err)) r.status = -1;
            return r;
        };
        auto json = [&](const net::ClientResponse& r) {
            JValue v;
            std::string e;
            json_parse(r.body, v, e);
            return v;
        };

        auto r = call("GET", "/api/v1/incidents?active=1", reader);
        REQUIRE(r.status == 200);
        JValue v = json(r);
        REQUIRE(v.get("incidents") && v.get("incidents")->arr.size() == 2);
        CHECK_EQ(v.get("active")->i, 2);
        CHECK_EQ(v.get("incidents")->arr[0].get("id")->i, int64_t(b));
        CHECK_EQ(v.get("incidents")->arr[1].get("alert_count")->i, 2);
        CHECK_EQ(call("GET", "/api/v1/incidents?status=maybe", reader).status, 400);
        CHECK_EQ(call("GET", "/api/v1/incidents?q=brute", reader).status, 200);
        CHECK_EQ(json(call("GET", "/api/v1/incidents?q=brute", reader)).get("incidents")->arr.size(), size_t(1));

        r = call("GET", "/api/v1/incidents/" + std::to_string(a), reader);
        REQUIRE(r.status == 200);
        v = json(r);
        REQUIRE(v.get("alerts"));
        CHECK_EQ(v.get("alerts")->arr.size(), size_t(2));
        CHECK_EQ(v.get("alerts")->arr[0].get("incident_id")->i, int64_t(a));
        CHECK_EQ(v.get("ip")->get("ip")->s, std::string("45.1.1.1"));
        CHECK(v.get("ip")->get("block")->is_null());
        CHECK_EQ(call("GET", "/api/v1/incidents/999", reader).status, 404);
        CHECK_EQ(call("GET", "/api/v1/incidents/abc", reader).status, 400);

        // алерт знает свой инцидент
        v = json(call("GET", "/api/v1/alerts/" + std::to_string(al[0].id), reader));
        CHECK_EQ(v.get("alert")->get("incident_id")->i, int64_t(a));

        // читатель не меняет
        CHECK_EQ(call("POST", "/api/v1/incidents/" + std::to_string(a) + "/assign", reader, R"({"assignee":"me"})").status,
                 403);
        r = call("POST", "/api/v1/incidents/" + std::to_string(a) + "/assign", analyst, R"({"assignee":"me"})");
        REQUIRE(r.status == 200);
        CHECK_EQ(json(r).get("incident")->get("assignee")->s, std::string("soc"));
        CHECK_EQ(call("POST", "/api/v1/incidents/" + std::to_string(a) + "/assign", analyst, R"({"assignee":"a b"})").status,
                 400);
        r = call("POST", "/api/v1/incidents/" + std::to_string(a) + "/notes", analyst, R"({"text":"  блокирую  "})");
        REQUIRE(r.status == 200);
        v = json(r);
        REQUIRE(v.get("incident")->get("notes")->arr.size() == 1);
        CHECK_EQ(v.get("incident")->get("notes")->arr[0].get("text")->s, std::string("блокирую"));
        CHECK_EQ(call("POST", "/api/v1/incidents/" + std::to_string(a) + "/notes", analyst, R"({"text":""})").status, 400);

        // «в работе» -> алерты «приняты»; «решён» -> алерты «решены»
        r = call("POST", "/api/v1/incidents/" + std::to_string(a) + "/status", analyst, R"({"status":"in_progress"})");
        REQUIRE(r.status == 200);
        CHECK_EQ(json(r).get("alerts_changed")->i, 2);
        CHECK(alerts.get(al[0].id)->status == AlertStatus::Acknowledged);
        r = call("POST", "/api/v1/incidents/" + std::to_string(a) + "/status", analyst,
                 R"({"status":"resolved","close_alerts":false})");
        REQUIRE(r.status == 200);
        CHECK_EQ(json(r).get("alerts_changed")->i, 0);
        CHECK(alerts.get(al[0].id)->status == AlertStatus::Acknowledged);
        r = call("POST", "/api/v1/incidents/" + std::to_string(a) + "/status", analyst, R"({"status":"resolved"})");
        CHECK_EQ(json(r).get("alerts_changed")->i, 2);
        CHECK(alerts.get(al[1].id)->status == AlertStatus::Resolved);
        CHECK_EQ(call("POST", "/api/v1/incidents/" + std::to_string(a) + "/status", analyst, R"({"status":"x"})").status, 400);

        // объединение
        CHECK_EQ(call("POST", "/api/v1/incidents/" + std::to_string(b) + "/merge", analyst, R"({"into":0})").status, 400);
        CHECK_EQ(call("POST", "/api/v1/incidents/" + std::to_string(b) + "/merge", analyst,
                      R"({"into":)" + std::to_string(b) + "}")
                     .status,
                 409);
        r = call("POST", "/api/v1/incidents/" + std::to_string(b) + "/merge", analyst, R"({"into":)" + std::to_string(a) + "}");
        REQUIRE(r.status == 200);
        CHECK_EQ(json(r).get("incident")->get("merged_into")->i, int64_t(a));
        v = json(call("GET", "/api/v1/incidents/" + std::to_string(a), reader));
        CHECK_EQ(v.get("incident")->get("alert_count")->i, 3);
        CHECK_EQ(v.get("alerts")->arr.size(), size_t(3));
        CHECK_EQ(call("POST", "/api/v1/incidents/" + std::to_string(a) + "/fly", analyst, "{}").status, 404);

        // счётчики в статистике
        v = json(call("GET", "/api/v1/stats", reader));
        REQUIRE(v.get("incidents"));
        CHECK_EQ(v.get("incidents")->get("active")->i, 0);
        server.stop();
    }
    pipe.stop();
}

TEST("incidents: speed of grouping a burst of alerts") {
    TmpDir d;
    IncidentStore s;
    std::string err;
    REQUIRE(s.open(d.path, 90LL * 86400000, err));
    const int64_t t0 = now_ms() - 3600000;
    std::vector<Alert> batch;
    uint64_t id = 1;
    auto start = std::chrono::steady_clock::now();
    for (int b = 0; b < 100; ++b) {
        batch.clear();
        for (int i = 0; i < 1000; ++i, ++id)
            batch.push_back(alert_at(id, "R" + std::to_string(i % 13), Severity(i % 5), "45.0." + std::to_string(i % 200) + ".1",
                                     t0 + int64_t(id)));
        s.on_alerts(batch);
    }
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    std::cout << "    incidents: 100000 alerts grouped in " << int(ms) << " ms (" << int(100000 / (ms / 1000)) << "/s)\n";
    CHECK_EQ(s.list({}).size(), size_t(50));  // по умолчанию limit 50
    CHECK_EQ(s.counts().active, 200u);
    CHECK_EQ(s.incident_of_alert(100000), s.incident_of_alert(100000 - 1000));
    s.close();
    IncidentStore s2;
    REQUIRE(s2.open(d.path, 90LL * 86400000, err));
    CHECK_EQ(s2.counts().active, 200u);
}
