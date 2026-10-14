// Тесты этапа 6В: отдача файлов частями, выгрузка CSV/JSON, отчёт за период, письмо с отчётом.
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "core/crypto.hpp"
#include "core/json.hpp"
#include "core/util.hpp"
#include "net/client.hpp"
#include "net/server.hpp"
#include "net/smtp.hpp"
#include "server/api.hpp"
#include "server/config.hpp"
#include "server/report.hpp"
#include "testing.hpp"

using namespace sentinel;
namespace fs = std::filesystem;

namespace {

struct TmpDir {
    std::string path;
    TmpDir() {
        path = (fs::temp_directory_path() / ("sentinel-rep-" + random_hex(6))).string();
        fs::create_directories(path);
    }
    ~TmpDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

std::string b64dec(std::string_view s) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    uint32_t acc = 0;
    int bits = 0;
    for (char c : s) {
        auto p = chars.find(c);
        if (p == std::string::npos) continue;
        acc = (acc << 6) | uint32_t(p);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(char((acc >> bits) & 0xFF));
        }
    }
    return out;
}

// Простейший CSV-разбор (кавычки, "" внутри) — для проверки выгрузки.
std::vector<std::vector<std::string>> parse_csv(std::string_view text, char sep) {
    std::vector<std::vector<std::string>> rows(1);
    std::string cell;
    bool q = false;
    for (size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        if (q) {
            if (c == '"' && i + 1 < text.size() && text[i + 1] == '"') {
                cell.push_back('"');
                ++i;
            } else if (c == '"') {
                q = false;
            } else {
                cell.push_back(c);
            }
        } else if (c == '"') {
            q = true;
        } else if (c == sep) {
            rows.back().push_back(cell);
            cell.clear();
        } else if (c == '\r') {
        } else if (c == '\n') {
            rows.back().push_back(cell);
            cell.clear();
            rows.emplace_back();
        } else {
            cell.push_back(c);
        }
    }
    if (rows.back().empty()) rows.pop_back();
    return rows;
}

}  // namespace

TEST("http: file body is streamed in parts, removed after sending, keep-alive and pipelining continue") {
    TmpDir d;
    std::string big(3 * 1024 * 1024 + 123, '\0');
    for (size_t i = 0; i < big.size(); ++i) big[i] = char('a' + (i * 7 + i / 1000) % 26);
    std::atomic<int> made{0};
    net::ServerOptions o;
    o.port = 0;
    o.workers = 1;
    net::HttpServer server(o, [&](const net::HttpRequest& rq, net::HttpResponse& rs) {
        if (rq.path == "/big") {
            std::string p = d.path + "/f" + std::to_string(made.fetch_add(1)) + ".tmp";
            std::ofstream(p, std::ios::binary) << big;
            rs.content_type = "text/plain";
            rs.send_file(p, big.size(), true);
        } else if (rq.path == "/empty") {
            std::string p = d.path + "/empty.tmp";
            std::ofstream(p, std::ios::binary).flush();
            rs.send_file(p, 0, true);
        } else if (rq.path == "/missing") {
            rs.send_file(d.path + "/nope", 10, false);
        } else {
            rs.body = "small:" + rq.path;
        }
    });
    std::string err;
    REQUIRE(server.start(err));
    net::Url u;
    net::parse_url("http://127.0.0.1:" + std::to_string(server.port()), u, err);
    net::HttpClient c(u, {});
    c.set_max_response(16u << 20);
    for (int k = 0; k < 2; ++k) {  // два раза подряд по одному соединению
        net::ClientResponse r;
        REQUIRE(c.request("GET", "/big", {}, "", r, err));
        CHECK_EQ(r.status, 200);
        CHECK_EQ(r.body.size(), big.size());
        CHECK(r.body == big);
        net::ClientResponse s;
        REQUIRE(c.request("GET", "/after", {}, "", s, err));
        CHECK_EQ(s.body, std::string("small:/after"));
    }
    net::ClientResponse r;
    REQUIRE(c.request("GET", "/empty", {}, "", r, err));
    CHECK_EQ(r.status, 200);
    CHECK(r.body.empty());
    REQUIRE(c.request("GET", "/missing", {}, "", r, err));
    CHECK_EQ(r.status, 500);
    // временные файлы удалены
    for (int i = 0; i < 50 && fs::exists(d.path + "/f1.tmp"); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    CHECK(!fs::exists(d.path + "/f0.tmp"));
    CHECK(!fs::exists(d.path + "/f1.tmp"));
    CHECK(!fs::exists(d.path + "/empty.tmp"));

#ifndef _WIN32
    // конвейер: три запроса одним куском — ответы по порядку, файл посередине
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(server.port());
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
    std::string reqs = "GET /one HTTP/1.1\r\nHost: x\r\n\r\nGET /big HTTP/1.1\r\nHost: x\r\n\r\n"
                       "GET /two HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    REQUIRE(::send(s, reqs.data(), reqs.size(), 0) == ssize_t(reqs.size()));
    std::string all;
    char buf[65536];
    while (true) {
        ssize_t k = ::recv(s, buf, sizeof(buf), 0);
        if (k <= 0) break;
        all.append(buf, size_t(k));
    }
    ::close(s);
    size_t p1 = all.find("small:/one"), pb = all.find(big.substr(0, 4096)), p2 = all.find("small:/two");
    CHECK(p1 != std::string::npos);
    CHECK(pb != std::string::npos);
    CHECK(p2 != std::string::npos);
    CHECK(p1 < pb && pb < p2);
    CHECK(all.find(big) != std::string::npos);
#endif
    server.stop();
}

TEST("api: export events, alerts and incidents as CSV, Excel CSV, JSON and NDJSON") {
    TmpDir d;
    Config cfg;
    cfg.data_dir = d.path;
    cfg.keys_file = d.path + "/keys.yaml";
    std::string reader = "reader-secret-1234567890", ingest = "ingest-secret-1234567890";
    cfg.keys = {{"viewer", Role::Read, sha256_hex(reader)}, {"agent", Role::Ingest, sha256_hex(ingest)}};
    std::string err;
    EventStore events;
    StoreOptions so;
    so.dir = d.path;
    so.fsync = false;
    so.compress_threads = 0;
    REQUIRE(events.open(so, err));
    const int64_t t0 = now_ms() - 3600000;
    std::vector<Event> batch;
    for (int i = 0; i < 2500; ++i) {
        Event e;
        e.ts = e.received = t0 + i;
        e[Field::Source] = "nginx";
        e[Field::SrcIp] = i % 2 ? "203.0.113.7" : "198.51.100.9";
        e[Field::HttpPath] = "/p" + std::to_string(i);
        e[Field::User] = i == 7 ? "=HYPERLINK(\"http://evil\")" : "ivan";
        e[Field::Message] = i == 9 ? "строка с \"кавычками\", запятой; и\nпереводом" : "GET /p" + std::to_string(i);
        e[Field::Raw] = "raw line " + std::to_string(i);
        if (i % 2) e.extra_set("geo.country", "DE");
        batch.push_back(std::move(e));
    }
    events.append(batch);
    events.flush();
    AlertStore alerts;
    REQUIRE(alerts.open(d.path, so.retention_ms, err));
    std::vector<Alert> al;
    for (int i = 0; i < 5; ++i) {
        Alert a;
        a.rule_id = "R" + std::to_string(i);
        a.rule_name = "Правило " + std::to_string(i);
        a.severity = Severity(i);
        a.src_ip = "203.0.113.7";
        a.message = "m" + std::to_string(i);
        a.ts = a.created = t0 + i;
        al.push_back(a);
    }
    alerts.add(al);
    IncidentStore incidents;
    REQUIRE(incidents.open(d.path, so.retention_ms, err));
    incidents.on_alerts(al);
    LiveStats live;
    Pipeline pipe(events, alerts, live, 1000);
    {
        Api api(cfg, events, alerts, live, pipe);
        api.set_incidents(&incidents);
        net::ServerOptions o;
        o.port = 0;
        o.workers = 2;
        net::HttpServer server(o, [&](const net::HttpRequest& rq, net::HttpResponse& rs) { api.handle(rq, rs); });
        REQUIRE(server.start(err));
        net::Url u;
        net::parse_url("http://127.0.0.1:" + std::to_string(server.port()), u, err);
        net::HttpClient c(u, {});
        c.set_max_response(64u << 20);
        auto call = [&](const std::string& path, const std::string& key = "reader-secret-1234567890") {
            net::ClientResponse r;
            if (!c.request("GET", path, {{"Authorization", "Bearer " + key}}, "", r, err)) r.status = -1;
            return r;
        };
        auto header = [](const net::ClientResponse& r, const std::string& name) {
            for (auto& h : r.headers)
                if (iequals(h.first, name)) return h.second;
            return std::string();
        };

        auto r = call("/api/v1/export/events?src_ip=203.0.113.7");
        REQUIRE(r.status == 200);
        CHECK(header(r, "Content-Type").find("text/csv") != std::string::npos);
        CHECK(header(r, "Content-Disposition").find("sentinel-events-") != std::string::npos);
        CHECK_EQ(header(r, "X-Export-Rows"), std::string("1250"));
        auto rows = parse_csv(r.body, ',');
        REQUIRE(rows.size() == 1251);
        CHECK_EQ(rows[0][0], std::string("id"));
        CHECK_EQ(rows[0].size(), size_t(24));
        CHECK_EQ(rows[1][7], std::string("203.0.113.7"));
        CHECK_EQ(rows[1][20], std::string("DE"));  // geo.country
        // формула обезврежена, кавычки и перевод строки сохранены
        bool found_formula = false, found_quote = false;
        for (auto& row : rows) {
            if (row.size() > 12 && row[12] == "'=HYPERLINK(\"http://evil\")") found_formula = true;
            if (row.size() > 23 && row[23] == "строка с \"кавычками\", запятой; и\nпереводом") found_quote = true;
        }
        CHECK(found_formula);
        rows = parse_csv(call("/api/v1/export/events?limit=10&format=excel").body, ';');
        REQUIRE(rows.size() == 11);
        CHECK(starts_with(rows[0][0], "\xEF\xBB\xBF"));  // BOM для Excel
        // время по местному поясу
        r = call("/api/v1/export/events?limit=1&tz=180");
        rows = parse_csv(r.body, ',');
        REQUIRE(rows.size() == 2);
        CHECK_EQ(rows[1][1].size(), size_t(19));
        CHECK_EQ(rows[1][1][10], ' ');
        CHECK_EQ(call("/api/v1/export/events?limit=3").body.find("raw line"), std::string::npos);
        CHECK(call("/api/v1/export/events?limit=3&raw=1").body.find("raw line") != std::string::npos);
        // все события, на найденной ячейке с переводом строки
        rows = parse_csv(call("/api/v1/export/events?limit=100000").body, ',');
        CHECK_EQ(rows.size(), size_t(2501));
        for (auto& row : rows)
            if (row.size() > 23 && row[23] == "строка с \"кавычками\", запятой; и\nпереводом") found_quote = true;
        CHECK(found_quote);

        r = call("/api/v1/export/events?limit=100&format=json");
        REQUIRE(r.status == 200);
        JValue v;
        REQUIRE(json_parse(r.body, v, err));
        REQUIRE(v.is_array());
        CHECK_EQ(v.arr.size(), size_t(100));
        CHECK_EQ(header(r, "X-Export-Truncated"), std::string("true"));
        r = call("/api/v1/export/events?limit=5&format=ndjson");
        auto lines = split(r.body, '\n');
        size_t n = 0;
        for (auto l : lines)
            if (!l.empty()) {
                JValue x;
                CHECK(json_parse(l, x, err));
                ++n;
            }
        CHECK_EQ(n, size_t(5));
        CHECK_EQ(call("/api/v1/export/events?format=pdf").status, 400);
        CHECK_EQ(call("/api/v1/export/events?from=yesterday").status, 400);
        CHECK_EQ(call("/api/v1/export/everything").status, 404);
        CHECK_EQ(call("/api/v1/export/events", "ingest-secret-1234567890").status, 403);

        rows = parse_csv(call("/api/v1/export/alerts?severity=medium").body, ',');
        REQUIRE(rows.size() == 4);
        CHECK_EQ(rows[0][12], std::string("incident_id"));
        CHECK(!rows[1][12].empty());
        r = call("/api/v1/export/incidents?format=json");
        REQUIRE(json_parse(r.body, v, err));
        REQUIRE(v.arr.size() == 1);
        CHECK_EQ(v.arr[0].get("alert_count")->i, 5);
        rows = parse_csv(call("/api/v1/export/incidents").body, ',');
        REQUIRE(rows.size() == 2);
        CHECK(rows[1][12].find("R4 (1)") != std::string::npos);
        // временные файлы не остаются
        size_t left = 0;
        if (fs::exists(d.path + "/tmp"))
            for (auto& e : fs::directory_iterator(d.path + "/tmp")) left += e.is_regular_file();
        for (int i = 0; i < 50 && left; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            left = 0;
            for (auto& e : fs::directory_iterator(d.path + "/tmp")) left += e.is_regular_file();
        }
        CHECK_EQ(left, size_t(0));
        server.stop();
    }
    pipe.stop();
}

TEST("report: numbers for the period, days, top lists, incidents close time, JSON, letter") {
    TmpDir d;
    std::string err;
    AlertStore alerts;
    REQUIRE(alerts.open(d.path, 90LL * 86400000, err));
    IncidentStore incidents;
    REQUIRE(incidents.open(d.path, 90LL * 86400000, err));
    BlockList blocks;
    REQUIRE(blocks.open(d.path + "/blocks.json", err));
    LiveStats live;
    const int64_t day = 86400000;
    const int64_t to = (now_ms() / day) * day;  // полночь UTC
    const int64_t from = to - 7 * day;
    std::vector<Alert> al;
    for (int i = 0; i < 30; ++i) {
        Alert a;
        a.rule_id = i < 20 ? "WEB-SQLI" : "AUTH-BRUTE";
        a.rule_name = i < 20 ? "SQL-инъекция" : "Перебор <паролей>";
        a.severity = i < 20 ? Severity::Critical : Severity::Medium;
        a.src_ip = i % 3 ? "203.0.113.7" : "198.51.100.9";
        a.ts = a.created = from + (i % 7) * day + 3600000;
        al.push_back(a);
    }
    Alert old;  // вне периода
    old.rule_id = "OLD";
    old.rule_name = "Старое";
    old.ts = old.created = from - day;
    al.push_back(old);
    alerts.add(al);
    alerts.set_status(al[0].id, AlertStatus::FalsePositive);
    auto notices = incidents.on_alerts(al);
    REQUIRE(!notices.empty());
    incidents.set_status(notices[0].id, IncidentStatus::Resolved, "ivan", err);
    ReportSources src;
    src.alerts = &alerts;
    src.incidents = &incidents;
    src.blocks = &blocks;
    src.live = &live;
    ReportData r = build_report(src, from, to, 0);
    CHECK_EQ(r.alerts, 30u);
    CHECK_EQ(r.days.size(), size_t(7));
    uint64_t sum = 0;
    for (auto& x : r.days) sum += x.alerts;
    CHECK_EQ(sum, 30u);
    CHECK_EQ(r.alerts_by_severity[size_t(Severity::Critical)], 20u);
    CHECK_EQ(r.alerts_by_status[size_t(AlertStatus::FalsePositive)], 1u);
    REQUIRE(r.top_rules.size() == 2);
    CHECK_EQ(r.top_rules[0].rule_id, std::string("WEB-SQLI"));
    CHECK_EQ(r.top_rules[0].false_positive, 1u);
    REQUIRE(!r.top_alert_ips.empty());
    CHECK_EQ(r.top_alert_ips[0].first, std::string("203.0.113.7"));
    CHECK_EQ(r.top_alert_ips[0].second, 20u);
    CHECK(r.inc_created >= 2);  // два IP (+ дни дальше окна)
    CHECK(r.events_partial);   // статистики событий нет
    // инцидент закрыт сейчас — за пределами периода (to = полночь сегодня)
    CHECK_EQ(r.inc_resolved, 0u);
    ReportData now_r = build_report(src, from, now_ms() + 1000, 0);
    CHECK_EQ(now_r.inc_resolved, 1u);
    CHECK(now_r.inc_median_close_ms > 0);

    std::string js;
    JsonWriter w(js);
    write_report_json(w, r);
    JValue v;
    REQUIRE(json_parse(js, v, err));
    CHECK_EQ(v.get("alerts")->get("total")->i, 30);
    CHECK_EQ(v.get("days")->arr.size(), size_t(7));
    CHECK_EQ(v.get("alerts")->get("top_rules")->arr[0].get("rule_id")->s, std::string("WEB-SQLI"));

    std::string html = report_html(r, "https://siem.example.com");
    CHECK(html.find("Перебор &lt;паролей&gt;") != std::string::npos);
    CHECK(html.find("<паролей>") == std::string::npos);
    CHECK(html.find("https://siem.example.com/incidents/") != std::string::npos);
    CHECK(html.find("https://siem.example.com/report?from=") != std::string::npos);
    std::string text = report_text(r, "");
    CHECK(text.find("Алерты: 30") != std::string::npos);
    CHECK(report_subject(r).find("30 алерт") != std::string::npos);

    // письмо из двух частей
    net::SmtpMessage msg{"siem@example.com", {"a@example.com"}, report_subject(r), text, html};
    std::string mime = net::build_mime_message(msg, now_ms(), "abc123@sentinel");
    CHECK(mime.find("multipart/alternative; boundary=\"=_sentinel_abc123\"") != std::string::npos);
    CHECK(mime.find("Content-Type: text/plain") != std::string::npos);
    CHECK(mime.find("Content-Type: text/html") != std::string::npos);
    CHECK(mime.find("--=_sentinel_abc123--") != std::string::npos);
    size_t hp = mime.find("Content-Type: text/html");
    size_t start = mime.find("\r\n\r\n", hp) + 4, end = mime.find("--=_sentinel_abc123--");
    CHECK(b64dec(mime.substr(start, end - start)) == html);
}

TEST("report: weekly schedule slots, first start, config") {
    const int64_t day = 86400000;
    // 2026-10-12 — понедельник
    const int64_t mon = days_from_civil(2026, 10, 12) * day;
    // понедельник 09:00 UTC: в 10:00 — слот сегодня, в 08:00 — неделю назад
    CHECK_EQ(ReportMailer::slot_at_or_before(mon + 10 * 3600000, 1, 9 * 60, 0), mon + 9 * 3600000);
    CHECK_EQ(ReportMailer::slot_at_or_before(mon + 8 * 3600000, 1, 9 * 60, 0), mon + 9 * 3600000 - 7 * day);
    CHECK_EQ(ReportMailer::slot_at_or_before(mon + 9 * 3600000, 1, 9 * 60, 0), mon + 9 * 3600000);
    // в среду — понедельничный слот этой недели
    CHECK_EQ(ReportMailer::slot_at_or_before(mon + 2 * day, 1, 9 * 60, 0), mon + 9 * 3600000);
    // пятница 18:30 по Москве (UTC+3) = 15:30 UTC
    CHECK_EQ(ReportMailer::slot_at_or_before(mon + 5 * day, 5, 18 * 60 + 30, 180), mon + 4 * day + 15 * 3600000 + 1800000);
    // воскресенье
    CHECK_EQ(ReportMailer::slot_at_or_before(mon + 7 * day - 1, 0, 0, 0), mon + 6 * day);

    TmpDir d;
    ReportConfig rc;
    rc.weekly = true;
    NotifyConfig nc;
    nc.email.host = "127.0.0.1";
    nc.email.port = 1;
    nc.email.from = "siem@example.com";
    nc.email.to = {"a@example.com"};
    {
        ReportMailer m(rc, nc, {}, d.path + "/reports.json");
        CHECK(m.enabled());
        CHECK_EQ(m.recipients().size(), size_t(1));
        m.tick(now_ms());  // первый запуск: ничего не шлёт, запоминает время
        CHECK(m.last_sent() > 0);
        CHECK(m.next_at(now_ms()) > now_ms());
        m.stop();
    }
    {
        ReportMailer m(rc, nc, {}, d.path + "/reports.json");
        CHECK(m.last_sent() > 0);  // переживает перезапуск
        std::string e = m.send_now("ivan");
        CHECK(!e.empty());  // почтовый сервер недоступен — ошибка, а не зависание
        CHECK(!m.last_error().empty());
    }
    NotifyConfig none;
    ReportMailer off(rc, none, {}, d.path + "/r2.json");
    CHECK(!off.enabled());
    CHECK(!off.send_now("x").empty());

    std::string err;
    std::string path = (fs::temp_directory_path() / ("sentinel-rep-cfg-" + random_hex(4) + ".yaml")).string();
    std::ofstream(path) << "notify:\n  email:\n    smtp: smtp.example.com:587\n    from: s@example.com\n    to: [a@example.com]\n"
                           "reports:\n  weekly:\n    day: пятница\n    time: '18:30'\n    to: [boss@example.com]\n";
    Config cfg;
    CHECK(load_config(path, cfg, err));
    CHECK(cfg.reports.weekly);
    CHECK_EQ(cfg.reports.weekday, 5);
    CHECK_EQ(cfg.reports.minute_of_day, 18 * 60 + 30);
    REQUIRE(cfg.reports.to.size() == 1);
    std::ofstream(path) << "reports:\n  weekly:\n    day: monday\n";  // нет почты
    Config c2;
    CHECK(!load_config(path, c2, err));
    std::ofstream(path) << "notify:\n  email:\n    smtp: s:25\n    from: s@e.com\n    to: [a@e.com]\nreports:\n  weekly:\n    day: someday\n";
    Config c3;
    CHECK(!load_config(path, c3, err));
    std::ofstream(path) << "notify:\n  email:\n    smtp: s:25\n    from: s@e.com\n    to: [a@e.com]\nreports:\n  weekly:\n    time: '25:00'\n";
    Config c4;
    CHECK(!load_config(path, c4, err));
    fs::remove(path);
}
