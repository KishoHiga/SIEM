// Тесты этапа 2: TLS, подключение агентов по токену, ключи без перезапуска, агент.
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

#include "agent/agent.hpp"
#include "agent/discover.hpp"
#include "agent/files.hpp"
#include "agent/winevent.hpp"
#include "core/crypto.hpp"
#include "core/json.hpp"
#include "core/util.hpp"
#include "detect/engine.hpp"
#include "detect/rules.hpp"
#include "net/client.hpp"
#include "net/server.hpp"
#include "net/tls.hpp"
#include "server/access.hpp"
#include "server/api.hpp"
#include "testing.hpp"

using namespace sentinel;
namespace fs = std::filesystem;

#ifndef SENTINEL_SOURCE_DIR
#define SENTINEL_SOURCE_DIR "."
#endif

namespace {

struct Tmp {
    std::string path;
    Tmp() {
        path = (fs::temp_directory_path() / ("sentinel-s2-" + random_hex(6))).string();
        fs::create_directories(path);
    }
    ~Tmp() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

void append_file(const std::string& path, const std::string& text) {
    std::ofstream f(path, std::ios::app | std::ios::binary);
    f << text;
}

// Сервер SIEM целиком (как в main), опционально с TLS.
struct Siem {
    Tmp dir;
    Config cfg;
    EventStore events;
    AlertStore alerts;
    LiveStats live;
    std::unique_ptr<Pipeline> pipe;
    std::unique_ptr<Api> api;
    std::unique_ptr<net::HttpServer> server;
    std::string admin = "admin-secret-1234567890";
    std::string fingerprint;

    explicit Siem(bool tls) {
        cfg.data_dir = dir.path;
        cfg.keys_file = dir.path + "/keys.yaml";
        cfg.keys = {{"admin", Role::Admin, sha256_hex(admin)}};
        std::string err;
        StoreOptions so;
        so.dir = dir.path;
        so.fsync = false;
        events.open(so, err);
        alerts.open(dir.path, so.retention_ms, err);
        auto res = load_rules_dir(std::string(SENTINEL_SOURCE_DIR) + "/rules");
        auto eng = std::make_unique<DetectionEngine>();
        eng->load(res.rules, err);
        pipe = std::make_unique<Pipeline>(events, alerts, live, 100000);
        pipe->start(std::move(eng));
        api = std::make_unique<Api>(cfg, events, alerts, live, *pipe);
        net::ServerOptions so2;
        so2.port = 0;
        so2.workers = 2;
        if (tls) {
            std::string cert = dir.path + "/tls/server.crt", key = dir.path + "/tls/server.key";
            if (!net::generate_self_signed(cert, key, {"localhost", "127.0.0.1"}, 30, fingerprint, err))
                std::cerr << "gen cert: " << err << "\n";
            so2.tls = net::TlsContext::server(cert, key, err);
            if (!so2.tls) std::cerr << "tls ctx: " << err << "\n";
        }
        server = std::make_unique<net::HttpServer>(so2, [this](const net::HttpRequest& rq, net::HttpResponse& rs) {
            api->handle(rq, rs);
        });
        if (!server->start(err)) std::cerr << "server: " << err << "\n";
    }
    ~Siem() {
        server->stop();
        pipe->stop();
        events.close();
        alerts.close();
    }
    std::string url(bool https) const {
        return std::string(https ? "https" : "http") + "://127.0.0.1:" + std::to_string(server->port());
    }
    void wait_idle() {
        for (int i = 0; i < 400 && pipe->stats().queued > 0; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
    size_t count_events(const std::string& query) {
        std::string err;
        net::Url u;
        net::parse_url(url(server_tls()), u, err);
        net::ClientTlsOptions t;
        t.pin_sha256 = fingerprint;
        net::HttpClient c(u, t);
        net::ClientResponse r;
        if (!c.request("GET", "/api/v1/events?limit=1000&" + query, {{"Authorization", "Bearer " + admin}}, "", r, err))
            return size_t(-1);
        JValue v;
        if (!json_parse(r.body, v, err) || !v.get("events")) return size_t(-1);
        return v.get("events")->arr.size();
    }
    bool server_tls() const { return !fingerprint.empty(); }
};

}  // namespace

TEST("net: parse_url") {
    net::Url u;
    std::string err;
    REQUIRE(net::parse_url("https://siem.example.com:8443/base/", u, err));
    CHECK(u.https);
    CHECK_EQ(u.host, std::string("siem.example.com"));
    CHECK_EQ(u.port, uint16_t(8443));
    CHECK_EQ(u.path, std::string("/base"));
    REQUIRE(net::parse_url("http://[::1]:8080", u, err));
    CHECK_EQ(u.host, std::string("::1"));
    REQUIRE(net::parse_url("https://host", u, err));
    CHECK_EQ(u.port, uint16_t(443));
    CHECK(!net::parse_url("ftp://x", u, err));
    CHECK(!net::parse_url("http://:80", u, err));
}

TEST("tls: https with pinned certificate works, wrong pin and plain http fail") {
    if (!net::tls_available()) return;
    Siem s(true);
    REQUIRE(!s.fingerprint.empty());
    std::string err;
    net::Url u;
    net::parse_url(s.url(true), u, err);

    net::ClientTlsOptions good;
    good.pin_sha256 = s.fingerprint;
    net::HttpClient c(u, good);
    net::ClientResponse r;
    REQUIRE(c.request("GET", "/health", {}, "", r, err));
    CHECK_EQ(r.status, 200);
    CHECK_EQ(c.server_fingerprint(), s.fingerprint);
    // повторный запрос по тому же соединению (keep-alive поверх TLS)
    CHECK(c.request("GET", "/api/v1/whoami", {{"Authorization", "Bearer " + s.admin}}, "", r, err) && r.status == 200);

    net::ClientTlsOptions bad;
    bad.pin_sha256 = "sha256:" + std::string(64, 'a');
    net::HttpClient c2(u, bad);
    CHECK(!c2.request("GET", "/health", {}, "", r, err));
    CHECK(err.find("fingerprint mismatch") != std::string::npos);

    // без закрепления самоподписанный сертификат не проходит проверку
    net::HttpClient c3(u, net::ClientTlsOptions{});
    CHECK(!c3.request("GET", "/health", {}, "", r, err));

    // обычный HTTP к HTTPS-серверу — отказ, сервер не падает
    net::Url plain = u;
    plain.https = false;
    net::HttpClient c4(plain, {}, 2000);
    CHECK(!c4.request("GET", "/health", {}, "", r, err) || r.status != 200);
    CHECK(c.request("GET", "/health", {}, "", r, err) && r.status == 200);
}

TEST("tls: large body over https") {
    if (!net::tls_available()) return;
    Siem s(true);
    std::string err;
    net::Url u;
    net::parse_url(s.url(true), u, err);
    net::ClientTlsOptions t;
    t.pin_sha256 = s.fingerprint;
    net::HttpClient c(u, t);
    std::string body;
    for (int i = 0; i < 20000; ++i)
        body += "Oct 12 10:00:01 h sshd[1]: Failed password for u" + std::to_string(i) + " from 10.9." +
                std::to_string(i / 256 % 256) + "." + std::to_string(i % 256) + " port 1 ssh2\n";
    net::ClientResponse r;
    REQUIRE(c.request("POST", "/api/v1/ingest", {{"Authorization", "Bearer " + s.admin}}, body, r, err));
    CHECK_EQ(r.status, 202);
    CHECK(r.body.find("20000") != std::string::npos);
}

TEST("access: enroll token gives an ingest key, single use, keys reload") {
    Siem s(false);
    std::string token, err;
    REQUIRE(s.api->enroll_store().create(3600000, 1, "test", token, err));
    net::Url u;
    net::parse_url(s.url(false), u, err);
    net::HttpClient c(u, {});
    net::ClientResponse r;
    std::string body = R"({"token":")" + token + R"(","host":"Web-01.prod"})";
    REQUIRE(c.request("POST", "/api/v1/enroll", {{"Content-Type", "application/json"}}, body, r, err));
    REQUIRE(r.status == 201);
    JValue v;
    REQUIRE(json_parse(r.body, v, err));
    std::string key = v.get("key")->s;
    CHECK_EQ(v.get("name")->s, std::string("agent-web-01.prod"));
    // ключ сразу работает для отправки, но не для чтения
    CHECK(c.request("POST", "/api/v1/ingest", {{"Authorization", "Bearer " + key}}, "hello\n", r, err) && r.status == 202);
    CHECK(c.request("GET", "/api/v1/events", {{"Authorization", "Bearer " + key}}, "", r, err) && r.status == 403);
    // токен одноразовый
    CHECK(c.request("POST", "/api/v1/enroll", {}, body, r, err) && r.status == 403);
    CHECK(c.request("POST", "/api/v1/enroll", {}, R"({"token":"sne_wrong_token_x"})", r, err) && r.status == 403);
    // агент виден в списке
    CHECK(c.request("GET", "/api/v1/agents", {{"Authorization", "Bearer " + s.admin}}, "", r, err) && r.status == 200);
    CHECK(r.body.find("agent-web-01.prod") != std::string::npos);

    // Ключ, созданный "снаружи" (keygen в файл), подхватывается без перезапуска
    Config other = s.cfg;
    other.keys.clear();
    load_keys_file(other, err);
    std::string secret;
    REQUIRE(create_key(other, "external", Role::Read, secret, err));
    CHECK(c.request("GET", "/api/v1/stats", {{"Authorization", "Bearer " + secret}}, "", r, err) && r.status == 401);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    s.api->keys().reload_if_changed();
    CHECK(c.request("GET", "/api/v1/stats", {{"Authorization", "Bearer " + secret}}, "", r, err) && r.status == 200);
}

TEST("access: expired enroll token is rejected") {
    Tmp d;
    EnrollStore st(d.path + "/t.yaml");
    std::string tok, err;
    REQUIRE(st.create(1, 5, "", tok, err));
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK(st.consume(tok) == EnrollStore::Result::Expired);
    REQUIRE(st.create(3600000, 2, "x'y", tok, err));
    CHECK(st.consume(tok) == EnrollStore::Result::Ok);
    CHECK(st.consume(tok) == EnrollStore::Result::Ok);
    CHECK(st.consume(tok) != EnrollStore::Result::Ok);
}

TEST("agent: glob and tailer") {
    using namespace sentinel::agent;
    CHECK(glob_match("*access*.log", "site.access.log"));
    CHECK(!glob_match("*access*.log", "error.log"));
    CHECK(glob_match("*-json.log", "abc123-json.log"));
    CHECK(glob_match("a?c", "abc"));
    Tmp d;
    fs::create_directories(d.path + "/c1");
    fs::create_directories(d.path + "/c2");
    append_file(d.path + "/c1/x-json.log", "1\n");
    append_file(d.path + "/c2/y-json.log", "2\n");
    append_file(d.path + "/c2/other.txt", "3\n");
    auto found = expand_glob(d.path + "/*/*-json.log");
    CHECK_EQ(found.size(), size_t(2));

    std::string f = d.path + "/app.log";
    append_file(f, "one\ntwo\r\nthr");
    FileTailer t(f, 0);
    std::vector<std::string> lines;
    t.read_lines(lines, 1 << 20);
    REQUIRE(lines.size() == 2);
    CHECK_EQ(lines[1], std::string("two"));
    CHECK_EQ(t.pending_offset(), uint64_t(9));
    // незаконченная строка дописалась
    append_file(f, "ee\n");
    lines.clear();
    t.read_lines(lines, 1 << 20);
    REQUIRE(lines.size() == 1);
    CHECK_EQ(lines[0], std::string("three"));
    // откат (сервер не принял) — те же строки ещё раз
    t.rewind();
    lines.clear();
    t.read_lines(lines, 1 << 20);
    CHECK_EQ(lines.size(), size_t(3));
    t.commit(t.pending_offset());
    // обрезка файла (copytruncate) — читаем сначала
    { std::ofstream tr(f, std::ios::trunc | std::ios::binary); tr << "new\n"; }
    lines.clear();
    t.read_lines(lines, 1 << 20);
    REQUIRE(lines.size() == 1);
    CHECK_EQ(lines[0], std::string("new"));
}

TEST("agent: windows event xml -> json, macOS log line conversion") {
    using namespace sentinel::agent;
    const char* xml =
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider "
        "Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated "
        "SystemTime='2026-10-12T15:00:00.1234567Z'/><Computer>WIN-SRV01</Computer></System><EventData>"
        "<Data Name='SubjectUserName'>-</Data><Data Name='TargetUserName'>administrator</Data>"
        "<Data Name='Status'>0xc000006d</Data><Data Name='LogonType'>10</Data>"
        "<Data Name='IpAddress'>203.0.113.77</Data></EventData></Event>";
    std::string js;
    REQUIRE(WinEventReader::xml_to_json(xml, js));
    JValue v;
    std::string err;
    REQUIRE(json_parse(js, v, err));
    CHECK_EQ(v.get("type")->s, std::string("auth"));
    CHECK_EQ(v.get("outcome")->s, std::string("failure"));
    CHECK_EQ(v.get("user")->s, std::string("administrator"));
    CHECK_EQ(v.get("src_ip")->s, std::string("203.0.113.77"));
    CHECK_EQ(v.get("host")->s, std::string("WIN-SRV01"));
    // служебный вход не нужен
    std::string svc = std::string(xml);
    svc.replace(svc.find("<Data Name='LogonType'>10"), 25, "<Data Name='LogonType'>5<");
    CHECK(!WinEventReader::xml_to_json(svc, js) || js.find("\"logon_type\":\"5\"") == std::string::npos);

    std::string line = "2026-10-12 18:01:02.123456+0300  localhost sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2";
    REQUIRE(convert_macos_log_line(line));
    CHECK(starts_with(line, "2026-10-12T18:01:02.123456+0300 localhost sshd[123]:"));
    std::string header = "Filtering the log data using \"process == sshd\"";
    CHECK(!convert_macos_log_line(header));
}

TEST("agent: end-to-end over https — rotation, restart without duplicates, server outage") {
    if (!net::tls_available()) return;
    using namespace sentinel::agent;
    Siem s(true);
    Tmp d;
    std::string log = d.path + "/auth.log";
    auto ssh = [](int i) {
        return "Oct 12 10:00:01 web-01 sshd[1]: Failed password for user" + std::to_string(i) +
               " from 198.51.100.7 port " + std::to_string(1000 + i) + " ssh2\n";
    };
    for (int i = 0; i < 3; ++i) append_file(log, ssh(i));

    // Подключение по токену, как это делает пользователь
    std::string token, err;
    REQUIRE(s.api->enroll_store().create(3600000, 1, "", token, err));
    AgentConfig cfg;
    cfg.path = d.path + "/agent.yaml";
    cfg.server = s.url(true);
    cfg.pin = s.fingerprint;
    cfg.host = "web-01";
    cfg.state_dir = d.path + "/state";
    std::string name;
    REQUIRE(Agent::enroll(cfg, token, err, name));
    CHECK(!cfg.key.empty());

    AgentConfig loaded;
    REQUIRE(load_agent_config(cfg.path, loaded, err));
    CHECK_EQ(loaded.key, cfg.key);
    CHECK_EQ(loaded.pin, cfg.pin);
    loaded.autodiscover = false;
    loaded.start_at = "beginning";
    SourceSpec src;
    src.path = log;
    src.format = "syslog";
    src.source = "auth";
    loaded.sources = {src};
    {
        Agent a(loaded);
        REQUIRE(a.init(err));
        std::string info;
        CHECK(a.test_connection(info, err));
        a.step();
        CHECK_EQ(a.stats().lines_sent, uint64_t(3));
        // ротация: старый файл переименован (в него ещё дописали), создан новый
        fs::rename(log, log + ".1");
        append_file(log + ".1", ssh(3));
        append_file(log, ssh(4));
        append_file(log, ssh(5));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        a.step();
        std::this_thread::sleep_for(std::chrono::milliseconds(2100));  // пересканирование раз в 2 с
        a.step();
        a.step();
        CHECK_EQ(a.stats().lines_sent, uint64_t(6));
        a.shutdown();
    }
    s.wait_idle();
    CHECK_EQ(s.count_events("src_ip=198.51.100.7"), size_t(6));

    // Перезапуск агента: ничего не дублируется, новые строки доходят
    append_file(log, ssh(6));
    {
        Agent a(loaded);
        REQUIRE(a.init(err));
        a.step();
        CHECK_EQ(a.stats().lines_sent, uint64_t(1));
        a.shutdown();
    }
    s.wait_idle();
    CHECK_EQ(s.count_events("src_ip=198.51.100.7"), size_t(7));
    // перебор с одного IP: 7 неудач -> алерт
    CHECK(s.alerts.query({}).size() >= 1);

    // Сервер недоступен: агент ждёт, позицию не сдвигает; потом досылает
    AgentConfig broken = loaded;
    broken.server = "https://127.0.0.1:1";  // никто не слушает
    append_file(log, ssh(7));
    {
        Agent a(broken);
        REQUIRE(a.init(err));
        a.step();
        CHECK_EQ(a.stats().lines_sent, uint64_t(0));
        CHECK(a.stats().send_errors >= 1);
        a.shutdown();
    }
    {
        Agent a(loaded);
        REQUIRE(a.init(err));
        a.step();
        CHECK_EQ(a.stats().lines_sent, uint64_t(1));
        a.shutdown();
    }
    s.wait_idle();
    CHECK_EQ(s.count_events("src_ip=198.51.100.7"), size_t(8));
}

TEST("agent: discover runs on this machine without crashing") {
    auto r = sentinel::agent::discover_sources();
    for (auto& src : r.sources) CHECK(!src.path.empty());
    CHECK(true);
}
