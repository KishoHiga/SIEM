#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <thread>

#include "core/crypto.hpp"
#include "core/json.hpp"
#include "core/util.hpp"
#include "detect/engine.hpp"
#include "detect/rules.hpp"
#include "net/server.hpp"
#include "net/socket.hpp"
#include "server/api.hpp"
#include "testing.hpp"

using namespace sentinel;
namespace fs = std::filesystem;

#ifndef SENTINEL_SOURCE_DIR
#define SENTINEL_SOURCE_DIR "."
#endif

namespace {

struct Resp {
    int status = 0;
    std::string body;
    std::string head;
};

// Читает один HTTP-ответ из сокета (по Content-Length).
bool read_response(net::socket_t s, std::string& buf, Resp& r) {
    char tmp[8192];
    while (true) {
        size_t he = buf.find("\r\n\r\n");
        if (he != std::string::npos) {
            r.head = buf.substr(0, he);
            r.status = std::atoi(buf.c_str() + 9);
            size_t cl = 0;
            size_t p = to_lower(r.head).find("content-length:");
            if (p != std::string::npos) cl = size_t(std::atol(r.head.c_str() + p + 15));
            if (r.status == 100) {  // промежуточный ответ
                buf.erase(0, he + 4);
                continue;
            }
            if (buf.size() >= he + 4 + cl) {
                r.body = buf.substr(he + 4, cl);
                buf.erase(0, he + 4 + cl);
                return true;
            }
        }
        long n = net::recv_some(s, tmp, sizeof(tmp));
        if (n <= 0) return false;
        buf.append(tmp, size_t(n));
    }
}

struct TestServer {
    std::string dir;
    Config cfg;
    EventStore events;
    AlertStore alerts;
    LiveStats live;
    std::unique_ptr<Pipeline> pipe;
    std::unique_ptr<Api> api;
    std::unique_ptr<net::HttpServer> server;
    std::string admin = "admin-secret", ingest = "ingest-secret", reader = "read-secret";

    TestServer() {
        dir = (fs::temp_directory_path() / ("sentinel-http-" + random_hex(6))).string();
        cfg.keys = {{"admin", Role::Admin, sha256_hex(admin)},
                    {"web-01", Role::Ingest, sha256_hex(ingest)},
                    {"viewer", Role::Read, sha256_hex(reader)}};
        std::string err;
        StoreOptions so;
        so.dir = dir;
        so.fsync = false;
        events.open(so, err);
        alerts.open(dir, so.retention_ms, err);
        auto res = load_rules_dir(std::string(SENTINEL_SOURCE_DIR) + "/rules");
        auto eng = std::make_unique<DetectionEngine>();
        eng->load(res.rules, err);
        pipe = std::make_unique<Pipeline>(events, alerts, live, 100000);
        pipe->start(std::move(eng));
        api = std::make_unique<Api>(cfg, events, alerts, live, *pipe);
        api->set_rules(res.rules);
        net::ServerOptions so2;
        so2.port = 0;
        so2.workers = 2;
        so2.max_body_bytes = 1 << 20;
        server = std::make_unique<net::HttpServer>(so2, [this](const net::HttpRequest& rq, net::HttpResponse& rs) {
            api->handle(rq, rs);
        });
        server->start(err);
    }
    ~TestServer() {
        server->stop();
        pipe->stop();
        events.close();
        alerts.close();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    Resp request(const std::string& method, const std::string& path, const std::string& key,
                 const std::string& body = "", const std::string& ctype = "text/plain") {
        std::string e;
        net::socket_t s = net::connect_tcp("127.0.0.1", server->port(), e);
        Resp r;
        if (s == net::kInvalidSocket) return r;
        std::string req = method + " " + path + " HTTP/1.1\r\nHost: t\r\n";
        if (!key.empty()) req += "Authorization: Bearer " + key + "\r\n";
        req += "Content-Type: " + ctype + "\r\nContent-Length: " + std::to_string(body.size()) +
               "\r\nConnection: close\r\n\r\n" + body;
        net::send_all(s, req.data(), req.size());
        std::string buf;
        read_response(s, buf, r);
        net::close_socket(s);
        return r;
    }

    void wait_idle() {
        for (int i = 0; i < 400 && pipe->stats().queued > 0; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
};

}  // namespace

TEST("http: health, auth and roles") {
    TestServer ts;
    CHECK_EQ(ts.request("GET", "/health", "").status, 200);
    CHECK_EQ(ts.request("GET", "/api/v1/events", "").status, 401);
    CHECK_EQ(ts.request("GET", "/api/v1/events", "wrong").status, 401);
    CHECK_EQ(ts.request("GET", "/api/v1/events", ts.ingest).status, 403);
    CHECK_EQ(ts.request("POST", "/api/v1/ingest", ts.reader, "x").status, 403);
    CHECK_EQ(ts.request("GET", "/api/v1/whoami", ts.reader).status, 200);
    CHECK_EQ(ts.request("GET", "/api/v1/nothing", ts.reader).status, 404);
    CHECK_EQ(ts.request("GET", "/api/v1/ingest", ts.ingest).status, 405);
    auto rules = ts.request("GET", "/api/v1/rules", ts.reader);
    CHECK_EQ(rules.status, 200);
    CHECK(rules.body.find("AUTH-BRUTE-001") != std::string::npos);
}

TEST("http: ingest raw lines -> events and alerts via API") {
    TestServer ts;
    std::string body =
        "203.0.113.50 - - [12/Oct/2026:10:00:00 +0000] \"GET /item?id=1%20UNION%20SELECT%201 HTTP/1.1\" 200 5 \"-\" \"x\"\n"
        "Oct 12 10:00:01 web-01 sshd[1]: Failed password for root from 45.9.9.9 port 1 ssh2\n"
        "\n"
        "just a plain line\n";
    auto r = ts.request("POST", "/api/v1/ingest", ts.ingest, body);
    CHECK_EQ(r.status, 202);
    CHECK(r.body.find("\"accepted\":3") != std::string::npos);
    ts.wait_idle();

    auto ev = ts.request("GET", "/api/v1/events?src_ip=45.9.9.9", ts.reader);
    REQUIRE(ev.status == 200);
    JValue v;
    std::string err;
    REQUIRE(json_parse(ev.body, v, err));
    REQUIRE(v.get("events")->arr.size() == 1);
    CHECK_EQ(v.get("events")->arr[0].get("user")->s, std::string("root"));

    auto al = ts.request("GET", "/api/v1/alerts?severity=high", ts.reader);
    REQUIRE(json_parse(al.body, v, err));
    REQUIRE(v.get("alerts")->arr.size() == 1);
    const JValue& a = v.get("alerts")->arr[0];
    CHECK_EQ(a.get("rule_id")->s, std::string("WEB-SQLI-001"));
    uint64_t id = uint64_t(a.get("id")->i);

    auto one = ts.request("GET", "/api/v1/alerts/" + std::to_string(id), ts.reader);
    REQUIRE(json_parse(one.body, v, err));
    CHECK(v.get("events")->arr.size() == 1);

    CHECK_EQ(ts.request("POST", "/api/v1/alerts/" + std::to_string(id) + "/status", ts.reader, R"({"status":"resolved"})").status, 403);
    CHECK_EQ(ts.request("POST", "/api/v1/alerts/" + std::to_string(id) + "/status", ts.admin, R"({"status":"bogus"})").status, 400);
    CHECK_EQ(ts.request("POST", "/api/v1/alerts/" + std::to_string(id) + "/status", ts.admin, R"({"status":"resolved"})").status, 200);
    CHECK_EQ(ts.request("POST", "/api/v1/alerts/999/status", ts.admin, R"({"status":"resolved"})").status, 404);
    auto res = ts.request("GET", "/api/v1/alerts?status=resolved", ts.reader);
    CHECK(res.body.find("WEB-SQLI-001") != std::string::npos);

    auto st = ts.request("GET", "/api/v1/stats?minutes=5", ts.reader);
    REQUIRE(json_parse(st.body, v, err));
    CHECK_EQ(v.get("events_since_start")->i, 3);
    CHECK(v.get("timeline")->arr.size() == 5);
}

TEST("http: ingest JSON objects and arrays") {
    TestServer ts;
    auto r = ts.request("POST", "/api/v1/ingest", ts.ingest,
                        R"([{"type":"auth","action":"login","outcome":"failure","user":"u1","src_ip":"7.7.7.7"},"Oct 12 10:00:01 h sshd[1]: Accepted password for u1 from 7.7.7.7 port 1 ssh2"])",
                        "application/json");
    CHECK_EQ(r.status, 202);
    CHECK_EQ(ts.request("POST", "/api/v1/ingest", ts.ingest, "{bad json", "application/json").status, 400);
    CHECK_EQ(ts.request("POST", "/api/v1/ingest", ts.ingest, "123", "application/json").status, 400);
    ts.wait_idle();
    auto ev = ts.request("GET", "/api/v1/events?src_ip=7.7.7.7&outcome=failure", ts.reader);
    CHECK(ev.body.find("\"user\":\"u1\"") != std::string::npos);
    CHECK(ev.body.find("Accepted") == std::string::npos);
}

TEST("http: keep-alive, pipelining, 100-continue, errors") {
    TestServer ts;
    std::string e;
    net::socket_t s = net::connect_tcp("127.0.0.1", ts.server->port(), e);
    REQUIRE(s != net::kInvalidSocket);
    std::string two = "GET /health HTTP/1.1\r\nHost: a\r\n\r\nGET /health HTTP/1.1\r\nHost: a\r\n\r\n";
    net::send_all(s, two.data(), two.size());
    std::string buf;
    Resp r1, r2;
    CHECK(read_response(s, buf, r1) && r1.status == 200);
    CHECK(read_response(s, buf, r2) && r2.status == 200);
    // Expect: 100-continue — тело отправляем после ответа 100
    std::string body = "Oct 12 10:00:01 h sshd[1]: Failed password for x from 1.2.3.4 port 1 ssh2";
    std::string h = "POST /api/v1/ingest HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer " + ts.ingest +
                    "\r\nContent-Length: " + std::to_string(body.size()) + "\r\nExpect: 100-continue\r\n\r\n";
    net::send_all(s, h.data(), h.size());
    char tmp[256];
    long n = net::recv_some(s, tmp, sizeof(tmp));
    CHECK(n > 0 && std::string(tmp, size_t(n)).find("100 Continue") != std::string::npos);
    net::send_all(s, body.data(), body.size());
    Resp r3;
    CHECK(read_response(s, buf, r3) && r3.status == 202);
    net::close_socket(s);

    auto raw = [&](const std::string& req) {
        net::socket_t c = net::connect_tcp("127.0.0.1", ts.server->port(), e);
        net::send_all(c, req.data(), req.size());
        std::string b;
        Resp r;
        read_response(c, b, r);
        net::close_socket(c);
        return r.status;
    };
    CHECK_EQ(raw("GARBAGE\r\n\r\n"), 400);
    CHECK_EQ(raw("GET /health HTTP/9.9\r\n\r\n"), 400);
    CHECK_EQ(raw("POST /api/v1/ingest HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), 501);
    CHECK_EQ(raw("POST /api/v1/ingest HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n"), 413);
    CHECK_EQ(raw("GET /health HTTP/1.1\r\nX: " + std::string(40000, 'a') + "\r\n\r\n"), 431);
}

TEST("http: brute force on API keys gets blocked") {
    TestServer ts;
    int last = 0;
    for (int i = 0; i < 25; ++i) last = ts.request("GET", "/api/v1/stats", "guess" + std::to_string(i)).status;
    CHECK_EQ(last, 429);
    CHECK_EQ(ts.request("GET", "/api/v1/stats", ts.reader).status, 429);  // IP заблокирован целиком
}

TEST("http: poll() backend (macOS/Windows path) works too") {
#ifdef _WIN32
    _putenv_s("SENTINEL_POLLER", "poll");
#else
    setenv("SENTINEL_POLLER", "poll", 1);
#endif
    {
        TestServer ts;
        CHECK_EQ(ts.request("GET", "/health", "").status, 200);
        auto r = ts.request("POST", "/api/v1/ingest", ts.ingest, std::string(200000, 'x') + "\n");
        CHECK_EQ(r.status, 202);
    }
#ifdef _WIN32
    _putenv_s("SENTINEL_POLLER", "");
#else
    unsetenv("SENTINEL_POLLER");
#endif
}

TEST("net: listening refuses a port another program already uses (macOS lets 127.0.0.1 share it with 0.0.0.0)") {
    std::string err;
    net::ServerOptions o;
    o.host = "0.0.0.0";
    o.port = 0;
    o.workers = 1;
    net::HttpServer other(o, [](const net::HttpRequest&, net::HttpResponse& rs) { rs.body = "other"; });
    REQUIRE(other.start(err));
    const uint16_t port = other.port();
    REQUIRE(port != 0);
    net::socket_t mine = net::listen_tcp("127.0.0.1", port, err);
    CHECK(mine == net::kInvalidSocket);
    CHECK(err.find(std::to_string(port)) != std::string::npos);
    if (mine != net::kInvalidSocket) net::close_socket(mine);
    CHECK(net::listen_tcp("0.0.0.0", port, err) == net::kInvalidSocket);
    other.stop();
    // порт освободился — занимается без ошибок
    net::socket_t again = net::listen_tcp("127.0.0.1", port, err);
    CHECK(again != net::kInvalidSocket);
    if (again != net::kInvalidSocket) net::close_socket(again);
}
