// Тесты этапа 3: вход в панель (сессии), защита от CSRF, токены подключения из панели,
// WebSocket-лента и раздача файлов панели.
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

#include "core/crypto.hpp"
#include "core/json.hpp"
#include "core/util.hpp"
#include "detect/engine.hpp"
#include "detect/rules.hpp"
#include "net/client.hpp"
#include "net/server.hpp"
#include "net/socket.hpp"
#include "server/api.hpp"
#include "server/live_feed.hpp"
#include "server/web.hpp"
#include "testing.hpp"

#if !defined(_WIN32)
#include <sys/socket.h>
#include <sys/time.h>
#endif

using namespace sentinel;
namespace fs = std::filesystem;

#ifndef SENTINEL_SOURCE_DIR
#define SENTINEL_SOURCE_DIR "."
#endif

namespace {

using Headers = std::vector<std::pair<std::string, std::string>>;

struct WebSiem {
    std::string dir;
    Config cfg;
    EventStore events;
    AlertStore alerts;
    LiveStats live;
    LiveFeed feed;
    std::unique_ptr<Pipeline> pipe;
    std::unique_ptr<Api> api;
    std::unique_ptr<net::HttpServer> server;
    std::string admin = "admin-secret-1234567890";
    std::string reader = "reader-secret-1234567890";
    std::string ingest = "ingest-secret-1234567890";

    WebSiem() {
        dir = (fs::temp_directory_path() / ("sentinel-s3-" + random_hex(6))).string();
        fs::create_directories(dir + "/web/assets");
        {
            std::ofstream(dir + "/web/index.html") << "<!doctype html><title>Sentinel</title><div id=root></div>";
            std::ofstream(dir + "/web/assets/app-1234.js") << "console.log(1)";
            std::ofstream(dir + "/secret.txt") << "top secret";
        }
        cfg.data_dir = dir;
        cfg.keys_file = dir + "/keys.yaml";
        cfg.keys = {{"admin", Role::Admin, sha256_hex(admin)},
                    {"viewer", Role::Read, sha256_hex(reader)},
                    {"web-01", Role::Ingest, sha256_hex(ingest)}};
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
        pipe->set_on_stored([this](const std::vector<Event>& e, const std::vector<Alert>& a) { feed.on_stored(e, a); });
        pipe->start(std::move(eng));
        api = std::make_unique<Api>(cfg, events, alerts, live, *pipe);
        api->set_web(std::make_shared<WebFiles>(dir + "/web"));
        api->set_agent_info("https://siem.local:8443", "sha256:abcd");
        net::ServerOptions so2;
        so2.port = 0;
        so2.workers = 2;
        so2.ws.path = "/ws/live";
        so2.ws.accept = [this](const net::HttpRequest& rq) { return api->ws_accept(rq); };
        server = std::make_unique<net::HttpServer>(so2, [this](const net::HttpRequest& rq, net::HttpResponse& rs) {
            api->handle(rq, rs);
        });
        if (!server->start(err)) std::cerr << "server: " << err << "\n";
        feed.set_sink([this](const std::string& m) { server->broadcast(m); });
    }
    ~WebSiem() {
        feed.set_sink(nullptr);
        server->stop();
        pipe->stop();
        events.close();
        alerts.close();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    net::ClientResponse call(const std::string& method, const std::string& path, const Headers& h = {},
                             const std::string& body = "") {
        net::Url u;
        u.host = "127.0.0.1";
        u.port = server->port();
        net::HttpClient c(u, {});
        net::ClientResponse r;
        std::string err;
        if (!c.request(method, path, h, body, r, err)) std::cerr << "request: " << err << "\n";
        return r;
    }
};

std::string session_cookie(const net::ClientResponse& r) {
    std::string sc = r.header("set-cookie");
    size_t semi = sc.find(';');
    return semi == std::string::npos ? sc : sc.substr(0, semi);
}

// Простейший клиент WebSocket для тестов.
struct WsClient {
    net::socket_t fd = net::kInvalidSocket;
    std::string buf;

    ~WsClient() {
        if (fd != net::kInvalidSocket) net::close_socket(fd);
    }

    // Возвращает HTTP-статус ответа на рукопожатие (101 — успех).
    int open(uint16_t port, const Headers& extra) {
        std::string err;
        fd = net::connect_tcp("127.0.0.1", port, err);
        if (fd == net::kInvalidSocket) return -1;
#if defined(_WIN32)
        DWORD tv = 5000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
        timeval tv{5, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
        std::string req = "GET /ws/live HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(port) +
                          "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";
        for (auto& h : extra) req += h.first + ": " + h.second + "\r\n";
        req += "\r\n";
        net::send_all(fd, req.data(), req.size());
        while (buf.find("\r\n\r\n") == std::string::npos) {
            char tmp[4096];
            long n = net::recv_some(fd, tmp, sizeof(tmp));
            if (n <= 0) return -1;
            buf.append(tmp, size_t(n));
        }
        size_t end = buf.find("\r\n\r\n");
        std::string head = buf.substr(0, end);
        buf.erase(0, end + 4);
        status_head = head;
        if (head.size() < 12) return -1;
        return int(parse_uint(head.substr(9, 3)).value_or(0));
    }

    // Отправить кадр от клиента (с маской, как требует стандарт).
    void send_frame(uint8_t opcode, const std::string& payload, bool masked = true) {
        std::string f;
        f.push_back(char(0x80 | opcode));
        f.push_back(char((masked ? 0x80 : 0) | payload.size()));
        const uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
        if (masked) f.append(reinterpret_cast<const char*>(mask), 4);
        for (size_t i = 0; i < payload.size(); ++i) f.push_back(char(payload[i] ^ (masked ? mask[i & 3] : 0)));
        net::send_all(fd, f.data(), f.size());
    }

    // Прочитать следующий кадр. false — соединение закрыто или тайм-аут.
    bool read_frame(uint8_t& opcode, std::string& payload) {
        for (;;) {
            if (buf.size() >= 2) {
                const uint8_t* p = reinterpret_cast<const uint8_t*>(buf.data());
                uint64_t len = p[1] & 0x7F;
                size_t pos = 2;
                if (len == 126 && buf.size() >= 4) {
                    len = (uint64_t(p[2]) << 8) | p[3];
                    pos = 4;
                } else if (len == 127 && buf.size() >= 10) {
                    len = 0;
                    for (int i = 0; i < 8; ++i) len = (len << 8) | p[2 + i];
                    pos = 10;
                } else if (len >= 126) {
                    pos = 0;
                }
                if (pos && buf.size() >= pos + len) {
                    opcode = p[0] & 0x0F;
                    payload = buf.substr(pos, size_t(len));
                    buf.erase(0, pos + size_t(len));
                    return true;
                }
            }
            char tmp[65536];
            long n = net::recv_some(fd, tmp, sizeof(tmp));
            if (n <= 0) return false;
            buf.append(tmp, size_t(n));
        }
    }

    std::string status_head;
};

}  // namespace

TEST("web: login by key sets HttpOnly cookie, session works, logout ends it") {
    WebSiem s;
    const Headers xrw = {{"X-Requested-With", "sentinel"}, {"Content-Type", "application/json"}};

    // без заголовка X-Requested-With вход запрещён (защита от подделки запроса с чужого сайта)
    CHECK_EQ(s.call("POST", "/api/v1/login", {}, "{\"key\":\"" + s.admin + "\"}").status, 403);
    CHECK_EQ(s.call("POST", "/api/v1/login", xrw, "{\"key\":\"wrong\"}").status, 401);
    CHECK_EQ(s.call("POST", "/api/v1/login", xrw, "not json").status, 400);
    // ключ агента (только отправка логов) в панель не пускает
    CHECK_EQ(s.call("POST", "/api/v1/login", xrw, "{\"key\":\"" + s.ingest + "\"}").status, 403);

    auto r = s.call("POST", "/api/v1/login", xrw, "{\"key\":\"" + s.admin + "\"}");
    CHECK_EQ(r.status, 200);
    std::string sc = r.header("set-cookie");
    CHECK(sc.find("HttpOnly") != std::string::npos);
    CHECK(sc.find("SameSite=Strict") != std::string::npos);
    CHECK(sc.find("Secure") == std::string::npos);  // без TLS флаг Secure сломал бы вход
    std::string cookie = session_cookie(r);
    CHECK(starts_with(cookie, "sentinel_session="));
    CHECK_EQ(cookie.size(), std::string("sentinel_session=").size() + 64);

    auto me = s.call("GET", "/api/v1/me", {{"Cookie", cookie}});
    CHECK_EQ(me.status, 200);
    JValue v;
    std::string err;
    CHECK(json_parse(me.body, v, err));
    CHECK(v.get("name") && v.get("name")->s == "admin");
    CHECK(v.get("is_admin") && v.get("is_admin")->b);
    CHECK(v.get("can_change_alerts") && v.get("can_change_alerts")->b);

    CHECK_EQ(s.call("GET", "/api/v1/stats", {{"Cookie", cookie}}).status, 200);
    CHECK_EQ(s.call("GET", "/api/v1/stats", {{"Cookie", "sentinel_session=" + std::string(64, 'a')}}).status, 401);

    // выход: без заголовка нельзя, с заголовком — сессия больше не работает
    CHECK_EQ(s.call("POST", "/api/v1/logout", {{"Cookie", cookie}}).status, 403);
    auto out = s.call("POST", "/api/v1/logout", {{"Cookie", cookie}, {"X-Requested-With", "sentinel"}});
    CHECK_EQ(out.status, 200);
    CHECK(out.header("set-cookie").find("Max-Age=0") != std::string::npos);
    CHECK_EQ(s.call("GET", "/api/v1/me", {{"Cookie", cookie}}).status, 401);
}

TEST("web: role from session, CSRF header required for changes via cookie") {
    WebSiem s;
    const Headers xrw = {{"X-Requested-With", "sentinel"}};
    std::string cookie = session_cookie(s.call("POST", "/api/v1/login", xrw, "{\"key\":\"" + s.reader + "\"}"));
    JValue v;
    std::string err;
    CHECK(json_parse(s.call("GET", "/api/v1/me", {{"Cookie", cookie}}).body, v, err));
    CHECK(v.get("role") && v.get("role")->s == "read");
    CHECK(v.get("can_change_alerts") && !v.get("can_change_alerts")->b);
    // читатель не может создавать токены подключения
    CHECK_EQ(s.call("POST", "/api/v1/enroll-tokens", {{"Cookie", cookie}, {"X-Requested-With", "sentinel"}}, "{}").status,
             403);

    std::string admin_cookie = session_cookie(s.call("POST", "/api/v1/login", xrw, "{\"key\":\"" + s.admin + "\"}"));
    // изменяющий запрос по cookie без заголовка — отказ, даже для администратора
    CHECK_EQ(s.call("POST", "/api/v1/enroll-tokens", {{"Cookie", admin_cookie}}, "{}").status, 403);
    // а с ключом в заголовке Authorization заголовок не нужен (это не браузер)
    CHECK_EQ(s.call("POST", "/api/v1/enroll-tokens", {{"Authorization", "Bearer " + s.admin}}, "{}").status, 201);
}

TEST("web: enroll token from the panel works for an agent") {
    WebSiem s;
    std::string cookie = session_cookie(
        s.call("POST", "/api/v1/login", {{"X-Requested-With", "sentinel"}}, "{\"key\":\"" + s.admin + "\"}"));
    auto r = s.call("POST", "/api/v1/enroll-tokens", {{"Cookie", cookie}, {"X-Requested-With", "sentinel"}},
                    "{\"ttl_hours\":2,\"uses\":2,\"label\":\"web servers\"}");
    CHECK_EQ(r.status, 201);
    JValue v;
    std::string err;
    CHECK(json_parse(r.body, v, err));
    std::string token = v.get("token") ? v.get("token")->s : "";
    CHECK(starts_with(token, "sne_"));
    CHECK(v.get("uses") && v.get("uses")->i == 2);
    std::string cmd = v.get("command") ? v.get("command")->s : "";
    CHECK(cmd.find("--server https://siem.local:8443") != std::string::npos);
    CHECK(cmd.find("--token " + token) != std::string::npos);
    CHECK(cmd.find("--pin sha256:abcd") != std::string::npos);

    // два подключения по токену проходят, третье — нет
    for (int i = 0; i < 3; ++i) {
        auto e = s.call("POST", "/api/v1/enroll", {}, "{\"token\":\"" + token + "\",\"host\":\"web-" + std::to_string(i) + "\"}");
        CHECK_EQ(e.status, i < 2 ? 201 : 403);
    }
}

TEST("web: websocket live feed — handshake, auth, origin, ping, broadcast") {
    WebSiem s;
    const uint16_t port = s.server->port();
    {
        WsClient anon;
        CHECK_EQ(anon.open(port, {}), 401);  // без входа ленту не дают
    }
    {
        WsClient agent;
        CHECK_EQ(agent.open(port, {{"Authorization", "Bearer " + s.ingest}}), 401);  // ключ агента не читает
    }
    std::string cookie = session_cookie(
        s.call("POST", "/api/v1/login", {{"X-Requested-With", "sentinel"}}, "{\"key\":\"" + s.reader + "\"}"));
    {
        WsClient evil;  // страница чужого сайта с нашей cookie
        CHECK_EQ(evil.open(port, {{"Cookie", cookie}, {"Origin", "https://evil.example"}}), 401);
    }
    WsClient ws;
    CHECK_EQ(ws.open(port, {{"Cookie", cookie}, {"Origin", "http://127.0.0.1:" + std::to_string(port)}}), 101);
    // ответ по RFC 6455 для ключа из примера стандарта
    CHECK(ws.status_head.find("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != std::string::npos);
    for (int i = 0; i < 200 && s.server->ws_clients() == 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK_EQ(s.server->ws_clients(), size_t(1));

    uint8_t op = 0;
    std::string payload;
    ws.send_frame(9, "hi");  // ping -> pong
    CHECK(ws.read_frame(op, payload));
    CHECK_EQ(int(op), 10);
    CHECK_EQ(payload, std::string("hi"));

    // события -> алерт -> одно сообщение tick со счётчиком, последними событиями и алертом
    std::string body;
    for (int i = 0; i < 12; ++i)
        body += "Jan 10 10:00:0" + std::to_string(i % 10) +
                " web sshd[1]: Failed password for root from 203.0.113.9 port 2222 ssh2\n";
    auto ing = s.call("POST", "/api/v1/ingest?format=syslog", {{"Authorization", "Bearer " + s.ingest}}, body);
    CHECK_EQ(ing.status, 202);
    for (int i = 0; i < 400 && s.pipe->stats().queued > 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    s.feed.tick(now_ms());
    CHECK(ws.read_frame(op, payload));
    CHECK_EQ(int(op), 1);
    JValue v;
    std::string err;
    CHECK(json_parse(payload, v, err));
    CHECK(v.get("type") && v.get("type")->s == "tick");
    CHECK(v.get("events") && v.get("events")->i == 12);
    CHECK(v.get("recent") && v.get("recent")->arr.size() == 12);
    CHECK(v.get("alerts") && !v.get("alerts")->arr.empty());
    if (v.get("recent") && !v.get("recent")->arr.empty()) {
        const JValue& e = v.get("recent")->arr[0];
        CHECK(e.get("src_ip") && e.get("src_ip")->s == "203.0.113.9");
        CHECK(e.get("raw") == nullptr);  // в ленте только короткая сводка
    }

    // тишина: следующий tick сразу не шлётся, пульс — не чаще раза в 5 с
    s.feed.tick(now_ms() + 100);
    s.feed.tick(now_ms() + 6000);
    CHECK(ws.read_frame(op, payload));
    CHECK(json_parse(payload, v, err));
    CHECK(v.get("events") && v.get("events")->i == 0);

    // немаскированный кадр от клиента — нарушение протокола, сервер закрывает
    ws.send_frame(1, "x", false);
    CHECK(ws.read_frame(op, payload));
    CHECK_EQ(int(op), 8);
    CHECK(!ws.read_frame(op, payload));
    for (int i = 0; i < 200 && s.server->ws_clients() != 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK_EQ(s.server->ws_clients(), size_t(0));
}

TEST("web: panel files — SPA fallback, cache, security headers, no path traversal") {
    WebSiem s;
    auto r = s.call("GET", "/");
    CHECK_EQ(r.status, 200);
    CHECK(r.body.find("<title>Sentinel</title>") != std::string::npos);
    CHECK(r.header("content-type").find("text/html") != std::string::npos);
    CHECK(r.header("content-security-policy").find("script-src 'self'") != std::string::npos);
    CHECK(r.header("content-security-policy").find("frame-ancestors 'none'") != std::string::npos);
    CHECK_EQ(r.header("x-frame-options"), std::string("DENY"));
    CHECK_EQ(r.header("cache-control"), std::string("no-store"));

    auto spa = s.call("GET", "/alerts/42");  // маршрут панели -> index.html
    CHECK_EQ(spa.status, 200);
    CHECK(spa.body.find("id=root") != std::string::npos);

    auto js = s.call("GET", "/assets/app-1234.js");
    CHECK_EQ(js.status, 200);
    CHECK(js.header("content-type").find("text/javascript") != std::string::npos);
    CHECK(js.header("cache-control").find("immutable") != std::string::npos);

    CHECK_EQ(s.call("GET", "/assets/missing.js").status, 404);
    CHECK_EQ(s.call("GET", "/../secret.txt").status, 400);
    CHECK_EQ(s.call("GET", "/assets/..%2f..%2fsecret.txt").status, 400);
    CHECK(s.call("GET", "/%2e%2e/secret.txt").body.find("top secret") == std::string::npos);
    CHECK_EQ(s.call("POST", "/").status, 404);
    // API по-прежнему отвечает JSON-ошибкой, а не страницей
    CHECK_EQ(s.call("GET", "/api/v1/nope", {{"Authorization", "Bearer " + s.admin}}).status, 404);
    CHECK_EQ(s.call("GET", "/health").status, 200);
}
