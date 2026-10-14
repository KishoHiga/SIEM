// Тесты этапа 4: IP и подсети, блокировки, уведомления, брандмауэр агента, сохранение статистики.
#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include <cstring>
#include <random>

#include "core/ip.hpp"
#include "testing.hpp"

using namespace sentinel;

TEST("ip: parse and format") {
    CHECK_EQ(format_ip(*parse_ip("1.2.3.4")), std::string("1.2.3.4"));
    CHECK(!parse_ip("1.2.3"));
    CHECK(!parse_ip("1.2.3.256"));
    CHECK(!parse_ip("01.2.3.4"));
    CHECK(!parse_ip("1.2.3.4 "));
    CHECK(!parse_ip(""));
    CHECK(!parse_ip("1.2.3.4;rm -rf /"));
    CHECK_EQ(format_ip(*parse_ip("2001:DB8:0:0:0:0:0:1")), std::string("2001:db8::1"));
    CHECK_EQ(format_ip(*parse_ip("::")), std::string("::"));
    CHECK_EQ(format_ip(*parse_ip("::1")), std::string("::1"));
    CHECK_EQ(format_ip(*parse_ip("fe80::1:2")), std::string("fe80::1:2"));
    CHECK_EQ(format_ip(*parse_ip("::ffff:203.0.113.7")), std::string("203.0.113.7"));
    CHECK_EQ(format_ip(*parse_ip("64:ff9b::192.0.2.33")), std::string("64:ff9b::c000:221"));
    CHECK(!parse_ip("1::2::3"));
    CHECK(!parse_ip("1:2:3:4:5:6:7:8:9"));
    CHECK(!parse_ip("12345::"));
    CHECK(!parse_ip(":1"));
    CHECK(!parse_ip("1:"));
    CHECK(!parse_ip("g::1"));
}

#ifndef _WIN32
TEST("ip: matches the system inet_pton/inet_ntop (fuzz)") {
    std::mt19937 rng(5);
    int mismatches = 0;
    for (int i = 0; i < 20000; ++i) {
        uint8_t raw[16];
        for (auto& x : raw) x = uint8_t(rng() % 4 == 0 ? 0 : rng());
        if (rng() % 3 == 0)
            for (int k = int(rng() % 8); k < 16 && rng() % 4; ++k) raw[k] = 0;
        char sys[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, raw, sys, sizeof(sys));
        auto mine = parse_ip(sys);
        if (!mine) {
            ++mismatches;
            continue;
        }
        bool mapped = true;
        for (int k = 0; k < 10; ++k) mapped = mapped && raw[k] == 0;
        mapped = mapped && raw[10] == 0xFF && raw[11] == 0xFF;
        if (mapped) continue;  // мы намеренно приводим ::ffff:x к IPv4
        std::string back = format_ip(*mine);
        uint8_t again[16];
        if (inet_pton(AF_INET6, back.c_str(), again) != 1 || std::memcmp(again, raw, 16) != 0) ++mismatches;
    }
    CHECK_EQ(mismatches, 0);
}
#endif

TEST("ip: cidr and private ranges") {
    auto c = parse_cidr("10.1.2.3/8");
    REQUIRE(c.has_value());
    CHECK_EQ(format_cidr(*c), std::string("10.0.0.0/8"));
    CHECK(c->contains(*parse_ip("10.200.0.1")));
    CHECK(!c->contains(*parse_ip("11.0.0.1")));
    CHECK(!c->contains(*parse_ip("::1")));
    auto c6 = parse_cidr("2001:db8::/32");
    REQUIRE(c6.has_value());
    CHECK(c6->contains(*parse_ip("2001:db8:ffff::1")));
    CHECK(!c6->contains(*parse_ip("2001:db9::1")));
    CHECK(parse_cidr("1.2.3.4")->prefix == 32);
    CHECK(!parse_cidr("1.2.3.4/33"));
    CHECK(!parse_cidr("1.2.3.4/"));
    CHECK(parse_cidr("0.0.0.0/0")->contains(*parse_ip("8.8.8.8")));
    for (auto p : {"127.0.0.1", "10.0.0.5", "192.168.1.1", "172.20.0.1", "169.254.1.1", "100.64.0.1", "::1", "fe80::1",
                   "fd00::1", "224.0.0.1"})
        CHECK(is_private_or_special(*parse_ip(p)));
    for (auto p : {"8.8.8.8", "203.0.113.5", "45.13.10.2", "2001:4860:4860::8888", "172.32.0.1"})
        CHECK(!is_private_or_special(*parse_ip(p)));
}

// ---------------------------------------------------------------------------
// Блокировки, уведомления, SMTP, API реагирования, сохранение статистики
// ---------------------------------------------------------------------------
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>

#include "core/crypto.hpp"
#include "core/json.hpp"
#include "core/util.hpp"
#include "detect/engine.hpp"
#include "detect/rules.hpp"
#include "net/client.hpp"
#include "net/server.hpp"
#include "net/smtp.hpp"
#include "net/socket.hpp"
#include "net/tls.hpp"
#include "server/api.hpp"
#include "server/blocklist.hpp"
#include "server/live_stats.hpp"
#include "server/notifier.hpp"
#include "server/report.hpp"

#ifndef SENTINEL_SOURCE_DIR
#define SENTINEL_SOURCE_DIR "."
#endif

namespace fs = std::filesystem;

namespace {

struct TmpDir {
    std::string path;
    TmpDir() {
        path = (fs::temp_directory_path() / ("sentinel-s4-" + random_hex(6))).string();
        fs::create_directories(path);
    }
    ~TmpDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

Alert make_alert(uint64_t id, const std::string& rule, Severity sev, const std::string& ip) {
    Alert a;
    a.id = id;
    a.rule_id = rule;
    a.rule_name = "Правило " + rule;
    a.severity = sev;
    a.src_ip = ip;
    a.host = "web-01";
    a.message = "Атака с " + ip;
    a.ts = a.created = now_ms();
    return a;
}

// Самоподписанный сертификат для поддельных серверов в тестах
struct TestCert {
    TmpDir dir;
    std::string cert, key, fp;
    bool ok = false;
    TestCert() {
        cert = dir.path + "/s.crt";
        key = dir.path + "/s.key";
        std::string err;
        ok = net::tls_available() && net::generate_self_signed(cert, key, {"localhost", "127.0.0.1"}, 5, fp, err);
    }
};

// Поддельный HTTP(S)-приёмник: запоминает запросы (Telegram / вебхук)
struct FakeHttp {
    std::mutex mu;
    std::vector<net::HttpRequest> got;
    int status = 200;
    std::unique_ptr<net::HttpServer> server;
    explicit FakeHttp(std::shared_ptr<net::TlsContext> tls = nullptr) {
        net::ServerOptions o;
        o.port = 0;
        o.workers = 1;
        o.tls = std::move(tls);
        server = std::make_unique<net::HttpServer>(o, [this](const net::HttpRequest& rq, net::HttpResponse& rs) {
            std::lock_guard<std::mutex> lock(mu);
            got.push_back(rq);
            rs.status = status;
            rs.body = status == 200 ? "{\"ok\":true}" : "{\"ok\":false,\"description\":\"Bad Request: chat not found\"}";
        });
        std::string err;
        server->start(err);
    }
    size_t count() {
        std::lock_guard<std::mutex> lock(mu);
        return got.size();
    }
};

// Поддельный SMTP-сервер: STARTTLS (если есть сертификат), AUTH PLAIN, приём письма.
struct FakeSmtp {
    net::socket_t lsock = net::kInvalidSocket;
    uint16_t port = 0;
    std::thread th;
    std::shared_ptr<net::TlsContext> tls;
    std::string user = "bot@example.com", pass = "s3cret";
    std::mutex mu;
    std::string data, mail_from, auth_line;
    std::vector<std::string> rcpt;
    bool used_tls = false;
    bool offer_starttls = true;

    explicit FakeSmtp(std::shared_ptr<net::TlsContext> t) : tls(std::move(t)) {
        std::string err;
        lsock = net::listen_tcp("127.0.0.1", 0, err);
        sockaddr_in a{};
        socklen_t len = sizeof(a);
        getsockname(lsock, reinterpret_cast<sockaddr*>(&a), &len);
        port = ntohs(a.sin_port);
        th = std::thread([this] { serve(); });
    }
    ~FakeSmtp() {
        net::close_socket(lsock);
        if (th.joinable()) th.join();
    }

    void serve() {
        net::socket_t c = ::accept(lsock, nullptr, nullptr);
        if (c == net::kInvalidSocket) return;
        std::unique_ptr<net::TlsConn> tc;
        std::string buf;
        auto send = [&](const std::string& s) {
            if (tc) {
                size_t w;
                tc->write(s.data(), s.size(), w);
            } else {
                net::send_all(c, s.data(), s.size());
            }
        };
        auto line = [&](std::string& out) {
            while (buf.find("\r\n") == std::string::npos) {
                char tmp[4096];
                long n;
                if (tc) {
                    size_t g = 0;
                    n = tc->read(tmp, sizeof(tmp), g) == net::TlsConn::Io::Ok ? long(g) : -1;
                } else {
                    n = net::recv_some(c, tmp, sizeof(tmp));
                }
                if (n <= 0) return false;
                buf.append(tmp, size_t(n));
            }
            size_t p = buf.find("\r\n");
            out = buf.substr(0, p);
            buf.erase(0, p + 2);
            return true;
        };
        send("220 fake.smtp ESMTP\r\n");
        std::string l;
        bool in_data = false;
        while (line(l)) {
            if (in_data) {
                if (l == ".") {
                    in_data = false;
                    send("250 OK queued\r\n");
                } else {
                    std::lock_guard<std::mutex> lock(mu);
                    data += l + "\n";
                }
                continue;
            }
            std::string up = to_lower(l);
            if (starts_with(up, "ehlo")) {
                std::string caps = "250-fake.smtp\r\n";
                if (offer_starttls && tls && !tc) caps += "250-STARTTLS\r\n";
                caps += "250 AUTH PLAIN LOGIN\r\n";
                send(caps);
            } else if (up == "starttls") {
                send("220 Ready to start TLS\r\n");
                tc = net::TlsConn::create(*tls, c, "");
                if (!tc || tc->handshake() != net::TlsConn::Io::Ok) break;
                std::lock_guard<std::mutex> lock(mu);
                used_tls = true;
                buf.clear();
            } else if (starts_with(up, "auth plain ")) {
                std::lock_guard<std::mutex> lock(mu);
                auth_line = l.substr(11);
                std::string expect = std::string(1, '\0') + user + std::string(1, '\0') + pass;
                bool ok = auth_line == base64_encode(reinterpret_cast<const uint8_t*>(expect.data()), expect.size());
                send(ok ? "235 2.7.0 Authentication successful\r\n" : "535 5.7.8 Bad credentials\r\n");
            } else if (starts_with(up, "mail from:")) {
                std::lock_guard<std::mutex> lock(mu);
                mail_from = l.substr(10);
                send("250 OK\r\n");
            } else if (starts_with(up, "rcpt to:")) {
                std::lock_guard<std::mutex> lock(mu);
                rcpt.push_back(l.substr(8));
                send("250 OK\r\n");
            } else if (up == "data") {
                in_data = true;
                send("354 End data with <CR><LF>.<CR><LF>\r\n");
            } else if (up == "quit") {
                send("221 Bye\r\n");
                break;
            } else {
                send("502 Not implemented\r\n");
            }
        }
        if (tc) tc->shutdown();
        tc.reset();
        net::close_socket(c);
    }
};

std::string b64decode(const std::string& in) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, bits = -8;
    for (char c : in) {
        size_t p = chars.find(c);
        if (p == std::string::npos) continue;
        val = (val << 6) + int(p);
        bits += 6;
        if (bits >= 0) {
            out.push_back(char((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

}  // namespace

TEST("blocks: manual, auto policy, allowlist, private, limit, expiry, persistence") {
    TmpDir d;
    std::string err;
    {
        BlockList bl;
        REQUIRE(bl.open(d.path + "/blocks.json", err));
        AutoBlockPolicy p;
        p.min_severity = Severity::Critical;
        p.rules = {"WEB-SCANNER-001"};
        p.duration_ms = 3600000;
        p.allowlist = {*parse_cidr("198.51.100.0/24")};
        p.max_per_minute = 3;
        bl.set_policy(p);
        uint64_t v0 = bl.version();

        CHECK(bl.add_manual("203.0.113.9", 0, "вручную", "ivan") == BlockList::Result::Added);
        CHECK(bl.add_manual("203.0.113.0/24", 60000, "", "ivan") == BlockList::Result::Added);
        CHECK(bl.add_manual("127.0.0.1", 0, "", "ivan") == BlockList::Result::Invalid);
        CHECK(bl.add_manual("0.0.0.0/0", 0, "", "ivan") == BlockList::Result::Invalid);
        CHECK(bl.add_manual("1.2.3.4; rm -rf /", 0, "", "ivan") == BlockList::Result::Invalid);
        CHECK(bl.add_manual("198.51.100.7", 0, "", "ivan") == BlockList::Result::Allowlisted);
        CHECK(bl.add_manual("198.0.0.0/8", 0, "", "ivan") == BlockList::Result::Allowlisted);  // перекрывает белый список
        CHECK(bl.version() > v0);

        auto added = bl.on_alerts({
            make_alert(1, "WEB-SQLI-001", Severity::Critical, "45.1.1.1"),      // блок
            make_alert(2, "AUTH-BRUTE-001", Severity::High, "45.1.1.2"),        // ниже порога
            make_alert(3, "WEB-SCANNER-001", Severity::Medium, "45.1.1.3"),     // правило в списке
            make_alert(4, "WEB-SQLI-001", Severity::Critical, "10.0.0.5"),      // частный адрес
            make_alert(5, "WEB-SQLI-001", Severity::Critical, "198.51.100.20"), // белый список
            make_alert(6, "WEB-SQLI-001", Severity::Critical, "45.1.1.1"),      // уже есть, тот же срок
            make_alert(7, "WEB-SQLI-001", Severity::Critical, ""),              // без IP
        });
        REQUIRE(added.size() == 2);
        CHECK_EQ(added[0].ip, std::string("45.1.1.1"));
        CHECK_EQ(added[1].ip, std::string("45.1.1.3"));
        CHECK_EQ(added[0].by, std::string("auto"));
        CHECK_EQ(added[0].alert_id, 1u);
        auto st = bl.stats();
        CHECK_EQ(st.skipped_private, 1u);
        CHECK_EQ(st.skipped_allowlist, 3u);  // 2 вручную + 1 автоматически
        // лимит в минуту: уже 2, можно ещё 1
        auto more = bl.on_alerts({make_alert(8, "WEB-SQLI-001", Severity::Critical, "45.2.2.1"),
                                  make_alert(9, "WEB-SQLI-001", Severity::Critical, "45.2.2.2")});
        CHECK_EQ(more.size(), size_t(1));
        CHECK(bl.stats().skipped_limit >= 1);
        // поиск: адрес внутри заблокированной подсети
        CHECK(bl.find("203.0.113.77").has_value());
        CHECK_EQ(bl.find("203.0.113.77")->ip, std::string("203.0.113.0/24"));
        CHECK(!bl.find("8.8.8.8").has_value());
        // истечение срока
        uint64_t v1 = bl.version();
        bl.tick(now_ms() + 2 * 3600000);  // через 2 часа: всё срочное истекло
        CHECK(bl.version() > v1);
        auto left = bl.list();
        REQUIRE(left.size() == 1);
        CHECK_EQ(left[0].ip, std::string("203.0.113.9"));  // бессрочная осталась
        CHECK(bl.remove("203.0.113.9"));
        CHECK(!bl.remove("203.0.113.9"));
        CHECK(bl.add_manual("2001:db8:1::/48", 0, "сеть v6", "ivan") == BlockList::Result::Added);
        bl.flush();
    }
    BlockList again;
    REQUIRE(again.open(d.path + "/blocks.json", err));
    auto l = again.list();
    REQUIRE(l.size() == 1);
    CHECK_EQ(l[0].ip, std::string("2001:db8:1::/48"));
    CHECK_EQ(l[0].reason, std::string("сеть v6"));
}

TEST("notify: message texts, html escaping, digest") {
    NotifyConfig c;
    c.panel_url = "https://siem.example.com/";
    Notifier n(c);
    Notifier::Item it;
    it.alert = make_alert(42, "WEB-XSS-001", Severity::High, "203.0.113.5");
    it.alert.message = "XSS: /s?q=<script>alert(1)</script>&x";
    it.repeats = 3;
    it.blocked_until = now_ms() + 3600000;
    std::string html = n.format_text(it, true);
    CHECK(html.find("<b>") != std::string::npos);
    CHECK(html.find("&lt;script&gt;") != std::string::npos);
    CHECK(html.find("<script>") == std::string::npos);
    CHECK(html.find("https://siem.example.com/alerts/42") != std::string::npos);
    CHECK(html.find("ещё 3 похожих") != std::string::npos);
    CHECK(html.find("заблокирован на 1 ч") != std::string::npos);
    std::string text = n.format_text(it, false);
    CHECK(text.find("<script>alert(1)</script>") != std::string::npos);
    CHECK_EQ(n.subject(it), std::string("[Sentinel] Высокий: Правило WEB-XSS-001 (203.0.113.5)"));

    std::vector<Notifier::Item> many;
    for (int i = 0; i < 15; ++i) {
        Notifier::Item x;
        x.alert = make_alert(uint64_t(i), "R" + std::to_string(i), i % 3 ? Severity::High : Severity::Critical, "45.0.0." + std::to_string(i));
        if (i < 4) x.blocked_until = 0;
        many.push_back(x);
    }
    std::string dg = n.format_digest(many, false);
    CHECK(dg.find("15 новых алертов") != std::string::npos);
    CHECK(dg.find("критических: 5") != std::string::npos);
    CHECK(dg.find("заблокировано IP: 4") != std::string::npos);
    CHECK(dg.find("…и ещё 5") != std::string::npos);
    CHECK_EQ(n.digest_subject({many[0]}), std::string("[Sentinel] 1 новый алерт"));
    CHECK_EQ(n.digest_subject({many[0], many[1], many[2]}), std::string("[Sentinel] 3 новых алерта"));
}

TEST("notify: telegram over https (pinned), webhook json, cooldown, digest, failures reported") {
    if (!net::tls_available()) return;
    TestCert cert;
    REQUIRE(cert.ok);
    std::string err;
    auto tls = net::TlsContext::server(cert.cert, cert.key, err);
    REQUIRE(tls != nullptr);
    FakeHttp tg(std::shared_ptr<net::TlsContext>(std::move(tls)));
    FakeHttp hook;

    NotifyConfig c;
    c.min_severity = Severity::High;
    c.cooldown_ms = 600000;
    c.batch_ms = 500;
    c.pin = cert.fp;
    c.telegram.bot_token = "123:SECRET";
    c.telegram.chat_id = "-100777";
    c.telegram.api_url = "https://127.0.0.1:" + std::to_string(tg.server->port());
    c.webhook.url = "http://127.0.0.1:" + std::to_string(hook.server->port()) + "/hook";
    c.webhook.format = "json";
    Notifier n(c);
    n.start();

    // 1 алерт high + повтор (склеится) + 1 low (ниже порога)
    n.enqueue({make_alert(1, "R1", Severity::High, "45.9.9.9")}, {});
    n.enqueue({make_alert(2, "R1", Severity::High, "45.9.9.9"), make_alert(3, "R2", Severity::Low, "45.9.9.8")}, {});
    for (int i = 0; i < 100 && (tg.count() < 1 || hook.count() < 1); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    REQUIRE(tg.count() == 1);
    REQUIRE(hook.count() == 1);
    {
        std::lock_guard<std::mutex> lock(tg.mu);
        CHECK_EQ(tg.got[0].path, std::string("/bot123:SECRET/sendMessage"));
        JValue v;
        REQUIRE(json_parse(tg.got[0].body, v, err));
        CHECK_EQ(v.get("chat_id")->s, std::string("-100777"));
        CHECK_EQ(v.get("parse_mode")->s, std::string("HTML"));
        CHECK(v.get("text")->s.find("45.9.9.9") != std::string::npos);
    }
    {
        std::lock_guard<std::mutex> lock(hook.mu);
        CHECK_EQ(hook.got[0].path, std::string("/hook"));
        JValue v;
        REQUIRE(json_parse(hook.got[0].body, v, err));
        CHECK_EQ(v.get("alert")->get("rule_id")->s, std::string("R1"));
    }
    CHECK_EQ(n.stats().suppressed, 1u);

    // всплеск: 6 разных алертов -> одна сводка в каждый канал
    std::vector<Alert> burst;
    for (int i = 0; i < 6; ++i) burst.push_back(make_alert(uint64_t(10 + i), "B" + std::to_string(i), Severity::Critical, "45.8.8." + std::to_string(i)));
    n.enqueue(burst, {});
    for (int i = 0; i < 100 && tg.count() < 2; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    CHECK_EQ(tg.count(), size_t(2));
    CHECK_EQ(n.stats().digests, 1u);

    // ошибка канала видна в статусе; тест из панели возвращает результат по каждому каналу
    tg.status = 400;
    auto res = n.send_test("ivan");
    REQUIRE(res.size() == 2);
    CHECK(!res[0].ok);
    CHECK(res[0].error.find("chat not found") != std::string::npos);
    CHECK(res[0].error.find("SECRET") == std::string::npos);  // токен не попадает в ошибки
    CHECK(res[1].ok);
    auto st = n.stats();
    CHECK(st.channels[0].failed >= 1);
    CHECK(!st.channels[0].last_error.empty());
    n.stop();

    // неверный отпечаток — отказ
    NotifyConfig bad = c;
    bad.pin = "sha256:" + std::string(64, '0');
    bad.webhook.url.clear();
    Notifier nb(bad);
    auto r2 = nb.send_test("x");
    REQUIRE(r2.size() == 1);
    CHECK(!r2[0].ok);
    CHECK(r2[0].error.find("fingerprint") != std::string::npos);
}

TEST("smtp: STARTTLS + AUTH PLAIN, utf-8 subject and body") {
    if (!net::tls_available()) return;
    TestCert cert;
    REQUIRE(cert.ok);
    std::string err;
    std::shared_ptr<net::TlsContext> tls(net::TlsContext::server(cert.cert, cert.key, err));
    REQUIRE(tls != nullptr);
    FakeSmtp smtp(tls);
    net::SmtpOptions o;
    o.host = "127.0.0.1";
    o.port = smtp.port;
    o.tls = "starttls";
    o.username = smtp.user;
    o.password = smtp.pass;
    o.tls_opt.pin_sha256 = cert.fp;
    o.timeout_ms = 5000;
    net::SmtpMessage m{"bot@example.com", {"admin@example.com", "ivan@example.com"},
                       "[Sentinel] Критический: SQL-инъекция в запросе (203.0.113.5) — очень длинная тема письма",
                       "Строка 1\n.начинается с точки\nСтрока 3", ""};
    REQUIRE(net::smtp_send(o, m, err));
    if (!err.empty()) std::cerr << err << "\n";
    smtp.th.join();
    std::lock_guard<std::mutex> lock(smtp.mu);
    CHECK(smtp.used_tls);
    CHECK_EQ(smtp.mail_from, std::string("<bot@example.com>"));
    REQUIRE(smtp.rcpt.size() == 2);
    CHECK_EQ(smtp.rcpt[1], std::string("<ivan@example.com>"));
    CHECK(smtp.data.find("Subject: =?UTF-8?B?") != std::string::npos);
    CHECK(smtp.data.find("Content-Transfer-Encoding: base64") != std::string::npos);
    // тело: раскодируем base64 и сверим
    size_t body_at = smtp.data.find("\n\n");
    REQUIRE(body_at != std::string::npos);
    std::string body = b64decode(smtp.data.substr(body_at + 2));
    CHECK_EQ(body, std::string("Строка 1\r\n.начинается с точки\r\nСтрока 3"));
}

TEST("report: weekly letter goes through SMTP as text + HTML") {
    if (!net::tls_available()) return;
    TestCert cert;
    REQUIRE(cert.ok);
    std::string err;
    std::shared_ptr<net::TlsContext> tls(net::TlsContext::server(cert.cert, cert.key, err));
    REQUIRE(tls != nullptr);
    FakeSmtp smtp(tls);
    TmpDir d;
    AlertStore alerts;
    REQUIRE(alerts.open(d.path, 90LL * 86400000, err));
    std::vector<Alert> al = {make_alert(0, "WEB-SQLI-001", Severity::Critical, "45.1.1.1")};
    alerts.add(al);
    NotifyConfig nc;
    nc.panel_url = "https://siem.example.com/";
    nc.pin = cert.fp;
    nc.email.host = "127.0.0.1";
    nc.email.port = smtp.port;
    nc.email.tls = "starttls";
    nc.email.username = smtp.user;
    nc.email.password = smtp.pass;
    nc.email.from = "bot@example.com";
    nc.email.to = {"admin@example.com"};
    ReportConfig rc;
    rc.weekly = true;
    rc.to = {"boss@example.com"};
    ReportSources src;
    src.alerts = &alerts;
    ReportMailer m(rc, nc, src, d.path + "/reports.json");
    CHECK_EQ(m.send_now("ivan"), std::string());
    smtp.th.join();
    std::lock_guard<std::mutex> lock(smtp.mu);
    REQUIRE(smtp.rcpt.size() == 1);
    CHECK_EQ(smtp.rcpt[0], std::string("<boss@example.com>"));
    CHECK(smtp.data.find("multipart/alternative") != std::string::npos);
    CHECK(smtp.data.find("text/html") != std::string::npos);
    CHECK(m.last_error().empty());
}

TEST("smtp: refuses plain connection when STARTTLS is required, reports bad password") {
    if (!net::tls_available()) return;
    std::string err;
    {
        FakeSmtp smtp(nullptr);  // сервер без TLS
        net::SmtpOptions o;
        o.host = "127.0.0.1";
        o.port = smtp.port;
        o.tls = "auto";
        o.username = smtp.user;
        o.password = smtp.pass;
        o.timeout_ms = 3000;
        CHECK(!net::smtp_send(o, {"a@b.c", {"d@e.f"}, "s", "b", ""}, err));
        CHECK(err.find("STARTTLS") != std::string::npos);
    }
    {
        FakeSmtp smtp(nullptr);
        net::SmtpOptions o;
        o.host = "127.0.0.1";
        o.port = smtp.port;
        o.tls = "none";  // доверенный локальный релей
        o.username = smtp.user;
        o.password = "wrong";
        o.timeout_ms = 3000;
        CHECK(!net::smtp_send(o, {"a@b.c", {"d@e.f"}, "s", "b", ""}, err));
        CHECK(err.find("535") != std::string::npos);
        CHECK(err.find("wrong") == std::string::npos);
    }
    // заголовки не принимают переводы строк (защита от подмены письма)
    net::SmtpOptions o;
    o.host = "127.0.0.1";
    o.port = 1;
    CHECK(!net::smtp_send(o, {"a@b.c\r\nBcc: x@y.z", {"d@e.f"}, "s", "b", ""}, err));
    CHECK_EQ(net::rfc5322_date(0), std::string("Thu, 01 Jan 1970 00:00:00 +0000"));
    CHECK_EQ(net::rfc5322_date(parse_iso8601("2026-10-12T20:21:05Z").value()), std::string("Mon, 12 Oct 2026 20:21:05 +0000"));
    CHECK_EQ(net::encode_header_utf8("plain subject"), std::string("plain subject"));
}

TEST("stats: dashboard counters survive restart") {
    TmpDir d;
    std::string path = d.path + "/stats.bin";
    int64_t now = now_ms();
    {
        LiveStats s;
        std::vector<Event> evs(5);
        for (int i = 0; i < 5; ++i) {
            evs[size_t(i)][Field::SrcIp] = "45.0.0." + std::to_string(i % 2);
            evs[size_t(i)][Field::Source] = "nginx";
            evs[size_t(i)][Field::Type] = "web";
        }
        s.add_events(evs, now);
        s.add_alerts(std::vector<Alert>(2), now);
        REQUIRE(s.save(path));
    }
    LiveStats r;
    REQUIRE(r.load(path));
    auto snap = r.snapshot(now, 5, 10);
    CHECK_EQ(snap.events_total, 5u);
    CHECK_EQ(snap.events_24h, 5u);
    CHECK_EQ(snap.alerts_24h, 2u);
    REQUIRE(!snap.top_ips.empty());
    CHECK_EQ(snap.top_ips[0].first, std::string("45.0.0.0"));
    CHECK_EQ(snap.top_ips[0].second, 3u);
    // повреждённый файл не принимается и ничего не ломает
    {
        std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(10);
        f.put('\x7f');
    }
    LiveStats z;
    CHECK(!z.load(path));
    CHECK_EQ(z.snapshot(now, 5, 10).events_total, 0u);
}

TEST("api: blocks and notify endpoints, roles, agent sync with versions, agents persisted") {
    TmpDir d;
    Config cfg;
    cfg.data_dir = d.path;
    cfg.keys_file = d.path + "/keys.yaml";
    std::string admin = "admin-secret-1234567890", reader = "reader-secret-1234567890",
                analyst = "analyst-secret-1234567890", agent = "agent-secret-1234567890";
    cfg.keys = {{"admin", Role::Admin, sha256_hex(admin)},
                {"viewer", Role::Read, sha256_hex(reader)},
                {"soc", Role::Analyst, sha256_hex(analyst)},
                {"agent-web", Role::Ingest, sha256_hex(agent)}};
    std::string err;
    EventStore events;
    AlertStore alerts;
    StoreOptions so;
    so.dir = d.path;
    so.fsync = false;
    REQUIRE(events.open(so, err));
    REQUIRE(alerts.open(d.path, so.retention_ms, err));
    LiveStats live;
    BlockList blocks;
    REQUIRE(blocks.open(d.path + "/blocks.json", err));
    Notifier notifier(NotifyConfig{});
    auto res = load_rules_dir(std::string(SENTINEL_SOURCE_DIR) + "/rules");
    auto eng = std::make_unique<DetectionEngine>();
    REQUIRE(eng->load(res.rules, err));
    Pipeline pipe(events, alerts, live, 100000);
    pipe.set_on_stored([&](const std::vector<Event>&, const std::vector<Alert>& al) {
        if (!al.empty()) notifier.enqueue(al, blocks.on_alerts(al));
    });
    pipe.start(std::move(eng));
    {
        Api api(cfg, events, alerts, live, pipe);
        api.set_response(&blocks, &notifier);
        net::ServerOptions o;
        o.port = 0;
        o.workers = 2;
        net::HttpServer server(o, [&](const net::HttpRequest& rq, net::HttpResponse& rs) { api.handle(rq, rs); });
        REQUIRE(server.start(err));
        net::Url u;
        net::parse_url("http://127.0.0.1:" + std::to_string(server.port()), u, err);
        net::HttpClient c(u, {});
        auto call = [&](const std::string& method, const std::string& path, const std::string& key, const std::string& body = "",
                        const std::vector<std::pair<std::string, std::string>>& extra = {}) {
            net::ClientResponse r;
            auto h = extra;
            h.emplace_back("Authorization", "Bearer " + key);
            h.emplace_back("Content-Type", "application/json");
            if (!c.request(method, path, h, body, r, err)) r.status = -1;
            return r;
        };

        CHECK_EQ(call("POST", "/api/v1/blocks", reader, R"({"ip":"203.0.113.50"})").status, 403);
        auto r = call("POST", "/api/v1/blocks", analyst, R"({"ip":"203.0.113.50","duration":"2h","reason":"ручная"})");
        CHECK_EQ(r.status, 201);
        CHECK_EQ(call("POST", "/api/v1/blocks", analyst, R"({"ip":"127.0.0.1"})").status, 400);
        CHECK_EQ(call("POST", "/api/v1/blocks", analyst, R"({"ip":"1.2.3.4","duration":"soon"})").status, 400);
        r = call("GET", "/api/v1/blocks", reader);
        REQUIRE(r.status == 200);
        JValue v;
        REQUIRE(json_parse(r.body, v, err));
        REQUIRE(v.get("blocks")->arr.size() == 1);
        CHECK_EQ(v.get("blocks")->arr[0].get("by")->s, std::string("soc"));
        CHECK(v.get("policy")->get("auto_block")->b);
        r = call("GET", "/api/v1/blocks?ip=203.0.113.50", reader);
        CHECK(r.body.find("\"blocked\":true") != std::string::npos);

        // агент: первая синхронизация — полный список, вторая — "без изменений"
        r = call("GET", "/api/v1/agent/blocks?version=0", agent, "", {{"X-Sentinel-Firewall", "nftables; applied=1"}});
        REQUIRE(r.status == 200);
        REQUIRE(json_parse(r.body, v, err));
        CHECK(v.get("changed")->b);
        uint64_t ver = uint64_t(v.get("version")->i);
        CHECK(r.body.find("203.0.113.50") != std::string::npos);
        r = call("GET", "/api/v1/agent/blocks?version=" + std::to_string(ver), agent);
        CHECK(r.body.find("\"changed\":false") != std::string::npos);
        CHECK_EQ(call("GET", "/api/v1/agent/blocks", reader).status, 403);
        CHECK_EQ(call("GET", "/api/v1/blocks", agent).status, 403);

        // атака -> критический алерт -> автоблокировка -> версия изменилась
        std::string sqli = "45.77.1.2 - - [12/Oct/2026:10:00:00 +0000] \"GET /p?id=1%20UNION%20SELECT%20pass HTTP/1.1\" 200 5 \"-\" \"x\"\n";
        CHECK_EQ(call("POST", "/api/v1/ingest", agent, sqli, {{"Content-Type", "text/plain"}}).status, 202);
        for (int i = 0; i < 100 && !blocks.find("45.77.1.2"); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        REQUIRE(blocks.find("45.77.1.2").has_value());
        r = call("GET", "/api/v1/agent/blocks?version=" + std::to_string(ver), agent);
        CHECK(r.body.find("\"changed\":true") != std::string::npos);
        CHECK(r.body.find("45.77.1.2") != std::string::npos);

        // разблокировка
        CHECK_EQ(call("DELETE", "/api/v1/blocks?ip=45.77.1.2", reader).status, 403);
        CHECK_EQ(call("DELETE", "/api/v1/blocks?ip=45.77.1.2", analyst).status, 200);
        CHECK_EQ(call("DELETE", "/api/v1/blocks?ip=45.77.1.2", analyst).status, 404);

        // уведомления: каналов нет
        r = call("GET", "/api/v1/notify", reader);
        CHECK(r.body.find("\"enabled\":false") != std::string::npos);
        CHECK_EQ(call("POST", "/api/v1/notify/test", analyst).status, 403);
        CHECK_EQ(call("POST", "/api/v1/notify/test", admin).status, 409);

        // агент виден со своим брандмауэром; список сохраняется на диск
        r = call("GET", "/api/v1/agents", reader);
        CHECK(r.body.find("nftables; applied=1") != std::string::npos);
        api.save_agents();
        server.stop();
    }
    {
        Api api2(cfg, events, alerts, live, pipe);
        api2.load_agents();
        net::HttpRequest rq;
        rq.method = "GET";
        rq.path = "/api/v1/agents";
        rq.headers.emplace_back("authorization", "Bearer " + reader);
        net::HttpResponse rs;
        api2.handle(rq, rs);
        CHECK(rs.body.find("agent-web") != std::string::npos);
        CHECK(rs.body.find("nftables; applied=1") != std::string::npos);
    }
    pipe.stop();
    events.close();
    alerts.close();
}
