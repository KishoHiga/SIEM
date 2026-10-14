// Тесты этапа 6А: база стран/сетей, чёрные списки, обогащение событий, загрузка списков по сети.
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "core/crypto.hpp"
#include "core/util.hpp"
#include "detect/engine.hpp"
#include "detect/rules.hpp"
#include "enrich/enricher.hpp"
#include "enrich/geo.hpp"
#include "enrich/threat.hpp"
#include "net/client.hpp"
#include "net/server.hpp"
#include "net/socket.hpp"
#include "parse/parsers.hpp"
#include "server/live_stats.hpp"
#include "testing.hpp"

using namespace sentinel;
namespace fs = std::filesystem;

namespace {

struct ETmp {
    std::string path;
    ETmp() {
        path = (fs::temp_directory_path() / ("sentinel-enr-" + random_hex(6))).string();
        fs::create_directories(path);
    }
    ~ETmp() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    std::string file(const std::string& name, const std::string& text) const {
        std::string p = path + "/" + name;
        std::ofstream(p, std::ios::binary) << text;
        return p;
    }
};

IpAddr ip(const char* s) { return *parse_ip(s); }

std::string country(const GeoDb& db, const char* s) { return std::string(db.lookup(ip(s)).country); }

// Простой сервер на сокете: на каждое соединение — заранее заданный ответ (для chunked и редиректов).
struct RawHttp {
    net::socket_t lsock = net::kInvalidSocket;
    uint16_t port = 0;
    std::thread th;
    std::mutex mu;
    std::vector<std::string> answers;  // по очереди
    std::vector<std::string> requests;
    explicit RawHttp(std::vector<std::string> a) : answers(std::move(a)) {
        std::string err;
        lsock = net::listen_tcp("127.0.0.1", 0, err);
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        getsockname(lsock, reinterpret_cast<sockaddr*>(&addr), &len);
        port = ntohs(addr.sin_port);
        th = std::thread([this] {
            for (size_t i = 0; i < answers.size(); ++i) {
                net::socket_t c = ::accept(lsock, nullptr, nullptr);
                if (c == net::kInvalidSocket) return;
                std::string buf;
                char tmp[4096];
                while (buf.find("\r\n\r\n") == std::string::npos) {
                    long n = net::recv_some(c, tmp, sizeof(tmp));
                    if (n <= 0) break;
                    buf.append(tmp, size_t(n));
                }
                {
                    std::lock_guard<std::mutex> lock(mu);
                    requests.push_back(buf.substr(0, buf.find("\r\n")));
                }
                // ответ отдаём маленькими кусками — проверяем сборку по частям
                const std::string& ans = answers[i];
                for (size_t off = 0; off < ans.size(); off += 7) {
                    if (!net::send_all(c, ans.data() + off, std::min<size_t>(7, ans.size() - off))) break;
                    if (off % 70 == 0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
                net::close_socket(c);
            }
        });
    }
    ~RawHttp() {
#ifndef _WIN32
        ::shutdown(lsock, SHUT_RDWR);  // будит accept в другом потоке
#endif
        net::close_socket(lsock);
        if (th.joinable()) th.join();
    }
    std::string url(const std::string& path) const { return "http://127.0.0.1:" + std::to_string(port) + path; }
};

}  // namespace

TEST("geo: import DB-IP country/ASN/city and iptoasn files, lookup at range edges, IPv6, save/load") {
    ETmp d;
    std::string c = d.file("country.csv",
                           "ip_start,ip_end,country\n"  // заголовок — пропускается
                           "1.0.0.0,1.0.0.255,AU\n"
                           "1.0.1.0,1.0.3.255,cn\n"
                           "5.0.0.0,5.255.255.255,RU\n"
                           "5.8.0.0,5.8.0.255,DE\n"  // вложенный диапазон обрезает больший
                           "2a00:1450::,2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff,US\n"
                           "9.9.9.9,9.9.9.9,ZZ\n");
    std::string a = d.file("asn.csv",
                           "1.0.0.0,1.0.0.255,13335,\"Cloudflare, Inc.\"\n"
                           "5.0.0.0,5.255.255.255,12389,\"PJSC \"\"Rostelecom\"\"\"\n");
    std::string t = d.file("iptoasn.tsv", "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n10.0.0.0\t10.255.255.255\t0\tNone\tNot routed\n");
    std::string city = d.file("city.csv", "77.88.0.0,77.88.63.255,EU,RU,Moscow,Moscow,55.75,37.61\n");
    GeoImportStats st;
    std::string err, out = d.path + "/geo/geo.bin";
    REQUIRE(GeoDb::import_files({c, a, t, city}, out, st, err));
    CHECK_EQ(st.files, size_t(4));
    CHECK(st.skipped_lines >= 1u);
    GeoDb db;
    REQUIRE(db.load(out, err));
    CHECK_EQ(country(db, "1.0.0.0"), std::string("AU"));
    CHECK_EQ(country(db, "1.0.0.255"), std::string("AU"));
    CHECK_EQ(country(db, "1.0.1.0"), std::string("CN"));   // приведено к верхнему регистру
    CHECK_EQ(country(db, "1.0.4.0"), std::string(""));     // за концом диапазона
    CHECK_EQ(country(db, "0.255.255.255"), std::string(""));
    CHECK_EQ(country(db, "5.8.0.10"), std::string("DE"));
    CHECK_EQ(country(db, "5.7.255.255"), std::string("RU"));
    CHECK_EQ(country(db, "9.9.9.9"), std::string(""));      // ZZ — неизвестно
    CHECK_EQ(country(db, "2a00:1450:4001::1"), std::string("US"));
    CHECK_EQ(country(db, "2a00:1451::1"), std::string(""));
    CHECK_EQ(country(db, "77.88.55.60"), std::string("RU"));
    CHECK_EQ(std::string(db.lookup(ip("77.88.55.60")).city), std::string("Moscow"));
    GeoInfo g = db.lookup(ip("1.0.0.7"));
    CHECK_EQ(std::string(g.asn), std::string("13335"));
    CHECK_EQ(std::string(g.org), std::string("Cloudflare, Inc."));
    CHECK_EQ(std::string(db.lookup(ip("5.1.2.3")).org), std::string("PJSC \"Rostelecom\""));
    CHECK_EQ(std::string(db.lookup(ip("8.8.8.8")).org), std::string("GOOGLE"));
    CHECK_EQ(country(db, "8.8.8.8"), std::string("US"));       // страна из iptoasn
    CHECK(db.lookup(ip("10.1.1.1")).asn.empty());              // «Not routed» пропущено
    CHECK(db.sources().size() == 4u);

    // повреждённый файл не загружается
    {
        std::fstream f(out, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(40);
        f.put('\x55');
    }
    GeoDb bad;
    CHECK(!bad.load(out, err));
    CHECK(!bad.load(d.file("junk.bin", "hello"), err));
    // файл без диапазонов — понятная ошибка
    CHECK(!GeoDb::import_files({d.file("empty.csv", "just,text\n")}, out, st, err));
    CHECK(err.find("no IP ranges") != std::string::npos);
}

TEST("geo: large table lookups match a linear scan (fuzz)") {
    GeoDb db;
    std::vector<std::tuple<uint32_t, uint32_t, std::string>> ref;
    uint32_t cur = 1000;
    for (int i = 0; i < 3000; ++i) {
        uint32_t len = uint32_t((i * 7919) % 5000 + 1);
        uint32_t gap = uint32_t((i * 104729) % 300);
        cur += gap;
        std::string cc = std::string(1, char('A' + i % 26)) + char('A' + (i / 26) % 26);
        ref.emplace_back(cur, cur + len - 1, cc);
        auto mk = [](uint32_t v) {
            IpAddr a;
            a.b[0] = uint8_t(v >> 24), a.b[1] = uint8_t(v >> 16), a.b[2] = uint8_t(v >> 8), a.b[3] = uint8_t(v);
            return a;
        };
        db.add(GeoDb::Country, mk(cur), mk(cur + len - 1), cc);
        cur += len;
    }
    db.finish();
    GeoDb loaded;
    {
        ETmp d;
        std::string p = d.file("g.bin", db.serialize()), err;
        REQUIRE(loaded.load(p, err));
    }
    for (uint32_t v = 900; v < cur + 100; v += 37) {
        std::string want;
        for (auto& [s, e, cc] : ref)
            if (v >= s && v <= e) want = cc;
        IpAddr a;
        a.b[0] = uint8_t(v >> 24), a.b[1] = uint8_t(v >> 16), a.b[2] = uint8_t(v >> 8), a.b[3] = uint8_t(v);
        CHECK_EQ(std::string(loaded.lookup(a).country), want);
    }
}

TEST("threat: list formats, matching v4/v6 subnets, too broad entries skipped") {
    size_t bad = 0;
    auto l = parse_threat_list(
        "# FireHOL level1\n"
        "1.10.16.0/20\n"
        "5.188.10.0/23 ; SBL123456\n"
        "  45.155.205.233  \n"
        "0.0.0.0/0\n"          // слишком широкая — пропуск
        "2001:db8:dead::/48\n"
        "garbage line\n"
        "\n",
        &bad);
    CHECK_EQ(l.size(), size_t(4));
    CHECK_EQ(bad, size_t(2));
    ThreatSet set;
    set.add("firehol", l);
    set.add("tor", parse_threat_list("45.155.205.233\n185.220.101.1\n1.10.16.5\n"));
    CHECK_EQ(set.match(ip("1.10.31.255")), uint64_t(1));
    CHECK_EQ(set.match(ip("1.10.32.0")), uint64_t(0));
    CHECK_EQ(set.match(ip("1.10.16.5")), uint64_t(3));
    CHECK_EQ(set.names_of(3), std::string("firehol,tor"));
    CHECK_EQ(set.match(ip("185.220.101.1")), uint64_t(2));
    CHECK_EQ(set.match(ip("2001:db8:dead:1::5")), uint64_t(1));
    CHECK_EQ(set.match(ip("2001:db8:beef::1")), uint64_t(0));
    CHECK_EQ(set.match(ip("8.8.8.8")), uint64_t(0));
    CHECK_EQ(set.entries(0), size_t(4));
}

TEST("enrich: public addresses get geo.* and ti.*, internal ones nothing; alerts carry the country") {
    auto db = std::make_shared<GeoDb>();
    db->add(GeoDb::Country, ip("203.0.113.0"), ip("203.0.113.255"), "NL");
    db->add(GeoDb::Asn, ip("203.0.113.0"), ip("203.0.113.255"), std::string("64500\x1f") + "Example Hosting");
    db->finish();
    auto ti = std::make_shared<ThreatSet>();
    ti->add("firehol", parse_threat_list("203.0.113.66\n10.0.0.0/8\n"));
    Enricher e;
    e.set_geo(db);
    e.set_threat(ti);
    ParseContext ctx;
    ctx.now_ms = now_ms();
    std::vector<Event> batch;
    for (const char* line : {"203.0.113.66 - - [12/Oct/2026:10:00:00 +0000] \"GET /.env HTTP/1.1\" 404 0 \"-\" \"curl\"",
                             "203.0.113.66 - - [12/Oct/2026:10:00:01 +0000] \"GET / HTTP/1.1\" 200 0 \"-\" \"curl\"",
                             "203.0.113.7 - - [12/Oct/2026:10:00:01 +0000] \"GET / HTTP/1.1\" 200 0 \"-\" \"curl\"",
                             "10.1.2.3 - - [12/Oct/2026:10:00:01 +0000] \"GET / HTTP/1.1\" 200 0 \"-\" \"curl\"",
                             "198.51.100.1 - - [12/Oct/2026:10:00:01 +0000] \"GET / HTTP/1.1\" 200 0 \"-\" \"curl\""}) {
        Event ev;
        REQUIRE(parse_line(line, LogFormat::Auto, ctx, ev));
        batch.push_back(std::move(ev));
    }
    e.enrich(batch);
    CHECK_EQ(std::string(batch[0].get("geo.country")), std::string("NL"));
    CHECK_EQ(std::string(batch[0].get("geo.org")), std::string("Example Hosting"));
    CHECK_EQ(std::string(batch[0].get("ti.listed")), std::string("true"));
    CHECK_EQ(std::string(batch[1].get("ti.lists")), std::string("firehol"));
    CHECK_EQ(std::string(batch[2].get("geo.asn")), std::string("64500"));
    CHECK(batch[2].get("ti.listed").empty());
    CHECK(batch[3].extra.empty());  // внутренняя сеть: ни страны, ни списков (хотя 10/8 в списке)
    CHECK(batch[4].get("geo.country").empty());

    IpReport r = e.lookup("203.0.113.66");
    CHECK(r.valid);
    CHECK(!r.internal);
    CHECK_EQ(r.country, std::string("NL"));
    REQUIRE(r.lists.size() == 1u);
    CHECK(e.lookup("192.168.1.1").internal);
    CHECK(!e.lookup("nope").valid);

    // правило по стране и по чёрному списку, страна попадает в поля алерта
    std::vector<Rule> rules;
    std::string err;
    REQUIRE(parse_rules_yaml("- id: GEO-1\n  name: from NL\n  type: match\n  where: {geo.country: NL, http.status: 404}\n"
                             "- id: TI-1\n  name: listed\n  type: match\n  cooldown: 0\n  where: {ti.listed: 'true'}\n",
                             "t.yml", rules, err));
    DetectionEngine eng;
    REQUIRE(eng.load(rules, err));
    std::vector<Alert> out;
    for (auto& ev : batch) eng.process(ev, out);
    size_t geo = 0, listed = 0;
    for (auto& a : out) {
        geo += a.rule_id == "GEO-1";
        listed += a.rule_id == "TI-1";
        bool has_country = false;
        for (auto& f : a.fields) has_country |= f.first == "geo.country" && f.second == "NL";
        CHECK(has_country);
    }
    CHECK_EQ(geo, size_t(1));
    CHECK_EQ(listed, size_t(2));
}

TEST("threat: lists downloaded over HTTP (redirect, chunked), file lists, copy on disk used when offline") {
    ETmp d;
    std::string body = "# list\n198.51.100.0/24\n203.0.113.9\n";
    net::ServerOptions o;
    o.port = 0;
    o.workers = 1;
    std::atomic<int> hits{0};
    std::atomic<bool> down{false};
    net::HttpServer server(o, [&](const net::HttpRequest& rq, net::HttpResponse& rs) {
        ++hits;
        if (down.load()) {
            rs.status = 503;
            rs.body = "busy";
            return;
        }
        if (rq.path == "/old") {
            rs.status = 302;
            rs.headers.emplace_back("Location", "/lists/firehol.netset");
            rs.body = "";
            return;
        }
        rs.content_type = "text/plain";
        rs.body = rq.path == "/lists/firehol.netset" ? body : "nope";
        if (rq.path != "/lists/firehol.netset") rs.status = 404;
    });
    std::string err;
    REQUIRE(server.start(err));
    std::string base = "http://127.0.0.1:" + std::to_string(server.port());
    std::string own = d.file("own.txt", "192.0.2.77\n");
    ThreatConfig cfg;
    cfg.lists = {{"firehol", base + "/old", ""}, {"own", "", own}, {"missing", base + "/nothing", ""}};
    std::shared_ptr<const ThreatSet> got;
    std::mutex mu;
    auto on = [&](std::shared_ptr<const ThreatSet> s) {
        std::lock_guard<std::mutex> lock(mu);
        got = std::move(s);
    };
    {
        ThreatFeeds feeds(cfg, d.path + "/cache", on);
        CHECK(feeds.refresh_all());
        std::lock_guard<std::mutex> lock(mu);
        REQUIRE(got != nullptr);
        CHECK_EQ(got->names().size(), size_t(2));
        CHECK_EQ(got->names_of(got->match(ip("198.51.100.200"))), std::string("firehol"));
        CHECK_EQ(got->names_of(got->match(ip("192.0.2.77"))), std::string("own"));
        auto st = feeds.status();
        REQUIRE(st.size() == 3u);
        CHECK_EQ(st[0].entries, size_t(2));
        CHECK(st[0].last_error.empty());
        CHECK(st[2].last_error.find("HTTP 404") != std::string::npos);
    }
    CHECK(fs::exists(d.path + "/cache/firehol.txt"));
    // перезапуск без связи: работает по копии на диске, ошибка видна в статусе
    down.store(true);
    got.reset();
    {
        ThreatFeeds feeds(cfg, d.path + "/cache", on);
        feeds.start();
        for (int i = 0; i < 200; ++i) {
            bool tried = false;
            for (auto& s : feeds.status()) tried |= s.last_try != 0 && s.name == "missing";
            if (tried) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        feeds.stop();
        std::lock_guard<std::mutex> lock(mu);
        REQUIRE(got != nullptr);
        CHECK(got->match(ip("203.0.113.9")) != 0);
        auto st = feeds.status();
        CHECK(st[0].entries == 2u);
        CHECK(st[0].last_error.find("HTTP 503") != std::string::npos);
    }
    server.stop();
}

TEST("http client: chunked response, body until close, redirect limits") {
    std::string chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                          "6\r\nhello \r\n1a;ext=1\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\nX-Trailer: 1\r\n\r\n";
    std::string until_close = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nline1\nline2\n";
    RawHttp srv({chunked, until_close});
    net::ClientResponse r;
    std::string err;
    REQUIRE(net::http_get(srv.url("/a?x=1"), {}, 5000, r, err));
    CHECK_EQ(r.status, 200);
    CHECK_EQ(r.body, std::string("hello abcdefghijklmnopqrstuvwxyz"));
    REQUIRE(net::http_get(srv.url("/b"), {}, 5000, r, err));
    CHECK_EQ(r.body, std::string("line1\nline2\n"));
    {
        std::lock_guard<std::mutex> lock(srv.mu);
        REQUIRE(srv.requests.size() == 2u);
        CHECK_EQ(srv.requests[0], std::string("GET /a?x=1 HTTP/1.1"));
    }
    // бесконечный редирект — остановка
    std::string loop = "HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    RawHttp lp({loop, loop, loop, loop, loop});
    CHECK(!net::http_get(lp.url("/start"), {}, 5000, r, err, 1 << 20, 3));
    CHECK(err.find("too many redirects") != std::string::npos);
    // ответ больше предела
    std::string big = "HTTP/1.1 200 OK\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n" + std::string(5000, 'x');
    RawHttp bg({big});
    CHECK(!net::http_get(bg.url("/big"), {}, 5000, r, err, 1000));
    CHECK(err.find("too large") != std::string::npos);
}

TEST("stats: countries, hourly history for reports, old stats file still loads") {
    LiveStats s;
    int64_t now = 1792000000000;
    std::vector<Event> evs(3);
    for (auto& e : evs) {
        e[Field::SrcIp] = "203.0.113.1";
        e[Field::Source] = "nginx";
        e.extra_set("geo.country", "NL");
    }
    evs[2].extra_set("geo.country", "DE");
    s.add_events(evs, now - 5 * 3600000);  // 5 часов назад
    s.add_events(evs, now);
    std::vector<Alert> al(2);
    s.add_alerts(al, now);
    auto snap = s.snapshot(now, 60, 10);
    REQUIRE(snap.top_countries.size() == 2u);
    CHECK_EQ(snap.top_countries[0].first, std::string("NL"));
    CHECK_EQ(snap.top_countries[0].second, uint64_t(4));
    auto p = s.period(now - 24 * 3600000, now, 10);
    CHECK_EQ(p.events, uint64_t(6));
    CHECK_EQ(p.alerts, uint64_t(2));
    CHECK_EQ(p.hours.size(), size_t(2));
    CHECK(p.data_from <= now - 5 * 3600000);
    // через 10 дней: на панели (сутки) пусто, в отчёте за месяц — всё
    int64_t later = now + 10LL * 86400000;
    s.add_events(evs, later);
    CHECK_EQ(s.snapshot(later, 60, 10).top_countries[0].second, uint64_t(2));
    CHECK_EQ(s.period(later - 31LL * 86400000, later, 10).events, uint64_t(9));
    CHECK_EQ(s.period(later - 31LL * 86400000, later, 10).top_countries[0].second, uint64_t(6));
    ETmp d;
    REQUIRE(s.save(d.path + "/stats.bin"));
    LiveStats z;
    REQUIRE(z.load(d.path + "/stats.bin"));
    CHECK_EQ(z.period(later - 31LL * 86400000, later, 10).events, uint64_t(9));

    // файл старого формата (этапы 4–5): загружается, страны пусты
    std::string body;
    put_varint(body, 42);  // всего событий
    put_varint(body, 0);   // минут нет
    put_varint(body, 1);   // один час
    put_varint(body, uint64_t(now / 3600000));
    for (int m = 0; m < 3; ++m) {
        put_varint(body, 1);
        put_bytes(body, m == 0 ? "1.2.3.4" : m == 1 ? "nginx" : "web");
        put_varint(body, 5);
    }
    std::string old;
    put_u32(old, 0x53544153);
    put_u32(old, crc32(body.data(), body.size()));
    old += body;
    { std::ofstream(d.path + "/old.bin", std::ios::binary) << old; }
    LiveStats o;
    REQUIRE(o.load(d.path + "/old.bin"));
    auto os = o.snapshot(now, 60, 10);
    CHECK_EQ(os.events_total, uint64_t(42));
    REQUIRE(os.top_ips.size() == 1u);
    CHECK(os.top_countries.empty());
}

#include "core/json.hpp"
#include "server/api.hpp"
#include "server/blocklist.hpp"
#include "server/pipeline.hpp"

TEST("api: IP card — country, lists, block, activity and alerts; events enriched at ingest") {
    ETmp d;
    Config cfg;
    cfg.data_dir = d.path;
    cfg.keys_file = d.path + "/keys.yaml";
    std::string reader = "reader-secret-1234567890", ingest = "ingest-secret-1234567890";
    cfg.keys = {{"viewer", Role::Read, sha256_hex(reader)}, {"web-01", Role::Ingest, sha256_hex(ingest)}};
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
    Enricher enr;
    auto db = std::make_shared<GeoDb>();
    db->add(GeoDb::Country, ip("203.0.113.0"), ip("203.0.113.255"), "NL");
    db->add(GeoDb::Asn, ip("203.0.113.0"), ip("203.0.113.255"), std::string("64500\x1f") + "Example Hosting");
    db->finish();
    enr.set_geo(db);
    auto ti = std::make_shared<ThreatSet>();
    ti->add("firehol", parse_threat_list("203.0.113.66\n"));
    enr.set_threat(ti);
    auto res = load_rules_dir(std::string(SENTINEL_SOURCE_DIR) + "/rules");
    auto eng = std::make_unique<DetectionEngine>();
    REQUIRE(eng->load(res.rules, err));
    Pipeline pipe(events, alerts, live, 100000);
    pipe.start(std::move(eng));
    {
        Api api(cfg, events, alerts, live, pipe);
        api.set_response(&blocks, nullptr);
        api.set_enrichment(&enr, nullptr);
        net::ServerOptions o;
        o.port = 0;
        o.workers = 2;
        net::HttpServer server(o, [&](const net::HttpRequest& rq, net::HttpResponse& rs) { api.handle(rq, rs); });
        REQUIRE(server.start(err));
        net::Url u;
        net::parse_url("http://127.0.0.1:" + std::to_string(server.port()), u, err);
        net::HttpClient c(u, {});
        auto call = [&](const std::string& m, const std::string& path, const std::string& key, const std::string& body = "") {
            net::ClientResponse r;
            if (!c.request(m, path, {{"Authorization", "Bearer " + key}, {"Content-Type", "text/plain"}}, body, r, err))
                r.status = -1;
            return r;
        };
        std::string lines;
        for (int i = 0; i < 8; ++i)
            lines += "203.0.113.66 - - [12/Oct/2026:10:00:0" + std::to_string(i) + " +0000] \"GET /item.php?id=1%20UNION%20SELECT%20pass HTTP/1.1\" 200 1 \"-\" \"sqlmap/1.7\"\n";
        lines += "203.0.113.66 - - [13/Oct/2026:10:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 1 \"-\" \"sqlmap/1.7\"\n";
        lines += "198.51.100.5 - - [13/Oct/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"Mozilla\"\n";
        REQUIRE(call("POST", "/api/v1/ingest", ingest, lines).status == 202);
        for (int i = 0; i < 300 && pipe.stats().queued > 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        Block b;
        REQUIRE(blocks.add_manual("203.0.113.0/24", 0, "хостинг атакующих", "ivan", &b) == BlockList::Result::Added);

        auto r = call("GET", "/api/v1/ip/203.0.113.66", reader);
        REQUIRE(r.status == 200);
        JValue v;
        REQUIRE(json_parse(r.body, v, err));
        CHECK_EQ(v.get("country")->s, std::string("NL"));
        CHECK_EQ(v.get("org")->s, std::string("Example Hosting"));
        CHECK(!v.get("internal")->b);
        REQUIRE(v.get("lists")->arr.size() == 1u);
        CHECK_EQ(v.get("block")->get("ip")->s, std::string("203.0.113.0/24"));  // заблокирована вся сеть
        const JValue* ev = v.get("events");
        CHECK_EQ(ev->get("count")->i, int64_t(9));
        CHECK_EQ(ev->get("by_day")->arr.size(), size_t(2));
        CHECK_EQ(ev->get("paths")->arr[0].get("value")->s, std::string("/item.php"));  // без строки запроса
        CHECK_EQ(ev->get("paths")->arr[0].get("count")->i, int64_t(8));
        CHECK_EQ(ev->get("user_agents")->arr[0].get("value")->s, std::string("sqlmap/1.7"));
        const JValue* al = v.get("alerts");
        CHECK(al->get("count")->i >= 1);
        bool sqli = false;
        for (auto& x : al->get("by_rule")->arr) sqli |= x.get("rule_id")->s == "WEB-SQLI-001";
        CHECK(sqli);
        // алерт несёт страну и список
        REQUIRE(!al->get("recent")->arr.empty());
        CHECK(al->get("recent")->arr[0].get("fields")->get("geo.country") != nullptr);

        // события сохранены с полями geo.* и ti.* — по ним ищется
        r = call("GET", "/api/v1/events?geo.country=NL&limit=100", reader);
        REQUIRE(json_parse(r.body, v, err));
        CHECK_EQ(v.get("events")->arr.size(), size_t(9));
        r = call("GET", "/api/v1/events?ti.listed=true&limit=100", reader);
        REQUIRE(json_parse(r.body, v, err));
        CHECK_EQ(v.get("events")->arr.size(), size_t(9));

        r = call("GET", "/api/v1/ip/10.0.0.1", reader);
        REQUIRE(json_parse(r.body, v, err));
        CHECK(v.get("internal")->b);
        CHECK_EQ(v.get("events")->get("count")->i, int64_t(0));
        CHECK_EQ(call("GET", "/api/v1/ip/not-an-ip", reader).status, 400);
        CHECK_EQ(call("GET", "/api/v1/ip/203.0.113.66", ingest).status, 403);
        r = call("GET", "/api/v1/stats?minutes=60", reader);
        CHECK(r.body.find("\"top_countries\":[{\"country\":\"NL\"") != std::string::npos);
        CHECK(r.body.find("\"country\":\"NL\",\"listed\":true") != std::string::npos);
        r = call("GET", "/api/v1/threat", reader);
        REQUIRE(r.status == 200);
        CHECK(r.body.find("\"available\":true") != std::string::npos);
        server.stop();
    }
    pipe.stop();
    events.close();
    alerts.close();
}
