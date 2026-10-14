// SentinelCore — замер скорости: разбор, обнаружение, запись, поиск и сквозной приём по HTTP.
//
//   sentinel-bench [--events N] [--rules DIR] [--threads T]
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <thread>

#include "core/crypto.hpp"
#include "core/log.hpp"
#include "core/util.hpp"
#include "detect/engine.hpp"
#include "detect/partition.hpp"
#include "detect/rules.hpp"
#include "net/server.hpp"
#include "parse/parsers.hpp"
#include "server/api.hpp"
#include "server/config.hpp"
#include "server/live_stats.hpp"
#include "server/pipeline.hpp"
#include "store/alert_store.hpp"
#include "store/event_store.hpp"

using namespace sentinel;
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

static double secs_since(Clock::time_point t) {
    return std::chrono::duration<double>(Clock::now() - t).count();
}

static std::string fmt_rate(double per_sec) {
    std::ostringstream os;
    os << std::fixed << std::setprecision(per_sec >= 100 ? 0 : 2);
    if (per_sec >= 1e6) os << std::setprecision(2) << per_sec / 1e6 << " млн/с";
    else if (per_sec >= 1e3) os << per_sec / 1e3 << " тыс/с";
    else os << per_sec << " /с";
    return os.str();
}

static std::vector<std::string> generate(size_t n) {
    std::mt19937_64 rng(42);
    static const char* paths[] = {"/", "/index.html", "/products", "/products/42", "/cart", "/api/v1/items?page=2",
                                  "/static/app.js", "/static/style.css?v=0x1f", "/blog/how-to-update-profile",
                                  "/search?q=red+shoes", "/login", "/account/settings", "/favicon.ico"};
    static const char* uas[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        "curl/8.4.0"};
    static const char* attacks[] = {"/item?id=1%20UNION%20SELECT%20password%20FROM%20users",
                                    "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                                    "/download?file=../../../../etc/passwd", "/.env", "/ping?host=1;cat%20/etc/passwd"};
    std::vector<std::string> out;
    out.reserve(n);
    char buf[512];
    for (size_t i = 0; i < n; ++i) {
        unsigned r = unsigned(rng() % 100);
        int sec = int(i / 1000 % 60), min = int(i / 60000 % 60);
        if (r < 80) {
            unsigned ip = unsigned(rng() % 5000);
            std::snprintf(buf, sizeof(buf),
                          "10.%u.%u.%u - - [12/Oct/2026:10:%02d:%02d +0000] \"GET %s HTTP/1.1\" %d %u \"-\" \"%s\"",
                          ip >> 16, (ip >> 8) & 255, ip & 255, min, sec, paths[rng() % 13], rng() % 50 ? 200 : 404,
                          unsigned(rng() % 20000), uas[rng() % 4]);
        } else if (r < 85) {
            std::snprintf(buf, sizeof(buf),
                          "203.0.113.%u - - [12/Oct/2026:10:%02d:%02d +0000] \"GET %s HTTP/1.1\" 200 512 \"-\" \"sqlmap/1.7\"",
                          unsigned(rng() % 50), min, sec, attacks[rng() % 5]);
        } else if (r < 95) {
            std::snprintf(buf, sizeof(buf),
                          "Oct 12 10:%02d:%02d web-01 sshd[%u]: Failed password for %s from 45.13.%u.%u port %u ssh2",
                          min, sec, unsigned(rng() % 30000), rng() % 2 ? "root" : "admin", unsigned(rng() % 4),
                          unsigned(rng() % 50), unsigned(30000 + rng() % 30000));
        } else if (r < 99) {
            std::snprintf(buf, sizeof(buf),
                          "Oct 12 10:%02d:%02d web-01 sshd[%u]: Accepted publickey for deploy from 10.0.0.%u port %u ssh2",
                          min, sec, unsigned(rng() % 30000), unsigned(rng() % 10), unsigned(30000 + rng() % 30000));
        } else {
            std::snprintf(buf, sizeof(buf),
                          "Oct 12 10:%02d:%02d web-01 sudo:     ivan : TTY=pts/0 ; PWD=/home/ivan ; USER=root ; COMMAND=/usr/bin/apt update",
                          min, sec);
        }
        out.emplace_back(buf);
    }
    return out;
}

int main(int argc, char** argv) {
    size_t n = 500000;
    std::string rules_dir = "rules";
    int threads = 4;
    int detect_threads = 0;  // 0 — как на сервере (по числу ядер)
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--events") && i + 1 < argc) n = size_t(std::stoull(argv[++i]));
        else if (!std::strcmp(argv[i], "--rules") && i + 1 < argc) rules_dir = argv[++i];
        else if (!std::strcmp(argv[i], "--threads") && i + 1 < argc) threads = std::stoi(argv[++i]);
        else if (!std::strcmp(argv[i], "--detect-threads") && i + 1 < argc) detect_threads = std::stoi(argv[++i]);
    }
    log::set_level(log::Level::Error);
    std::cout << "SentinelCore benchmark: " << n << " строк логов, процессор: " << std::thread::hardware_concurrency()
              << " потоков\n\n";

    auto lines = generate(n);
    size_t bytes = 0;
    for (auto& l : lines) bytes += l.size() + 1;

    // 1. Разбор
    ParseContext ctx;
    ctx.now_ms = parse_iso8601("2026-10-12T12:00:00Z").value();
    std::vector<Event> events(n);
    auto t = Clock::now();
    for (size_t i = 0; i < n; ++i) {
        parse_line(lines[i], LogFormat::Auto, ctx, events[i]);
        events[i].id = i + 1;
    }
    double tp = secs_since(t);
    std::cout << "1. Разбор логов (1 поток):        " << fmt_rate(double(n) / tp) << "  (" << std::fixed
              << std::setprecision(0) << double(bytes) / tp / 1e6 << " МБ/с)\n";

    // 2. Обнаружение
    auto res = load_rules_dir(rules_dir);
    if (!res.errors.empty()) {
        std::cerr << "rules errors: " << res.errors[0] << "\n";
        return 1;
    }
    DetectionEngine eng;
    std::string err;
    if (!eng.load(res.rules, err)) {
        std::cerr << err << "\n";
        return 1;
    }
    std::vector<Alert> alerts;
    t = Clock::now();
    for (auto& e : events) eng.process(e, alerts);
    double td = secs_since(t);
    auto es = eng.stats();
    std::cout << "2. Обнаружение (" << res.rules.size() << " правил, 1 поток): " << fmt_rate(double(n) / td)
              << "  алертов: " << alerts.size() << ", подавлено повторов: " << es.suppressed << "\n";

    // 2б. Обнаружение в нескольких потоках: события делятся по IP, правила «не по IP» — в общем потоке
    int dt = detect_threads > 0 ? detect_threads : std::max(2, Pipeline::auto_threads());
    {
        RulePartition part = partition_rules(res.rules);
        std::vector<std::unique_ptr<DetectionEngine>> engs;
        for (int k = 0; k < dt; ++k) {
            engs.push_back(std::make_unique<DetectionEngine>());
            engs.back()->load(part.sharded, err);
        }
        auto glob = std::make_unique<DetectionEngine>();
        glob->load(part.global, err);
        std::vector<uint32_t> shard(events.size());
        std::vector<std::vector<Alert>> outs(size_t(dt) + 1);
        t = Clock::now();
        for (size_t i = 0; i < events.size(); ++i) shard[i] = uint32_t(shard_of(events[i][Field::SrcIp], size_t(dt)));
        std::vector<std::thread> th;
        for (int k = 0; k < dt; ++k)
            th.emplace_back([&, k] {
                for (size_t i = 0; i < events.size(); ++i)
                    if (shard[i] == uint32_t(k)) engs[size_t(k)]->process(events[i], outs[size_t(k)]);
            });
        th.emplace_back([&] {
            if (!part.global.empty())
                for (auto& e : events) glob->process(e, outs[size_t(dt)]);
        });
        for (auto& x : th) x.join();
        double tdp = secs_since(t);
        size_t na = 0;
        for (auto& o : outs) na += o.size();
        std::cout << "   Обнаружение, " << dt << " потока по IP + 1 общий: " << fmt_rate(double(n) / tdp)
                  << "  (в " << std::setprecision(1) << td / tdp << " раза быстрее, алертов: " << na
                  << (na == alerts.size() ? " — те же" : " — ОТЛИЧАЕТСЯ!") << ")\n";
    }

    // 3. Запись
    std::string dir = (fs::temp_directory_path() / ("sentinel-bench-" + random_hex(4))).string();
    {
        EventStore st;
        StoreOptions so;
        so.dir = dir;
        so.fsync = false;
        if (!st.open(so, err)) {
            std::cerr << err << "\n";
            return 1;
        }
        std::vector<Event> copy = events;
        t = Clock::now();
        for (size_t i = 0; i < copy.size(); i += 5000) {
            std::vector<Event> batch(std::make_move_iterator(copy.begin() + long(i)),
                                     std::make_move_iterator(copy.begin() + long(std::min(i + 5000, copy.size()))));
            st.append(batch);
        }
        st.flush();
        double ts = secs_since(t);
        auto ss = st.stats();
        std::cout << "3. Запись на диск со сжатием:     " << fmt_rate(double(n) / ts) << "  (на диске "
                  << std::setprecision(1) << double(ss.bytes_on_disk) / 1e6 << " МБ, сжатие "
                  << double(ss.raw_bytes) / double(ss.bytes_on_disk) << "x)\n";

        // 4. Поиск
        EventQuery q;
        q.equals = {{"src_ip", "10.0.7.7"}};
        q.limit = 1000;
        t = Clock::now();
        size_t found = 0;
        for (int k = 0; k < 20; ++k) found = st.query(q).size();
        double tq = secs_since(t) / 20;
        std::cout << "4. Поиск по IP (bloom-фильтры):    " << std::setprecision(1) << tq * 1000 << " мс на запрос ("
                  << found << " событий)\n";
        EventQuery qa;
        qa.equals = {{"src_ip", "192.168.99.99"}};  // такого IP нет — блоки отсекаются фильтрами
        t = Clock::now();
        for (int k = 0; k < 20; ++k) found = st.query(qa).size();
        std::cout << "   Поиск отсутствующего IP:        " << std::setprecision(2) << secs_since(t) / 20 * 1000
                  << " мс (данные не читаются)\n";
        EventQuery q2;
        q2.text = "etc/passwd";
        q2.limit = 100;
        t = Clock::now();
        found = st.query(q2).size();
        std::cout << "   Поиск по тексту (100 новых):    " << std::setprecision(1) << secs_since(t) * 1000 << " мс\n";
        st.close();
    }
    fs::remove_all(dir);

    // 5. Сквозной приём по HTTP: разбор + обнаружение + запись
    std::string dir2 = (fs::temp_directory_path() / ("sentinel-bench-" + random_hex(4))).string();
    {
        Config cfg;
        cfg.data_dir = dir2;
        std::string key = "bench-key";
        cfg.keys.push_back({"bench", Role::Admin, sha256_hex(key)});
        EventStore st;
        StoreOptions so;
        so.dir = dir2;
        so.fsync = false;
        st.open(so, err);
        AlertStore as;
        as.open(dir2, so.retention_ms, err);
        LiveStats live;
        Pipeline pipe(st, as, live, 2'000'000);
        pipe.set_detect_threads(detect_threads);
        auto e2 = std::make_unique<DetectionEngine>();
        e2->load(res.rules, err);
        pipe.start(std::move(e2));
        Api api(cfg, st, as, live, pipe);
        net::ServerOptions sopt;
        sopt.port = 0;
        sopt.workers = threads;
        net::HttpServer server(sopt, [&](const net::HttpRequest& rq, net::HttpResponse& rs) { api.handle(rq, rs); });
        if (!server.start(err)) {
            std::cerr << err << "\n";
            return 1;
        }
        // готовим тела запросов по 2000 строк
        std::vector<std::string> bodies;
        for (size_t i = 0; i < n; i += 2000) {
            std::string b;
            for (size_t k = i; k < std::min(i + 2000, n); ++k) {
                b += lines[k];
                b += '\n';
            }
            bodies.push_back(std::move(b));
        }
        std::atomic<size_t> next{0}, ok{0}, busy{0};
        t = Clock::now();
        std::vector<std::thread> clients;
        for (int c = 0; c < threads; ++c) {
            clients.emplace_back([&] {
                std::string e;
                net::socket_t s = net::connect_tcp("127.0.0.1", server.port(), e);
                if (s == net::kInvalidSocket) return;
                std::string resp;
                char buf[4096];
                while (true) {
                    size_t i = next.fetch_add(1);
                    if (i >= bodies.size()) break;
                    std::string req = "POST /api/v1/ingest HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + key +
                                      "\r\nContent-Type: text/plain\r\nContent-Length: " +
                                      std::to_string(bodies[i].size()) + "\r\n\r\n" + bodies[i];
                    if (!net::send_all(s, req.data(), req.size())) break;
                    resp.clear();
                    while (resp.find("\r\n\r\n") == std::string::npos ||
                           resp.size() < resp.find("\r\n\r\n") + 4 + 16) {
                        long r = net::recv_some(s, buf, sizeof(buf));
                        if (r <= 0) break;
                        resp.append(buf, size_t(r));
                        if (resp.find("}") != std::string::npos) break;
                    }
                    if (resp.find(" 202 ") != std::string::npos) ++ok;
                    else if (resp.find(" 503 ") != std::string::npos) {
                        ++busy;
                        next.fetch_sub(0);
                    }
                }
                net::close_socket(s);
            });
        }
        for (auto& th : clients) th.join();
        double t_send = secs_since(t);
        // ждём, пока конвейер всё обработает и запишет
        while (pipe.stats().queued > 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        pipe.stop();
        double t_all = secs_since(t);
        auto ps = pipe.stats();
        std::cout << "5. Сквозной приём по HTTP (" << threads << " клиента): " << fmt_rate(double(ps.accepted) / t_all)
                  << "  (приём " << fmt_rate(double(ps.accepted) / t_send) << ", принято " << ps.accepted
                  << ", отказов 503: " << busy.load() << ", алертов: " << ps.engine.alerts << ", потоков обнаружения: "
                  << ps.detect_threads << (ps.global_thread ? "+1" : "") << ")\n";
        server.stop();
        st.close();
        as.close();
    }
    fs::remove_all(dir2);
    return 0;
}
