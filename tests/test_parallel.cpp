// Тесты этапа 5: обнаружение в нескольких потоках даёт те же алерты, что и в одном.
#include <algorithm>
#include <atomic>
#include <climits>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <thread>

#include "core/crypto.hpp"
#include "detect/engine.hpp"
#include "detect/partition.hpp"
#include "detect/rules.hpp"
#include "parse/parsers.hpp"
#include "server/pipeline.hpp"
#include "testing.hpp"

using namespace sentinel;
namespace fs = std::filesystem;

#ifndef SENTINEL_SOURCE_DIR
#define SENTINEL_SOURCE_DIR "."
#endif

namespace {

struct PTmp {
    std::string path;
    PTmp() {
        path = (fs::temp_directory_path() / ("sentinel-par-" + random_hex(6))).string();
        fs::create_directories(path);
    }
    ~PTmp() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

std::vector<Rule> repo_rules() {
    auto res = load_rules_dir(std::string(SENTINEL_SOURCE_DIR) + "/rules");
    return res.rules;
}

std::vector<Rule> parse_rules(const std::string& yaml) {
    std::vector<Rule> out;
    std::string err;
    parse_rules_yaml(yaml, "test.yml", out, err);
    return out;
}

// Смесь трафика: обычные запросы, атаки на сайт, перебор SSH, успешные входы после перебора, sudo.
std::vector<Event> make_traffic(size_t n, uint64_t seed) {
    std::mt19937_64 rng(seed);
    static const char* paths[] = {"/", "/index.html", "/products/42", "/login", "/cart", "/static/app.js"};
    static const char* attacks[] = {"/item?id=1%20UNION%20SELECT%20password%20FROM%20users",
                                    "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "/download?file=../../../../etc/passwd",
                                    "/.env", "/ping?host=1;cat%20/etc/passwd", "/wp-login.php"};
    static const char* users[] = {"root", "admin", "ivan", "deploy", "guest", "oracle", "test"};
    ParseContext ctx;
    ctx.now_ms = 1792000000000;
    std::vector<Event> out;
    out.reserve(n);
    char buf[512];
    for (size_t i = 0; i < n; ++i) {
        unsigned r = unsigned(rng() % 100);
        int sec = int(i / 40 % 60), min = int(i / 2400 % 60);
        if (r < 55) {
            unsigned ip = unsigned(rng() % 300);
            std::snprintf(buf, sizeof(buf),
                          "198.18.%u.%u - - [12/Oct/2026:10:%02d:%02d +0000] \"GET %s HTTP/1.1\" %d 512 \"-\" \"Mozilla/5.0\"",
                          ip >> 8, ip & 255, min, sec, paths[rng() % 6], rng() % 4 ? 200 : 404);
        } else if (r < 70) {
            std::snprintf(buf, sizeof(buf),
                          "203.0.113.%u - - [12/Oct/2026:10:%02d:%02d +0000] \"%s %s HTTP/1.1\" %d 200 \"-\" \"%s\"",
                          unsigned(rng() % 40), min, sec, rng() % 3 ? "GET" : "POST", attacks[rng() % 6],
                          rng() % 2 ? 404 : 200, rng() % 5 ? "Mozilla/5.0" : "sqlmap/1.7");
        } else if (r < 88) {
            std::snprintf(buf, sizeof(buf),
                          "Oct 12 10:%02d:%02d web-01 sshd[%u]: Failed password for %s from 45.13.%u.%u port %u ssh2",
                          min, sec, unsigned(rng() % 30000), users[rng() % 7], unsigned(rng() % 2),
                          unsigned(rng() % 20), unsigned(30000 + rng() % 30000));
        } else if (r < 94) {
            std::snprintf(buf, sizeof(buf),
                          "Oct 12 10:%02d:%02d web-01 sshd[%u]: Accepted password for %s from 45.13.%u.%u port %u ssh2",
                          min, sec, unsigned(rng() % 30000), users[rng() % 7], unsigned(rng() % 2),
                          unsigned(rng() % 20), unsigned(30000 + rng() % 30000));
        } else if (r < 98) {
            std::snprintf(buf, sizeof(buf),
                          "Oct 12 10:%02d:%02d web-0%u sudo:   %s : 3 incorrect password attempts ; TTY=pts/0 ; "
                          "PWD=/home/x ; USER=root ; COMMAND=/bin/sh",
                          min, sec, unsigned(rng() % 3), users[rng() % 7]);
        } else {
            std::snprintf(buf, sizeof(buf),
                          "Oct 12 10:%02d:%02d web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=185.220.%u.%u DST=10.0.0.5 "
                          "PROTO=TCP SPT=40000 DPT=%u",
                          min, sec, unsigned(rng() % 2), unsigned(rng() % 5), unsigned(20 + rng() % 3000));
        }
        Event ev;
        if (parse_line(buf, LogFormat::Auto, ctx, ev)) out.push_back(std::move(ev));
    }
    for (size_t i = 0; i < out.size(); ++i) out[i].id = i + 1;
    return out;
}

// Алерт без номера — для сравнения наборов.
std::string sig(const Alert& a) {
    std::string s = a.rule_id + "|" + a.src_ip + "|" + a.user + "|" + a.host + "|" + std::to_string(a.count) + "|";
    for (auto id : a.event_ids) s += std::to_string(id) + ",";
    return s;
}

std::multiset<std::string> run_engine(const std::vector<Rule>& rules, const std::vector<Event>& evs) {
    DetectionEngine e;
    std::string err;
    e.load(rules, err);
    std::vector<Alert> out;
    for (auto& ev : evs) e.process(ev, out);
    std::multiset<std::string> s;
    for (auto& a : out) s.insert(sig(a));
    return s;
}

struct PipeRun {
    std::multiset<std::string> alerts;
    std::map<std::string, size_t> by_rule;
    size_t events = 0;
    bool ordered = true;
    PipelineStats stats;
};

PipeRun run_pipeline(const std::vector<Rule>& rules, const std::vector<Event>& evs, int threads, size_t batch,
                     std::function<void(Pipeline&, size_t)> during = nullptr) {
    PTmp d;
    std::string err;
    EventStore events;
    AlertStore alerts;
    StoreOptions so;
    so.dir = d.path;
    so.fsync = false;
    events.open(so, err);
    alerts.open(d.path, so.retention_ms, err);
    LiveStats live;
    PipeRun out;
    std::mutex mu;
    uint64_t last_id = 0;
    {
        Pipeline p(events, alerts, live, 10'000'000);
        p.set_detect_threads(threads);
        p.set_on_stored([&](const std::vector<Event>& ev, const std::vector<Alert>& al) {
            std::lock_guard<std::mutex> lock(mu);
            for (auto& e : ev) {
                if (e.id <= last_id) out.ordered = false;
                last_id = e.id;
            }
            out.events += ev.size();
            uint64_t prev_trigger = 0;
            for (auto& a : al) {
                out.alerts.insert(sig(a));
                ++out.by_rule[a.rule_id];
                uint64_t t = a.event_ids.empty() ? 0 : a.event_ids.back();
                if (t < prev_trigger) out.ordered = false;
                prev_trigger = t;
            }
        });
        auto eng = std::make_unique<DetectionEngine>();
        eng->load(rules, err);
        p.start(std::move(eng));
        for (size_t i = 0; i < evs.size(); i += batch) {
            std::vector<Event> b(evs.begin() + long(i), evs.begin() + long(std::min(evs.size(), i + batch)));
            while (!p.submit(std::move(b))) std::this_thread::sleep_for(std::chrono::milliseconds(1));
            if (during) during(p, i / batch);
        }
        p.stop();
        out.stats = p.stats();
    }
    events.close();
    alerts.close();
    return out;
}

}  // namespace

TEST("parallel: rules are split by source IP, chains stay together") {
    auto rules = repo_rules();
    REQUIRE(!rules.empty());
    RulePartition p = partition_rules(rules);
    CHECK_EQ(p.sharded.size() + p.global.size(), rules.size());
    bool priv_global = false, compromise_sharded = false;
    for (auto& r : p.global) priv_global |= r.id == "PRIV-FAIL-001";
    for (auto& r : p.sharded) compromise_sharded |= r.id == "AUTH-COMPROMISE-001";
    CHECK(priv_global);         // считает по [user, host]
    CHECK(compromise_sharded);  // цепочка по IP вместе с AUTH-BRUTE-001

    // цепочка по IP, ссылающаяся на правило «по пользователю», уходит в общий поток вместе с ним
    auto custom = parse_rules(R"(
- id: U-FAIL
  name: by user
  type: threshold
  threshold: 3
  window: 60
  group_by: [user]
  where: { type: auth, outcome: failure }
- id: SEQ
  name: chain
  type: sequence
  group_by: [src_ip]
  within: 600
  steps:
    - rule: U-FAIL
    - where: { outcome: success }
- id: IP-ONLY
  name: by ip
  type: match
  where: { type: web }
- id: OFF
  name: disabled
  enabled: false
  type: match
  group_by: [user]
  where: { type: web }
)");
    REQUIRE(custom.size() == 4u);
    RulePartition c = partition_rules(custom);
    REQUIRE(c.global.size() == 2u);
    REQUIRE(c.sharded.size() == 1u);
    CHECK_EQ(c.sharded[0].id, std::string("IP-ONLY"));  // group_by по умолчанию — src_ip
    CHECK(c.global[0].id == "U-FAIL" || c.global[1].id == "U-FAIL");

    // одинаковый адрес — всегда один поток, адреса распределяются по потокам
    std::vector<size_t> load(4, 0);
    for (int i = 0; i < 4000; ++i) {
        std::string ip = "10." + std::to_string(i % 7) + "." + std::to_string(i / 7 % 256) + "." + std::to_string(i % 251);
        size_t s = shard_of(ip, 4);
        CHECK_EQ(s, shard_of(ip, 4));
        ++load[s];
    }
    for (auto l : load) CHECK(l > 700 && l < 1300);
    CHECK_EQ(shard_of("anything", 1), size_t(0));
}

TEST("parallel: 1, 2, 3 and 7 threads give exactly the same alerts as a single engine") {
    auto rules = repo_rules();
    auto evs = make_traffic(60000, 7);
    REQUIRE(evs.size() > 55000u);
    auto expected = run_engine(rules, evs);
    REQUIRE(expected.size() > 100u);  // в смеси есть все виды атак
    std::map<std::string, size_t> kinds;
    for (auto& s : expected) ++kinds[s.substr(0, s.find('|'))];
    CHECK(kinds.count("PRIV-FAIL-001"));         // общий поток
    CHECK(kinds.count("AUTH-COMPROMISE-001"));   // цепочка
    CHECK(kinds.count("AUTH-BRUTE-001"));        // порог
    CHECK(kinds.count("WEB-SQLI-001"));          // совпадение

    for (int threads : {1, 2, 3, 7}) {
        for (size_t batch : {size_t(1), size_t(977), size_t(5000)}) {
            if (batch == 1 && threads != 3) continue;  // по одному событию — медленно, достаточно одного варианта
            std::vector<Event> part(evs.begin(), evs.begin() + long(batch == 1 ? 8000 : evs.size()));
            auto want = batch == 1 ? run_engine(rules, part) : expected;
            PipeRun r = run_pipeline(rules, part, threads, batch);
            CHECK_EQ(r.events, part.size());
            CHECK(r.ordered);
            CHECK_EQ(r.alerts.size(), want.size());
            CHECK(r.alerts == want);
            CHECK_EQ(r.stats.detect_threads, threads);
            CHECK_EQ(r.stats.global_thread, threads > 1);
            if (threads > 1) {
                CHECK_EQ(r.stats.global_rules, size_t(1));
                CHECK_EQ(r.stats.shard_events.size(), size_t(threads));
                uint64_t sum = 0;
                for (auto v : r.stats.shard_events) sum += v;
                CHECK_EQ(sum, uint64_t(part.size()));
                CHECK_EQ(r.stats.engine.events, uint64_t(part.size()));
            }
            CHECK_EQ(r.stats.engine.alerts, uint64_t(want.size()));
        }
    }
}

TEST("parallel: rules reload while events flow — nothing lost, order kept, new rules apply to later batches") {
    auto rules = repo_rules();
    auto evs = make_traffic(40000, 11);
    // перед заменой — без правила SQL-инъекций, после — со всеми правилами
    std::vector<Rule> without;
    for (auto& r : rules)
        if (r.id != "WEB-SQLI-001") without.push_back(r);
    size_t switch_after = 0;
    PipeRun r = run_pipeline(without, evs, 3, 1000, [&](Pipeline& p, size_t i) {
        if (i == 15) {
            auto e = std::make_unique<DetectionEngine>();
            std::string err;
            e->load(rules, err);
            p.replace_engine(std::move(e));
            switch_after = (i + 1) * 1000;
        }
        if (i % 7 == 3) {  // статистика из другого потока во время работы
            auto st = p.stats();
            CHECK(st.detect_threads == 3);
        }
    });
    CHECK_EQ(r.events, evs.size());
    CHECK(r.ordered);
    CHECK(r.by_rule["WEB-SQLI-001"] > 0);
    // SQL-инъекции до замены не обнаруживались
    for (auto& s : r.alerts) {
        if (s.rfind("WEB-SQLI-001|", 0) != 0) continue;
        uint64_t first = std::stoull(s.substr(s.rfind('|') + 1));
        CHECK(first > switch_after);
    }
}

TEST("parallel: full queue rejects, stop drains everything, restart works") {
    PTmp d;
    std::string err;
    EventStore events;
    AlertStore alerts;
    StoreOptions so;
    so.dir = d.path;
    so.fsync = false;
    REQUIRE(events.open(so, err));
    REQUIRE(alerts.open(d.path, so.retention_ms, err));
    LiveStats live;
    auto evs = make_traffic(5000, 3);
    size_t stored = 0;
    {
        Pipeline p(events, alerts, live, 3000);
        p.set_detect_threads(4);
        p.set_on_stored([&](const std::vector<Event>& ev, const std::vector<Alert>&) { stored += ev.size(); });
        CHECK(!p.submit(std::vector<Event>(evs.begin(), evs.begin() + 10)));  // ещё не запущен
        auto eng = std::make_unique<DetectionEngine>();
        eng->load(repo_rules(), err);
        p.start(std::move(eng));
        CHECK(!p.submit(std::vector<Event>(evs.begin(), evs.begin() + 3001)));  // больше очереди — отказ
        CHECK(p.submit(std::vector<Event>(evs.begin(), evs.begin() + 2000)));
        CHECK(p.submit(std::vector<Event>(evs.begin() + 2000, evs.begin() + 3000)));
        p.stop();
        CHECK_EQ(stored, size_t(3000));
        CHECK_EQ(p.stats().queued, uint64_t(0));
        CHECK_EQ(p.stats().rejected, uint64_t(3011));
        CHECK(!p.submit(std::vector<Event>(evs.begin(), evs.begin() + 10)));  // после остановки
        auto eng2 = std::make_unique<DetectionEngine>();
        eng2->load(repo_rules(), err);
        p.start(std::move(eng2));
        CHECK(p.submit(std::vector<Event>(evs.begin() + 3000, evs.end())));
        p.stop();
        CHECK_EQ(stored, size_t(5000));
    }
    CHECK_EQ(events.max_id(), uint64_t(5000));
    // без правил: события всё равно сохраняются
    {
        Pipeline p(events, alerts, live, 1000);
        p.set_detect_threads(2);
        p.start(nullptr);
        CHECK(p.submit(std::vector<Event>(evs.begin(), evs.begin() + 100)));
        p.stop();
    }
    CHECK_EQ(events.max_id(), uint64_t(5100));
    events.close();
    alerts.close();
}

TEST("store: parallel compression keeps block order, events stay searchable in flight, reopen reads all") {
    auto evs = make_traffic(30000, 21);
    std::string ref_dump;
    for (int threads : {0, 3}) {
        PTmp d;
        std::string err;
        {
            EventStore st;
            StoreOptions so;
            so.dir = d.path;
            so.fsync = false;
            so.block_events = 700;
            so.compress_threads = threads;
            REQUIRE(st.open(so, err));
            std::atomic<bool> done{false};
            std::atomic<size_t> seen_max{0};
            // поиск из другого потока во время записи: ни одно событие не «пропадает»
            std::thread reader([&] {
                while (!done.load()) {
                    EventQuery q;
                    q.limit = 5;
                    auto r = st.query(q);
                    if (!r.empty()) seen_max.store(std::max<size_t>(seen_max.load(), size_t(r[0].id)));
                    auto s = st.stats();
                    CHECK(s.events <= evs.size());
                }
            });
            for (size_t i = 0; i < evs.size(); i += 1300) {
                std::vector<Event> b(evs.begin() + long(i), evs.begin() + long(std::min(evs.size(), i + 1300)));
                size_t last = size_t(b.back().id);
                st.append(b);
                CHECK(st.get(last).has_value());  // только что добавленное уже находится
                EventQuery q;
                q.limit = 1;
                auto r = st.query(q);
                REQUIRE(!r.empty());
                CHECK_EQ(size_t(r[0].id), last);
            }
            done.store(true);
            reader.join();
            CHECK_EQ(st.stats().events, uint64_t(evs.size()));
            st.close();
        }
        EventStore again;
        StoreOptions so;
        so.dir = d.path;
        so.fsync = false;
        so.compress_threads = threads;
        REQUIRE(again.open(so, err));
        CHECK_EQ(again.max_id(), uint64_t(evs.size()));
        CHECK_EQ(again.stats().events, uint64_t(evs.size()));
        std::string dump;
        size_t n = again.scan(INT64_MIN, INT64_MAX, evs.size() + 10, [&](const Event& e) {
            dump += std::to_string(e.id) + e[Field::SrcIp] + "|";
            return true;
        });
        CHECK_EQ(n, evs.size());
        // блоки на диске по порядку: id идут подряд
        uint64_t prev = 0;
        bool ordered = true;
        again.scan(INT64_MIN, INT64_MAX, evs.size(), [&](const Event& e) {
            if (e.id != prev + 1) ordered = false;
            prev = e.id;
            return true;
        });
        CHECK(ordered);
        EventQuery q;
        q.equals = {{"src_ip", "45.13.1.7"}};
        q.limit = 100000;
        size_t by_ip = again.query(q).size();
        size_t want = 0;
        for (auto& e : evs) want += e[Field::SrcIp] == "45.13.1.7";
        CHECK_EQ(by_ip, want);
        if (threads == 0) ref_dump = dump;
        else CHECK(dump == ref_dump);  // с потоками и без — одно и то же содержимое
        again.close();
    }
}
