#include <filesystem>
#include <fstream>
#include <random>

#include "core/crypto.hpp"
#include "core/util.hpp"
#include "store/alert_store.hpp"
#include "store/codec.hpp"
#include "store/event_store.hpp"
#include "store/lz.hpp"
#include "testing.hpp"

using namespace sentinel;
namespace fs = std::filesystem;

namespace {
struct TempDir {
    std::string path;
    TempDir() {
        path = (fs::temp_directory_path() / ("sentinel-test-" + random_hex(6))).string();
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

Event make_event(uint64_t id, int64_t ts) {
    Event e;
    e.id = id;
    e.ts = ts;
    e.received = ts + 5;
    e[Field::Type] = "web";
    e[Field::Source] = "nginx";
    e[Field::SrcIp] = "10.0." + std::to_string((id / 256) % 256) + "." + std::to_string(id % 256);
    e[Field::HttpMethod] = "GET";
    e[Field::HttpPath] = "/page/" + std::to_string(id % 50);
    e[Field::HttpStatus] = id % 10 == 0 ? "404" : "200";
    e[Field::Message] = "GET /page/" + std::to_string(id % 50) + " -> 200 marker" + std::to_string(id);
    e.extra_set("k", "v" + std::to_string(id % 3));
    return e;
}
}  // namespace

TEST("lz: roundtrip on different data") {
    std::mt19937 rng(1);
    std::vector<std::string> inputs = {"", "a", "abcd", "abcdabcdabcdabcdabcdabcd", std::string(100000, 'x')};
    std::string rnd;
    for (int i = 0; i < 70000; ++i) rnd.push_back(char(rng()));
    inputs.push_back(rnd);
    std::string logs;
    for (int i = 0; i < 2000; ++i)
        logs += "203.0.113." + std::to_string(i % 20) + " - - [12/Oct/2026:10:00:00 +0000] \"GET /api/items/" +
                std::to_string(i) + " HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0 (X11; Linux x86_64)\"\n";
    inputs.push_back(logs);
    for (auto& in : inputs) {
        std::string c, d;
        lz::compress(in, c);
        CHECK(lz::decompress(c, in.size(), d));
        CHECK(d == in);
    }
    std::string c;
    lz::compress(logs, c);
    CHECK(c.size() * 4 < logs.size());  // логи сжимаются минимум в 4 раза
}

TEST("lz: corrupt input never crashes") {
    std::mt19937 rng(2);
    std::string src;
    for (int i = 0; i < 5000; ++i) src += "token" + std::to_string(i % 37) + " ";
    std::string c;
    lz::compress(src, c);
    for (int it = 0; it < 3000; ++it) {
        std::string bad = c;
        int muts = 1 + int(rng() % 4);
        for (int k = 0; k < muts; ++k) bad[rng() % bad.size()] = char(rng());
        if (rng() % 3 == 0) bad.resize(rng() % bad.size());
        std::string out;
        lz::decompress(bad, src.size(), out);
    }
    CHECK(true);
}

TEST("codec: event and alert roundtrip") {
    Event e = make_event(42, 1700000000123);
    e[Field::Raw] = std::string("bin\0ary", 7);
    std::string buf;
    encode_event(e, buf);
    Reader r(buf);
    Event d;
    REQUIRE(decode_event(r, d));
    CHECK_EQ(d.id, 42u);
    CHECK_EQ(d.ts, int64_t(1700000000123));
    CHECK_EQ(d.received, int64_t(1700000000128));
    CHECK(d.f == e.f);
    CHECK(d.extra == e.extra);

    Alert a;
    a.id = 7;
    a.ts = 1;
    a.created = 2;
    a.rule_id = "R";
    a.rule_name = "Правило";
    a.severity = Severity::High;
    a.status = AlertStatus::Resolved;
    a.src_ip = "1.2.3.4";
    a.message = "msg";
    a.count = 5;
    a.event_ids = {1, 2, 3};
    a.fields = {{"a", "b"}};
    std::string ab;
    encode_alert(a, ab);
    Reader ar(ab);
    Alert b;
    REQUIRE(decode_alert(ar, b));
    CHECK_EQ(b.rule_name, a.rule_name);
    CHECK(b.severity == Severity::High && b.status == AlertStatus::Resolved);
    CHECK(b.event_ids == a.event_ids);
}

TEST("store: write, query, reopen") {
    TempDir tmp;
    StoreOptions opt;
    opt.dir = tmp.path;
    opt.block_events = 1000;
    opt.fsync = false;
    const int64_t t0 = 1760000000000;
    {
        EventStore st;
        std::string err;
        REQUIRE(st.open(opt, err));
        std::vector<Event> batch;
        for (uint64_t i = 1; i <= 10500; ++i) {
            batch.push_back(make_event(i, t0 + int64_t(i) * 1000));
            if (batch.size() == 700) st.append(batch);
        }
        st.append(batch);
        // 500 событий ещё в памяти — должны находиться
        EventQuery q;
        q.limit = 5;
        auto r = st.query(q);
        REQUIRE(r.size() == 5);
        CHECK_EQ(r[0].id, 10500u);
        CHECK_EQ(r[4].id, 10496u);
        st.close();
    }
    EventStore st;
    std::string err;
    REQUIRE(st.open(opt, err));
    CHECK_EQ(st.max_id(), 10500u);
    auto s = st.stats();
    CHECK_EQ(s.events, 10500u);
    CHECK(s.bytes_on_disk * 3 < s.raw_bytes);  // сжатие

    EventQuery byip;
    byip.equals = {{"src_ip", "10.0.1.44"}};  // id = 256 + 44 = 300
    auto r = st.query(byip);
    REQUIRE(r.size() == 1);
    CHECK_EQ(r[0].id, 300u);
    CHECK_EQ(r[0][Field::HttpPath], std::string("/page/0"));

    EventQuery bytext;
    bytext.text = "MARKER777";
    auto r2 = st.query(bytext);
    // marker777, marker7770..7779 -> 11
    CHECK_EQ(r2.size(), size_t(11));

    EventQuery bytime;
    bytime.from = t0 + 5000 * 1000;
    bytime.to = t0 + 5009 * 1000;
    bytime.limit = 1000;
    CHECK_EQ(st.query(bytime).size(), size_t(10));

    EventQuery page;
    page.limit = 3;
    page.before_id = 101;
    auto r3 = st.query(page);
    REQUIRE(r3.size() == 3);
    CHECK_EQ(r3[0].id, 100u);

    EventQuery extra;
    extra.equals = {{"k", "v2"}, {"http.status", "404"}};
    extra.limit = 100000;
    // id%3==2 и id%10==0 -> id%30==20
    CHECK_EQ(st.query(extra).size(), size_t(10500 / 30));

    auto one = st.get(1234);
    REQUIRE(one.has_value());
    CHECK_EQ(one->id, 1234u);
    CHECK(!st.get(999999).has_value());
}

TEST("store: damaged tail is cut, earlier data survives") {
    TempDir tmp;
    StoreOptions opt;
    opt.dir = tmp.path;
    opt.block_events = 100;
    opt.fsync = false;
    {
        EventStore st;
        std::string err;
        REQUIRE(st.open(opt, err));
        std::vector<Event> batch;
        for (uint64_t i = 1; i <= 300; ++i) batch.push_back(make_event(i, 1760000000000 + int64_t(i)));
        st.append(batch);
        st.close();
    }
    // Портим конец файла: дописываем мусор и обрезаем последний блок наполовину
    std::string seg;
    for (auto& e : fs::directory_iterator(tmp.path + "/events")) seg = e.path().string();
    REQUIRE(!seg.empty());
    auto size = fs::file_size(seg);
    fs::resize_file(seg, size - 50);
    {
        std::ofstream f(seg, std::ios::app | std::ios::binary);
        f << "garbage";
    }
    EventStore st;
    std::string err;
    REQUIRE(st.open(opt, err));
    CHECK_EQ(st.stats().events, 200u);  // два целых блока из трёх
    EventQuery q;
    q.limit = 1000;
    CHECK_EQ(st.query(q).size(), size_t(200));
}

TEST("store: retention deletes old segments") {
    TempDir tmp;
    StoreOptions opt;
    opt.dir = tmp.path;
    opt.block_events = 10;
    opt.fsync = false;
    opt.retention_ms = 1000;
    opt.segment_max_age_ms = 1;
    opt.compress_threads = 0;  // блоки пишутся сразу (с потоками сжатия — в течение flush_interval)
    EventStore st;
    std::string err;
    REQUIRE(st.open(opt, err));
    std::vector<Event> batch;
    for (uint64_t i = 1; i <= 30; ++i) batch.push_back(make_event(i, 1760000000000));
    st.append(batch);
    st.tick(now_ms() + 10);  // закрыть текущий сегмент
    CHECK(st.stats().segments >= 1);
    st.tick(now_ms() + 10LL * 86400 * 1000);  // "через 10 дней"
    CHECK_EQ(st.stats().segments, 0u);
    CHECK_EQ(st.stats().events, 0u);
}

TEST("alerts: add, status, reopen, damaged tail") {
    TempDir tmp;
    std::string err;
    {
        AlertStore as;
        REQUIRE(as.open(tmp.path, 86400000LL * 30, err));
        std::vector<Alert> v(3);
        for (int i = 0; i < 3; ++i) {
            v[size_t(i)].rule_id = "R" + std::to_string(i);
            v[size_t(i)].ts = now_ms();
            v[size_t(i)].severity = i == 2 ? Severity::Critical : Severity::Low;
            v[size_t(i)].src_ip = "1.1.1." + std::to_string(i);
        }
        as.add(v);
        CHECK_EQ(v[2].id, 3u);
        CHECK(as.set_status(2, AlertStatus::Resolved));
        CHECK(!as.set_status(99, AlertStatus::Resolved));
        as.close();
    }
    {
        std::ofstream f(tmp.path + "/alerts.log", std::ios::app | std::ios::binary);
        f << "\x10\x00\x00\x00junk";
    }
    AlertStore as;
    REQUIRE(as.open(tmp.path, 86400000LL * 30, err));
    CHECK_EQ(as.max_id(), 3u);
    CHECK(as.get(2)->status == AlertStatus::Resolved);
    AlertQuery q;
    q.min_severity = Severity::High;
    auto r = as.query(q);
    REQUIRE(r.size() == 1);
    CHECK_EQ(r[0].rule_id, std::string("R2"));
    auto c = as.counts(0);
    CHECK_EQ(c.total, 3u);
    CHECK_EQ(c.by_status[size_t(AlertStatus::Resolved)], 1u);
    std::vector<Alert> more(1);
    more[0].rule_id = "R9";
    as.add(more);
    CHECK_EQ(more[0].id, 4u);
}
