// Тесты этапа 4 (агент): тексты команд брандмауэров, nginx и своя команда, синхронизация списка с сервером.
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>

#include "agent/agent.hpp"
#include "agent/firewall.hpp"
#include "agent/process.hpp"
#include "core/crypto.hpp"
#include "core/json.hpp"
#include "core/util.hpp"
#include "detect/engine.hpp"
#include "detect/rules.hpp"
#include "net/client.hpp"
#include "net/server.hpp"
#include "server/api.hpp"
#include "server/blocklist.hpp"
#include "server/live_stats.hpp"
#include "testing.hpp"

using namespace sentinel;
using namespace sentinel::agent;
namespace fs = std::filesystem;

namespace {

struct FwTmp {
    std::string path;
    FwTmp() {
        path = (fs::temp_directory_path() / ("sentinel-fw-" + random_hex(6))).string();
        fs::create_directories(path);
    }
    ~FwTmp() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

std::vector<Cidr> cidrs(std::initializer_list<const char*> l) {
    std::vector<Cidr> out;
    for (auto s : l) out.push_back(*parse_cidr(s));
    return out;
}

std::string read_all(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Запоминает вызовы вместо запуска nft/iptables/...
struct FakeRunner {
    std::mutex mu;
    std::vector<std::vector<std::string>> calls;
    std::vector<std::string> inputs;
    int fail_exit = 0;  // != 0 — все вызовы "падают"
    Runner runner() {
        return [this](const std::vector<std::string>& argv, const std::string& in) {
            std::lock_guard<std::mutex> lock(mu);
            calls.push_back(argv);
            inputs.push_back(in);
            ProcResult r;
            r.started = true;
            r.exit_code = fail_exit;
            if (fail_exit) r.output = "Error: something went wrong\nsecond line";
            return r;
        };
    }
    std::string joined(size_t i) {
        std::string s;
        for (auto& a : calls[i]) s += (s.empty() ? "" : " ") + a;
        return s;
    }
};

}  // namespace

TEST("firewall: command texts for nftables, iptables, pf, windows, nginx") {
    auto v4 = cidrs({"203.0.113.9", "198.51.100.0/24"});
    auto v6 = cidrs({"2001:db8::1", "2001:db8:1::/48"});
    std::string nft = nft_script(v4, v6);
    CHECK(nft.find("table inet sentinel {}\ndelete table inet sentinel\n") == 0);
    CHECK(nft.find("elements = { 203.0.113.9, 198.51.100.0/24 }") != std::string::npos);
    CHECK(nft.find("elements = { 2001:db8::1, 2001:db8:1::/48 }") != std::string::npos);
    CHECK(nft.find("hook prerouting priority -300") != std::string::npos);
    CHECK(nft.find("ip saddr @blocked4 drop") != std::string::npos);
    // пустой список — наборы без elements (синтаксис nft не допускает пустых { })
    std::string empty = nft_script({}, {});
    CHECK(empty.find("elements") == std::string::npos);
    CHECK(empty.find("set blocked4") != std::string::npos);

    std::string ipt = iptables_restore_script(v4);
    CHECK_EQ(ipt, std::string("*raw\n:SENTINEL - [0:0]\n-A SENTINEL -s 203.0.113.9 -j DROP\n"
                              "-A SENTINEL -s 198.51.100.0/24 -j DROP\nCOMMIT\n"));
    CHECK_EQ(iptables_restore_script({}), std::string("*raw\n:SENTINEL - [0:0]\nCOMMIT\n"));

    std::string pf = pf_rules(v4, v6);
    CHECK(pf.find("table <sentinel_blocked> persist { 203.0.113.9, 198.51.100.0/24, 2001:db8::1, 2001:db8:1::/48 }") == 0);
    CHECK(pf.find("block drop in quick from <sentinel_blocked>") != std::string::npos);
    CHECK(pf_rules({}, {}).find("persist\n") != std::string::npos);

    std::vector<Cidr> many;
    for (int i = 1; i <= 450; ++i) many.push_back(*parse_cidr("10." + std::to_string(i / 250) + ".0." + std::to_string(i % 250)));
    auto chunks = windows_remoteip_chunks(many);
    REQUIRE(chunks.size() == 3u);
    CHECK(chunks[0].find("10.0.0.1,10.0.0.2,") == 0);
    CHECK_EQ(split(chunks[2], ',').size(), size_t(50));
    CHECK(windows_remoteip_chunks({}).empty());

    std::string ng = nginx_deny_file(v4);
    CHECK(ng.find("deny 203.0.113.9;\ndeny 198.51.100.0/24;\n") != std::string::npos);
    CHECK(ng.find("allow") == std::string::npos);
}

TEST("firewall: backends run the right programs, errors are reported, mode none/auto/unknown") {
    FwTmp d;
    std::string err;
    FirewallConfig cfg;
    CHECK(Firewall::create(cfg, d.path, nullptr, err) == nullptr);  // none
    CHECK(err.empty());
    cfg.mode = "bogus";
    CHECK(Firewall::create(cfg, d.path, nullptr, err) == nullptr);
    CHECK(!err.empty());
    cfg.mode = "command";
    CHECK(Firewall::create(cfg, d.path, nullptr, err) == nullptr);  // без command:
    CHECK(!err.empty());

    auto v4 = cidrs({"203.0.113.9"});
    auto v6 = cidrs({"2001:db8::1"});
    {
        FakeRunner fr;
        cfg.mode = "nftables";
        auto fw = Firewall::create(cfg, d.path, fr.runner(), err);
        REQUIRE(fw != nullptr);
        CHECK_EQ(std::string(fw->name()), std::string("nftables"));
        REQUIRE(fw->apply(v4, v6, err));
        REQUIRE(fr.calls.size() == 1u);
        CHECK_EQ(fr.joined(0), std::string("nft -f -"));
        CHECK_EQ(fr.inputs[0], nft_script(v4, v6));
        CHECK(fw->clear(err));
        CHECK_EQ(fr.joined(1), std::string("nft delete table inet sentinel"));
        fr.fail_exit = 1;
        CHECK(!fw->apply(v4, v6, err));
        CHECK(err.find("nft failed (exit 1): Error: something went wrong") != std::string::npos);
        CHECK(err.find("second line") == std::string::npos);
    }
    {
        FakeRunner fr;
        cfg.mode = "pf";
        auto fw = Firewall::create(cfg, d.path, fr.runner(), err);
        REQUIRE(fw != nullptr);
        REQUIRE(fw->apply(v4, v6, err));
        REQUIRE(fw->apply(v4, {}, err));
        REQUIRE(fr.calls.size() == 3u);  // pfctl -E только один раз
        CHECK_EQ(fr.joined(0), std::string("pfctl -E"));
        CHECK_EQ(fr.joined(1), std::string("pfctl -a com.apple/sentinel -f -"));
        CHECK_EQ(fr.inputs[2], pf_rules(v4, {}));
    }
    {
        FakeRunner fr;
        cfg.mode = "windows";
        auto fw = Firewall::create(cfg, d.path, fr.runner(), err);
        REQUIRE(fw != nullptr);
        REQUIRE(fw->apply(v4, v6, err));
        REQUIRE(fr.calls.size() == 2u);  // удалить старые правила, добавить одно новое
        CHECK_EQ(fr.joined(0), std::string("netsh advfirewall firewall delete rule name=SentinelCore Block"));
        CHECK_EQ(fr.joined(1), std::string("netsh advfirewall firewall add rule name=SentinelCore Block dir=in "
                                           "action=block remoteip=203.0.113.9,2001:db8::1"));
        // пустой список — только удаление
        REQUIRE(fw->apply({}, {}, err));
        CHECK_EQ(fr.calls.size(), size_t(3));
    }
    {
        FakeRunner fr;
        cfg.mode = "iptables";
        auto fw = Firewall::create(cfg, d.path, fr.runner(), err);
        REQUIRE(fw != nullptr);
        REQUIRE(fw->apply(v4, {}, err));
        REQUIRE(fr.calls.size() >= 2u);
        CHECK_EQ(fr.joined(0), std::string("iptables-restore --noflush"));
        CHECK_EQ(fr.inputs[0], iptables_restore_script(v4));
        // -C прошла (fake вернул 0) — переход в цепочку уже есть, второй раз не вставляем
        CHECK_EQ(fr.joined(1), std::string("iptables -t raw -C PREROUTING -j SENTINEL"));
        for (auto& c : fr.calls) CHECK(c[0] != "iptables" || c.size() < 4 || c[3] != "-I");
    }
#ifndef _WIN32
    cfg.mode = "auto";
    auto fw = Firewall::create(cfg, d.path, FakeRunner().runner(), err);
    // в контейнере может не быть ни nft, ни iptables — тогда понятная ошибка
    CHECK(fw != nullptr || err.find("no supported firewall") != std::string::npos);
#endif
}

#ifndef _WIN32
TEST("firewall: real processes — run_process, nginx backend with rollback, command backend") {
    // run_process: вывод, код возврата, stdin, таймаут, несуществующая программа
    ProcResult r = run_process({"/bin/sh", "-c", "cat; echo err >&2; exit 3"}, "hello\n", 5000);
    CHECK(r.started);
    CHECK_EQ(r.exit_code, 3);
    CHECK(r.output.find("hello") != std::string::npos);
    CHECK(r.output.find("err") != std::string::npos);
    std::string big(3 << 20, 'x');  // больше буфера канала — запись не должна зависнуть
    r = run_process({"/bin/sh", "-c", "wc -c"}, big, 10000);
    CHECK(r.ok());
    CHECK(r.output.find(std::to_string(big.size())) != std::string::npos);
    r = run_process({"/bin/sh", "-c", "exec head -c 1 >/dev/null"}, big, 10000);  // закрыла stdin раньше времени
    CHECK(r.ok());
    auto t0 = std::chrono::steady_clock::now();
    r = run_process({"/bin/sleep", "5"}, "", 200);
    CHECK(r.timed_out);
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(3));
    r = run_process({"/nonexistent/program"}, "", 2000);
    CHECK(!r.ok());
    std::string p;
    CHECK(find_executable("sh", p));
    CHECK(!find_executable("definitely-not-a-program-xyz", p));

    FwTmp d;
    std::string err;
    auto v4 = cidrs({"203.0.113.9", "198.51.100.0/24"});
    auto v6 = cidrs({"2001:db8::1"});

    // nginx: проверка конфигурации прошла — файл записан
    FirewallConfig cfg;
    cfg.mode = "nginx";
    cfg.nginx_file = d.path + "/nginx/conf.d/sentinel-blocklist.conf";
    cfg.nginx_bin = d.path + "/fake-nginx";
    {
        std::ofstream f(cfg.nginx_bin);
        f << "#!/bin/sh\necho \"$@\" >> " << d.path << "/nginx.calls\n"
          << "[ -f " << d.path << "/nginx.broken ] && [ \"$1\" = \"-t\" ] && { echo 'nginx: [emerg] bad'; exit 1; }\nexit 0\n";
    }
    fs::permissions(cfg.nginx_bin, fs::perms::owner_all);
    auto fw = Firewall::create(cfg, d.path, nullptr, err);
    REQUIRE(fw != nullptr);
    REQUIRE(fw->apply(v4, v6, err));
    CHECK_EQ(read_all(cfg.nginx_file), nginx_deny_file({v4[0], v4[1], v6[0]}));
    CHECK_EQ(read_all(d.path + "/nginx.calls"), std::string("-t\n-s reload\n"));
    REQUIRE(fw->apply(v4, v6, err));  // ничего не изменилось — nginx не трогаем
    CHECK_EQ(read_all(d.path + "/nginx.calls"), std::string("-t\n-s reload\n"));
    // nginx -t не прошла — возвращаем прежний файл, reload не делаем
    { std::ofstream(d.path + "/nginx.broken") << "1"; }
    CHECK(!fw->apply(cidrs({"192.0.2.1"}), {}, err));
    CHECK(err.find("[emerg] bad") != std::string::npos);
    CHECK_EQ(read_all(cfg.nginx_file), nginx_deny_file({v4[0], v4[1], v6[0]}));
    fs::remove(d.path + "/nginx.broken");
    REQUIRE(fw->clear(err));
    CHECK(read_all(cfg.nginx_file).find("deny") == std::string::npos);

    // своя команда: получает путь к файлу; путь с пробелом и кавычкой не ломает команду
    FirewallConfig cc;
    cc.mode = "command";
    cc.list_file = d.path + "/list it's.txt";
    std::string copy = d.path + "/copied.txt";
    cc.command = "sh -c 'cp \"$1\" " + copy + "' x";  // программа получает путь к файлу первым аргументом
    auto cmd = Firewall::create(cc, d.path, nullptr, err);
    REQUIRE(cmd != nullptr);
    REQUIRE(cmd->apply(v4, v6, err));
    CHECK_EQ(read_all(copy), std::string("203.0.113.9\n198.51.100.0/24\n2001:db8::1\n"));
    FirewallConfig bad = cc;
    // свой код выхода; не зависит от оболочки (bash на macOS не принимает лишний аргумент у exit)
    bad.command = "sh -c 'exit 7' x";
    auto badfw = Firewall::create(bad, d.path, nullptr, err);
    CHECK(!badfw->apply(v4, {}, err));
    CHECK(err.find("exit 7") != std::string::npos);
}
#endif

TEST("agent config: firewall as a word or a map, validation, enroll writes 'firewall: none'") {
    FwTmp d;
    std::string path = d.path + "/agent.yaml", err;
    AgentConfig c;
    { std::ofstream(path) << "server: http://127.0.0.1:1\nkey: k\nfirewall: auto\n"; }
    REQUIRE(load_agent_config(path, c, err));
    CHECK_EQ(c.firewall.mode, std::string("auto"));
    { std::ofstream(path) << "firewall: off\n"; }
    REQUIRE(load_agent_config(path, c, err));
    CHECK_EQ(c.firewall.mode, std::string("none"));
    {
        std::ofstream(path) << "firewall:\n  mode: nginx\n  nginx_file: /tmp/x.conf\n  allowlist: ['10.0.0.0/8', '203.0.113.5']\n"
                               "  sync_seconds: 1\n";
    }
    REQUIRE(load_agent_config(path, c, err));
    CHECK_EQ(c.firewall.mode, std::string("nginx"));
    CHECK_EQ(c.firewall.nginx_file, std::string("/tmp/x.conf"));
    CHECK_EQ(c.firewall.allowlist.size(), size_t(2));
    CHECK_EQ(c.firewall.sync_seconds, 5);  // не чаще 5 с
    { std::ofstream(path) << "firewall: ufw\n"; }
    CHECK(!load_agent_config(path, c, err));
    { std::ofstream(path) << "firewall:\n  mode: command\n"; }
    CHECK(!load_agent_config(path, c, err));
    { std::ofstream(path) << "firewall:\n  mode: nftables\n  allowlist: ['10.0.0.300']\n"; }
    CHECK(!load_agent_config(path, c, err));
    CHECK(err.find("10.0.0.300") != std::string::npos);

    AgentConfig s;
    s.path = d.path + "/new.yaml";
    s.server = "https://siem:8443";
    s.key = "snt_x";
    REQUIRE(save_agent_config(s, err));
    CHECK(read_all(s.path).find("\nfirewall: none\n") != std::string::npos);
    AgentConfig back;
    REQUIRE(load_agent_config(s.path, back, err));
    CHECK_EQ(back.firewall.mode, std::string("none"));
}

TEST("agent: block list sync — first load, versions, allowlist, server address, retry after failure, panel status") {
    FwTmp d;
    Config cfg;
    cfg.data_dir = d.path;
    cfg.keys_file = d.path + "/keys.yaml";
    std::string admin = "admin-secret-1234567890", agent_key = "agent-secret-1234567890";
    cfg.keys = {{"admin", Role::Admin, sha256_hex(admin)}, {"agent-web", Role::Ingest, sha256_hex(agent_key)}};
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
    auto eng = std::make_unique<DetectionEngine>();
    Pipeline pipe(events, alerts, live, 1000);
    pipe.start(std::move(eng));
    {
        Api api(cfg, events, alerts, live, pipe);
        api.set_response(&blocks, nullptr);
        net::ServerOptions o;
        o.port = 0;
        o.workers = 2;
        net::HttpServer server(o, [&](const net::HttpRequest& rq, net::HttpResponse& rs) { api.handle(rq, rs); });
        REQUIRE(server.start(err));

        REQUIRE(blocks.add_manual("203.0.113.9", 0, "test", "admin") == BlockList::Result::Added);
        REQUIRE(blocks.add_manual("198.51.100.0/24", 0, "test", "admin") == BlockList::Result::Added);
        REQUIRE(blocks.add_manual("198.51.100.77", 0, "test", "admin") == BlockList::Result::Added);  // внутри /24
        REQUIRE(blocks.add_manual("192.0.2.10", 0, "test", "admin") == BlockList::Result::Added);  // в allowlist агента
        REQUIRE(blocks.add_manual("2001:db8::1", 0, "test", "admin") == BlockList::Result::Added);

        AgentConfig ac;
        ac.path = d.path + "/agent.yaml";
        ac.server = "http://127.0.0.1:" + std::to_string(server.port());
        ac.key = agent_key;
        ac.host = "web-01";
        ac.state_dir = d.path + "/state";
        ac.autodiscover = false;
        ac.firewall.mode = "nftables";
        ac.firewall.allowlist = {"192.0.2.0/28"};
        FakeRunner fr;
        Agent a(ac);
        a.set_firewall_runner(fr.runner());
        REQUIRE(a.init(err));
        CHECK_EQ(a.firewall_status(), std::string("nftables; waiting"));

        REQUIRE(a.sync_blocks(err));
        REQUIRE(fr.calls.size() == 1u);
        const std::string& script = fr.inputs[0];
        CHECK(script.find("203.0.113.9") != std::string::npos);
        CHECK(script.find("198.51.100.0/24") != std::string::npos);
        CHECK(script.find("198.51.100.77") == std::string::npos);  // покрыт подсетью
        CHECK(script.find("192.0.2.10") == std::string::npos);     // allowlist
        CHECK(script.find("2001:db8::1") != std::string::npos);
        CHECK_EQ(a.firewall_status(), std::string("nftables; applied=3; skipped=1"));

        REQUIRE(a.sync_blocks(err));  // версия та же — брандмауэр не трогаем
        CHECK_EQ(fr.calls.size(), size_t(1));

        // адрес самого SIEM не блокируется, даже если его заблокировали в панели
        REQUIRE(blocks.add_manual("127.0.0.1", 0, "", "admin") == BlockList::Result::Invalid);  // сервер не даст
        REQUIRE(blocks.remove("203.0.113.9"));
        fr.fail_exit = 1;  // nft упал — версия не запоминается, применим снова
        CHECK(!a.sync_blocks(err));
        CHECK(a.firewall_status().find("nftables; error=nft failed (exit 1)") == 0);
        fr.fail_exit = 0;
        REQUIRE(a.sync_blocks(err));
        CHECK_EQ(fr.calls.size(), size_t(3));
        CHECK(fr.inputs[2].find("203.0.113.9") == std::string::npos);
        CHECK_EQ(a.firewall_status(), std::string("nftables; applied=2; skipped=1"));

        // сервер видит состояние брандмауэра агента (для панели)
        net::Url u;
        net::parse_url(ac.server, u, err);
        net::HttpClient c(u, {});
        net::ClientResponse r;
        REQUIRE(c.request("GET", "/api/v1/agents", {{"Authorization", "Bearer " + admin}}, "", r, err));
        CHECK(r.body.find("\"firewall\":\"nftables; applied=2; skipped=1\"") != std::string::npos ||
              r.body.find("\"firewall\":\"nftables; error=") != std::string::npos);
        CHECK(r.body.find("blocks_synced") != std::string::npos);

        // step() сам синхронизирует по расписанию (первый раз — сразу)
        FakeRunner fr2;
        Agent b(ac);
        b.set_firewall_runner(fr2.runner());
        REQUIRE(b.init(err));
        b.step();
        CHECK_EQ(fr2.calls.size(), size_t(1));
        b.step();
        CHECK_EQ(fr2.calls.size(), size_t(1));  // версия та же — брандмауэр не трогаем
        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        b.step();  // состояние изменилось — через ~1 с агент сообщает его серверу
        REQUIRE(c.request("GET", "/api/v1/agents", {{"Authorization", "Bearer " + admin}}, "", r, err));
        CHECK(r.body.find("\"firewall\":\"nftables; applied=2; skipped=1\"") != std::string::npos);
        CHECK_EQ(fr2.calls.size(), size_t(1));

        // пустой список на сервере при первом запуске — агент всё равно применяет (убирает старое)
        for (auto& bl : blocks.list()) blocks.remove(bl.ip);
        FakeRunner fr3;
        Agent e(ac);
        e.set_firewall_runner(fr3.runner());
        REQUIRE(e.init(err));
        REQUIRE(e.sync_blocks(err));
        REQUIRE(fr3.calls.size() == 1u);
        CHECK(fr3.inputs[0].find("elements") == std::string::npos);
        CHECK(e.firewall_clear(err));
        CHECK_EQ(fr3.joined(1), std::string("nft delete table inet sentinel"));

        // агент без брандмауэра: sync_blocks — понятная ошибка, статус none
        AgentConfig off = ac;
        off.firewall.mode = "none";
        Agent n(off);
        REQUIRE(n.init(err));
        CHECK(!n.sync_blocks(err));
        CHECK_EQ(n.firewall_status(), std::string("none"));
        server.stop();
    }
    pipe.stop();
    events.close();
    alerts.close();
}
