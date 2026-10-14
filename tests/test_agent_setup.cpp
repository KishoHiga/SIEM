// Тесты простой настройки агента: 'sentinel-agent add/remove' правят agent.yaml как текст,
// метка источника и формат угадываются, файл службы собирается правильно.
#include <filesystem>
#include <fstream>

#include "agent/agent_config.hpp"
#include "agent/setup.hpp"
#include "core/crypto.hpp"
#include "core/util.hpp"
#include "testing.hpp"

using namespace sentinel;
using namespace sentinel::agent;
namespace fs = std::filesystem;

namespace {

// Загрузить конфиг из текста через временный файл.
AgentConfig load_text(const std::string& text) {
    std::string p = (fs::temp_directory_path() / ("sentinel-agent-" + random_hex(6) + ".yaml")).string();
    { std::ofstream(p, std::ios::binary) << text; }
    AgentConfig cfg;
    std::string err;
    CHECK(load_agent_config(p, cfg, err));
    if (!err.empty()) std::cerr << err << "\n";
    std::error_code ec;
    fs::remove(p, ec);
    return cfg;
}

SourceSpec spec(const std::string& path, const std::string& fmt, const std::string& label) {
    SourceSpec s;
    s.path = path;
    s.format = fmt;
    s.source = label;
    return s;
}

}  // namespace

TEST("agent add: new 'sources' section, comments and other settings kept") {
    std::string text =
        "# мои настройки\nserver: 'https://siem:8443'\nkey: 'snt_x'   # ключ\nfirewall: none\n# sources:\n#   - path: x\n\n";
    std::string out = yaml_add_source(text, spec("/srv/shop/logs/access.log", "nginx", "shop"));
    CHECK(out.find("# мои настройки") != std::string::npos);
    CHECK(out.find("key: 'snt_x'   # ключ") != std::string::npos);
    AgentConfig c = load_text(out);
    CHECK_EQ(c.server, std::string("https://siem:8443"));
    REQUIRE(c.sources.size() == 1);
    CHECK_EQ(c.sources[0].path, std::string("/srv/shop/logs/access.log"));
    CHECK_EQ(c.sources[0].format, std::string("nginx"));
    CHECK_EQ(c.sources[0].source, std::string("shop"));

    // второй файл — в тот же раздел; путь с пробелом и кавычкой
    out = yaml_add_source(out, spec("/Users/me/My Site/it's.log", "json", "my-site"));
    c = load_text(out);
    REQUIRE(c.sources.size() == 2);
    CHECK_EQ(c.sources[1].path, std::string("/Users/me/My Site/it's.log"));
    CHECK_EQ(c.sources[1].format, std::string("json"));
}

TEST("agent add: existing section in the middle, own indentation, 'sources: []'") {
    std::string text =
        "server: 'http://127.0.0.1:8080'\nsources:\n- path: /var/log/a.log\n  format: syslog\n\n# конец\nfirewall: none\n";
    std::string out = yaml_add_source(text, spec("/var/log/b.log", "nginx", "b"));
    AgentConfig c = load_text(out);
    REQUIRE(c.sources.size() == 2);
    CHECK_EQ(c.sources[0].path, std::string("/var/log/a.log"));
    CHECK_EQ(c.sources[1].path, std::string("/var/log/b.log"));
    CHECK_EQ(c.firewall.mode, std::string("none"));  // настройка после раздела не сломалась

    out = yaml_add_source("server: 'x'\nsources: []\nhost: 'web'\n", spec("/x.log", "kv", "x"));
    c = load_text(out);
    REQUIRE(c.sources.size() == 1);
    CHECK_EQ(c.host, std::string("web"));

    // как у агента на Mac после enroll + ручной правки
    out = yaml_add_source(
        "server: 'http://127.0.0.1:8080'\nfirewall: none\nsources:\n  - path: /Users/u/SupSearch/server/logs/access.log\n"
        "    format: nginx\n    source: supsearch\n",
        spec("/Users/u/blog/access.log", "nginx", "blog"));
    c = load_text(out);
    REQUIRE(c.sources.size() == 2);
    CHECK_EQ(c.sources[1].source, std::string("blog"));
}

TEST("agent remove: drops one item, the empty section disappears") {
    std::string text = "server: 'x'\n";
    text = yaml_add_source(text, spec("/a.log", "nginx", "a"));
    text = yaml_add_source(text, spec("/b.log", "nginx", "b"));
    text += "host: 'h'\n";
    std::string out;
    CHECK(!yaml_remove_source(text, "/nope.log", out));
    REQUIRE(yaml_remove_source(text, "/a.log", out));
    AgentConfig c = load_text(out);
    REQUIRE(c.sources.size() == 1);
    CHECK_EQ(c.sources[0].path, std::string("/b.log"));
    CHECK_EQ(c.host, std::string("h"));
    REQUIRE(yaml_remove_source(out, "/b.log", out));
    c = load_text(out);
    CHECK(c.sources.empty());
    CHECK(out.find("sources:") == std::string::npos);
    CHECK_EQ(c.host, std::string("h"));
}

TEST("agent add: label from the path") {
    CHECK_EQ(guess_source_name("/Users/me/SupSearch/server/logs/access.log"), std::string("supsearch"));
    CHECK_EQ(guess_source_name("/var/log/nginx/access.log"), std::string("nginx"));
    CHECK_EQ(guess_source_name("/var/www/My Shop/logs/error.log"), std::string("my-shop"));
    CHECK_EQ(guess_source_name("/var/log/shop-requests.log"), std::string("shop-requests"));
    CHECK_EQ(guess_source_name("/srv/app/storage/logs/laravel.log"), std::string("laravel"));
    CHECK_EQ(guess_source_name("C:/inetpub/logs/LogFiles/W3SVC1/u_ex*.log"), std::string("w3svc1"));
}

TEST("agent add: format from the last lines") {
    auto g = guess_log_format({"1.2.3.4 - - [10/Oct/2026:13:55:36 +0300] \"POST /api/auth/login HTTP/1.1\" 401 20 \"-\" \"curl\"",
                               "1.2.3.4 - - [10/Oct/2026:13:55:37 +0300] \"GET / HTTP/1.1\" 200 5 \"-\" \"curl\""});
    CHECK_EQ(g.format, std::string("nginx"));
    CHECK_EQ(g.recognized, 2);
    CHECK(g.example.find("1.2.3.4") != std::string::npos);
    g = guess_log_format({"{\"time\":\"2026-10-10T10:00:00Z\",\"level\":\"info\",\"msg\":\"login failed\",\"ip\":\"5.6.7.8\"}"});
    CHECK_EQ(g.format, std::string("json"));
    g = guess_log_format({});
    CHECK_EQ(g.format, std::string("auto"));
    CHECK_EQ(g.checked, 0);
}

TEST("agent add: tail of a file without the cut first line") {
    std::string p = (fs::temp_directory_path() / ("sentinel-tail-" + random_hex(6) + ".log")).string();
    {
        std::ofstream o(p, std::ios::binary);
        for (int i = 0; i < 5000; ++i) o << "line number " << i << " with some padding to make it longer\n";
    }
    auto t = tail_lines(p, 3);
    REQUIRE(t.size() == 3);
    CHECK(starts_with(t[2], "line number 4999 "));
    CHECK(starts_with(t[0], "line number 4997 "));
    std::error_code ec;
    fs::remove(p, ec);
}

TEST("agent service: launchd and systemd files") {
    std::string plist = launchd_plist("/Users/me/sentinel agent/sentinel-agent", "/Users/me/sentinel agent/agent.yaml",
                                      "/Users/me/Library/Logs/SentinelCore/agent.log");
    CHECK(plist.find("<string>com.sentinelcore.agent</string>") != std::string::npos);
    CHECK(plist.find("<string>/Users/me/sentinel agent/sentinel-agent</string>") != std::string::npos);
    CHECK(plist.find("<string>run</string>") != std::string::npos);
    CHECK(plist.find("<key>KeepAlive</key><true/>") != std::string::npos);
    CHECK(plist.find("<key>WorkingDirectory</key><string>/Users/me/sentinel agent</string>") != std::string::npos);
    std::string unit = systemd_unit("/opt/sentinel/sentinel-agent", "/opt/sentinel/agent 1.yaml");
    CHECK(unit.find("ExecStart=\"/opt/sentinel/sentinel-agent\" run -c \"/opt/sentinel/agent 1.yaml\"") != std::string::npos);
    CHECK(unit.find("Restart=always") != std::string::npos);
    CHECK(unit.find("WantedBy=multi-user.target") != std::string::npos);
}

TEST("agent: only one agent per settings folder") {
    std::string dir = (fs::temp_directory_path() / ("sentinel-lock-" + random_hex(6))).string();
    std::string err;
    {
        InstanceLock a;
        REQUIRE(a.acquire(dir, err));
#if !defined(_WIN32)
        // flock — на открытый файл: второй open в том же процессе тоже получит отказ
        InstanceLock b;
        CHECK(!b.acquire(dir, err));
        CHECK(err.find("already running") != std::string::npos);
#endif
    }
    InstanceLock c;  // первый вышел — можно снова
    CHECK(c.acquire(dir, err));
    std::error_code ec;
    fs::remove_all(dir, ec);
}
