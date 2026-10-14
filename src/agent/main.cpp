// SentinelCore Agent — собирает логи на сервере с сайтом и отправляет их в SIEM.
//
//   sentinel-agent discover                                   что будет собираться
//   sentinel-agent enroll --server URL --token sne_... [--pin sha256:...]   подключиться
//   sentinel-agent test                                       проверить связь и ключ
//   sentinel-agent run                                        работать
//   sentinel-agent service                                    как запустить как службу
//   sentinel-agent firewall-clear                             убрать все блокировки агента из брандмауэра
#include <atomic>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <iostream>

#include "agent/agent.hpp"
#include "agent/discover.hpp"
#include "core/log.hpp"
#include "net/tls.hpp"

using namespace sentinel;
using namespace sentinel::agent;
namespace fs = std::filesystem;

static std::atomic<bool> g_stop{false};
static void on_signal(int) { g_stop.store(true); }

static void usage() {
    std::cout << "SentinelCore Agent " << kAgentVersion << "\n\n"
              << "Usage:\n"
              << "  sentinel-agent discover                 show log sources found on this machine\n"
              << "  sentinel-agent enroll --server URL --token TOKEN [--pin sha256:...] [--ca FILE] [--host NAME]\n"
              << "  sentinel-agent test                     check connection and key\n"
              << "  sentinel-agent run                      collect and send logs\n"
              << "  sentinel-agent service                  how to run as a system service\n"
              << "  sentinel-agent firewall-clear           remove all agent blocks from the firewall\n\n"
              << "Common option: -c agent.yaml (default: ./agent.yaml)\n";
}

int main(int argc, char** argv) {
    std::string cmd = "run", config = "agent.yaml", server, token, pin, ca, host;
    bool insecure = false, debug = false;
    int i = 1;
    if (i < argc && argv[i][0] != '-') cmd = argv[i++];
    for (; i < argc; ++i) {
        std::string k = argv[i];
        auto next = [&](std::string& out) {
            if (i + 1 >= argc) return false;
            out = argv[++i];
            return true;
        };
        if ((k == "-c" || k == "--config") && next(config)) continue;
        if (k == "--server" && next(server)) continue;
        if (k == "--token" && next(token)) continue;
        if (k == "--pin" && next(pin)) continue;
        if (k == "--ca" && next(ca)) continue;
        if (k == "--host" && next(host)) continue;
        if (k == "--insecure") {
            insecure = true;
            continue;
        }
        if (k == "--debug") {
            debug = true;
            continue;
        }
        usage();
        return 2;
    }
    if (debug) log::set_level(log::Level::Debug);

    if (cmd == "version") {
        std::cout << "sentinel-agent " << kAgentVersion << " (TLS: " << net::tls_library_version() << ")\n";
        return 0;
    }
    if (cmd == "help" || cmd == "-h" || cmd == "--help") {
        usage();
        return 0;
    }

    AgentConfig cfg;
    std::string err;
    if (!load_agent_config(config, cfg, err)) {
        std::cerr << "config error: " << err << "\n";
        return 1;
    }

    if (cmd == "discover") {
        auto d = discover_sources();
        std::cout << "Log sources found on this machine (" << cfg.host << "):\n\n";
        if (d.sources.empty()) std::cout << "  (nothing found automatically — add sources to " << config << ")\n";
        for (auto& s : d.sources)
            std::cout << "  [" << s.source << "] " << s.path << "\n      " << s.note << " (format: " << s.format << ")\n";
        for (auto& w : d.warnings) std::cout << "\n  ! " << w;
        if (!d.warnings.empty()) std::cout << "\n";
        return 0;
    }

    if (cmd == "enroll") {
        if (server.empty() || token.empty()) {
            std::cerr << "usage: sentinel-agent enroll --server https://SIEM:8443 --token sne_... [--pin sha256:...]\n";
            return 2;
        }
        cfg.server = server;
        if (!pin.empty()) cfg.pin = pin;
        if (!ca.empty()) cfg.ca_file = ca;
        if (!host.empty()) cfg.host = host;
        cfg.insecure = insecure;
        std::string name;
        if (!Agent::enroll(cfg, token, err, name)) {
            std::cerr << "error: " << err << "\n";
            return 1;
        }
        std::cout << "Connected to " << cfg.server << " as '" << name << "'.\n"
                  << "Settings saved to " << fs::absolute(config).string() << "\n\n"
                  << "Next: sentinel-agent run" << (config == "agent.yaml" ? "" : " -c " + config) << "\n";
        return 0;
    }

    if (cmd == "service") {
        std::string exe = fs::absolute(argv[0]).string();
        std::string conf = fs::absolute(config).string();
#if defined(__APPLE__)
        std::cout << "Save as /Library/LaunchDaemons/com.sentinel.agent.plist and run:\n"
                  << "  sudo launchctl load -w /Library/LaunchDaemons/com.sentinel.agent.plist\n\n"
                  << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n"
                  << "  <key>Label</key><string>com.sentinel.agent</string>\n"
                  << "  <key>ProgramArguments</key><array><string>" << exe << "</string><string>run</string>"
                  << "<string>-c</string><string>" << conf << "</string></array>\n"
                  << "  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n</dict></plist>\n";
#elif defined(_WIN32)
        std::cout << "Run in an Administrator command prompt:\n"
                  << "  sc create SentinelAgent binPath= \"\\\"" << exe << "\\\" run -c \\\"" << conf
                  << "\\\"\" start= auto\n  sc start SentinelAgent\n";
#else
        std::cout << "Save as /etc/systemd/system/sentinel-agent.service and run:\n"
                  << "  sudo systemctl daemon-reload && sudo systemctl enable --now sentinel-agent\n\n"
                  << "[Unit]\nDescription=SentinelCore Agent\nAfter=network-online.target\n\n"
                  << "[Service]\nExecStart=" << exe << " run -c " << conf << "\n"
                  << "Restart=always\nRestartSec=5\n# Права на чтение логов без полного root:\n"
                  << "# User=sentinel\n# SupplementaryGroups=adm systemd-journal\n\n"
                  << "[Install]\nWantedBy=multi-user.target\n";
#endif
        return 0;
    }

    Agent agent(cfg);
    if (!agent.init(err)) {
        std::cerr << "error: " << err << "\n";
        return 1;
    }

    if (cmd == "test") {
        std::string info;
        if (!agent.test_connection(info, err)) {
            std::cerr << "connection FAILED: " << err << "\n";
            return 1;
        }
        std::cout << "connection OK: " << info << "\n";
        if (cfg.firewall.mode == "none") {
            std::cout << "firewall: off (enable with 'firewall: auto' in " << config << ")\n";
        } else if (!agent.sync_blocks(err) || !agent.sync_blocks(err)) {  // второй раз — сообщить серверу итог
            std::cerr << "firewall FAILED: " << err << "\n";
            return 1;
        } else {
            std::cout << "firewall: " << agent.firewall_status() << "\n";
        }
        return 0;
    }

    if (cmd == "firewall-clear") {
        if (!agent.firewall_clear(err)) {
            std::cerr << "error: " << err << "\n";
            return 1;
        }
        std::cout << "firewall: all SentinelCore blocks removed\n";
        return 0;
    }

    if (cmd == "run") {
        std::signal(SIGINT, on_signal);
        std::signal(SIGTERM, on_signal);
        log::info("sentinel-agent ", kAgentVersion, " sending to ", cfg.server, " as host ", cfg.host);
        agent.run(g_stop);
        agent.shutdown();
        auto st = agent.stats();
        log::info("agent stopped: sent ", st.lines_sent, " lines");
        return 0;
    }
    usage();
    return 2;
}
