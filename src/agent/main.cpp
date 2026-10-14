// SentinelCore Agent — собирает логи на сервере с сайтом и отправляет их в SIEM.
//
//   sentinel-agent discover                                   что будет собираться
//   sentinel-agent enroll --server URL --token sne_... [--pin sha256:...]   подключиться
//   sentinel-agent test                                       проверить связь и ключ
//   sentinel-agent run                                        работать
//   sentinel-agent add <файл>                                 читать журнал сайта (remove / sources)
//   sentinel-agent service install|uninstall|status           работать в фоне, запускаться само
//   sentinel-agent firewall-clear                             убрать все блокировки агента из брандмауэра
#include <atomic>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>

#include "agent/agent.hpp"
#include "agent/discover.hpp"
#include "agent/setup.hpp"
#include "core/log.hpp"
#include "net/tls.hpp"

using namespace sentinel;
using namespace sentinel::agent;
namespace fs = std::filesystem;

static std::atomic<bool> g_stop{false};
static std::string g_self = "sentinel-agent";  // как набрали команду (./sentinel-agent) — для подсказок
static void on_signal(int) { g_stop.store(true); }

static void usage() {
    std::cout << "SentinelCore Agent " << kAgentVersion << "\n\n"
              << "Usage:\n"
              << "  sentinel-agent enroll --server URL --token TOKEN [--pin sha256:...] [--ca FILE] [--host NAME]\n"
              << "  sentinel-agent add FILE [--format nginx|json|syslog|kv] [--name LABEL] [--from-beginning]\n"
              << "                                          read this log file (for example your site's access.log)\n"
              << "  sentinel-agent remove FILE              stop reading a file added with 'add'\n"
              << "  sentinel-agent sources                  what the agent reads now\n"
              << "  sentinel-agent discover                 log sources found on this machine automatically\n"
              << "  sentinel-agent test                     check connection and key\n"
              << "  sentinel-agent run                      collect and send logs (in this window)\n"
              << "  sentinel-agent service install          run in the background and start by itself\n"
              << "  sentinel-agent service uninstall|status|print\n"
              << "  sentinel-agent firewall-clear           remove all agent blocks from the firewall\n\n"
              << "Common option: -c agent.yaml (default: ./agent.yaml, or agent.yaml next to the program)\n";
}

static std::string human_size(uint64_t b) {
    const char* u[] = {"B", "KB", "MB", "GB"};
    double v = double(b);
    int i = 0;
    while (v >= 1024 && i < 3) {
        v /= 1024;
        ++i;
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), i ? "%.1f %s" : "%.0f %s", v, u[i]);
    return buf;
}

static int cmd_add(const AgentConfig& cfg, const std::string& config, const std::string& file, std::string format,
                   std::string name, bool from_beginning) {
    std::error_code ec;
    bool mask = file.find('*') != std::string::npos;
    std::string path = mask ? fs::absolute(file, ec).lexically_normal().string()
                            : fs::weakly_canonical(fs::absolute(file, ec), ec).string();
    if (path.empty()) path = file;
    if (!mask && fs::is_directory(path, ec)) {
        std::cerr << "error: " << path << " is a folder. Give the log file itself, for example " << path
                  << "/access.log\n";
        return 1;
    }
    for (auto& s : cfg.sources)
        if (s.path == path) {
            std::cout << "Already added: " << path << " [" << s.source << "]\n";
            return 0;
        }
    if (format.empty() || format == "auto") {
        format = "auto";
        if (!mask && fs::exists(path, ec)) {
            FormatGuess g = guess_log_format(tail_lines(path, 20));
            if (g.checked == 0) {
                std::cout << "The file is empty for now — that is fine, the agent will read new lines.\n";
            } else if (g.recognized == 0) {
                std::cout << "! None of the last " << g.checked << " lines looks like a known log format.\n"
                          << "  The SIEM will still keep them as text, but rules (password guessing, attacks)\n"
                          << "  work best with the nginx/Apache 'combined' format or JSON lines.\n";
            } else {
                format = g.format;
                std::cout << "Format: " << format << " (" << g.recognized << " of the last " << g.checked
                          << " lines recognized)\n";
                if (!g.example.empty()) std::cout << "  last line is understood as: " << g.example << "\n";
            }
        }
    } else if (format != "nginx" && format != "json" && format != "syslog" && format != "kv" && format != "plain") {
        std::cerr << "error: --format must be auto | nginx | json | syslog | kv | plain\n";
        return 2;
    }
    if (!mask && !fs::exists(path, ec)) {
        std::cout << "! " << path << " does not exist yet. The agent will start reading it as soon as it appears.\n";
    } else if (!mask) {
        std::ifstream probe(path, std::ios::binary);
        if (!probe) {
            std::cerr << "error: no permission to read " << path << ".\n"
#if !defined(_WIN32)
                      << "  Run with sudo, or give read access: sudo chmod o+r " << path << "\n"
#endif
                ;
            return 1;
        }
    }
    SourceSpec s;
    s.path = path;
    s.format = format;
    s.source = name.empty() ? guess_source_name(path) : name;
    s.from_beginning = from_beginning;
    std::string text;
    {
        std::ifstream in(config, std::ios::binary);
        if (in) text.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }
    std::string next = yaml_add_source(text, s);
    // проверка: новый файл читается и в нём есть наш источник
    AgentConfig check;
    std::string err, tmp = config + ".check";
    if (!write_file_atomic(tmp, next, err) || !load_agent_config(tmp, check, err)) {
        fs::remove(tmp, ec);
        std::cerr << "error: could not update " << config << ": " << err << "\n";
        return 1;
    }
    fs::remove(tmp, ec);
    bool found = std::any_of(check.sources.begin(), check.sources.end(), [&](const SourceSpec& x) { return x.path == path; });
    if (!found) {
        std::cerr << "error: could not add the source to " << config << " (unexpected layout of 'sources:')\n";
        return 1;
    }
    if (!write_file_atomic(config, next, err)) {
        std::cerr << "error: " << err << "\n";
        return 1;
    }
    std::cout << "Added: " << path << "\n  label in the SIEM: " << s.source << "   format: " << s.format << "\n"
              << "  " << (from_beginning ? "the whole file will be sent, then new lines" : "only new lines will be sent")
              << "\n\n";
    bool installed = false, running = false;
    std::string details;
    service_status(installed, running, details);
    if (running)
        std::cout << "The background agent picks it up within a few seconds — nothing else to do.\n";
    else
        std::cout << "If the agent is already running, it picks this up within a few seconds.\n"
                  << "Not running yet? Start it in the background: " << g_self << " service install\n";
    std::cout << "Check in the panel: open your site, then look at the live feed on the main page (label "
              << s.source << ").\n";
    return 0;
}

static int cmd_remove(const std::string& config, const std::string& file) {
    std::error_code ec;
    std::string text;
    {
        std::ifstream in(config, std::ios::binary);
        if (in) text.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }
    std::string next, err;
    std::vector<std::string> tries = {file};
    std::string abs = fs::absolute(file, ec).lexically_normal().string();
    if (!abs.empty()) tries.push_back(abs);
    std::string canon = fs::weakly_canonical(fs::absolute(file, ec), ec).string();
    if (!canon.empty()) tries.push_back(canon);
    for (auto& t : tries) {
        if (yaml_remove_source(text, t, next)) {
            if (!write_file_atomic(config, next, err)) {
                std::cerr << "error: " << err << "\n";
                return 1;
            }
            std::cout << "Removed: " << t << ". A running agent stops reading it within a few seconds.\n";
            return 0;
        }
    }
    std::cerr << "Not found among sources added in " << config << ": " << file
              << "\n(see the list: " << g_self << " sources; automatically found logs can be skipped with 'exclude:')\n";
    return 1;
}

static int cmd_sources(const AgentConfig& cfg, const std::string& config) {
    std::vector<std::string> warnings;
    auto list = effective_sources(cfg, &warnings);
    std::cout << "Settings: " << config << "\n\n";
    if (list.empty()) std::cout << "  nothing yet. Add your site's log: " << g_self << " add /path/to/access.log\n";
    for (auto& s : list) {
        bool manual = std::any_of(cfg.sources.begin(), cfg.sources.end(), [&](const SourceSpec& x) { return x.path == s.path; });
        std::cout << "  [" << s.source << "] " << s.path << "  (" << (manual ? "added" : "found automatically") << ", "
                  << s.format << ")\n";
        if (s.kind == "file" && s.path.find('*') == std::string::npos) {
            std::error_code ec;
            if (!fs::exists(s.path, ec)) std::cout << "      ! file does not exist yet\n";
            else std::cout << "      size " << human_size(fs::file_size(s.path, ec)) << "\n";
        }
    }
    for (auto& w : warnings) std::cout << "\n  ! " << w;
    if (!warnings.empty()) std::cout << "\n";
    bool installed = false, running = false;
    std::string details;
    service_status(installed, running, details);
    std::cout << "\nBackground service: " << (running ? "running" : installed ? "installed, NOT running" : "not installed")
              << (details.empty() ? "" : " (" + details + ")") << "\n";
    return 0;
}

#if defined(_WIN32)
// Служба Windows: диспетчер служб запускает "sentinel-agent run --service -c ...".
// Без регистрации через StartServiceCtrlDispatcher Windows через 30 с снимает процесс (ошибка 1053).
#include <winsock2.h>
#include <windows.h>

static SERVICE_STATUS_HANDLE g_svc = nullptr;
static std::string g_svc_config;
static int g_svc_exit = 0;

static void svc_state(DWORD state, DWORD exit_code = 0) {
    SERVICE_STATUS st{};
    st.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    st.dwCurrentState = state;
    st.dwControlsAccepted = state == SERVICE_RUNNING ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    st.dwWin32ExitCode = exit_code ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR;
    st.dwServiceSpecificExitCode = exit_code;
    st.dwWaitHint = state == SERVICE_RUNNING || state == SERVICE_STOPPED ? 0 : 10000;
    if (g_svc) SetServiceStatus(g_svc, &st);
}

static DWORD WINAPI svc_ctrl(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        svc_state(SERVICE_STOP_PENDING);
        g_stop.store(true);
    }
    return NO_ERROR;
}

static void WINAPI svc_main(DWORD, LPSTR*) {
    g_svc = RegisterServiceCtrlHandlerExA("SentinelAgent", svc_ctrl, nullptr);
    if (!g_svc) return;
    svc_state(SERVICE_START_PENDING);
    // журнал агента — в agent.log рядом с настройками (у службы нет окна)
    std::error_code ec;
    fs::path logp = fs::path(g_svc_config).parent_path() / "agent.log";
    if (fs::file_size(logp, ec) > 10u * 1024 * 1024) fs::rename(logp, logp.string() + ".1", ec);
    if (std::freopen(logp.string().c_str(), "a", stderr)) std::setvbuf(stderr, nullptr, _IONBF, 0);
    AgentConfig cfg;
    std::string err;
    if (!load_agent_config(g_svc_config, cfg, err)) {
        log::error("config error: ", err);
        g_svc_exit = 1;
        svc_state(SERVICE_STOPPED, 1);
        return;
    }
    Agent agent(cfg);
    if (!agent.init(err)) {
        log::error(err);
        g_svc_exit = 1;
        svc_state(SERVICE_STOPPED, 1);
        return;
    }
    svc_state(SERVICE_RUNNING);
    log::info("sentinel-agent ", kAgentVersion, " (service) sending to ", cfg.server, " as host ", cfg.host);
    agent.run(g_stop);
    agent.shutdown();
    log::info("agent stopped: sent ", agent.stats().lines_sent, " lines");
    svc_state(SERVICE_STOPPED);
}

static int run_windows_service(const std::string& config) {
    g_svc_config = config;
    char name[] = "SentinelAgent";
    SERVICE_TABLE_ENTRYA table[] = {{name, svc_main}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherA(table)) {
        std::cerr << "'--service' is used by the Windows service manager. To run in this window: sentinel-agent run\n";
        return 1;
    }
    return g_svc_exit;
}
#endif

int main(int argc, char** argv) {
    if (argc > 0 && argv[0] && *argv[0]) {
        g_self = argv[0];
        if (g_self.find(' ') != std::string::npos) g_self = "\"" + g_self + "\"";
    }
    std::string cmd = "run", config = "agent.yaml", server, token, pin, ca, host, format, name;
    std::vector<std::string> args;
    bool insecure = false, debug = false, config_given = false, from_beginning = false, as_service = false;
    int i = 1;
    if (i < argc && argv[i][0] != '-') cmd = argv[i++];
    for (; i < argc; ++i) {
        std::string k = argv[i];
        auto next = [&](std::string& out) {
            if (i + 1 >= argc) return false;
            out = argv[++i];
            return true;
        };
        if ((k == "-c" || k == "--config") && next(config)) {
            config_given = true;
            continue;
        }
        if (k == "--format" && next(format)) continue;
        if (k == "--name" && next(name)) continue;
        if (k == "--from-beginning") {
            from_beginning = true;
            continue;
        }
        if (k == "--service") {
            as_service = true;
            continue;
        }
        if (!k.empty() && k[0] != '-') {
            args.push_back(k);
            continue;
        }
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

    const std::string exe = executable_path(argv[0]);
    {
        // Без -c: ./agent.yaml, а если его нет — agent.yaml рядом с программой
        // (тогда 'add' и 'service' работают из любой папки).
        std::error_code ec;
        if (!config_given && !fs::exists(config, ec)) {
            fs::path beside = fs::path(exe).parent_path() / "agent.yaml";
            if (fs::exists(beside, ec)) config = beside.string();
        }
        fs::path abs = fs::absolute(config, ec);
        if (!ec) config = abs.lexically_normal().string();
    }
#if defined(_WIN32)
    if (cmd == "run" && as_service) return run_windows_service(config);
#else
    (void)as_service;
#endif

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
        std::string who;
        if (!Agent::enroll(cfg, token, err, who)) {
            std::cerr << "error: " << err << "\n";
            return 1;
        }
        std::cout << "Connected to " << cfg.server << " as '" << who << "'.\n"
                  << "Settings saved to " << fs::absolute(config).string() << "\n\n"
                  << "Next steps:\n"
                  << "  1) tell the agent which log to read (your site's access log), for example:\n"
                  << "       " << g_self << " add /var/log/nginx/access.log\n"
                  << "  2) run it in the background (starts by itself after reboot):\n"
                  << "       " << g_self << " service install\n"
                  << "     or just in this window: " << g_self << " run\n";
        return 0;
    }

    if (cmd == "add") {
        if (args.size() != 1) {
            std::cerr << "usage: " << g_self << " add /path/to/access.log [--format nginx] [--name mysite]\n";
            return 2;
        }
        return cmd_add(cfg, config, args[0], format, name, from_beginning);
    }
    if (cmd == "remove") {
        if (args.size() != 1) {
            std::cerr << "usage: " << g_self << " remove /path/to/access.log\n";
            return 2;
        }
        return cmd_remove(config, args[0]);
    }
    if (cmd == "sources") return cmd_sources(cfg, config);

    if (cmd == "service") {
        std::string sub = args.empty() ? "status" : args[0];
        std::string out;
        if (sub == "install") {
            if (cfg.server.empty() || cfg.key.empty()) {
                std::cerr << "error: connect the agent first (" << g_self << " enroll --server URL --token TOKEN)\n";
                return 1;
            }
            if (!service_install(exe, config, out, err)) {
                std::cerr << "error: " << err << "\n";
                return 1;
            }
            std::cout << out << "\nCheck: " << g_self << " service status\n";
            return 0;
        }
        if (sub == "uninstall" || sub == "remove") {
            if (!service_uninstall(out, err)) {
                std::cerr << "error: " << err << "\n";
                return 1;
            }
            std::cout << out;
            return 0;
        }
        if (sub == "print") {
            ServiceInfo si = service_info();
#if defined(__APPLE__)
            std::cout << "# " << si.file << "\n" << launchd_plist(exe, config, si.log_hint);
#elif defined(_WIN32)
            std::cout << "sc create SentinelAgent binPath= \"\\\"" << exe << "\\\" run --service -c \\\"" << config
                      << "\\\"\" start= auto\n";
#else
            std::cout << "# " << si.file << "\n" << systemd_unit(exe, config);
#endif
            return 0;
        }
        if (sub == "status") {
            bool installed = false, running = false;
            std::string details;
            service_status(installed, running, details);
            std::cout << "Background service: "
                      << (running ? "running" : installed ? "installed, NOT running" : "not installed")
                      << (details.empty() ? "" : " (" + details + ")") << "\n";
            if (!installed) std::cout << "Install: " << g_self << " service install\n";
            return running || !installed ? 0 : 1;
        }
        std::cerr << "usage: " << g_self << " service install | uninstall | status | print\n";
        return 2;
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
