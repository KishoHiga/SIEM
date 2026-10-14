#include "agent/agent_config.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "core/util.hpp"
#include "core/yaml.hpp"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace sentinel::agent {

std::string default_host_name() {
    char buf[256] = {};
#ifdef _WIN32
    DWORD n = sizeof(buf);
    if (GetComputerNameA(buf, &n)) return std::string(buf, n);
    return "windows-host";
#else
    if (gethostname(buf, sizeof(buf) - 1) == 0 && buf[0]) return buf;
    return "host";
#endif
}

bool load_agent_config(const std::string& path, AgentConfig& cfg, std::string& error) {
    cfg = AgentConfig{};
    cfg.path = path;
    std::ifstream in(path, std::ios::binary);
    if (in) {
        std::stringstream ss;
        ss << in.rdbuf();
        YNode n;
        if (!parse_yaml(ss.str(), n, error)) {
            error = path + ": " + error;
            return false;
        }
        cfg.server = n.str("server");
        cfg.key = n.str("key");
        cfg.pin = n.str("pin");
        cfg.ca_file = n.str("ca_file");
        cfg.insecure = n.boolean("insecure").value_or(false);
        cfg.host = n.str("host");
        cfg.state_dir = n.str("state_dir");
        cfg.autodiscover = n.boolean("autodiscover").value_or(true);
        cfg.start_at = n.str("start_at", "end");
        if (auto v = n.integer("batch_kb")) cfg.batch_bytes = size_t(std::max<int64_t>(16, *v)) * 1024;
        if (auto v = n.integer("flush_ms")) cfg.flush_ms = int(std::max<int64_t>(100, *v));
        cfg.exclude = n.strings("exclude");
        if (const YNode* fw = n.get("firewall"); fw && !fw->is_null()) {
            FirewallConfig& f = cfg.firewall;
            if (fw->is_scalar()) {
                f.mode = fw->scalar;
            } else if (fw->is_map()) {
                f.mode = fw->str("mode", "auto");
                f.nginx_file = fw->str("nginx_file", f.nginx_file);
                f.nginx_bin = fw->str("nginx_bin", f.nginx_bin);
                f.command = fw->str("command");
                f.list_file = fw->str("list_file");
                f.allowlist = fw->strings("allowlist");
                if (auto v = fw->integer("sync_seconds")) f.sync_seconds = int(std::clamp<int64_t>(*v, 5, 3600));
            } else {
                error = path + ": 'firewall' must be a mode name or a map";
                return false;
            }
            f.mode = to_lower(trim(f.mode));
            if (f.mode == "off" || f.mode == "false" || f.mode == "no") f.mode = "none";
            if (f.mode == "true" || f.mode == "yes" || f.mode == "on") f.mode = "auto";
            static const char* kModes[] = {"none", "auto", "nftables", "iptables", "pf", "windows", "nginx", "command"};
            bool known = false;
            for (const char* m : kModes) known |= f.mode == m;
            if (!known) {
                error = path + ": firewall mode must be none | auto | nftables | iptables | pf | windows | nginx | command";
                return false;
            }
            if (f.mode == "command" && f.command.empty()) {
                error = path + ": firewall mode 'command' needs 'command: /path/to/program'";
                return false;
            }
            for (auto& a : f.allowlist) {
                if (!parse_cidr(a)) {
                    error = path + ": firewall allowlist: bad address '" + a + "'";
                    return false;
                }
            }
        }
        if (const YNode* src = n.get("sources")) {
            for (auto& s : src->seq) {
                SourceSpec sp;
                sp.kind = s.str("kind", "file");
                sp.path = s.str("path");
                sp.format = s.str("format", "auto");
                sp.source = s.str("source");
                sp.from_beginning = s.boolean("from_beginning").value_or(false);
                if (sp.path.empty()) {
                    error = path + ": each source needs 'path'";
                    return false;
                }
                if (sp.kind != "file" && sp.kind != "command" && sp.kind != "windows_event") {
                    error = path + ": source kind must be file | command | windows_event";
                    return false;
                }
                if (sp.source.empty()) sp.source = fs::path(sp.path).stem().string();
                cfg.sources.push_back(sp);
            }
        }
    }
    if (cfg.host.empty()) cfg.host = default_host_name();
    if (cfg.state_dir.empty()) {
        fs::path p = fs::path(path).parent_path();
        cfg.state_dir = ((p.empty() ? fs::path(".") : p) / "state").string();
    }
    return true;
}

static std::string q(const std::string& s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') out += "''";
        else if (c != '\n' && c != '\r') out.push_back(c);
    }
    return out + "'";
}

bool save_agent_config(const AgentConfig& cfg, std::string& error) {
    std::error_code ec;
    fs::path p(cfg.path);
    if (p.has_parent_path()) fs::create_directories(p.parent_path(), ec);
    std::string tmp = cfg.path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            error = "cannot write " + tmp;
            return false;
        }
        out << "# Настройки SentinelCore Agent. Создано командой 'sentinel-agent enroll'.\n"
            << "server: " << q(cfg.server) << "\n"
            << "key: " << q(cfg.key) << "   # личный ключ агента (только отправка логов)\n";
        if (!cfg.pin.empty()) out << "pin: " << q(cfg.pin) << "   # отпечаток сертификата сервера\n";
        if (!cfg.ca_file.empty()) out << "ca_file: " << q(cfg.ca_file) << "\n";
        if (cfg.insecure) out << "insecure: true   # ВНИМАНИЕ: сертификат сервера не проверяется\n";
        out << "host: " << q(cfg.host) << "\n"
            << "autodiscover: " << (cfg.autodiscover ? "true" : "false")
            << "   # сам находит nginx, apache, auth.log, syslog, docker...\n"
            << "start_at: " << cfg.start_at << "   # end — только новые записи; beginning — с начала файлов\n"
            << "# exclude: ['/var/log/syslog']\n"
            << "# sources:          # дополнительные источники вручную\n"
            << "#   - path: /var/log/myapp/*.log\n"
            << "#     format: json  # auto | nginx | syslog | json | kv\n"
            << "#     source: myapp\n"
            << "# Блокировка атакующих адресов на этом сервере (список ведёт SIEM):\n"
            << "#   firewall: auto   # auto | nftables | iptables | pf | windows | nginx | command | none\n"
            << "firewall: " << (cfg.firewall.mode.empty() ? std::string("none") : cfg.firewall.mode) << "\n";
        bool header = false;
        for (auto& s : cfg.sources) {
            if (!header) out << "sources:\n";
            header = true;
            out << "  - kind: " << s.kind << "\n    path: " << q(s.path) << "\n    format: " << s.format
                << "\n    source: " << q(s.source) << "\n";
        }
        if (!out) {
            error = "cannot write " + tmp;
            return false;
        }
    }
#ifndef _WIN32
    fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
#endif
    fs::rename(tmp, cfg.path, ec);
    if (ec) {
        fs::remove(cfg.path, ec);
        fs::rename(tmp, cfg.path, ec);
    }
    if (ec) {
        error = "cannot write " + cfg.path;
        return false;
    }
    return true;
}

}  // namespace sentinel::agent
