#include "agent/firewall.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

#include "core/log.hpp"
#include "core/util.hpp"

#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace sentinel::agent {

namespace {

constexpr const char* kWinRule = "SentinelCore Block";
constexpr const char* kPfAnchor = "com.apple/sentinel";  // вложенный якорь: macOS уже подключает "com.apple/*"

std::string join_cidrs(const std::vector<Cidr>& v, const char* sep) {
    std::string out;
    for (auto& c : v) {
        if (!out.empty()) out += sep;
        out += format_cidr(c);
    }
    return out;
}

std::string first_line(const std::string& s) {
    std::string t(trim(s));
    size_t nl = t.find('\n');
    return (nl == std::string::npos ? t : t.substr(0, nl)).substr(0, 200);
}

bool run_ok(const Runner& run, const std::vector<std::string>& argv, const std::string& in, std::string& error) {
    ProcResult r = run(argv, in);
    if (r.ok()) return true;
    if (!r.started) error = "cannot run " + argv[0];
    else if (r.timed_out) error = argv[0] + " timed out";
    else error = argv[0] + " failed (exit " + std::to_string(r.exit_code) + "): " + first_line(r.output);
    return false;
}

bool write_file_atomic(const std::string& path, const std::string& content, std::string& error) {
    std::error_code ec;
    fs::path p(path);
    if (p.has_parent_path()) fs::create_directories(p.parent_path(), ec);
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        f << content;
        if (!f) {
            error = "cannot write " + tmp;
            return false;
        }
    }
    fs::rename(tmp, path, ec);
    if (ec) {
        fs::remove(path, ec);
        fs::rename(tmp, path, ec);
    }
    if (ec) {
        error = "cannot write " + path;
        return false;
    }
    return true;
}

std::vector<Cidr> merge(const std::vector<Cidr>& a, const std::vector<Cidr>& b) {
    std::vector<Cidr> all = a;
    all.insert(all.end(), b.begin(), b.end());
    return all;
}

// ---------------- nftables ----------------
class Nftables : public Firewall {
public:
    explicit Nftables(Runner r) : run_(std::move(r)) {}
    const char* name() const override { return "nftables"; }
    bool apply(const std::vector<Cidr>& v4, const std::vector<Cidr>& v6, std::string& error) override {
        return run_ok(run_, {"nft", "-f", "-"}, nft_script(v4, v6), error);
    }
    bool clear(std::string& error) override {
        ProcResult r = run_({"nft", "delete", "table", "inet", "sentinel"}, "");
        if (r.ok() || r.output.find("No such file") != std::string::npos) return true;
        error = "nft: " + first_line(r.output);
        return false;
    }

private:
    Runner run_;
};

// ---------------- iptables ----------------
class Iptables : public Firewall {
public:
    Iptables(Runner r, bool has_v6) : run_(std::move(r)), v6_(has_v6) {}
    const char* name() const override { return "iptables"; }
    bool apply(const std::vector<Cidr>& v4, const std::vector<Cidr>& v6, std::string& error) override {
        if (!family("iptables", v4, error)) return false;
        if (v6_) return family("ip6tables", v6, error);
        if (!v6.empty()) log::warn("firewall: ip6tables not found, ", v6.size(), " IPv6 blocks are not applied");
        return true;
    }
    bool clear(std::string& error) override {
        for (const char* t : {"iptables", "ip6tables"}) {
            if (std::string(t) == "ip6tables" && !v6_) continue;
            run_({t, "-t", "raw", "-D", "PREROUTING", "-j", "SENTINEL"}, "");
            run_({t, "-t", "raw", "-F", "SENTINEL"}, "");
            run_({t, "-t", "raw", "-X", "SENTINEL"}, "");
        }
        error.clear();
        return true;
    }

private:
    bool family(const std::string& tool, const std::vector<Cidr>& list, std::string& error) {
        if (!run_ok(run_, {tool + "-restore", "--noflush"}, iptables_restore_script(list), error)) return false;
        // переход в нашу цепочку — один раз, в начало PREROUTING (до conntrack и NAT Docker)
        if (!run_({tool, "-t", "raw", "-C", "PREROUTING", "-j", "SENTINEL"}, "").ok())
            return run_ok(run_, {tool, "-t", "raw", "-I", "PREROUTING", "1", "-j", "SENTINEL"}, "", error);
        return true;
    }
    Runner run_;
    bool v6_;
};

// ---------------- pf (macOS) ----------------
class Pf : public Firewall {
public:
    explicit Pf(Runner r) : run_(std::move(r)) {}
    const char* name() const override { return "pf"; }
    bool apply(const std::vector<Cidr>& v4, const std::vector<Cidr>& v6, std::string& error) override {
        if (!enabled_) {
            run_({"pfctl", "-E"}, "");  // включить pf (если уже включён — просто увеличит счётчик)
            enabled_ = true;
        }
        return run_ok(run_, {"pfctl", "-a", kPfAnchor, "-f", "-"}, pf_rules(v4, v6), error);
    }
    bool clear(std::string& error) override { return run_ok(run_, {"pfctl", "-a", kPfAnchor, "-F", "all"}, "", error); }

private:
    Runner run_;
    bool enabled_ = false;
};

// ---------------- Windows ----------------
class WindowsFw : public Firewall {
public:
    explicit WindowsFw(Runner r) : run_(std::move(r)) {}
    const char* name() const override { return "windows"; }
    bool apply(const std::vector<Cidr>& v4, const std::vector<Cidr>& v6, std::string& error) override {
        std::string ignored;
        clear(ignored);
        for (auto& chunk : windows_remoteip_chunks(merge(v4, v6)))
            if (!run_ok(run_,
                        {"netsh", "advfirewall", "firewall", "add", "rule", std::string("name=") + kWinRule, "dir=in",
                         "action=block", "remoteip=" + chunk},
                        "", error))
                return false;
        return true;
    }
    bool clear(std::string& error) override {
        // "No rules match" — тоже успех
        run_({"netsh", "advfirewall", "firewall", "delete", "rule", std::string("name=") + kWinRule}, "");
        error.clear();
        return true;
    }

private:
    Runner run_;
};

// ---------------- nginx ----------------
class NginxFw : public Firewall {
public:
    NginxFw(Runner r, std::string file, std::string bin) : run_(std::move(r)), file_(std::move(file)), bin_(std::move(bin)) {}
    const char* name() const override { return "nginx"; }
    bool apply(const std::vector<Cidr>& v4, const std::vector<Cidr>& v6, std::string& error) override {
        return write_and_reload(nginx_deny_file(merge(v4, v6)), error);
    }
    bool clear(std::string& error) override { return write_and_reload(nginx_deny_file({}), error); }

private:
    bool write_and_reload(const std::string& content, std::string& error) {
        std::string old;
        bool had_old = false;
        {
            std::ifstream in(file_, std::ios::binary);
            if (in) {
                std::stringstream ss;
                ss << in.rdbuf();
                old = ss.str();
                had_old = true;
            }
        }
        if (had_old && old == content) return true;
        if (!write_file_atomic(file_, content, error)) return false;
        if (!run_ok(run_, {bin_, "-t"}, "", error)) {
            // конфигурация не прошла проверку — вернуть как было, чтобы не сломать сайт
            std::string ignored;
            if (had_old) write_file_atomic(file_, old, ignored);
            else fs::remove(file_);
            return false;
        }
        return run_ok(run_, {bin_, "-s", "reload"}, "", error);
    }
    Runner run_;
    std::string file_, bin_;
};

// ---------------- своя команда ----------------
class CommandFw : public Firewall {
public:
    CommandFw(Runner r, std::string cmd, std::string file) : run_(std::move(r)), cmd_(std::move(cmd)), file_(std::move(file)) {}
    const char* name() const override { return "command"; }
    bool apply(const std::vector<Cidr>& v4, const std::vector<Cidr>& v6, std::string& error) override {
        std::string list;
        for (auto& c : merge(v4, v6)) list += format_cidr(c) + "\n";
        if (!write_file_atomic(file_, list, error)) return false;
#ifdef _WIN32
        return run_ok(run_, {"cmd", "/c", cmd_, file_}, "", error);
#else
        return run_ok(run_, {"/bin/sh", "-c", cmd_ + " \"$1\"", "sentinel-firewall", file_}, "", error);
#endif
    }
    bool clear(std::string& error) override { return apply({}, {}, error); }

private:
    Runner run_;
    std::string cmd_, file_;
};

}  // namespace

Runner default_runner() {
    return [](const std::vector<std::string>& argv, const std::string& in) { return run_process(argv, in, 60000); };
}

std::string nft_script(const std::vector<Cidr>& v4, const std::vector<Cidr>& v6) {
    std::string s;
    // создать (если нет) и удалить таблицу, затем описать заново — всё одной транзакцией nft -f
    s += "table inet sentinel {}\n";
    s += "delete table inet sentinel\n";
    s += "table inet sentinel {\n";
    s += "  set blocked4 {\n    type ipv4_addr\n    flags interval\n    auto-merge\n";
    if (!v4.empty()) s += "    elements = { " + join_cidrs(v4, ", ") + " }\n";
    s += "  }\n";
    s += "  set blocked6 {\n    type ipv6_addr\n    flags interval\n    auto-merge\n";
    if (!v6.empty()) s += "    elements = { " + join_cidrs(v6, ", ") + " }\n";
    s += "  }\n";
    s += "  chain prerouting {\n    type filter hook prerouting priority -300; policy accept;\n";
    s += "    ip saddr @blocked4 drop\n    ip6 saddr @blocked6 drop\n  }\n";
    s += "}\n";
    return s;
}

std::string iptables_restore_script(const std::vector<Cidr>& list) {
    std::string s = "*raw\n:SENTINEL - [0:0]\n";  // с --noflush объявленная цепочка очищается
    for (auto& c : list) s += "-A SENTINEL -s " + format_cidr(c) + " -j DROP\n";
    s += "COMMIT\n";
    return s;
}

std::string pf_rules(const std::vector<Cidr>& v4, const std::vector<Cidr>& v6) {
    std::vector<Cidr> all = merge(v4, v6);
    std::string s = "table <sentinel_blocked> persist";
    if (!all.empty()) s += " { " + join_cidrs(all, ", ") + " }";
    s += "\nblock drop in quick from <sentinel_blocked> to any\n";
    return s;
}

std::vector<std::string> windows_remoteip_chunks(const std::vector<Cidr>& all, size_t per_rule) {
    std::vector<std::string> out;
    for (size_t i = 0; i < all.size(); i += per_rule) {
        std::vector<Cidr> part(all.begin() + long(i), all.begin() + long(std::min(all.size(), i + per_rule)));
        out.push_back(join_cidrs(part, ","));
    }
    return out;
}

std::string nginx_deny_file(const std::vector<Cidr>& all) {
    std::string s = "# SentinelCore: адреса, заблокированные SIEM. Файл перезаписывается агентом — не редактируйте.\n";
    for (auto& c : all) s += "deny " + format_cidr(c) + ";\n";
    return s;
}

std::string Firewall::detect_auto() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "pf";
#else
    std::string p;
    if (find_executable("nft", p)) return "nftables";
    if (find_executable("iptables-restore", p)) return "iptables";
    return "";
#endif
}

std::unique_ptr<Firewall> Firewall::create(const FirewallConfig& cfg, const std::string& state_dir, Runner runner,
                                           std::string& error) {
    error.clear();
    std::string mode = to_lower(cfg.mode);
    if (mode.empty() || mode == "none" || mode == "off") return nullptr;
    if (!runner) runner = default_runner();
    if (mode == "auto") {
        mode = detect_auto();
        if (mode.empty()) {
            error = "no supported firewall found (install nftables or iptables, or use firewall: nginx / command)";
            return nullptr;
        }
    }
#ifndef _WIN32
    if ((mode == "nftables" || mode == "iptables" || mode == "pf") && geteuid() != 0)
        log::warn("firewall: ", mode, " needs root — run the agent as root (or as a service)");
#endif
    if (mode == "nftables") return std::make_unique<Nftables>(runner);
    if (mode == "iptables") {
        std::string p;
        return std::make_unique<Iptables>(runner, find_executable("ip6tables-restore", p));
    }
    if (mode == "pf") return std::make_unique<Pf>(runner);
    if (mode == "windows") return std::make_unique<WindowsFw>(runner);
    if (mode == "nginx") return std::make_unique<NginxFw>(runner, cfg.nginx_file, cfg.nginx_bin);
    if (mode == "command") {
        if (cfg.command.empty()) {
            error = "firewall: command needs 'command:' (a program that receives the block list file)";
            return nullptr;
        }
        std::string file = cfg.list_file.empty() ? state_dir + "/blocklist.txt" : cfg.list_file;
        return std::make_unique<CommandFw>(runner, cfg.command, file);
    }
    error = "unknown firewall mode '" + cfg.mode + "' (none | auto | nftables | iptables | pf | windows | nginx | command)";
    return nullptr;
}

}  // namespace sentinel::agent
