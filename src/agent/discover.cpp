#include "agent/discover.hpp"

#include <algorithm>
#include <filesystem>

#include "agent/files.hpp"
#include "core/util.hpp"

namespace fs = std::filesystem;

namespace sentinel::agent {

namespace {

struct Candidate {
    const char* pattern;
    const char* format;
    const char* source;
    const char* note;
    const char* name_must_contain;  // для масок: например "access" (error.log не берём)
};

void add_files(const Candidate& c, DiscoveryResult& r) {
    auto files = expand_glob(c.pattern);
    bool any = false;
    for (auto& f : files) {
        if (c.name_must_contain && fs::path(f).filename().string().find(c.name_must_contain) == std::string::npos)
            continue;
        if (ends_with(f, ".gz") || ends_with(f, ".1") || ends_with(f, ".old")) continue;  // старые ротации
        if (!readable(f)) {
            r.warnings.push_back(f + ": found but no permission to read (run the agent as root or add it to group 'adm')");
            continue;
        }
        any = true;
    }
    if (!any) return;
    SourceSpec s;
    s.kind = "file";
    s.path = c.pattern;
    s.format = c.format;
    s.source = c.source;
    s.note = c.note;
    r.sources.push_back(s);
}

[[maybe_unused]] bool exists(const char* p) {
    std::error_code ec;
    return fs::exists(p, ec);
}

}  // namespace

DiscoveryResult discover_sources() {
    DiscoveryResult r;
#if defined(_WIN32)
    SourceSpec s;
    s.kind = "windows_event";
    s.path = "Security";
    s.format = "json";
    s.source = "windows";
    s.note = "Windows Security log: logons, failed logons, lockouts, new users, group changes";
    r.sources.push_back(s);
    add_files({"C:/nginx/logs/access.log", "nginx", "nginx", "nginx access log", nullptr}, r);
#elif defined(__APPLE__)
    const Candidate files[] = {
        {"/opt/homebrew/var/log/nginx/*.log", "nginx", "nginx", "nginx (Homebrew) access log", "access"},
        {"/usr/local/var/log/nginx/*.log", "nginx", "nginx", "nginx (Homebrew) access log", "access"},
        {"/var/log/apache2/access_log", "nginx", "apache", "Apache access log", nullptr},
    };
    for (auto& c : files) add_files(c, r);
    if (exists("/usr/bin/log")) {
        SourceSpec s;
        s.kind = "command";
        s.path = "/usr/bin/log stream --style syslog --predicate 'process == \"sshd\" OR process == \"sudo\" OR process == \"su\" OR process == \"sshd-session\"'";
        s.format = "macos_log";
        s.source = "macos";
        s.note = "macOS unified log: SSH logins, sudo, su";
        r.sources.push_back(s);
    }
#else
    const Candidate files[] = {
        {"/var/log/nginx/*.log", "nginx", "nginx", "nginx access logs", "access"},
        {"/var/log/apache2/*.log", "nginx", "apache", "Apache access logs", "access"},
        {"/var/log/httpd/*access_log", "nginx", "apache", "Apache (RHEL) access log", nullptr},
        {"/var/log/auth.log", "syslog", "auth", "SSH, sudo, su, logins (Debian/Ubuntu)", nullptr},
        {"/var/log/secure", "syslog", "auth", "SSH, sudo, su, logins (RHEL/CentOS)", nullptr},
        {"/var/log/syslog", "syslog", "syslog", "system log incl. firewall (UFW/iptables)", nullptr},
        {"/var/log/messages", "syslog", "syslog", "system log incl. firewall (RHEL)", nullptr},
        {"/var/lib/docker/containers/*/*-json.log", "json", "docker", "Docker container logs", nullptr},
    };
    for (auto& c : files) add_files(c, r);
    bool have_auth = std::any_of(r.sources.begin(), r.sources.end(), [](const SourceSpec& s) { return s.source == "auth"; });
    if (!have_auth && exists("/run/systemd/journal") && (exists("/usr/bin/journalctl") || exists("/bin/journalctl"))) {
        // Современные системы без rsyslog: SSH/sudo пишутся только в journald
        SourceSpec s;
        s.kind = "command";
        s.path = "journalctl -f -n 0 -o short-iso --no-pager";
        s.format = "syslog";
        s.source = "journald";
        s.note = "systemd journal: SSH, sudo (/var/log/auth.log is missing or not readable)";
        r.sources.push_back(s);
    }
#endif
    return r;
}

std::vector<SourceSpec> effective_sources(const AgentConfig& cfg, std::vector<std::string>* warnings) {
    std::vector<SourceSpec> out;
    if (cfg.autodiscover) {
        auto d = discover_sources();
        out = d.sources;
        if (warnings) warnings->insert(warnings->end(), d.warnings.begin(), d.warnings.end());
    }
    for (auto& s : cfg.sources) {
        bool dup = std::any_of(out.begin(), out.end(), [&](const SourceSpec& x) { return x.path == s.path; });
        if (!dup) out.push_back(s);
    }
    out.erase(std::remove_if(out.begin(), out.end(),
                             [&](const SourceSpec& s) {
                                 return std::find(cfg.exclude.begin(), cfg.exclude.end(), s.path) != cfg.exclude.end();
                             }),
              out.end());
    return out;
}

}  // namespace sentinel::agent
