#include "agent/setup.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "agent/process.hpp"
#include "core/util.hpp"
#include "core/yaml.hpp"
#include "parse/parsers.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

namespace fs = std::filesystem;

namespace sentinel::agent {

// ---------------- agent.yaml как текст ----------------

namespace {

std::vector<std::string> split_keep(const std::string& text) {
    std::vector<std::string> lines;
    std::string cur;
    for (char c : text) {
        if (c == '\n') {
            if (!cur.empty() && cur.back() == '\r') cur.pop_back();
            lines.push_back(std::move(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) lines.push_back(std::move(cur));
    return lines;
}

std::string join(const std::vector<std::string>& lines) {
    std::string out;
    for (auto& l : lines) out += l + "\n";
    return out;
}

size_t indent_of(const std::string& l) {
    size_t i = 0;
    while (i < l.size() && l[i] == ' ') ++i;
    return i;
}

bool blank_or_comment(const std::string& l) {
    std::string_view t = trim(l);
    return t.empty() || t[0] == '#';
}

std::string yq(const std::string& s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') out += "''";
        else if (c != '\n' && c != '\r') out.push_back(c);
    }
    return out + "'";
}

// Где раздел sources: строка заголовка, конец раздела (не включая), отступ элементов.
struct Block {
    long head = -1;
    size_t end = 0;   // первая строка после раздела
    size_t last = 0;  // последняя строка с содержимым раздела (для вставки)
    size_t indent = 2;
    bool inline_empty = false;  // "sources: []"
};

Block find_sources(const std::vector<std::string>& lines) {
    Block b;
    for (size_t i = 0; i < lines.size(); ++i) {
        const std::string& l = lines[i];
        if (!starts_with(l, "sources:")) continue;
        std::string_view rest = trim(std::string_view(l).substr(8));
        if (!rest.empty() && rest[0] == '#') rest = "";
        if (!rest.empty() && rest != "[]") continue;  // "sources: [что-то]" — оставляем как есть, добавим новый раздел нельзя
        b.head = long(i);
        b.inline_empty = rest == "[]";
        b.last = i;
        size_t j = i + 1;
        bool indent_known = false;
        for (; j < lines.size(); ++j) {
            const std::string& x = lines[j];
            if (blank_or_comment(x)) continue;
            if (x[0] != ' ' && x[0] != '-') break;  // следующая настройка верхнего уровня
            if (!indent_known && trim(x).substr(0, 1) == "-") {
                b.indent = indent_of(x);
                indent_known = true;
            }
            b.last = j;
        }
        b.end = b.last + 1;
        return b;
    }
    return b;
}

std::string item_text(const SourceSpec& s, size_t ind) {
    std::string pad(ind, ' ');
    std::string out = pad + "- path: " + yq(s.path) + "\n" + pad + "  format: " + s.format + "\n" + pad +
                      "  source: " + yq(s.source) + "\n";
    if (s.from_beginning) out += pad + "  from_beginning: true\n";
    return out;
}

}  // namespace

std::string yaml_add_source(const std::string& text, const SourceSpec& s) {
    std::vector<std::string> lines = split_keep(text);
    Block b = find_sources(lines);
    std::vector<std::string> item = split_keep(item_text(s, b.indent));
    if (b.head < 0) {
        while (!lines.empty() && trim(lines.back()).empty()) lines.pop_back();
        lines.push_back("sources:   # журналы, которые агент читает (добавлены командой 'sentinel-agent add')");
        item = split_keep(item_text(s, 2));
        lines.insert(lines.end(), item.begin(), item.end());
        return join(lines);
    }
    if (b.inline_empty) lines[size_t(b.head)] = "sources:";
    lines.insert(lines.begin() + long(b.end), item.begin(), item.end());
    return join(lines);
}

bool yaml_remove_source(const std::string& text, const std::string& path, std::string& out) {
    std::vector<std::string> lines = split_keep(text);
    Block b = find_sources(lines);
    if (b.head < 0) return false;
    // элементы: строки "- " с отступом раздела
    std::vector<size_t> starts;
    for (size_t i = size_t(b.head) + 1; i < b.end; ++i)
        if (!blank_or_comment(lines[i]) && indent_of(lines[i]) == b.indent && trim(lines[i]).substr(0, 1) == "-")
            starts.push_back(i);
    int left = int(starts.size());
    bool removed = false;
    for (size_t k = starts.size(); k-- > 0;) {
        size_t from = starts[k];
        size_t to = k + 1 < starts.size() ? starts[k + 1] : b.end;
        std::string chunk = "x:\n";
        for (size_t i = from; i < to; ++i) chunk += lines[i] + "\n";
        YNode n;
        std::string err;
        if (!parse_yaml(chunk, n, err)) continue;
        const YNode* x = n.get("x");
        if (!x || !x->is_seq() || x->seq.empty()) continue;
        std::string p = x->seq[0].is_map() ? x->seq[0].str("path") : x->seq[0].scalar;
        if (p != path) continue;
        lines.erase(lines.begin() + long(from), lines.begin() + long(to));
        removed = true;
        --left;
    }
    if (!removed) return false;
    if (left == 0) lines.erase(lines.begin() + b.head);  // раздел опустел
    out = join(lines);
    return true;
}

std::string guess_source_name(const std::string& path) {
    static const char* kGenericFiles[] = {"access", "error", "app", "server", "output", "out", "log", "logs",
                                          "requests", "request", "combined", "access_log", "error_log", "web",
                                          "http", "production", "development", "laravel", "django", "flask"};
    static const char* kGenericDirs[] = {"logs", "log", "server", "api", "backend", "frontend", "var", "tmp",
                                         "storage", "app", "src", "www", "html", "public", "current", "shared",
                                         "opt", "srv", "data", "runtime", "dist", "build", "wp-content", "httpd"};
    auto clean = [](std::string s) {
        std::string out;
        for (char c : to_lower(s)) {
            bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
            if (ok) out.push_back(c);
            else if (!out.empty() && out.back() != '-') out.push_back('-');
        }
        while (!out.empty() && (out.back() == '-' || out.back() == '.')) out.pop_back();
        while (!out.empty() && (out.front() == '-' || out.front() == '.')) out.erase(out.begin());
        return out;
    };
    fs::path p(path);
    std::string stem = to_lower(p.stem().string());
    if (ends_with(stem, ".log")) stem = stem.substr(0, stem.size() - 4);
    bool generic_file = stem.find('*') != std::string::npos;
    for (const char* g : kGenericFiles) generic_file |= stem == g;
    if (!generic_file && !clean(stem).empty()) return clean(stem);
    fs::path dir = p.parent_path();
    for (int depth = 0; depth < 4 && !dir.empty() && dir != dir.root_path(); ++depth, dir = dir.parent_path()) {
        std::string name = to_lower(dir.filename().string());
        bool generic = name.empty();
        for (const char* g : kGenericDirs) generic |= name == g;
        if (!generic && !clean(name).empty()) return clean(name);
    }
    std::string s = clean(stem);
    return s.empty() ? "site" : s;
}

std::vector<std::string> tail_lines(const std::string& path, size_t max_lines) {
    std::vector<std::string> out;
    std::ifstream in(path, std::ios::binary);
    if (!in) return out;
    in.seekg(0, std::ios::end);
    std::streamoff size = in.tellg();
    std::streamoff from = size > 65536 ? size - 65536 : 0;
    in.seekg(from);
    std::string buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::vector<std::string> lines = split_keep(buf);
    if (from > 0 && !lines.empty()) lines.erase(lines.begin());  // первая строка обрезана
    for (auto it = lines.rbegin(); it != lines.rend() && out.size() < max_lines; ++it)
        if (!trim(*it).empty()) out.push_back(*it);
    std::reverse(out.begin(), out.end());
    return out;
}

FormatGuess guess_log_format(const std::vector<std::string>& lines) {
    FormatGuess g;
    g.checked = int(lines.size());
    if (lines.empty()) return g;
    ParseContext ctx;
    ctx.now_ms = now_ms();
    struct Cand {
        const char* name;
        bool (*fn)(std::string_view, const ParseContext&, Event&);
    };
    const Cand cands[] = {{"json", parse_json_line}, {"nginx", parse_nginx}, {"syslog", parse_syslog}, {"kv", parse_keyvalue}};
    int best = 0;
    const Cand* winner = nullptr;
    for (auto& c : cands) {
        int ok = 0;
        for (auto& l : lines) {
            Event ev;
            if (c.fn(l, ctx, ev)) ++ok;
        }
        if (ok > best) {
            best = ok;
            winner = &c;
        }
    }
    if (!winner) return g;
    g.format = winner->name;
    g.recognized = best;
    for (auto it = lines.rbegin(); it != lines.rend(); ++it) {
        Event ev;
        if (!winner->fn(*it, ctx, ev)) continue;
        enrich_event(ev);
        std::string ex;
        if (!ev[Field::SrcIp].empty()) ex += "ip " + ev[Field::SrcIp] + ", ";
        if (!ev[Field::User].empty()) ex += "user " + ev[Field::User] + ", ";
        std::string m = ev[Field::Message];
        if (m.size() > 100) m = m.substr(0, 100) + "...";
        ex += "\"" + m + "\"";
        g.example = ex;
        break;
    }
    return g;
}

bool write_file_atomic(const std::string& path, const std::string& text, std::string& error) {
    std::error_code ec;
    fs::path p(path);
    if (p.has_parent_path()) fs::create_directories(p.parent_path(), ec);
    bool existed = fs::exists(p, ec);
    fs::perms mode = existed ? fs::status(p, ec).permissions() : (fs::perms::owner_read | fs::perms::owner_write);
    std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            error = "cannot write " + tmp + " (no permission? try with sudo / as Administrator)";
            return false;
        }
        out << text;
        if (!out) {
            error = "cannot write " + tmp;
            return false;
        }
    }
#ifndef _WIN32
    fs::permissions(tmp, mode, fs::perm_options::replace, ec);
#else
    (void)mode;
#endif
    fs::rename(tmp, p, ec);
    if (ec) {
        fs::remove(p, ec);
        fs::rename(tmp, p, ec);
    }
    if (ec) {
        error = "cannot write " + path;
        return false;
    }
    return true;
}

// ---------------- фоновая служба ----------------

namespace {

[[maybe_unused]] const char* kLabel = "com.sentinelcore.agent";
[[maybe_unused]] const char* kUnit = "sentinel-agent";
[[maybe_unused]] const char* kWinName = "SentinelAgent";

std::string xml_esc(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            default: out.push_back(c);
        }
    }
    return out;
}

// systemd: путь в кавычках, \ и " экранированы
std::string sd_quote(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '\\' || c == '"') out.push_back('\\');
        if (c == '%') out.push_back('%');
        out.push_back(c);
    }
    return out + "\"";
}

// WorkingDirectory: путь без кавычек, % удваивается
std::string sd_path(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '%') out.push_back('%');
        out.push_back(c);
    }
    return out;
}

[[maybe_unused]] bool is_root() {
#if defined(_WIN32)
    return false;
#else
    return geteuid() == 0;
#endif
}

[[maybe_unused]] std::string home_dir() {
    const char* h = std::getenv("HOME");
    return h ? h : "";
}

[[maybe_unused]] ProcResult run(const std::vector<std::string>& argv) { return run_process(argv, "", 30000); }

}  // namespace

std::string launchd_plist(const std::string& exe, const std::string& config, const std::string& log_file) {
    std::string dir = fs::path(config).parent_path().string();
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
           "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
           "<plist version=\"1.0\">\n<dict>\n"
           "  <key>Label</key><string>" + std::string(kLabel) + "</string>\n"
           "  <key>ProgramArguments</key>\n  <array>\n"
           "    <string>" + xml_esc(exe) + "</string>\n    <string>run</string>\n"
           "    <string>-c</string>\n    <string>" + xml_esc(config) + "</string>\n  </array>\n"
           "  <key>WorkingDirectory</key><string>" + xml_esc(dir) + "</string>\n"
           "  <key>RunAtLoad</key><true/>\n"
           "  <key>KeepAlive</key><true/>\n"
           "  <key>ThrottleInterval</key><integer>10</integer>\n"
           "  <key>ProcessType</key><string>Background</string>\n"
           "  <key>StandardOutPath</key><string>" + xml_esc(log_file) + "</string>\n"
           "  <key>StandardErrorPath</key><string>" + xml_esc(log_file) + "</string>\n"
           "</dict>\n</plist>\n";
}

std::string systemd_unit(const std::string& exe, const std::string& config) {
    std::string dir = fs::path(config).parent_path().string();
    return "# SentinelCore Agent — создано командой 'sentinel-agent service install'\n"
           "[Unit]\nDescription=SentinelCore Agent (sends logs to the SIEM)\n"
           "After=network-online.target\nWants=network-online.target\n\n"
           "[Service]\nExecStart=" + sd_quote(exe) + " run -c " + sd_quote(config) + "\n"
           "WorkingDirectory=" + sd_path(dir) + "\n"
           "Restart=always\nRestartSec=5\n\n"
           "[Install]\nWantedBy=multi-user.target\n";
}

ServiceInfo service_info() {
    ServiceInfo si;
#if defined(__APPLE__)
    if (is_root()) {
        si.kind = "launchd-system";
        si.file = std::string("/Library/LaunchDaemons/") + kLabel + ".plist";
        si.log_hint = "/Library/Logs/SentinelCore/agent.log";
    } else {
        si.kind = "launchd-user";
        si.file = home_dir() + "/Library/LaunchAgents/" + kLabel + ".plist";
        si.log_hint = home_dir() + "/Library/Logs/SentinelCore/agent.log";
    }
#elif defined(_WIN32)
    si.kind = "windows";
    si.log_hint = "agent.log next to agent.yaml";
#else
    si.kind = "systemd";
    si.file = std::string("/etc/systemd/system/") + kUnit + ".service";
    si.log_hint = std::string("journalctl -u ") + kUnit + " -f";
#endif
    return si;
}

#if defined(__APPLE__)
static std::string launchd_domain() { return is_root() ? "system" : "gui/" + std::to_string(getuid()); }
#endif

bool service_install(const std::string& exe, const std::string& config, std::string& out, std::string& error) {
    ServiceInfo si = service_info();
    std::error_code ec;
    if (!fs::exists(config, ec)) {
        error = "settings file " + config + " not found. Connect the agent first: sentinel-agent enroll ...";
        return false;
    }
#if defined(__APPLE__)
    if (exe.find("/AppTranslocation/") != std::string::npos || starts_with(exe, "/Volumes/")) {
        error = "the agent runs from a temporary place (" + exe +
                "). Copy sentinel-agent into a permanent folder (for example ~/sentinel-agent) and run it from there";
        return false;
    }
    std::string log_file = si.log_hint;
    fs::create_directories(fs::path(log_file).parent_path(), ec);
    fs::create_directories(fs::path(si.file).parent_path(), ec);
    std::string domain = launchd_domain();
    // уже установлена — снять старую (новые пути / новая версия)
    run({"/bin/launchctl", "bootout", domain + "/" + kLabel});
    if (!write_file_atomic(si.file, launchd_plist(exe, config, log_file), error)) return false;
    fs::permissions(si.file, fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::others_read,
                    fs::perm_options::replace, ec);
    ProcResult r = run({"/bin/launchctl", "bootstrap", domain, si.file});
    if (!r.ok()) {
        ProcResult r2 = run({"/bin/launchctl", "load", "-w", si.file});  // старые macOS
        if (!r2.ok()) {
            error = "launchctl could not start the agent: " + std::string(trim(r.output)) + " " + std::string(trim(r2.output));
            return false;
        }
    }
    out = "Installed: the agent now runs in the background and starts by itself after login" +
          std::string(is_root() ? " (system-wide, starts at boot)" : "") + ".\n" + "  service file: " + si.file +
          "\n  agent log:    " + log_file + "\n";
    return true;
#elif defined(_WIN32)
    std::string bin = "\"" + exe + "\" run --service -c \"" + config + "\"";
    run({"sc.exe", "stop", kWinName});
    run({"sc.exe", "delete", kWinName});
    ProcResult r = run({"sc.exe", "create", kWinName, "binPath=", bin, "start=", "auto", "DisplayName=", "SentinelCore Agent"});
    if (!r.ok()) {
        std::string o(trim(r.output));
        error = "could not create the service: " + o +
                (o.find("5") != std::string::npos ? "\nRun the command prompt as Administrator." : "");
        return false;
    }
    run({"sc.exe", "description", kWinName, "Sends logs to the SentinelCore SIEM"});
    run({"sc.exe", "failure", kWinName, "reset=", "60", "actions=", "restart/5000/restart/5000/restart/30000"});
    r = run({"sc.exe", "start", kWinName});
    if (!r.ok()) {
        error = "service created but did not start: " + std::string(trim(r.output));
        return false;
    }
    out = "Installed: Windows service 'SentinelAgent' starts automatically with Windows.\n  agent log: " +
          (fs::path(config).parent_path() / "agent.log").string() + "\n";
    return true;
#else
    if (!is_root()) {
        error = "a system service needs administrator rights. Run:\n  sudo " + exe + " service install -c " + config;
        return false;
    }
    std::string systemctl;
    if (!find_executable("systemctl", systemctl) || !fs::exists("/run/systemd/system", ec)) {
        error = "systemd is not running on this machine. Start the agent in the background like this:\n  nohup " + exe +
                " run -c " + config + " >> " + (fs::path(config).parent_path() / "agent.log").string() + " 2>&1 &";
        return false;
    }
    if (!write_file_atomic(si.file, systemd_unit(exe, config), error)) return false;
    fs::permissions(si.file, fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::others_read,
                    fs::perm_options::replace, ec);
    ProcResult r = run({systemctl, "daemon-reload"});
    if (r.ok()) r = run({systemctl, "enable", kUnit});
    if (r.ok()) r = run({systemctl, "restart", kUnit});
    if (!r.ok()) {
        error = "systemctl failed: " + std::string(trim(r.output));
        return false;
    }
    out = "Installed: the agent now runs in the background and starts with the system.\n  service file: " + si.file +
          "\n  agent log:    " + si.log_hint + "\n";
    return true;
#endif
}

bool service_uninstall(std::string& out, std::string& error) {
    ServiceInfo si = service_info();
    std::error_code ec;
#if defined(__APPLE__)
    ProcResult r = run({"/bin/launchctl", "bootout", launchd_domain() + "/" + kLabel});
    if (!r.ok() && fs::exists(si.file, ec)) run({"/bin/launchctl", "unload", "-w", si.file});
    bool had = fs::remove(si.file, ec);
    out = had || r.ok() ? "Removed: the agent no longer runs in the background.\n" : "The service was not installed.\n";
    return true;
#elif defined(_WIN32)
    run({"sc.exe", "stop", kWinName});
    ProcResult r = run({"sc.exe", "delete", kWinName});
    if (!r.ok() && r.output.find("1060") == std::string::npos) {
        error = "could not remove the service: " + std::string(trim(r.output)) + "\nRun as Administrator.";
        return false;
    }
    out = r.ok() ? "Removed: the SentinelAgent service is deleted.\n" : "The service was not installed.\n";
    return true;
#else
    if (!fs::exists(si.file, ec)) {
        out = "The service was not installed.\n";
        return true;
    }
    if (!is_root()) {
        error = "needs administrator rights: sudo sentinel-agent service uninstall";
        return false;
    }
    std::string systemctl = "systemctl";
    find_executable("systemctl", systemctl);
    run({systemctl, "disable", "--now", kUnit});
    fs::remove(si.file, ec);
    run({systemctl, "daemon-reload"});
    out = "Removed: the agent no longer runs in the background.\n";
    return true;
#endif
}

void service_status(bool& installed, bool& running, std::string& details) {
    ServiceInfo si = service_info();
    std::error_code ec;
    installed = running = false;
#if defined(__APPLE__)
    installed = fs::exists(si.file, ec);
    ProcResult r = run({"/bin/launchctl", "print", launchd_domain() + "/" + kLabel});
    if (r.ok()) {
        running = r.output.find("state = running") != std::string::npos;
        size_t p = r.output.find("pid = ");
        if (p != std::string::npos) details = "pid " + r.output.substr(p + 6, r.output.find('\n', p) - p - 6);
        size_t e = r.output.find("last exit code = ");
        if (!running && e != std::string::npos)
            details = "last exit code " + r.output.substr(e + 17, r.output.find('\n', e) - e - 17);
    }
    if (installed) details += (details.empty() ? "" : "; ") + std::string("log: ") + si.log_hint;
#elif defined(_WIN32)
    ProcResult r = run({"sc.exe", "query", kWinName});
    installed = r.ok();
    running = r.output.find("RUNNING") != std::string::npos;
    details = installed ? "Windows service SentinelAgent" : "";
#else
    installed = fs::exists(si.file, ec);
    std::string systemctl = "systemctl";
    find_executable("systemctl", systemctl);
    ProcResult r = run({systemctl, "is-active", kUnit});
    running = r.ok() && trim(r.output) == "active";
    if (installed) details = "log: " + si.log_hint;
#endif
}

InstanceLock::~InstanceLock() {
#if defined(_WIN32)
    if (handle_) CloseHandle(static_cast<HANDLE>(handle_));
#else
    if (fd_ >= 0) close(fd_);  // flock снимается вместе с дескриптором
#endif
}

bool InstanceLock::acquire(const std::string& state_dir, std::string& error) {
    std::error_code ec;
    fs::create_directories(state_dir, ec);
    std::string path = (fs::path(state_dir) / "agent.lock").string();
#if defined(_WIN32)
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        error = GetLastError() == ERROR_SHARING_VIOLATION
                    ? "another sentinel-agent is already running with these settings (maybe the SentinelAgent service)."
                      " Stop it first: sc stop SentinelAgent"
                    : "cannot create " + path;
        return false;
    }
    handle_ = h;
    return true;
#else
    int fd = ::open(path.c_str(), O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        error = "cannot create " + path + " (no permission? the background service may run as root — use sudo)";
        return false;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        char buf[32] = {};
        ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
        std::string pid = n > 0 ? std::string(trim(std::string_view(buf, size_t(n)))) : "";
        ::close(fd);
        error = "another sentinel-agent is already running with these settings" + (pid.empty() ? "" : " (pid " + pid + ")") +
                ".\nIf it is the background service, you do not need to start it by hand: sentinel-agent service status."
                "\nOtherwise stop the other one first (Ctrl+C in its window, or kill " + (pid.empty() ? "<pid>" : pid) + ").";
        return false;
    }
    std::string me = std::to_string(getpid()) + "\n";
    if (ftruncate(fd, 0) == 0 && pwrite(fd, me.data(), me.size(), 0) < 0) {
    }
    fd_ = fd;
    return true;
#endif
}

std::string executable_path(const char* argv0) {
    std::error_code ec;
#if defined(_WIN32)
    char buf[MAX_PATH * 2] = {};
    DWORD n = GetModuleFileNameA(nullptr, buf, DWORD(sizeof(buf)));
    if (n > 0 && n < sizeof(buf)) return std::string(buf, n);
#elif defined(__APPLE__)
    char buf[4096] = {};
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) {
        fs::path p = fs::weakly_canonical(buf, ec);
        if (!ec) return p.string();
        return buf;
    }
#else
    fs::path p = fs::read_symlink("/proc/self/exe", ec);
    if (!ec) return p.string();
#endif
    return fs::absolute(argv0, ec).string();
}

}  // namespace sentinel::agent
