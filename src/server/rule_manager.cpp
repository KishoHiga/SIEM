#include "server/rule_manager.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <unordered_set>

#include "core/log.hpp"
#include "core/util.hpp"
#include "parse/parsers.hpp"

namespace fs = std::filesystem;

namespace sentinel {

namespace {

bool read_text(const fs::path& p, std::string& out) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return false;
    std::stringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

bool is_rule_file(const fs::path& p) {
    auto ext = p.extension().string();
    return ext == ".yml" || ext == ".yaml";
}

// Имя автора/действия в имени файла версии — только безопасные символы.
std::string safe_part(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (is_alnum(c) || c == '-') out.push_back(c);
        else if (!out.empty() && out.back() != '-') out.push_back('-');
        if (out.size() >= 40) break;
    }
    return out.empty() ? "unknown" : out;
}

std::string unquote(std::string_view v) {
    v = trim(v);
    if (size_t h = v.find(" #"); h != std::string_view::npos) v = trim(v.substr(0, h));
    if (v.size() >= 2 && (v.front() == '\'' || v.front() == '"') && v.back() == v.front()) v = v.substr(1, v.size() - 2);
    return std::string(v);
}

size_t indent_of(std::string_view line) {
    size_t i = 0;
    while (i < line.size() && line[i] == ' ') ++i;
    return i;
}

constexpr size_t kMaxRuleText = 256 * 1024;
constexpr size_t kMaxVersions = 50;

}  // namespace

RuleManager::RuleManager(std::string rules_dir, std::string history_dir)
    : dir_(std::move(rules_dir)), history_dir_(std::move(history_dir)) {}

int64_t RuleManager::dir_stamp() const {
    int64_t stamp = 0;
    std::error_code ec;
    for (auto& e : fs::directory_iterator(dir_, ec)) {
        auto t = fs::last_write_time(e.path(), ec);
        stamp += int64_t(t.time_since_epoch().count() % 1000000007) + int64_t(e.path().string().size()) +
                 int64_t(fs::file_size(e.path(), ec) % 1000003);
    }
    return stamp;
}

std::map<std::string, std::string> RuleManager::read_files() const {
    std::map<std::string, std::string> out;
    std::error_code ec;
    for (auto& e : fs::directory_iterator(dir_, ec)) {
        if (!e.is_regular_file() || !is_rule_file(e.path())) continue;
        std::string text;
        if (read_text(e.path(), text)) out[e.path().filename().string()] = std::move(text);
    }
    return out;
}

RuleManager::Candidate RuleManager::build(const std::map<std::string, std::string>& files) const {
    Candidate c;
    for (auto& [name, text] : files) {
        std::vector<Rule> rules;
        std::string err;
        if (!parse_rules_yaml(text, name, rules, err)) {
            c.errors.push_back(name + ": " + err);
            continue;
        }
        for (auto& r : rules) c.all.push_back(std::move(r));
    }
    validate_rules(c.all, c.errors);
    return c;
}

bool RuleManager::reload(std::string& error) {
    std::lock_guard<std::mutex> lock(mu_);
    return reload_locked(error);
}

bool RuleManager::reload_locked(std::string& error) {
    std::error_code ec;
    if (!fs::is_directory(dir_, ec)) {
        fs::create_directories(dir_, ec);
        if (!fs::is_directory(dir_, ec)) {
            error = dir_ + ": rules directory not found and cannot be created";
            return false;
        }
        log::warn("rules: created empty rules directory ", dir_);
    }
    Candidate c = build(read_files());
    for (auto& e : c.errors) log::error("rules: ", e);
    auto eng = std::make_unique<DetectionEngine>();
    if (!eng->load(c.all, error)) {
        log::error("rules: ", error, " — keeping previous rules");
        stamp_ = dir_stamp();
        return false;
    }
    size_t enabled = 0;
    for (auto& r : c.all) enabled += r.enabled;
    log::info("rules: loaded ", enabled, " enabled rules from ", dir_,
              c.errors.empty() ? "" : " (some files have errors, see above)");
    rules_ = c.all;
    errors_ = c.errors;
    stamp_ = dir_stamp();
    if (apply_) apply_(std::move(eng), rules_);
    return true;
}

bool RuleManager::reload_if_changed() {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (dir_stamp() == stamp_) return false;
    }
    std::string err;
    reload(err);
    return true;
}

std::vector<Rule> RuleManager::rules() const {
    std::lock_guard<std::mutex> lock(mu_);
    return rules_;
}

std::vector<std::string> RuleManager::load_errors() const {
    std::lock_guard<std::mutex> lock(mu_);
    return errors_;
}

std::string RuleManager::file_of(const std::string& id) const {
    for (auto& r : rules_)
        if (r.id == id) return r.file;
    return "";
}

bool RuleManager::source(const std::string& id, std::string& file, std::string& text, std::string& error) const {
    std::lock_guard<std::mutex> lock(mu_);
    file = file_of(id);
    if (file.empty()) {
        error = "rule not found";
        return false;
    }
    if (!read_text(fs::path(dir_) / file, text)) {
        error = "cannot read " + file;
        return false;
    }
    return true;
}

std::string RuleManager::file_name_for(const std::string& id) {
    std::string out;
    for (char c : id) {
        char l = to_lower_ascii(c);
        if (is_alnum(l)) out.push_back(l);
        else if (!out.empty() && out.back() != '_') out.push_back('_');
        if (out.size() >= 60) break;
    }
    while (!out.empty() && out.back() == '_') out.pop_back();
    if (out.empty()) out = "rule";
    return out + ".yml";
}

RuleCheck RuleManager::check_files(const std::string& file, const std::string* text) const {
    RuleCheck res;
    res.file = file;
    if (text && text->size() > kMaxRuleText) {
        res.error = "rule file is too large (max 256 KB)";
        return res;
    }
    auto files = read_files();
    Candidate before = build(files);
    std::set<std::string> old_errors(before.errors.begin(), before.errors.end());

    std::vector<Rule> mine;
    if (text) {
        std::string err;
        if (!parse_rules_yaml(*text, file, mine, err)) {
            res.error = err;
            res.errors.push_back(err);
            return res;
        }
        if (mine.empty()) {
            res.error = "no rules in the text";
            return res;
        }
        for (auto& r : mine) res.rule_ids.push_back(r.id);
        files[file] = *text;
    } else {
        files.erase(file);
    }
    Candidate after = build(files);
    for (auto& e : after.errors)
        if (!old_errors.count(e) || starts_with(e, file + ":")) res.errors.push_back(e);
    if (!res.errors.empty()) {
        res.error = res.errors.front();
        return res;
    }
    DetectionEngine eng;
    std::string err;
    if (!eng.load(after.all, err)) {
        res.error = err;
        res.errors.push_back(err);
        return res;
    }
    if (text) {
        std::vector<Rule> checked;
        for (auto& r : after.all)
            if (r.file == file) checked.push_back(r);
        RuleTestReport rep = run_rule_tests(checked);
        res.test_cases = rep.cases;
        res.test_failures = rep.failures;
        for (auto& e : rep.errors) res.errors.push_back(e);
        if (!rep.failures.empty()) {
            const auto& f = rep.failures.front();
            res.error = "rule " + f.rule_id + ": example " + (f.expected_alert ? "in 'match' gives no alert" : "in 'no_match' gives an alert") +
                        ": " + f.line;
            return res;
        }
        if (!rep.errors.empty()) {
            res.error = rep.errors.front();
            return res;
        }
    }
    res.ok = true;
    return res;
}

RuleCheck RuleManager::check(const std::string& id, const std::string& text) const {
    std::lock_guard<std::mutex> lock(mu_);
    std::string file;
    if (!id.empty()) {
        file = file_of(id);
        if (file.empty()) {
            RuleCheck r;
            r.error = "rule not found";
            return r;
        }
    } else {
        std::vector<Rule> parsed;
        std::string err;
        std::string base = parse_rules_yaml(text, "new.yml", parsed, err) && !parsed.empty() ? file_name_for(parsed[0].id)
                                                                                            : std::string("new-rule.yml");
        file = base;
        std::error_code ec;
        for (int n = 2; fs::exists(fs::path(dir_) / file, ec); ++n)
            file = base.substr(0, base.size() - 4) + "-" + std::to_string(n) + ".yml";
    }
    return check_files(file, &text);
}

bool RuleManager::write_file(const std::string& file, const std::string& text, std::string& error) const {
    fs::path p = fs::path(dir_) / file;
    std::string tmp = p.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        out << text;
        if (!out) {
            error = "cannot write " + tmp;
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, p, ec);
    if (ec) {
        fs::remove(p, ec);
        fs::rename(tmp, p, ec);
    }
    if (ec) {
        fs::remove(tmp, ec);
        error = "cannot write " + p.string();
        return false;
    }
    return true;
}

void RuleManager::record(const std::string& file, const std::string& action, const std::string& by,
                         const std::string& text) {
    if (history_dir_.empty()) return;
    fs::path d = fs::path(history_dir_) / file;
    std::error_code ec;
    fs::create_directories(d, ec);
    static int64_t last = 0;  // одинаковое время у двух версий — сдвигаем на 1 мс
    int64_t ts = std::max(now_ms(), last + 1);
    last = ts;
    std::string name = std::to_string(ts) + "_" + safe_part(action) + "_" + safe_part(by) + ".yml";
    std::ofstream(d / name, std::ios::binary) << text;
    // хранить последние kMaxVersions версий
    std::vector<fs::path> all;
    for (auto& e : fs::directory_iterator(d, ec))
        if (e.is_regular_file()) all.push_back(e.path());
    std::sort(all.begin(), all.end());
    while (all.size() > kMaxVersions) {
        fs::remove(all.front(), ec);
        all.erase(all.begin());
    }
}

RuleCheck RuleManager::save(const std::string& id, const std::string& text, const std::string& by) {
    std::lock_guard<std::mutex> lock(mu_);
    RuleCheck res;
    std::string file;
    bool creating = id.empty();
    std::string old_text;
    if (creating) {
        std::vector<Rule> parsed;
        std::string err;
        if (!parse_rules_yaml(text, "new.yml", parsed, err) || parsed.empty()) {
            res.error = parsed.empty() && err.empty() ? "no rules in the text" : err;
            res.errors.push_back(res.error);
            return res;
        }
        std::string base = file_name_for(parsed[0].id);
        file = base;
        std::error_code ec;
        for (int n = 2; fs::exists(fs::path(dir_) / file, ec); ++n)
            file = base.substr(0, base.size() - 4) + "-" + std::to_string(n) + ".yml";
    } else {
        file = file_of(id);
        if (file.empty()) {
            res.error = "rule not found";
            return res;
        }
        read_text(fs::path(dir_) / file, old_text);
    }
    res = check_files(file, &text);
    if (!res.ok) return res;
    if (!creating && old_text == text) return res;  // ничего не изменилось
    std::error_code ec;
    if (!creating && !fs::exists(fs::path(history_dir_) / file, ec)) record(file, "original", "file", old_text);
    if (!write_file(file, text, res.error)) {
        res.ok = false;
        return res;
    }
    record(file, creating ? "create" : "update", by, text);
    log::info("rules: ", file, creating ? " created by " : " changed by ", by);
    std::string err;
    if (!reload_locked(err)) {
        res.ok = false;
        res.error = "saved, but reload failed: " + err;
    }
    return res;
}

RuleCheck RuleManager::remove(const std::string& id, const std::string& by) {
    std::lock_guard<std::mutex> lock(mu_);
    RuleCheck res;
    std::string file = file_of(id);
    if (file.empty()) {
        res.error = "rule not found";
        return res;
    }
    size_t in_file = 0;
    for (auto& r : rules_) in_file += r.file == file;
    if (in_file > 1) {
        res.error = "file " + file + " has several rules — remove this one in the editor";
        return res;
    }
    res = check_files(file, nullptr);
    if (!res.ok) return res;
    std::string old_text;
    read_text(fs::path(dir_) / file, old_text);
    record(file, "delete", by, old_text);
    std::error_code ec;
    if (!fs::remove(fs::path(dir_) / file, ec)) {
        res.ok = false;
        res.error = "cannot delete " + file;
        return res;
    }
    log::info("rules: ", file, " deleted by ", by);
    std::string err;
    reload_locked(err);
    return res;
}

bool RuleManager::edit_enabled(const std::string& text, const std::string& id, bool enabled, std::string& out) {
    std::vector<std::string> lines;
    for (auto l : split(text, '\n')) lines.emplace_back(l);
    // строка "id: X" или "- id: X"
    size_t id_line = std::string::npos, key_col = 0;
    for (size_t i = 0; i < lines.size(); ++i) {
        std::string_view l = lines[i];
        size_t ind = indent_of(l);
        std::string_view rest = l.substr(ind);
        size_t col = ind;
        if (starts_with(rest, "- ")) {
            size_t k = 2;
            while (k < rest.size() && rest[k] == ' ') ++k;
            rest = rest.substr(k);
            col += k;
        }
        if (!starts_with(rest, "id:")) continue;
        if (unquote(rest.substr(3)) != id) continue;
        id_line = i;
        key_col = col;
        break;
    }
    if (id_line == std::string::npos) return false;
    // границы описания правила: до строки с меньшим отступом (или следующего элемента списка)
    size_t end = lines.size();
    for (size_t i = id_line + 1; i < lines.size(); ++i) {
        std::string_view l = lines[i];
        std::string_view t = trim(l);
        if (t.empty() || t[0] == '#') continue;
        if (t == "---" || indent_of(l) < key_col) {
            end = i;
            break;
        }
    }
    const std::string value = enabled ? "true" : "false";
    const std::string pad(key_col, ' ');
    bool done = false;
    for (size_t i = id_line + 1; i < end; ++i) {
        std::string_view l = lines[i];
        if (indent_of(l) != key_col || !starts_with(l.substr(key_col), "enabled:")) continue;
        std::string cr = (!l.empty() && l.back() == '\r') ? "\r" : "";
        lines[i] = pad + "enabled: " + value + cr;
        done = true;
        break;
    }
    if (!done && !enabled) {
        std::string cr = (!lines[id_line].empty() && lines[id_line].back() == '\r') ? "\r" : "";
        lines.insert(lines.begin() + long(id_line) + 1, pad + "enabled: " + value + cr);
    }
    out.clear();
    for (size_t i = 0; i < lines.size(); ++i) {
        if (i) out.push_back('\n');
        out += lines[i];
    }
    // проверка: правка дала нужный результат
    std::vector<Rule> parsed;
    std::string err;
    if (!parse_rules_yaml(out, "x.yml", parsed, err)) return false;
    for (auto& r : parsed)
        if (r.id == id) return r.enabled == enabled;
    return false;
}

RuleCheck RuleManager::set_enabled(const std::string& id, bool enabled, const std::string& by) {
    std::string file, text, err;
    RuleCheck res;
    if (!source(id, file, text, err)) {
        res.error = err;
        return res;
    }
    std::string edited;
    if (!edit_enabled(text, id, enabled, edited)) {
        res.error = "cannot change 'enabled' automatically — edit the rule text";
        return res;
    }
    std::lock_guard<std::mutex> lock(mu_);
    if (file_of(id) != file) {
        res.error = "rule changed meanwhile, try again";
        return res;
    }
    res = check_files(file, &edited);
    if (!res.ok) return res;
    if (edited == text) return res;
    std::error_code ec;
    if (!fs::exists(fs::path(history_dir_) / file, ec)) record(file, "original", "file", text);
    if (!write_file(file, edited, res.error)) {
        res.ok = false;
        return res;
    }
    record(file, enabled ? "enable" : "disable", by, edited);
    log::info("rules: ", id, enabled ? " enabled by " : " disabled by ", by);
    std::string rerr;
    reload_locked(rerr);
    return res;
}

std::vector<RuleVersion> RuleManager::history(const std::string& id) const {
    std::vector<RuleVersion> out;
    std::string file;
    {
        std::lock_guard<std::mutex> lock(mu_);
        file = file_of(id);
    }
    if (file.empty() || history_dir_.empty()) return out;
    std::error_code ec;
    for (auto& e : fs::directory_iterator(fs::path(history_dir_) / file, ec)) {
        std::string name = e.path().filename().string();
        std::string stem = name.substr(0, name.size() > 4 ? name.size() - 4 : 0);
        auto parts = split(stem, '_');
        if (parts.size() < 3) continue;
        RuleVersion v;
        v.ts = parse_int(parts[0]).value_or(0);
        v.action = std::string(parts[1]);
        v.by = std::string(parts[2]);
        v.name = name;
        out.push_back(std::move(v));
    }
    std::sort(out.begin(), out.end(), [](const RuleVersion& a, const RuleVersion& b) { return a.ts > b.ts; });
    return out;
}

bool RuleManager::version_text(const std::string& id, const std::string& version, std::string& text) const {
    if (version.empty() || version.find('/') != std::string::npos || version.find('\\') != std::string::npos ||
        version.find("..") != std::string::npos)
        return false;
    std::string file;
    {
        std::lock_guard<std::mutex> lock(mu_);
        file = file_of(id);
    }
    if (file.empty()) return false;
    return read_text(fs::path(history_dir_) / file / version, text);
}

bool RuleManager::prepare_dry(const std::string& text, DryRun& out, DetectionEngine& eng) const {
    if (text.size() > kMaxRuleText) {
        out.error = "rule text is too large";
        return false;
    }
    std::vector<Rule> mine;
    std::string err;
    if (!parse_rules_yaml(text, "test.yml", mine, err)) {
        out.error = err;
        return false;
    }
    if (mine.empty()) {
        out.error = "no rules in the text";
        return false;
    }
    std::set<std::string> have;
    for (auto& r : mine) {
        r.enabled = true;  // проверяем и отключённое правило
        have.insert(r.id);
        out.tested_ids.push_back(r.id);
    }
    // цепочкам нужны правила, на которые они ссылаются — берём рабочие
    std::vector<Rule> current = rules();
    for (bool added = true; added;) {
        added = false;
        std::vector<std::string> need;
        for (auto& r : mine)
            for (auto& s : r.steps)
                if (!s.rule_id.empty() && !have.count(s.rule_id)) need.push_back(s.rule_id);
        for (auto& id : need) {
            if (have.count(id)) continue;
            for (auto& r : current)
                if (r.id == id) {
                    Rule copy = r;
                    copy.enabled = true;
                    mine.push_back(std::move(copy));
                    have.insert(id);
                    out.helper_ids.push_back(id);
                    added = true;
                    break;
                }
        }
    }
    std::vector<std::string> errors;
    validate_rules(mine, errors);
    if (!errors.empty()) {
        out.errors = errors;
        out.error = errors.front();
        return false;
    }
    if (!eng.load(mine, err)) {
        out.error = err;
        return false;
    }
    return true;
}

DryRun RuleManager::try_lines(const std::string& text, const std::vector<std::string>& lines,
                              const std::string& format, int tz_minutes) const {
    DryRun out;
    auto t0 = std::chrono::steady_clock::now();
    DetectionEngine eng;
    if (!prepare_dry(text, out, eng)) return out;
    {
        std::vector<Rule> mine;
        std::string err;
        parse_rules_yaml(text, "test.yml", mine, err);
        out.tests = run_rule_tests(mine);
    }
    ParseContext ctx;
    ctx.now_ms = now_ms();
    ctx.tz_offset_minutes = tz_minutes;
    LogFormat fmt = log_format_from_name(format);
    std::unordered_set<std::string> ips;
    for (size_t i = 0; i < lines.size(); ++i) {
        std::string_view l = trim(lines[i]);
        if (l.empty()) continue;
        DryRunLine dl;
        dl.index = i;
        dl.parsed = parse_line(l, fmt, ctx, dl.event);
        if (dl.parsed) {
            dl.event.id = i + 1;
            ++out.events;
            std::vector<Alert> fired;
            eng.process(dl.event, fired);
            for (auto& a : fired) {
                ++out.alerts_by_rule[a.rule_id];
                if (!a.src_ip.empty()) ips.insert(a.src_ip);
                dl.alerts.push_back(out.alerts.size());
                out.alerts.push_back(std::move(a));
            }
            int64_t t = dl.event.time();
            if (!out.first_ts || t < out.first_ts) out.first_ts = t;
            if (t > out.last_ts) out.last_ts = t;
        }
        out.lines.push_back(std::move(dl));
    }
    out.distinct_ips = ips.size();
    out.took_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    out.ok = true;
    return out;
}

DryRun RuleManager::try_history(const std::string& text, const EventStore& store, int64_t from, int64_t to,
                                size_t max_events) const {
    DryRun out;
    auto t0 = std::chrono::steady_clock::now();
    DetectionEngine eng;
    if (!prepare_dry(text, out, eng)) return out;
    std::unordered_set<std::string> ips;
    std::vector<Alert> fired;
    out.events = store.scan(from, to, max_events, [&](const Event& ev) {
        fired.clear();
        eng.process(ev, fired);
        int64_t t = ev.time();
        if (!out.first_ts || t < out.first_ts) out.first_ts = t;
        if (t > out.last_ts) out.last_ts = t;
        for (auto& a : fired) {
            ++out.alerts_by_rule[a.rule_id];
            if (!a.src_ip.empty() && ips.size() < 100000) ips.insert(a.src_ip);
            if (out.alerts.size() < DryRun::kMaxSample) out.alerts.push_back(std::move(a));
        }
        return true;
    });
    out.truncated = out.events >= max_events;
    out.distinct_ips = ips.size();
    out.took_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    out.ok = true;
    return out;
}

}  // namespace sentinel
