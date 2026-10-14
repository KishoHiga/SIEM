#include "parse/parsers.hpp"

#include "core/util.hpp"

namespace sentinel {

LogFormat log_format_from_name(std::string_view n) {
    if (iequals(n, "json") || iequals(n, "ndjson") || iequals(n, "docker")) return LogFormat::Json;
    if (iequals(n, "nginx") || iequals(n, "apache") || iequals(n, "clf") || iequals(n, "combined"))
        return LogFormat::Nginx;
    if (iequals(n, "syslog") || iequals(n, "auth") || iequals(n, "authlog")) return LogFormat::Syslog;
    if (iequals(n, "kv") || iequals(n, "keyvalue") || iequals(n, "firewall")) return LogFormat::KeyValue;
    if (iequals(n, "plain") || iequals(n, "text")) return LogFormat::Plain;
    return LogFormat::Auto;
}

const char* log_format_name(LogFormat f) {
    switch (f) {
        case LogFormat::Auto: return "auto";
        case LogFormat::Json: return "json";
        case LogFormat::Nginx: return "nginx";
        case LogFormat::Syslog: return "syslog";
        case LogFormat::KeyValue: return "kv";
        case LogFormat::Plain: return "plain";
    }
    return "auto";
}

namespace {

struct Cursor {
    std::string_view s;
    size_t p = 0;

    bool done() const { return p >= s.size(); }
    char peek() const { return p < s.size() ? s[p] : '\0'; }
    void skip_spaces() {
        while (p < s.size() && s[p] == ' ') ++p;
    }
    std::string_view token() {
        skip_spaces();
        size_t st = p;
        while (p < s.size() && s[p] != ' ') ++p;
        return s.substr(st, p - st);
    }
    // "..." с экранированием \" и \\ (остальные \xHH оставляем как есть)
    bool quoted(std::string& out) {
        skip_spaces();
        if (peek() != '"') return false;
        ++p;
        out.clear();
        while (p < s.size()) {
            char c = s[p++];
            if (c == '\\' && p < s.size() && (s[p] == '"' || s[p] == '\\')) {
                out.push_back(s[p++]);
                continue;
            }
            if (c == '"') return true;
            out.push_back(c);
        }
        return false;
    }
    std::string_view rest() {
        skip_spaces();
        return s.substr(p < s.size() ? p : s.size());
    }
};

bool all_digits(std::string_view s) {
    if (s.empty()) return false;
    for (char c : s)
        if (!is_digit(c)) return false;
    return true;
}

void set_if(Event& ev, Field f, std::string_view v) {
    if (!v.empty() && v != "-") ev[f].assign(v.data(), v.size());
}

}  // namespace

// ---------------- nginx / apache ----------------

bool parse_clf_time(std::string_view s, int64_t& out_ms) {
    // 10/Oct/2000:13:55:36 -0700
    if (s.size() < 20) return false;
    auto num = [&](size_t pos, size_t n, int& v) -> bool {
        if (pos + n > s.size()) return false;
        v = 0;
        for (size_t i = 0; i < n; ++i) {
            if (!is_digit(s[pos + i])) return false;
            v = v * 10 + (s[pos + i] - '0');
        }
        return true;
    };
    int d, y, h, mi, sec;
    if (!num(0, 2, d) || s[2] != '/') return false;
    unsigned mon = month_from_abbr(s.substr(3, 3));
    if (!mon || s[6] != '/') return false;
    if (!num(7, 4, y) || s[11] != ':') return false;
    if (!num(12, 2, h) || s[14] != ':' || !num(15, 2, mi) || s[17] != ':' || !num(18, 2, sec)) return false;
    int64_t offset_min = 0;
    if (s.size() >= 26 && s[20] == ' ' && (s[21] == '+' || s[21] == '-')) {
        int oh, om;
        if (!num(22, 2, oh) || !num(24, 2, om)) return false;
        offset_min = (s[21] == '-' ? -1 : 1) * (oh * 60 + om);
    }
    int64_t days = days_from_civil(y, mon, unsigned(d));
    out_ms = (days * 86400 + h * 3600 + mi * 60 + sec - offset_min * 60) * 1000;
    return true;
}

bool parse_nginx(std::string_view line, const ParseContext& ctx, Event& ev) {
    // Быстрая проверка формы до разбора
    if (line.find(" [") == std::string_view::npos || line.find('"') == std::string_view::npos) return false;
    Cursor c{line};
    std::string_view ip = c.token();
    std::string_view ident = c.token();
    std::string_view user = c.token();
    if (ip.empty() || ident.empty() || user.empty()) return false;
    c.skip_spaces();
    if (c.peek() != '[') return false;
    size_t close = line.find(']', c.p);
    if (close == std::string_view::npos) return false;
    std::string_view tstr = line.substr(c.p + 1, close - c.p - 1);
    c.p = close + 1;
    std::string request;
    if (!c.quoted(request)) return false;
    std::string_view status = c.token();
    if (status.size() != 3 || !all_digits(status)) return false;
    std::string_view bytes = c.token();
    std::string referer, ua;
    if (c.quoted(referer)) c.quoted(ua);

    int64_t ts = 0;
    if (parse_clf_time(tstr, ts)) {
        if (tstr.size() < 26) ts -= int64_t(ctx.tz_offset_minutes) * 60000;
        ev.ts = ts;
    }
    set_if(ev, Field::SrcIp, ip);
    set_if(ev, Field::User, user);

    // "GET /path HTTP/1.1"
    std::string_view req = request;
    size_t sp1 = req.find(' ');
    size_t sp2 = sp1 == std::string_view::npos ? std::string_view::npos : req.rfind(' ');
    bool method_ok = sp1 != std::string_view::npos && sp1 > 0 && sp1 <= 16;
    for (size_t i = 0; method_ok && i < sp1; ++i)
        if (!(req[i] >= 'A' && req[i] <= 'Z')) method_ok = false;
    if (method_ok) {
        ev[Field::HttpMethod].assign(req.substr(0, sp1));
        if (sp2 != sp1 && starts_with(req.substr(sp2 + 1), "HTTP/"))
            ev[Field::HttpPath].assign(req.substr(sp1 + 1, sp2 - sp1 - 1));
        else
            ev[Field::HttpPath].assign(req.substr(sp1 + 1));
        ev[Field::Action] = ev[Field::HttpMethod];
    } else {
        ev[Field::HttpPath] = request;  // мусорный запрос (сканеры) — сохраняем как есть
        ev[Field::Action] = "request";
    }
    ev[Field::HttpStatus].assign(status);
    if (all_digits(bytes)) ev[Field::Bytes].assign(bytes);
    set_if(ev, Field::HttpReferer, referer);
    set_if(ev, Field::HttpUserAgent, ua);
    ev[Field::Type] = "web";
    ev[Field::Outcome] = status[0] < '4' ? "success" : "failure";
    if (ev[Field::Source].empty()) ev[Field::Source] = ctx.source_hint.empty() ? "nginx" : std::string(ctx.source_hint);
    ev[Field::Message] = request;
    ev[Field::Message] += " -> ";
    ev[Field::Message].append(status);
    return true;
}

// ---------------- syslog ----------------

static bool parse_bsd_time(std::string_view s, const ParseContext& ctx, int64_t& out) {
    // "Oct 12 13:55:36" (день может быть дополнен пробелом: "Oct  2")
    if (s.size() < 15) return false;
    unsigned mon = month_from_abbr(s.substr(0, 3));
    if (!mon || s[3] != ' ') return false;
    int d = 0;
    if (s[4] == ' ' && is_digit(s[5])) {
        d = s[5] - '0';
    } else if (is_digit(s[4]) && is_digit(s[5])) {
        d = (s[4] - '0') * 10 + (s[5] - '0');
    } else {
        return false;
    }
    if (s[6] != ' ') return false;
    auto two = [&](size_t pos, int& v) {
        if (!is_digit(s[pos]) || !is_digit(s[pos + 1])) return false;
        v = (s[pos] - '0') * 10 + (s[pos + 1] - '0');
        return true;
    };
    int h, mi, sec;
    if (!two(7, h) || s[9] != ':' || !two(10, mi) || s[12] != ':' || !two(13, sec)) return false;
    int64_t now = ctx.now_ms ? ctx.now_ms : now_ms();
    int64_t y;
    unsigned cm, cd;
    civil_from_days(now / 86400000, y, cm, cd);
    auto make = [&](int64_t year) {
        return (days_from_civil(year, mon, unsigned(d)) * 86400 + h * 3600 + mi * 60 + sec) * 1000 -
               int64_t(ctx.tz_offset_minutes) * 60000;
    };
    out = make(y);
    if (out > now + 2 * 86400000LL) out = make(y - 1);  // декабрьская запись, прочитанная в январе
    return true;
}

static void split_tag(std::string_view tag, Event& ev) {
    // "sshd[1234]" -> process=sshd, pid=1234
    size_t br = tag.find('[');
    if (br != std::string_view::npos && ends_with(tag, "]")) {
        ev[Field::Process].assign(tag.substr(0, br));
        ev.extra_set("pid", tag.substr(br + 1, tag.size() - br - 2));
    } else {
        ev[Field::Process].assign(tag);
    }
}

bool parse_syslog(std::string_view line, const ParseContext& ctx, Event& ev) {
    Cursor c{line};
    int pri = -1;
    if (c.peek() == '<') {
        size_t close = line.find('>');
        if (close == std::string_view::npos || close < 2 || close > 4) return false;
        auto v = parse_int(line.substr(1, close - 1));
        if (!v || *v < 0 || *v > 191) return false;
        pri = int(*v);
        c.p = close + 1;
    }
    // RFC 5424: "<PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG"
    if (pri >= 0 && c.p + 1 < line.size() && line[c.p] == '1' && line[c.p + 1] == ' ') {
        c.p += 2;
        std::string_view ts = c.token();
        std::string_view host = c.token();
        std::string_view app = c.token();
        std::string_view procid = c.token();
        std::string_view msgid = c.token();
        if (ts.empty() || host.empty() || app.empty()) return false;
        if (ts != "-") {
            if (auto t = parse_iso8601(ts)) ev.ts = *t;
        }
        set_if(ev, Field::Host, host);
        set_if(ev, Field::Process, app);
        if (procid != "-") ev.extra_set("pid", procid);
        if (msgid != "-" && !msgid.empty()) ev.extra_set("msgid", msgid);
        c.skip_spaces();
        if (c.peek() == '[') {
            // структурированные данные: пропускаем [..][..] с учётом кавычек
            bool in_q = false;
            int depth = 0;
            while (c.p < line.size()) {
                char ch = line[c.p];
                if (in_q) {
                    if (ch == '\\') ++c.p;
                    else if (ch == '"') in_q = false;
                } else if (ch == '"') {
                    in_q = true;
                } else if (ch == '[') {
                    ++depth;
                } else if (ch == ']') {
                    --depth;
                    if (depth == 0 && (c.p + 1 >= line.size() || line[c.p + 1] != '[')) {
                        ++c.p;
                        break;
                    }
                }
                ++c.p;
            }
        } else if (c.peek() == '-') {
            ++c.p;
        }
        std::string_view msg = c.rest();
        if (starts_with(msg, "\xEF\xBB\xBF")) msg.remove_prefix(3);
        ev[Field::Message].assign(msg);
    } else {
        // BSD: "Oct 12 13:55:36 host tag[pid]: msg" или ISO-время вместо BSD
        c.skip_spaces();
        std::string_view rest = line.substr(c.p);
        int64_t ts = 0;
        if (parse_bsd_time(rest, ctx, ts)) {
            c.p += 15;
        } else {
            size_t save = c.p;
            std::string_view tok = c.token();
            auto t = parse_iso8601(tok);
            if (!t) {
                if (pri < 0) return false;  // без PRI и без времени — это не syslog
                c.p = save;
            } else {
                ts = *t;
            }
        }
        if (ts) ev.ts = ts;
        // host и tag
        std::string_view t1 = c.token();
        bool t1_is_tag = !t1.empty() && t1.back() == ':';
        if (t1_is_tag) {
            split_tag(t1.substr(0, t1.size() - 1), ev);
        } else {
            set_if(ev, Field::Host, t1);
            size_t save2 = c.p;
            std::string_view t2 = c.token();
            if (!t2.empty() && t2.back() == ':') {
                split_tag(t2.substr(0, t2.size() - 1), ev);
            } else if (size_t colon = t2.find("]:"); colon != std::string_view::npos) {
                split_tag(t2.substr(0, colon + 1), ev);
                c.p = size_t(t2.data() - line.data()) + colon + 2;
            } else {
                c.p = save2;  // тега нет, дальше сообщение
            }
        }
        ev[Field::Message].assign(c.rest());
    }
    if (pri >= 0) {
        static const char* sev[] = {"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"};
        ev.extra_set("syslog_severity", sev[pri % 8]);
        ev.extra_set("syslog_facility", std::to_string(pri / 8));
    }
    if (ev[Field::Type].empty()) ev[Field::Type] = "system";
    if (ev[Field::Source].empty()) ev[Field::Source] = ctx.source_hint.empty() ? "syslog" : std::string(ctx.source_hint);
    return true;
}

// ---------------- key=value ----------------

static void kv_assign(Event& ev, std::string_view k, std::string_view v) {
    std::string key = to_lower(k);
    if (key == "src" || key == "srcip" || key == "src_ip" || key == "source_ip") set_if(ev, Field::SrcIp, v);
    else if (key == "dst" || key == "dstip" || key == "dst_ip" || key == "dest_ip") set_if(ev, Field::DstIp, v);
    else if (key == "spt" || key == "sport" || key == "src_port" || key == "srcport") set_if(ev, Field::SrcPort, v);
    else if (key == "dpt" || key == "dport" || key == "dst_port" || key == "dstport") set_if(ev, Field::DstPort, v);
    else if (key == "proto" || key == "protocol") set_if(ev, Field::Proto, v);
    else if (key == "action") set_if(ev, Field::Action, to_lower(v));
    else if (key == "user" || key == "username" || key == "usr") set_if(ev, Field::User, v);
    else if (key == "host" || key == "hostname") set_if(ev, Field::Host, v);
    else if (key == "msg" || key == "message") set_if(ev, Field::Message, v);
    else if (key == "outcome" || key == "result") set_if(ev, Field::Outcome, to_lower(v));
    else if (!v.empty()) ev.extra_set(k, v);
}

// Разбирает все key=value в строке; возвращает число найденных пар.
static int scan_kv(std::string_view line, Event& ev) {
    int pairs = 0;
    size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && line[i] == ' ') ++i;
        size_t ks = i;
        while (i < line.size() && (is_alpha(line[i]) || is_digit(line[i]) || line[i] == '_' || line[i] == '.' || line[i] == '-'))
            ++i;
        if (i < line.size() && line[i] == '=' && i > ks) {
            std::string_view key = line.substr(ks, i - ks);
            ++i;
            std::string val;
            if (i < line.size() && line[i] == '"') {
                ++i;
                while (i < line.size() && line[i] != '"') {
                    if (line[i] == '\\' && i + 1 < line.size()) ++i;
                    val.push_back(line[i++]);
                }
                if (i < line.size()) ++i;
            } else {
                size_t vs = i;
                while (i < line.size() && line[i] != ' ') ++i;
                val.assign(line.substr(vs, i - vs));
            }
            kv_assign(ev, key, val);
            ++pairs;
        } else {
            while (i < line.size() && line[i] != ' ') ++i;  // не пара — пропускаем слово
        }
    }
    return pairs;
}

bool parse_keyvalue(std::string_view line, const ParseContext& ctx, Event& ev) {
    Event tmp;
    if (scan_kv(line, tmp) < 2) return false;
    for (size_t i = 0; i < kFieldCount; ++i)
        if (!tmp.f[i].empty()) ev.f[i] = std::move(tmp.f[i]);
    for (auto& kv : tmp.extra) ev.extra_set(kv.first, kv.second);
    if (ev[Field::Message].empty()) ev[Field::Message].assign(line);
    if (!ev[Field::SrcIp].empty() && !ev[Field::DstIp].empty() && ev[Field::Type].empty()) ev[Field::Type] = "network";
    if (ev[Field::Type].empty()) ev[Field::Type] = "event";
    if (ev[Field::Source].empty()) ev[Field::Source] = ctx.source_hint.empty() ? "kv" : std::string(ctx.source_hint);
    return true;
}

// ---------------- JSON ----------------

static bool json_time(const JValue& v, int64_t& out) {
    if (v.is_string()) {
        if (auto t = parse_iso8601(v.s)) {
            out = *t;
            return true;
        }
        if (auto n = parse_double(v.s)) {
            JValue num;
            num.type = JValue::Type::Number;
            num.d = *n;
            return json_time(num, out);
        }
        return false;
    }
    if (v.is_number()) {
        double d = v.d;
        if (d <= 0) return false;
        if (d < 1e11) out = int64_t(d * 1000.0);         // секунды
        else if (d < 1e14) out = int64_t(d);             // миллисекунды
        else out = int64_t(d / 1000.0);                  // микросекунды
        return true;
    }
    return false;
}

static void json_flatten(const JValue& v, std::string& path, Event& ev, int depth) {
    if (depth > 8) return;
    if (v.is_object()) {
        size_t base = path.size();
        for (auto& kv : v.obj) {
            if (!path.empty()) path.push_back('.');
            path += kv.first;
            json_flatten(kv.second, path, ev, depth + 1);
            path.resize(base);
        }
        return;
    }
    if (v.is_null()) return;
    if (path == "ts" || path == "timestamp" || path == "time" || path == "@timestamp" || path == "date" ||
        path == "event.created") {
        int64_t t;
        if (ev.ts == 0 && json_time(v, t)) {
            ev.ts = t;
            return;
        }
    }
    std::string text = v.as_text();
    if (auto f = field_from_name(path)) {
        if (ev[*f].empty()) ev[*f] = std::move(text);
    } else {
        ev.extra_set(path, text);
    }
}

bool event_from_json(const JValue& obj, const ParseContext& ctx, Event& ev) {
    if (!obj.is_object()) return false;
    std::string path;
    json_flatten(obj, path, ev, 0);
    if (ev[Field::Source].empty()) ev[Field::Source] = ctx.source_hint.empty() ? "json" : std::string(ctx.source_hint);
    if (ev[Field::Type].empty()) {
        if (!ev[Field::HttpPath].empty() || !ev[Field::HttpStatus].empty()) ev[Field::Type] = "web";
        else ev[Field::Type] = "app";
    }
    if (ev[Field::Outcome].empty() && !ev[Field::HttpStatus].empty())
        ev[Field::Outcome] = ev[Field::HttpStatus][0] < '4' ? "success" : "failure";
    return true;
}

bool parse_json_line(std::string_view line, const ParseContext& ctx, Event& ev) {
    JValue v;
    std::string err;
    if (!json_parse(line, v, err) || !v.is_object()) return false;
    // Docker json-file: {"log":"...","stream":"stdout","time":"..."}
    const JValue* log = v.get("log");
    if (log && log->is_string() && v.obj.size() <= 4) {
        std::string_view inner = log->s;
        while (!inner.empty() && (inner.back() == '\n' || inner.back() == '\r')) inner.remove_suffix(1);
        if (!inner.empty() && inner.front() != '{') {
            parse_line(inner, LogFormat::Auto, ctx, ev);
            if (const JValue* t = v.get("time")) {
                int64_t ts;
                if (ev.ts == 0 && json_time(*t, ts)) ev.ts = ts;
            }
            if (const JValue* s = v.get("stream"); s && s->is_string()) ev.extra_set("stream", s->s);
            return true;
        }
    }
    return event_from_json(v, ctx, ev);
}

// ---------------- Обогащение ----------------

namespace {

// Достаёт слово после маркера: after("... from 1.2.3.4 port 22", " from ") -> "1.2.3.4"
std::string_view word_after(std::string_view s, std::string_view marker) {
    size_t p = s.find(marker);
    if (p == std::string_view::npos) return {};
    p += marker.size();
    size_t e = p;
    while (e < s.size() && s[e] != ' ' && s[e] != ';') ++e;
    return s.substr(p, e - p);
}

void ssh_enrich(Event& ev) {
    const std::string& m = ev[Field::Message];
    auto login = [&](const char* outcome) {
        ev[Field::Type] = "auth";
        ev[Field::Action] = "login";
        ev[Field::Outcome] = outcome;
        set_if(ev, Field::SrcIp, word_after(m, " from "));
        set_if(ev, Field::SrcPort, word_after(m, " port "));
        if (ev[Field::Proto].empty()) ev[Field::Proto] = "ssh";
    };
    if (starts_with(m, "Failed ") || starts_with(m, "Accepted ")) {
        bool ok = m[0] == 'A';
        std::string_view method = word_after(m, ok ? "Accepted " : "Failed ");
        std::string_view user = word_after(m, " for ");
        if (user == "invalid") {
            user = word_after(m, " invalid user ");
            ev.extra_set("invalid_user", "true");
        }
        set_if(ev, Field::User, user);
        ev.extra_set("auth_method", method);
        login(ok ? "success" : "failure");
    } else if (starts_with(m, "Invalid user ")) {
        set_if(ev, Field::User, word_after(m, "Invalid user "));
        ev.extra_set("invalid_user", "true");
        login("failure");
        ev[Field::Action] = "invalid_user";  // дублирует следующую строку "Failed password" — не считаем дважды
    } else if (m.find("maximum authentication attempts exceeded for ") != std::string::npos) {
        std::string_view user = word_after(m, " exceeded for ");
        if (user == "invalid") user = word_after(m, " invalid user ");
        set_if(ev, Field::User, user);
        login("failure");
        ev[Field::Action] = "max_attempts";
    } else if (starts_with(m, "Did not receive identification string from ") ||
               starts_with(m, "Bad protocol version identification")) {
        ev[Field::Type] = "network";
        ev[Field::Action] = "ssh_probe";
        set_if(ev, Field::SrcIp, word_after(m, " from "));
        set_if(ev, Field::SrcPort, word_after(m, " port "));
    }
}

void pam_enrich(Event& ev) {
    // pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=root
    const std::string& m = ev[Field::Message];
    if (m.find("authentication failure") == std::string::npos) return;
    ev[Field::Type] = "auth";
    ev[Field::Action] = "pam";
    ev[Field::Outcome] = "failure";
    set_if(ev, Field::SrcIp, word_after(m, " rhost="));
    std::string_view u = word_after(m, " user=");
    if (!u.empty()) set_if(ev, Field::User, u);
    size_t lp = m.find('('), cp = m.find(':', lp == std::string::npos ? 0 : lp);
    if (lp != std::string::npos && cp != std::string::npos && cp > lp)
        ev.extra_set("pam_service", std::string_view(m).substr(lp + 1, cp - lp - 1));
}

void sudo_enrich(Event& ev) {
    // "ivan : TTY=pts/0 ; PWD=/home/ivan ; USER=root ; COMMAND=/usr/bin/id"
    // "ivan : 3 incorrect password attempts ; TTY=pts/0 ; ..."
    const std::string& m = ev[Field::Message];
    if (starts_with(m, "pam_unix(")) {
        pam_enrich(ev);
        return;
    }
    size_t colon = m.find(" : ");
    if (colon == std::string::npos) return;
    ev[Field::Type] = "privilege";
    ev[Field::Action] = "sudo";
    set_if(ev, Field::User, trim(std::string_view(m).substr(0, colon)));
    ev[Field::Outcome] = "success";
    auto parts = split(std::string_view(m).substr(colon + 3), ';');
    for (auto part : parts) {
        part = trim(part);
        size_t eq = part.find('=');
        if (eq == std::string_view::npos) {
            if (!part.empty()) {
                ev[Field::Outcome] = "failure";
                ev.extra_set("reason", part);
            }
            continue;
        }
        std::string_view k = part.substr(0, eq), v = part.substr(eq + 1);
        if (k == "COMMAND") ev.extra_set("command", v);
        else if (k == "USER") ev.extra_set("target_user", v);
        else if (k == "TTY") ev.extra_set("tty", v);
        else if (k == "PWD") ev.extra_set("pwd", v);
    }
}

void su_enrich(Event& ev) {
    const std::string& m = ev[Field::Message];
    if (starts_with(m, "pam_unix(")) {
        pam_enrich(ev);
        return;
    }
    // "FAILED SU (to root) ivan on pts/0" | "(to root) ivan on pts/0"
    bool failed = starts_with(m, "FAILED SU");
    size_t to = m.find("(to ");
    if (to == std::string::npos) return;
    size_t close = m.find(')', to);
    if (close == std::string::npos) return;
    ev[Field::Type] = "privilege";
    ev[Field::Action] = "su";
    ev[Field::Outcome] = failed ? "failure" : "success";
    ev.extra_set("target_user", std::string_view(m).substr(to + 4, close - to - 4));
    set_if(ev, Field::User, word_after(std::string_view(m).substr(close), ") "));
}

void firewall_enrich(Event& ev) {
    const std::string& m = ev[Field::Message];
    if (m.find("SRC=") == std::string::npos || m.find("DST=") == std::string::npos) return;
    Event tmp;
    scan_kv(m, tmp);
    for (Field f : {Field::SrcIp, Field::DstIp, Field::SrcPort, Field::DstPort, Field::Proto})
        if (!tmp[f].empty()) ev[f] = tmp[f];
    if (auto* in = tmp.extra_get("IN")) ev.extra_set("in_iface", *in);
    ev[Field::Type] = "network";
    std::string up;
    up.reserve(m.size());
    for (char ch : m) up.push_back(char(ch >= 'a' && ch <= 'z' ? ch - 32 : ch));
    if (up.find("BLOCK") != std::string::npos || up.find("DROP") != std::string::npos ||
        up.find("REJECT") != std::string::npos || up.find("DENY") != std::string::npos)
        ev[Field::Action] = "block";
    else if (up.find("ALLOW") != std::string::npos || up.find("ACCEPT") != std::string::npos)
        ev[Field::Action] = "allow";
    else
        ev[Field::Action] = "log";
    ev[Field::Proto] = to_lower(ev[Field::Proto]);
}

}  // namespace

void enrich_event(Event& ev) {
    const std::string& proc = ev[Field::Process];
    if (proc.empty()) return;
    if (proc == "sshd" || starts_with(proc, "sshd-")) {
        if (starts_with(ev[Field::Message], "pam_unix(")) pam_enrich(ev);
        else ssh_enrich(ev);
    } else if (proc == "sudo") {
        sudo_enrich(ev);
    } else if (proc == "su") {
        su_enrich(ev);
    } else if (proc == "kernel") {
        firewall_enrich(ev);
    } else if (starts_with(ev[Field::Message], "pam_unix(")) {
        pam_enrich(ev);
    }
}

// ---------------- Общая точка входа ----------------

bool parse_line(std::string_view line, LogFormat fmt, const ParseContext& ctx, Event& ev) {
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.remove_suffix(1);
    std::string_view t = trim(line);
    if (t.empty()) return false;
    if (ev.received == 0) ev.received = ctx.now_ms ? ctx.now_ms : now_ms();

    bool ok = false;
    switch (fmt) {
        case LogFormat::Json: ok = parse_json_line(t, ctx, ev); break;
        case LogFormat::Nginx: ok = parse_nginx(t, ctx, ev); break;
        case LogFormat::Syslog: ok = parse_syslog(t, ctx, ev); break;
        case LogFormat::KeyValue: ok = parse_keyvalue(t, ctx, ev); break;
        case LogFormat::Plain: break;
        case LogFormat::Auto: {
            char c0 = t[0];
            if (c0 == '{') ok = parse_json_line(t, ctx, ev);
            if (!ok && c0 == '<') ok = parse_syslog(t, ctx, ev);
            if (!ok) ok = parse_nginx(t, ctx, ev);
            if (!ok && (month_from_abbr(t.substr(0, 3)) || (t.size() > 10 && is_digit(c0) && t[4] == '-')))
                ok = parse_syslog(t, ctx, ev);
            if (!ok) ok = parse_keyvalue(t, ctx, ev);
            break;
        }
    }
    if (!ok) {
        // Не распознали — всё равно сохраняем как простое сообщение (данные не теряем).
        Event fresh;
        fresh.received = ev.received;
        ev = std::move(fresh);
        ev[Field::Message].assign(t);
        ev[Field::Type] = "log";
        ev[Field::Source] = ctx.source_hint.empty() ? "plain" : std::string(ctx.source_hint);
    }
    if (ev[Field::Raw].empty()) ev[Field::Raw].assign(line);
    enrich_event(ev);
    if (ev[Field::Host].empty() && !ctx.host_hint.empty()) ev[Field::Host].assign(ctx.host_hint);
    if (!ctx.source_hint.empty() && ev[Field::Source].empty()) ev[Field::Source].assign(ctx.source_hint);
    if (ev.ts == 0) ev.ts = ev.received;
    return true;
}

}  // namespace sentinel
