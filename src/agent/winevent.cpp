#include "agent/winevent.hpp"

#include "core/json.hpp"
#include "core/util.hpp"

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <winevt.h>
#endif

namespace sentinel::agent {

namespace {

// Значение атрибута или текста элемента в XML события (простая разметка Windows, без пространств имён).
std::string xml_text(const std::string& xml, const std::string& tag) {
    size_t p = xml.find("<" + tag);
    while (p != std::string::npos) {
        char after = p + 1 + tag.size() < xml.size() ? xml[p + 1 + tag.size()] : 0;
        if (after == '>' || after == ' ' || after == '/') break;
        p = xml.find("<" + tag, p + 1);
    }
    if (p == std::string::npos) return "";
    size_t gt = xml.find('>', p);
    if (gt == std::string::npos || xml[gt - 1] == '/') return "";
    size_t end = xml.find("</" + tag + ">", gt);
    if (end == std::string::npos) return "";
    return xml.substr(gt + 1, end - gt - 1);
}

std::string xml_attr(const std::string& xml, const std::string& tag, const std::string& attr) {
    size_t p = xml.find("<" + tag);
    if (p == std::string::npos) return "";
    size_t gt = xml.find('>', p);
    std::string_view el(xml.data() + p, (gt == std::string::npos ? xml.size() : gt) - p);
    size_t a = el.find(attr + "=");
    if (a == std::string_view::npos) return "";
    a += attr.size() + 1;
    if (a >= el.size()) return "";
    char q = el[a];
    if (q != '\'' && q != '"') return "";
    size_t e = el.find(q, a + 1);
    if (e == std::string_view::npos) return "";
    return std::string(el.substr(a + 1, e - a - 1));
}

std::string xml_unescape(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '&') {
            static const struct {
                const char* e;
                char c;
            } ents[] = {{"&lt;", '<'}, {"&gt;", '>'}, {"&amp;", '&'}, {"&quot;", '"'}, {"&apos;", '\''}};
            bool done = false;
            for (auto& x : ents) {
                size_t n = std::char_traits<char>::length(x.e);
                if (s.compare(i, n, x.e) == 0) {
                    out.push_back(x.c);
                    i += n - 1;
                    done = true;
                    break;
                }
            }
            if (done) continue;
        }
        out.push_back(s[i]);
    }
    return out;
}

// <Data Name='TargetUserName'>bob</Data>
std::string data_field(const std::string& xml, const std::string& name) {
    for (const char* q : {"'", "\""}) {
        std::string marker = std::string("<Data Name=") + q + name + q;
        size_t p = xml.find(marker);
        if (p == std::string::npos) continue;
        size_t gt = xml.find('>', p);
        if (gt == std::string::npos || xml[gt - 1] == '/') return "";
        size_t end = xml.find("</Data>", gt);
        if (end == std::string::npos) return "";
        std::string v = xml_unescape(xml.substr(gt + 1, end - gt - 1));
        return v == "-" ? "" : v;
    }
    return "";
}

}  // namespace

bool WinEventReader::xml_to_json(const std::string& xml, std::string& json) {
    std::string id = xml_text(xml, "EventID");
    if (id.empty()) return false;
    std::string ts = xml_attr(xml, "TimeCreated", "SystemTime");
    std::string computer = xml_unescape(xml_text(xml, "Computer"));
    std::string target = data_field(xml, "TargetUserName");
    std::string subject = data_field(xml, "SubjectUserName");
    std::string ip = data_field(xml, "IpAddress");
    std::string logon_type = data_field(xml, "LogonType");

    std::string type, action, outcome, user = target, text;
    if (id == "4624" || id == "4625") {
        // Служебные входы (тип 5 — службы, 0 — система) и машинные учётки — шум
        if (logon_type == "5" || logon_type == "0" || ends_with(target, "$")) return false;
        type = "auth";
        action = "login";
        outcome = id == "4624" ? "success" : "failure";
        text = id == "4624" ? "An account was successfully logged on" : "An account failed to log on";
    } else if (id == "4740") {
        type = "auth";
        action = "lockout";
        outcome = "failure";
        text = "A user account was locked out";
    } else if (id == "4720" || id == "4726") {
        type = "account";
        action = id == "4720" ? "user_created" : "user_deleted";
        outcome = "success";
        text = id == "4720" ? "A user account was created" : "A user account was deleted";
    } else if (id == "4728" || id == "4732" || id == "4756") {
        type = "account";
        action = "group_member_added";
        outcome = "success";
        user = data_field(xml, "MemberName");
        text = "A member was added to a security-enabled group " + target;
    } else if (id == "4672") {
        if (subject == "SYSTEM" || subject == "LOCAL SERVICE" || subject == "NETWORK SERVICE" || ends_with(subject, "$"))
            return false;
        type = "privilege";
        action = "admin_logon";
        outcome = "success";
        user = subject;
        text = "Special privileges assigned to new logon";
    } else if (id == "1102") {
        type = "system";
        action = "audit_log_cleared";
        outcome = "success";
        user = data_field(xml, "SubjectUserName");
        if (user.empty()) user = xml_unescape(xml_text(xml, "SubjectUserName"));
        text = "The audit log was cleared";
    } else {
        type = "system";
        action = "event_" + id;
        text = "Windows event " + id;
    }
    std::string message = "Windows " + id + ": " + text;
    if (!user.empty()) message += " (user " + user + (ip.empty() ? "" : " from " + ip) + ")";

    json.clear();
    JsonWriter w(json);
    w.begin_object();
    if (!ts.empty()) w.kv("ts", ts);
    w.kv("source", "windows").kv("process", "security").kv("type", type).kv("action", action);
    if (!outcome.empty()) w.kv("outcome", outcome);
    if (!computer.empty()) w.kv("host", computer);
    if (!user.empty()) w.kv("user", user);
    if (!ip.empty()) w.kv("src_ip", ip);
    w.kv("message", message);
    w.kv("event_id", id);
    if (!logon_type.empty()) w.kv("logon_type", logon_type);
    std::string status = data_field(xml, "Status");
    if (!status.empty()) w.kv("status_code", status);
    std::string sub = data_field(xml, "SubStatus");
    if (!sub.empty()) w.kv("sub_status", sub);
    if (!subject.empty() && subject != user) w.kv("subject_user", subject);
    w.end_object();
    return true;
}

WinEventReader::WinEventReader(std::string channel, std::string bookmark)
    : channel_(std::move(channel)), committed_(bookmark), pending_(std::move(bookmark)) {}

WinEventReader::~WinEventReader() = default;

#ifdef _WIN32

namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring w(size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), w.data(), n);
    return w;
}

std::string narrow(const wchar_t* w) {
    if (!w || !*w) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s(size_t(n > 0 ? n - 1 : 0), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

bool render(EVT_HANDLE h, DWORD flags, std::string& out) {
    DWORD used = 0, props = 0;
    EvtRender(nullptr, h, flags, 0, nullptr, &used, &props);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || used == 0) return false;
    std::vector<wchar_t> buf(used / sizeof(wchar_t) + 1);
    if (!EvtRender(nullptr, h, flags, used, buf.data(), &used, &props)) return false;
    out = narrow(buf.data());
    return true;
}

const wchar_t* kQuery =
    L"*[System[(EventID=4624 or EventID=4625 or EventID=4740 or EventID=4720 or EventID=4726 or "
    L"EventID=4728 or EventID=4732 or EventID=4756 or EventID=4672 or EventID=1102)]]";

}  // namespace

bool WinEventReader::read(std::vector<std::string>& json_lines, size_t max_events, std::string& error) {
    std::wstring ch = widen(channel_);
    EVT_HANDLE q = EvtQuery(nullptr, ch.c_str(), kQuery, EvtQueryChannelPath | EvtQueryForwardDirection);
    if (!q) {
        DWORD e = GetLastError();
        error = e == ERROR_ACCESS_DENIED ? "access to the " + channel_ + " log denied (run the agent as Administrator)"
                                         : "EvtQuery failed, error " + std::to_string(e);
        return false;
    }
    EVT_HANDLE bm = nullptr;
    bool skip_current = false;
    if (pending_.empty()) {
        // Первый запуск: прошлые события не шлём, запоминаем последнее как отправную точку.
        bm = EvtCreateBookmark(nullptr);
        if (EvtSeek(q, 0, nullptr, 0, EvtSeekRelativeToLast)) {
            EVT_HANDLE h = nullptr;
            DWORD got = 0;
            if (EvtNext(q, 1, &h, 0, 0, &got) && got == 1) {
                EvtUpdateBookmark(bm, h);
                EvtClose(h);
            }
        }
        std::string xml;
        if (render(bm, EvtRenderBookmark, xml)) pending_ = committed_ = xml;
        else pending_ = committed_ = "<BookmarkList/>";
        EvtClose(bm);
        EvtClose(q);
        return true;
    }
    std::wstring bw = widen(pending_);
    bm = EvtCreateBookmark(pending_ == "<BookmarkList/>" ? nullptr : bw.c_str());
    if (!bm) bm = EvtCreateBookmark(nullptr);
    if (pending_ != "<BookmarkList/>") {
        if (!EvtSeek(q, 1, bm, 0, EvtSeekRelativeToBookmark)) {
            // Событие закладки исчезло (журнал очищен/перезаписан) — читаем с последнего
            EvtSeek(q, 0, nullptr, 0, EvtSeekRelativeToLast);
            skip_current = true;
        }
    }
    size_t produced = 0;
    EVT_HANDLE hs[64];
    while (produced < max_events) {
        DWORD got = 0;
        if (!EvtNext(q, 64, hs, 0, 0, &got)) {
            DWORD e = GetLastError();
            if (e != ERROR_NO_MORE_ITEMS && e != ERROR_TIMEOUT) error = "EvtNext failed, error " + std::to_string(e);
            break;
        }
        for (DWORD i = 0; i < got; ++i) {
            if (skip_current) {
                skip_current = false;
            } else {
                std::string xml, js;
                if (render(hs[i], EvtRenderEventXml, xml) && xml_to_json(xml, js)) {
                    json_lines.push_back(std::move(js));
                    ++produced;
                }
            }
            EvtUpdateBookmark(bm, hs[i]);
            EvtClose(hs[i]);
        }
    }
    std::string xml;
    if (render(bm, EvtRenderBookmark, xml)) pending_ = xml;
    EvtClose(bm);
    EvtClose(q);
    return error.empty();
}

#else

bool WinEventReader::read(std::vector<std::string>&, size_t, std::string& error) {
    error = "Windows event log is only available on Windows";
    return false;
}

#endif

}  // namespace sentinel::agent
