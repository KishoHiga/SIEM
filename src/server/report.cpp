#include "server/report.hpp"

#include <algorithm>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <unordered_map>

#include "core/log.hpp"
#include "core/util.hpp"
#include "net/smtp.hpp"

namespace sentinel {

namespace {

constexpr int64_t kDay = 86400000;

const char* sev_ru(Severity s) {
    switch (s) {
        case Severity::Critical: return "Критический";
        case Severity::High: return "Высокий";
        case Severity::Medium: return "Средний";
        case Severity::Low: return "Низкий";
        default: return "Инфо";
    }
}

const char* sev_color(Severity s) {
    switch (s) {
        case Severity::Critical: return "#e11d48";
        case Severity::High: return "#ea580c";
        case Severity::Medium: return "#ca8a04";
        case Severity::Low: return "#2563eb";
        default: return "#64748b";
    }
}

const char* inc_status_ru(IncidentStatus s) {
    switch (s) {
        case IncidentStatus::Open: return "Открыт";
        case IncidentStatus::InProgress: return "В работе";
        case IncidentStatus::Resolved: return "Решён";
        case IncidentStatus::FalsePositive: return "Ложная тревога";
    }
    return "";
}

std::string esc(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '<') out += "&lt;";
        else if (c == '>') out += "&gt;";
        else if (c == '&') out += "&amp;";
        else if (c == '"') out += "&quot;";
        else out.push_back(c);
    }
    return out;
}

// Начало местного дня, в который попадает ms.
int64_t day_start(int64_t ms, int tz) {
    int64_t off = int64_t(tz) * 60000;
    int64_t local = ms + off;
    int64_t d = local >= 0 ? local / kDay : (local - kDay + 1) / kDay;
    return d * kDay - off;
}

std::string date_ru(int64_t ms, int tz) {  // 13.10.2026
    std::string s = format_iso8601(ms + int64_t(tz) * 60000);
    return s.substr(8, 2) + "." + s.substr(5, 2) + "." + s.substr(0, 4);
}

std::string date_short(int64_t ms, int tz) {  // 13.10
    std::string s = format_iso8601(ms + int64_t(tz) * 60000);
    return s.substr(8, 2) + "." + s.substr(5, 2);
}

std::string num(uint64_t n) {  // 1 234 567
    std::string s = std::to_string(n), out;
    int k = 0;
    for (auto it = s.rbegin(); it != s.rend(); ++it) {
        if (k && k % 3 == 0) out.push_back(' ');
        out.push_back(*it);
        ++k;
    }
    std::reverse(out.begin(), out.end());
    return out;
}

// 1 алерт, 2 алерта, 5 алертов
std::string plural_ru(uint64_t n, const char* one, const char* few, const char* many) {
    uint64_t d10 = n % 10, d100 = n % 100;
    const char* w = (d10 == 1 && d100 != 11) ? one : (d10 >= 2 && d10 <= 4 && (d100 < 12 || d100 > 14)) ? few : many;
    return std::to_string(n) + " " + w;
}

std::string duration_ru(int64_t ms) {
    int64_t m = ms / 60000;
    if (m < 60) return std::to_string(std::max<int64_t>(m, 1)) + " мин";
    int64_t h = m / 60;
    if (h < 48) return std::to_string(h) + " ч " + std::to_string(m % 60) + " мин";
    return std::to_string(h / 24) + " дн " + std::to_string(h % 24) + " ч";
}

std::string period_ru(const ReportData& r) {
    return date_ru(r.from, r.tz_minutes) + " — " + date_ru(r.to - 1, r.tz_minutes);
}

template <class M>
std::vector<std::pair<std::string, uint64_t>> top_of(const M& m, size_t n) {
    std::vector<std::pair<std::string, uint64_t>> v(m.begin(), m.end());
    std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.second != b.second ? a.second > b.second : a.first < b.first; });
    if (v.size() > n) v.resize(n);
    return v;
}

}  // namespace

int local_utc_offset_minutes_now() {
    std::time_t t = std::time(nullptr);
    std::tm lt{}, gt{};
#ifdef _WIN32
    localtime_s(&lt, &t);
    gmtime_s(&gt, &t);
#else
    localtime_r(&t, &lt);
    gmtime_r(&t, &gt);
#endif
    gt.tm_isdst = lt.tm_isdst;
    std::time_t as_local = std::mktime(&gt);
    return int(std::difftime(t, as_local) / 60);
}

ReportData build_report(const ReportSources& src, int64_t from, int64_t to, int tz) {
    ReportData r;
    r.from = from;
    r.to = to;
    r.generated = now_ms();
    r.tz_minutes = tz;

    // дни периода
    std::map<int64_t, size_t> day_idx;
    for (int64_t d = day_start(from, tz); d < to && r.days.size() < 400; d += kDay) {
        day_idx[d] = r.days.size();
        r.days.push_back({d, 0, 0, 0});
    }
    auto day_of = [&](int64_t ms) -> ReportData::Day* {
        auto it = day_idx.find(day_start(ms, tz));
        return it == day_idx.end() ? nullptr : &r.days[it->second];
    };

    if (src.live) {
        auto p = src.live->period(from, to, 10);
        r.events = p.events;
        r.events_data_from = p.data_from;
        r.events_partial = p.data_from == 0 || p.data_from > from + 3600000;
        for (auto& h : p.hours)
            if (auto* d = day_of(h.first)) d->events += h.second.first;
        r.top_ips = p.top_ips;
        r.top_sources = p.top_sources;
        r.by_type = p.by_type;
        r.top_countries = p.top_countries;
        for (auto& ip : r.top_ips) {
            std::string cc;
            if (src.enricher) cc = src.enricher->lookup(ip.first).country;
            r.top_ip_country.push_back(cc);
        }
    }

    if (src.alerts) {
        AlertQuery q;
        q.from = from;
        q.to = to - 1;
        q.limit = 50'000'000;
        auto list = src.alerts->query(q);
        std::unordered_map<std::string, ReportData::RuleRow> rules;
        std::unordered_map<std::string, uint64_t> ips;
        for (auto& a : list) {
            ++r.alerts;
            ++r.alerts_by_severity[size_t(a.severity)];
            ++r.alerts_by_status[size_t(a.status)];
            if (auto* d = day_of(a.ts)) ++d->alerts;
            auto& rr = rules[a.rule_id];
            if (rr.rule_id.empty()) {
                rr.rule_id = a.rule_id;
                rr.rule_name = a.rule_name;
            }
            rr.severity = std::max(rr.severity, a.severity);
            ++rr.count;
            if (a.status == AlertStatus::FalsePositive) ++rr.false_positive;
            if (!a.src_ip.empty() && ips.size() < 200000) ++ips[a.src_ip];
        }
        for (auto& kv : rules) r.top_rules.push_back(kv.second);
        std::sort(r.top_rules.begin(), r.top_rules.end(), [](auto& a, auto& b) {
            return a.count != b.count ? a.count > b.count : a.rule_id < b.rule_id;
        });
        if (r.top_rules.size() > 15) r.top_rules.resize(15);
        r.top_alert_ips = top_of(ips, 10);
    }

    if (src.incidents) {
        IncidentQuery q;
        q.limit = 50'000'000;
        auto list = src.incidents->list(q);
        std::vector<int64_t> close_times;
        for (auto& i : list) {
            if (i.active()) {
                ++r.inc_active_now;
                if (i.assignee.empty()) ++r.inc_unassigned_now;
            }
            if (i.created >= from && i.created < to) {
                ++r.inc_created;
                ++r.inc_by_severity[size_t(i.severity)];
                if (auto* d = day_of(i.created)) ++d->incidents;
                if (!i.merged_into)
                    r.top_incidents.push_back({i.id, i.title(), i.assignee, i.severity, i.status, i.alert_count, i.created});
            }
            // закрыт за период: последняя смена статуса на «решён» / «ложная тревога»
            if (!i.active() && !i.merged_into) {
                int64_t closed = 0;
                for (auto it = i.history.rbegin(); it != i.history.rend(); ++it)
                    if (it->kind == "status") {
                        if (it->value == "resolved" || it->value == "false_positive") closed = it->ts;
                        break;
                    }
                if (closed >= from && closed < to) {
                    if (i.status == IncidentStatus::FalsePositive) ++r.inc_false_positive;
                    else ++r.inc_resolved;
                    close_times.push_back(std::max<int64_t>(0, closed - i.created));
                }
            }
        }
        if (!close_times.empty()) {
            std::nth_element(close_times.begin(), close_times.begin() + long(close_times.size() / 2), close_times.end());
            r.inc_median_close_ms = close_times[close_times.size() / 2];
        }
        std::sort(r.top_incidents.begin(), r.top_incidents.end(), [](auto& a, auto& b) {
            if (a.severity != b.severity) return a.severity > b.severity;
            if (a.alert_count != b.alert_count) return a.alert_count > b.alert_count;
            return a.id > b.id;
        });
        if (r.top_incidents.size() > 10) r.top_incidents.resize(10);
    }

    if (src.blocks) {
        auto list = src.blocks->list();
        r.blocks_active = list.size();
        for (auto& b : list)
            if (b.created >= from && b.created < to) (b.by == "auto" ? r.blocks_new_auto : r.blocks_new_manual)++;
    }
    if (src.events) r.storage = src.events->stats();
    return r;
}

void write_report_json(JsonWriter& w, const ReportData& r) {
    auto pairs = [&](const char* name, const char* k, const std::vector<std::pair<std::string, uint64_t>>& v) {
        w.key(name).begin_array();
        for (auto& p : v) w.begin_object().kv(k, p.first).kv("count", p.second).end_object();
        w.end_array();
    };
    w.begin_object();
    w.kv("from", format_iso8601(r.from)).kv("to", format_iso8601(r.to)).kv("generated", format_iso8601(r.generated));
    w.kv("tz_minutes", int64_t(r.tz_minutes));
    w.key("days").begin_array();
    for (auto& d : r.days)
        w.begin_object()
            .kv("day", format_iso8601(d.day))
            .kv("events", d.events)
            .kv("alerts", d.alerts)
            .kv("incidents", d.incidents)
            .end_object();
    w.end_array();
    w.key("events").begin_object();
    w.kv("total", r.events).kv("partial", r.events_partial);
    w.kv("data_from", r.events_data_from ? format_iso8601(r.events_data_from) : std::string());
    w.key("top_ips").begin_array();
    for (size_t i = 0; i < r.top_ips.size(); ++i) {
        w.begin_object().kv("ip", r.top_ips[i].first).kv("count", r.top_ips[i].second);
        if (i < r.top_ip_country.size() && !r.top_ip_country[i].empty()) w.kv("country", r.top_ip_country[i]);
        w.end_object();
    }
    w.end_array();
    pairs("top_sources", "source", r.top_sources);
    pairs("by_type", "type", r.by_type);
    pairs("top_countries", "country", r.top_countries);
    w.end_object();

    w.key("alerts").begin_object();
    w.kv("total", r.alerts);
    w.key("by_severity").begin_object();
    for (int s = 0; s < 5; ++s) w.kv(severity_name(Severity(s)), r.alerts_by_severity[s]);
    w.end_object();
    w.key("by_status").begin_object();
    for (int s = 0; s < 4; ++s) w.kv(alert_status_name(AlertStatus(s)), r.alerts_by_status[s]);
    w.end_object();
    w.key("top_rules").begin_array();
    for (auto& x : r.top_rules)
        w.begin_object()
            .kv("rule_id", x.rule_id)
            .kv("rule_name", x.rule_name)
            .kv("severity", severity_name(x.severity))
            .kv("count", x.count)
            .kv("false_positive", x.false_positive)
            .end_object();
    w.end_array();
    pairs("top_ips", "ip", r.top_alert_ips);
    w.end_object();

    w.key("incidents").begin_object();
    w.kv("created", r.inc_created).kv("resolved", r.inc_resolved).kv("false_positive", r.inc_false_positive);
    w.kv("active_now", r.inc_active_now).kv("unassigned_now", r.inc_unassigned_now);
    w.kv("median_close_sec", r.inc_median_close_ms / 1000);
    w.key("by_severity").begin_object();
    for (int s = 0; s < 5; ++s) w.kv(severity_name(Severity(s)), r.inc_by_severity[s]);
    w.end_object();
    w.key("top").begin_array();
    for (auto& x : r.top_incidents)
        w.begin_object()
            .kv("id", x.id)
            .kv("title", x.title)
            .kv("severity", severity_name(x.severity))
            .kv("status", incident_status_name(x.status))
            .kv("assignee", x.assignee)
            .kv("alert_count", x.alert_count)
            .kv("created", format_iso8601(x.created))
            .end_object();
    w.end_array();
    w.end_object();

    w.key("blocks").begin_object();
    w.kv("active", uint64_t(r.blocks_active)).kv("new_auto", r.blocks_new_auto).kv("new_manual", r.blocks_new_manual);
    w.end_object();
    w.key("storage").begin_object();
    w.kv("events", r.storage.events).kv("bytes_on_disk", r.storage.bytes_on_disk);
    w.end_object();
    w.end_object();
}

std::string report_subject(const ReportData& r) {
    std::string s = "[Sentinel] Отчёт за " + period_ru(r) + ": ";
    s += plural_ru(r.inc_created, "инцидент", "инцидента", "инцидентов") + ", " +
         plural_ru(r.alerts, "алерт", "алерта", "алертов");
    uint64_t hot = r.inc_by_severity[size_t(Severity::Critical)] + r.inc_by_severity[size_t(Severity::High)];
    if (hot) s += ", серьёзных: " + std::to_string(hot);
    return s;
}

std::string report_text(const ReportData& r, const std::string& panel_url) {
    std::ostringstream o;
    o << "Отчёт SentinelCore за " << period_ru(r) << "\n\n";
    o << "События: " << num(r.events) << (r.events_partial ? " (статистика есть не за весь период)" : "") << "\n";
    o << "Алерты: " << num(r.alerts) << " — критических " << r.alerts_by_severity[4] << ", высоких "
      << r.alerts_by_severity[3] << ", средних " << r.alerts_by_severity[2] << "; ложных: " << r.alerts_by_status[3] << "\n";
    o << "Инциденты: новых " << r.inc_created << ", решено " << r.inc_resolved << ", ложных тревог "
      << r.inc_false_positive << "; сейчас открыто " << r.inc_active_now << " (без ответственного "
      << r.inc_unassigned_now << ")\n";
    if (r.inc_median_close_ms) o << "Обычное время до закрытия инцидента: " << duration_ru(r.inc_median_close_ms) << "\n";
    o << "Блокировки: действует " << r.blocks_active << ", новых за период: автоматически " << r.blocks_new_auto
      << ", вручную " << r.blocks_new_manual << "\n";
    if (!r.top_incidents.empty()) {
        o << "\nГлавные инциденты:\n";
        for (auto& i : r.top_incidents)
            o << "  #" << i.id << " [" << sev_ru(i.severity) << ", " << inc_status_ru(i.status) << "] " << i.title << " — "
              << plural_ru(i.alert_count, "алерт", "алерта", "алертов") << (i.assignee.empty() ? "" : ", ответственный " + i.assignee) << "\n";
    }
    if (!r.top_rules.empty()) {
        o << "\nЧаще всего срабатывали правила:\n";
        for (auto& x : r.top_rules) o << "  " << x.rule_name << " (" << x.rule_id << "): " << x.count << "\n";
    }
    if (!r.top_alert_ips.empty()) {
        o << "\nАдреса с наибольшим числом алертов:\n";
        for (auto& x : r.top_alert_ips) o << "  " << x.first << ": " << x.second << "\n";
    }
    if (!panel_url.empty())
        o << "\nПодробный отчёт: " << panel_url << "/report?from=" << format_iso8601(r.from)
          << "&to=" << format_iso8601(r.to) << "\n";
    o << "\n— SentinelCore SIEM\n";
    return o.str();
}

std::string report_html(const ReportData& r, const std::string& panel_url) {
    std::ostringstream o;
    const char* td = "padding:6px 10px;border-bottom:1px solid #e5e7eb;font-size:13px;";
    const char* th = "padding:6px 10px;border-bottom:2px solid #d1d5db;font-size:12px;color:#6b7280;text-align:left;";
    auto badge = [](Severity s) {
        return std::string("<span style=\"display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;"
                           "font-weight:600;color:#fff;background:") +
               sev_color(s) + "\">" + sev_ru(s) + "</span>";
    };
    auto stat = [&](const std::string& label, const std::string& value, const std::string& sub, const char* color) {
        o << "<td style=\"width:25%;padding:12px;border:1px solid #e5e7eb;border-radius:8px;vertical-align:top\">"
          << "<div style=\"font-size:12px;color:#6b7280\">" << esc(label) << "</div>"
          << "<div style=\"font-size:24px;font-weight:700;color:" << color << "\">" << esc(value) << "</div>"
          << "<div style=\"font-size:12px;color:#6b7280\">" << esc(sub) << "</div></td>";
    };
    o << "<!doctype html><html><head><meta charset=\"utf-8\"></head>"
      << "<body style=\"margin:0;background:#f3f4f6;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;color:#111827\">"
      << "<div style=\"max-width:720px;margin:0 auto;padding:20px\">"
      << "<div style=\"background:#0f172a;color:#fff;padding:16px 20px;border-radius:10px 10px 0 0\">"
      << "<div style=\"font-size:13px;opacity:.7\">SentinelCore SIEM</div>"
      << "<div style=\"font-size:20px;font-weight:700\">Отчёт за " << esc(period_ru(r)) << "</div></div>"
      << "<div style=\"background:#fff;padding:20px;border-radius:0 0 10px 10px\">";

    uint64_t hot = r.inc_by_severity[4] + r.inc_by_severity[3];
    o << "<table style=\"width:100%;border-collapse:separate;border-spacing:8px\"><tr>";
    stat("Событий", num(r.events), r.events_partial ? "статистика не за весь период" : "за период", "#111827");
    stat("Алертов", num(r.alerts), "ложных: " + num(r.alerts_by_status[3]), "#111827");
    stat("Новых инцидентов", num(r.inc_created), "серьёзных: " + num(hot), hot ? "#e11d48" : "#111827");
    stat("Открыто сейчас", num(r.inc_active_now), "без ответственного: " + num(r.inc_unassigned_now),
         r.inc_active_now ? "#ea580c" : "#16a34a");
    o << "</tr></table>";

    // по дням — простые полоски
    uint64_t maxd = 1;
    for (auto& d : r.days) maxd = std::max(maxd, d.alerts);
    if (!r.days.empty() && r.days.size() <= 62) {
        o << "<h3 style=\"font-size:15px;margin:18px 0 6px\">Алерты по дням</h3><table style=\"width:100%;border-collapse:collapse\">";
        for (auto& d : r.days) {
            int w = int(d.alerts * 100 / maxd);
            o << "<tr><td style=\"width:60px;font-size:12px;color:#6b7280;padding:2px 0\">" << date_short(d.day, r.tz_minutes)
              << "</td><td style=\"padding:2px 0\"><div style=\"height:12px;border-radius:3px;background:#3b82f6;width:"
              << std::max(w, d.alerts ? 2 : 0) << "%\"></div></td><td style=\"width:60px;text-align:right;font-size:12px\">"
              << num(d.alerts) << "</td></tr>";
        }
        o << "</table>";
    }

    o << "<h3 style=\"font-size:15px;margin:18px 0 6px\">Инциденты</h3><p style=\"font-size:13px;margin:0 0 8px\">"
      << "Решено: <b>" << r.inc_resolved << "</b>, ложных тревог: <b>" << r.inc_false_positive << "</b>";
    if (r.inc_median_close_ms) o << ", обычно закрываются за <b>" << esc(duration_ru(r.inc_median_close_ms)) << "</b>";
    o << ".</p>";
    if (!r.top_incidents.empty()) {
        o << "<table style=\"width:100%;border-collapse:collapse\"><tr><th style=\"" << th << "\">№</th><th style=\"" << th
          << "\">Инцидент</th><th style=\"" << th << "\">Важность</th><th style=\"" << th << "\">Статус</th><th style=\"" << th
          << "\">Алертов</th></tr>";
        for (auto& i : r.top_incidents) {
            std::string title = esc(i.title);
            if (!panel_url.empty())
                title = "<a style=\"color:#2563eb;text-decoration:none\" href=\"" + esc(panel_url) + "/incidents/" +
                        std::to_string(i.id) + "\">" + title + "</a>";
            o << "<tr><td style=\"" << td << "color:#6b7280\">#" << i.id << "</td><td style=\"" << td << "\">" << title
              << (i.assignee.empty() ? "" : "<div style=\"font-size:11px;color:#6b7280\">" + esc(i.assignee) + "</div>")
              << "</td><td style=\"" << td << "\">" << badge(i.severity) << "</td><td style=\"" << td << "\">"
              << inc_status_ru(i.status) << "</td><td style=\"" << td << "\">" << num(i.alert_count) << "</td></tr>";
        }
        o << "</table>";
    } else {
        o << "<p style=\"font-size:13px;color:#16a34a\">Новых инцидентов не было.</p>";
    }

    if (!r.top_rules.empty()) {
        o << "<h3 style=\"font-size:15px;margin:18px 0 6px\">Чаще всего срабатывали правила</h3>"
          << "<table style=\"width:100%;border-collapse:collapse\"><tr><th style=\"" << th << "\">Правило</th><th style=\"" << th
          << "\">Важность</th><th style=\"" << th << "\">Алертов</th><th style=\"" << th << "\">Ложных</th></tr>";
        for (auto& x : r.top_rules)
            o << "<tr><td style=\"" << td << "\">" << esc(x.rule_name) << "<div style=\"font-size:11px;color:#6b7280\">"
              << esc(x.rule_id) << "</div></td><td style=\"" << td << "\">" << badge(x.severity) << "</td><td style=\"" << td
              << "\">" << num(x.count) << "</td><td style=\"" << td << "\">" << num(x.false_positive) << "</td></tr>";
        o << "</table>";
    }

    if (!r.top_alert_ips.empty()) {
        o << "<h3 style=\"font-size:15px;margin:18px 0 6px\">Адреса с наибольшим числом алертов</h3>"
          << "<table style=\"width:100%;border-collapse:collapse\">";
        for (auto& x : r.top_alert_ips)
            o << "<tr><td style=\"" << td << "font-family:Menlo,Consolas,monospace\">" << esc(x.first) << "</td><td style=\""
              << td << "text-align:right\">" << num(x.second) << "</td></tr>";
        o << "</table>";
    }

    o << "<p style=\"font-size:13px;margin:18px 0 0\">Блокировки: действует <b>" << r.blocks_active
      << "</b>, новых за период — автоматически <b>" << r.blocks_new_auto << "</b>, вручную <b>" << r.blocks_new_manual
      << "</b>.</p>";
    if (!panel_url.empty())
        o << "<p style=\"margin:18px 0 0\"><a style=\"display:inline-block;background:#2563eb;color:#fff;padding:8px 16px;"
             "border-radius:6px;text-decoration:none;font-size:14px\" href=\""
          << esc(panel_url) << "/report?from=" << format_iso8601(r.from) << "&amp;to=" << format_iso8601(r.to)
          << "\">Открыть полный отчёт</a></p>";
    o << "</div><p style=\"font-size:11px;color:#9ca3af;text-align:center\">SentinelCore SIEM · сформировано "
      << esc(date_ru(r.generated, r.tz_minutes)) << "</p></div></body></html>";
    return o.str();
}

// ---------------- еженедельное письмо ----------------

ReportMailer::ReportMailer(ReportConfig cfg, NotifyConfig notify, ReportSources src, std::string state_file)
    : cfg_(std::move(cfg)), notify_(std::move(notify)), src_(src), state_file_(std::move(state_file)) {
    while (!notify_.panel_url.empty() && notify_.panel_url.back() == '/') notify_.panel_url.pop_back();
    to_ = cfg_.to.empty() ? notify_.email.to : cfg_.to;
    std::ifstream f(state_file_);
    std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    JValue v;
    std::string err;
    if (!text.empty() && json_parse(text, v, err) && v.is_object())
        if (const JValue* x = v.get("weekly_last_sent"); x && x->is_number()) last_sent_.store(x->i);
}

ReportMailer::~ReportMailer() { stop(); }

void ReportMailer::stop() {
    if (th_.joinable()) th_.join();
}

std::string ReportMailer::last_error() const {
    std::lock_guard<std::mutex> lock(mu_);
    return last_error_;
}

void ReportMailer::save_state() {
    std::string tmp = state_file_ + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        f << "{\"weekly_last_sent\":" << last_sent_.load() << "}\n";
        if (!f) return;
    }
    std::error_code ec;
    std::filesystem::rename(tmp, state_file_, ec);
}

int64_t ReportMailer::slot_at_or_before(int64_t now, int weekday, int minute_of_day, int tz) {
    const int64_t off = int64_t(tz) * 60000;
    const int64_t local = now + off;
    int64_t days = local >= 0 ? local / kDay : (local - kDay + 1) / kDay;
    int wd = int(((days % 7) + 7 + 4) % 7);  // 1970-01-01 — четверг
    int back = (wd - weekday + 7) % 7;
    int64_t slot = (days - back) * kDay + int64_t(minute_of_day) * 60000;
    if (slot > local) slot -= 7 * kDay;
    return slot - off;
}

int64_t ReportMailer::next_at(int64_t now) const {
    if (!enabled()) return 0;
    int64_t slot = slot_at_or_before(now, cfg_.weekday, cfg_.minute_of_day, local_utc_offset_minutes_now());
    return slot > last_sent_.load() ? now : slot + 7 * kDay;
}

std::string ReportMailer::send(int64_t from, int64_t to) {
    int tz = local_utc_offset_minutes_now();
    ReportData r = build_report(src_, from, to, tz);
    net::SmtpOptions o;
    o.host = notify_.email.host;
    o.port = notify_.email.port;
    o.tls = notify_.email.tls;
    o.username = notify_.email.username;
    o.password = notify_.email.password;
    o.tls_opt.ca_file = notify_.ca_file;
    o.tls_opt.pin_sha256 = notify_.pin;
    net::SmtpMessage msg{notify_.email.from, to_, report_subject(r), report_text(r, notify_.panel_url),
                         report_html(r, notify_.panel_url)};
    std::string err;
    bool ok = net::smtp_send(o, msg, err);
    std::lock_guard<std::mutex> lock(mu_);
    last_error_ = ok ? "" : err;
    if (ok) log::info("report: weekly report sent to ", to_.size(), " address(es)");
    else log::warn("report: cannot send weekly report: ", err);
    return ok ? "" : err;
}

void ReportMailer::tick(int64_t now) {
    if (!enabled() || busy_.load()) return;
    int64_t slot = slot_at_or_before(now, cfg_.weekday, cfg_.minute_of_day, local_utc_offset_minutes_now());
    if (last_sent_.load() == 0) {  // первый запуск: начинаем со следующего раза, без «долга»
        last_sent_.store(now);
        save_state();
        return;
    }
    if (slot <= last_sent_.load() || now < retry_after_.load()) return;
    if (th_.joinable()) th_.join();
    busy_.store(true);
    th_ = std::thread([this, slot] {
        std::string err = send(slot - 7 * kDay, slot);
        if (err.empty()) {
            last_sent_.store(slot);
            save_state();
        } else {
            retry_after_.store(now_ms() + 30 * 60000);  // почта недоступна — повтор через 30 минут
        }
        busy_.store(false);
    });
}

std::string ReportMailer::send_now(const std::string& who) {
    if (to_.empty() || !notify_.email.enabled()) return "e-mail is not configured (notify.email)";
    log::info("report: sending report now (requested by ", who, ")");
    const int64_t now = now_ms();
    return send(now - 7 * kDay, now);
}

}  // namespace sentinel
