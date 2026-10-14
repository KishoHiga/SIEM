// SentinelCore — отчёт за период: события, алерты, инциденты, блокировки.
//
// Один и тот же отчёт идёт в панель (страница «Отчёт», печать в PDF через браузер) и на почту
// (еженедельное письмо в HTML). Цифры событий берутся из почасовой статистики (LiveStats, до 32 дней),
// алерты и инциденты — из своих хранилищ.
#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "core/json.hpp"
#include "enrich/enricher.hpp"
#include "server/blocklist.hpp"
#include "server/config.hpp"
#include "server/live_stats.hpp"
#include "store/alert_store.hpp"
#include "store/event_store.hpp"
#include "store/incident_store.hpp"

namespace sentinel {

struct ReportSources {
    const EventStore* events = nullptr;
    const AlertStore* alerts = nullptr;
    const IncidentStore* incidents = nullptr;
    const BlockList* blocks = nullptr;
    const LiveStats* live = nullptr;
    const Enricher* enricher = nullptr;
};

struct ReportData {
    int64_t from = 0, to = 0, generated = 0;
    int tz_minutes = 0;  // часовой пояс для разбивки по дням

    struct Day {
        int64_t day = 0;  // начало дня (местного) в мс UTC
        uint64_t events = 0, alerts = 0, incidents = 0;
    };
    std::vector<Day> days;

    uint64_t events = 0;
    int64_t events_data_from = 0;  // с какого часа есть статистика (0 — нет)
    bool events_partial = false;   // период начинается раньше, чем есть почасовые данные
    std::vector<std::pair<std::string, uint64_t>> top_ips, top_sources, by_type, top_countries;
    std::vector<std::string> top_ip_country;  // страна для top_ips (по порядку)

    uint64_t alerts = 0;
    uint64_t alerts_by_severity[5] = {0, 0, 0, 0, 0};
    uint64_t alerts_by_status[4] = {0, 0, 0, 0};
    struct RuleRow {
        std::string rule_id, rule_name;
        Severity severity = Severity::Info;
        uint64_t count = 0, false_positive = 0;
    };
    std::vector<RuleRow> top_rules;
    std::vector<std::pair<std::string, uint64_t>> top_alert_ips;

    uint64_t inc_created = 0, inc_resolved = 0, inc_false_positive = 0;
    uint64_t inc_by_severity[5] = {0, 0, 0, 0, 0};  // созданных за период
    uint64_t inc_active_now = 0, inc_unassigned_now = 0;
    int64_t inc_median_close_ms = 0;  // медиана «от открытия до закрытия» для закрытых за период
    struct IncRow {
        uint64_t id = 0;
        std::string title, assignee;
        Severity severity = Severity::Info;
        IncidentStatus status = IncidentStatus::Open;
        uint64_t alert_count = 0;
        int64_t created = 0;
    };
    std::vector<IncRow> top_incidents;

    size_t blocks_active = 0;
    uint64_t blocks_new_auto = 0, blocks_new_manual = 0;  // из действующих — созданных за период

    StoreStats storage;
};

// Собрать отчёт за [from, to). tz_minutes — сдвиг местного времени от UTC (для дней).
ReportData build_report(const ReportSources& src, int64_t from, int64_t to, int tz_minutes);
void write_report_json(JsonWriter& w, const ReportData& r);
// Письмо: тема, текст и HTML (стили прямо в тегах — так их показывают почтовые программы).
std::string report_subject(const ReportData& r);
std::string report_text(const ReportData& r, const std::string& panel_url);
std::string report_html(const ReportData& r, const std::string& panel_url);

int local_utc_offset_minutes_now();

// Еженедельное письмо с отчётом (раздел reports: в sentinel.yaml). Время отправки — местное время сервера.
class ReportMailer {
public:
    ReportMailer(ReportConfig cfg, NotifyConfig notify, ReportSources src, std::string state_file);
    ~ReportMailer();

    bool enabled() const { return cfg_.weekly && !to_.empty() && notify_.email.enabled(); }
    // Из главного цикла: пора ли отправлять (отправка — в отдельном потоке).
    void tick(int64_t now);
    // Отправить отчёт за последние 7 дней сейчас (кнопка в панели). Возвращает ошибку или "".
    std::string send_now(const std::string& who);
    // Когда следующая отправка (0 — выключено), когда была последняя.
    int64_t next_at(int64_t now) const;
    int64_t last_sent() const { return last_sent_.load(); }
    std::string last_error() const;
    const std::vector<std::string>& recipients() const { return to_; }
    void stop();

    // Последний момент расписания не позже now (для тестов — с заданным часовым поясом).
    static int64_t slot_at_or_before(int64_t now, int weekday, int minute_of_day, int tz_minutes);

private:
    std::string send(int64_t from, int64_t to);
    void save_state();

    ReportConfig cfg_;
    NotifyConfig notify_;
    ReportSources src_;
    std::string state_file_;
    std::vector<std::string> to_;
    std::atomic<int64_t> last_sent_{0};
    std::atomic<int64_t> retry_after_{0};
    std::atomic<bool> busy_{false};
    mutable std::mutex mu_;
    std::string last_error_;
    std::thread th_;
};

}  // namespace sentinel
