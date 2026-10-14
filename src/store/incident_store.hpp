// SentinelCore — инциденты: алерты одной атаки в одной карточке.
//
// Группировка: алерты с одного IP (или, если IP нет, одного пользователя на сервере) попадают в один
// открытый инцидент, пока атака не затихнет на window (по умолчанию час). Важность инцидента — самая
// высокая из его алертов. У инцидента есть статус, ответственный, заметки; два инцидента можно объединить.
//
// Хранение: журнал data/incidents.log из коротких записей (создан, +алерт, статус, ответственный, заметка,
// объединение) с CRC — как у алертов: переживает перезапуск, повреждённый хвост отрезается.
#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/event.hpp"
#include "store/file.hpp"

namespace sentinel {

enum class IncidentStatus : uint8_t { Open = 0, InProgress = 1, Resolved = 2, FalsePositive = 3 };
const char* incident_status_name(IncidentStatus s);
std::optional<IncidentStatus> incident_status_from_name(std::string_view s);

struct IncidentNote {
    uint64_t id = 0;
    int64_t ts = 0;
    std::string by;
    std::string text;
};

// Что меняли люди: статус, ответственный, объединение (для ленты в карточке).
struct IncidentChange {
    int64_t ts = 0;
    std::string by;
    std::string kind;   // status | assign | merged_into | merged_from
    std::string value;  // новый статус, имя, номер инцидента
};

struct IncidentRule {
    std::string rule_id;
    std::string rule_name;
    Severity severity = Severity::Info;
    uint64_t count = 0;
};

struct Incident {
    uint64_t id = 0;
    std::string key;        // ip:1.2.3.4 | user:ivan@web-01 | rule:X@web-01
    std::string src_ip, user, host;
    Severity severity = Severity::Info;
    IncidentStatus status = IncidentStatus::Open;
    std::string assignee;
    int64_t created = 0;    // когда открыт
    int64_t updated = 0;    // последнее изменение (алерт, статус, заметка)
    int64_t first_alert = 0, last_alert = 0;
    uint64_t alert_count = 0;
    std::vector<uint64_t> alert_ids;  // последние kMaxAlertIds
    std::vector<IncidentRule> rules;  // в порядке появления
    std::vector<std::string> hosts, users;  // разные (до 20)
    std::vector<IncidentNote> notes;
    std::vector<IncidentChange> history;  // последние kMaxHistory
    uint64_t merged_into = 0;  // объединён с другим (тогда закрыт)

    bool active() const { return status == IncidentStatus::Open || status == IncidentStatus::InProgress; }
    std::string title() const;  // «SQL-инъекция и ещё 2 · 1.2.3.4»
    static constexpr size_t kMaxAlertIds = 2000;
    static constexpr size_t kMaxHistory = 300;
};

// Что произошло с инцидентом после очередной пачки алертов (для уведомлений).
struct IncidentNotice {
    uint64_t id = 0;
    std::string title;
    Severity severity = Severity::Info;
    bool is_new = false;
    bool escalated = false;  // важность выросла
    uint64_t alert_count = 0;
    Alert alert;             // последний алерт
};

struct IncidentQuery {
    std::optional<IncidentStatus> status;
    bool active_only = false;  // открытые и в работе
    std::optional<Severity> min_severity;
    std::string text;          // в названии, IP, пользователе, сервере, правилах
    std::string assignee;      // "-" — без ответственного
    size_t limit = 50;
    uint64_t before_id = 0;
};

struct IncidentCounts {
    uint64_t active = 0;
    uint64_t unassigned = 0;
    uint64_t by_severity[5] = {0, 0, 0, 0, 0};  // активных
};

class IncidentStore {
public:
    bool open(const std::string& dir, int64_t retention_ms, std::string& error);
    void close();
    void set_window(int64_t ms) { window_ms_ = ms; }
    // Раз в час из главного цикла: удалить старые, сжать журнал.
    void maintain();

    // Разложить новые алерты (с номерами) по инцидентам.
    std::vector<IncidentNotice> on_alerts(const std::vector<Alert>& alerts);

    std::vector<Incident> list(const IncidentQuery& q) const;
    std::optional<Incident> get(uint64_t id) const;
    uint64_t incident_of_alert(uint64_t alert_id) const;  // 0 — нет
    IncidentCounts counts() const;

    // Изменения от людей. false — нет такого инцидента или нельзя (error заполнен).
    bool set_status(uint64_t id, IncidentStatus st, const std::string& by, std::string& error);
    bool assign(uint64_t id, const std::string& assignee, const std::string& by, std::string& error);
    bool add_note(uint64_t id, const std::string& by, const std::string& text, std::string& error);
    // Перенести алерты src в dst; src закрывается со ссылкой на dst.
    bool merge(uint64_t src, uint64_t dst, const std::string& by, std::string& error);

private:
    void apply_alert(Incident& inc, uint64_t alert_id, const std::string& rule_id, const std::string& rule_name,
                     Severity sev, int64_t ts, const std::string& host, const std::string& user);
    bool append(uint8_t type, const std::string& payload);
    void rewrite_compacted();
    void prune_locked(bool force_index);
    void merge_locked(Incident& s, Incident& d, const std::string& by, int64_t ts);
    void status_locked(Incident& inc, IncidentStatus st, const std::string& by, int64_t ts);
    void assign_locked(Incident& inc, const std::string& who, const std::string& by, int64_t ts);
    Incident* find_locked(uint64_t id);

    std::string path_;
    int64_t retention_ms_ = 90LL * 86400000;
    int64_t window_ms_ = 3600 * 1000;
    mutable std::mutex mu_;
    std::vector<Incident> incidents_;                    // по возрастанию id
    std::unordered_map<uint64_t, size_t> index_;         // id -> позиция
    std::unordered_map<std::string, uint64_t> by_key_;   // ключ -> последний активный инцидент
    std::unordered_map<uint64_t, uint64_t> alert_to_inc_;
    File file_;
    uint64_t next_id_ = 1, next_note_ = 1;
    uint64_t records_ = 0;  // записей в журнале (для сжатия)
    std::string batch_;     // записи пачки алертов — пишутся на диск одним вызовом
    bool batching_ = false;
};

}  // namespace sentinel
