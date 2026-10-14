// SentinelCore — нормализованное событие безопасности и алерт.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sentinel {

// Все поля события хранятся строками: единый быстрый доступ по номеру поля.
enum class Field : uint8_t {
    Source,         // откуда: nginx, sshd, syslog, app...
    Type,           // web, auth, network, privilege, system
    Host,           // имя хоста-источника
    Process,        // sshd, sudo, nginx...
    SrcIp,
    SrcPort,
    DstIp,
    DstPort,
    Proto,
    User,
    Action,         // login, GET, sudo, block...
    Outcome,        // success | failure
    HttpMethod,
    HttpPath,
    HttpStatus,
    HttpUserAgent,
    HttpReferer,
    Bytes,
    Message,
    Raw,
    Count_
};

constexpr size_t kFieldCount = size_t(Field::Count_);

const char* field_name(Field f);
// Имя поля (включая синонимы вроде source_ip, username) -> поле.
std::optional<Field> field_from_name(std::string_view name);

struct Event {
    uint64_t id = 0;
    int64_t ts = 0;        // время события, мс UTC
    int64_t received = 0;  // время приёма сервером, мс UTC
    std::array<std::string, kFieldCount> f;
    std::vector<std::pair<std::string, std::string>> extra;

    std::string& operator[](Field x) { return f[size_t(x)]; }
    const std::string& operator[](Field x) const { return f[size_t(x)]; }

    // Значение по имени: известное поле, "extra.<имя>" или имя доп. поля.
    std::string_view get(std::string_view name) const;
    const std::string* extra_get(std::string_view key) const;
    void extra_set(std::string_view key, std::string_view value);

    int64_t time() const { return ts != 0 ? ts : received; }
    void clear();
};

enum class Severity : uint8_t { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 };
const char* severity_name(Severity s);
std::optional<Severity> severity_from_name(std::string_view s);

enum class AlertStatus : uint8_t { New = 0, Acknowledged = 1, Resolved = 2, FalsePositive = 3 };
const char* alert_status_name(AlertStatus s);
std::optional<AlertStatus> alert_status_from_name(std::string_view s);

struct Alert {
    uint64_t id = 0;
    int64_t ts = 0;          // время события, вызвавшего алерт
    int64_t created = 0;     // время создания
    std::string rule_id;
    std::string rule_name;
    Severity severity = Severity::Medium;
    AlertStatus status = AlertStatus::New;
    std::string src_ip;
    std::string user;
    std::string host;
    std::string message;
    uint64_t count = 1;               // сколько событий/повторов объединено
    std::vector<uint64_t> event_ids;  // связанные события
    std::vector<std::pair<std::string, std::string>> fields;
};

}  // namespace sentinel
