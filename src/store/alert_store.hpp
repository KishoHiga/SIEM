// SentinelCore — хранилище алертов: журнал записей (alerts.log) + индекс в памяти.
// Записи: новый алерт или смена статуса. При старте журнал перечитывается,
// повреждённый хвост отрезается, устаревшие алерты удаляются (с уплотнением файла).
#pragma once

#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/event.hpp"
#include "store/file.hpp"

namespace sentinel {

struct AlertQuery {
    int64_t from = std::numeric_limits<int64_t>::min();
    int64_t to = std::numeric_limits<int64_t>::max();
    std::optional<AlertStatus> status;
    std::optional<Severity> min_severity;
    std::string rule_id;
    std::string src_ip;
    size_t limit = 100;
    uint64_t before_id = 0;
};

struct AlertCounts {
    uint64_t total = 0;
    uint64_t by_severity[5] = {0, 0, 0, 0, 0};
    uint64_t by_status[4] = {0, 0, 0, 0};
};

struct RuleAlertCount {
    uint64_t total = 0;
    uint64_t open = 0;      // new + acknowledged
    uint64_t false_positive = 0;
    int64_t last = 0;       // когда создан последний
};

class AlertStore {
public:
    bool open(const std::string& dir, int64_t retention_ms, std::string& error);
    void close();

    // Назначает id и сохраняет. Возвращает копии с id.
    void add(std::vector<Alert>& alerts);
    bool set_status(uint64_t id, AlertStatus status);

    std::vector<Alert> query(const AlertQuery& q) const;
    std::optional<Alert> get(uint64_t id) const;
    AlertCounts counts(int64_t since_ms) const;
    std::unordered_map<std::string, RuleAlertCount> counts_by_rule(int64_t since_ms) const;
    uint64_t max_id() const;

private:
    bool append_record(uint8_t type, const std::string& payload);
    void rewrite_compacted();

    std::string path_;
    int64_t retention_ms_ = 0;
    mutable std::mutex mu_;
    std::vector<Alert> alerts_;  // по возрастанию id
    std::unordered_map<uint64_t, size_t> index_;
    File file_;
    uint64_t next_id_ = 1;
};

}  // namespace sentinel
