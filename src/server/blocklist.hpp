// SentinelCore — список заблокированных IP и автоблокировка по алертам.
//
// Сервер только ведёт список; применяют его агенты в брандмауэрах своих серверов
// (см. agent/firewall). У списка есть номер версии: агент спрашивает «что нового
// после версии N» и получает полный список, только если он изменился.
//
// Защита от ошибок:
//   - адреса из белого списка (allowlist) не блокируются никогда — ни вручную, ни автоматически;
//   - автоматически не блокируются частные/служебные адреса (свои сети, loopback и т.п.);
//   - автоматических блокировок не больше max_per_minute в минуту (всплеск ложных алертов
//     не превратится в блокировку половины интернета).
#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "core/event.hpp"
#include "core/ip.hpp"

namespace sentinel {

struct Block {
    std::string ip;       // адрес или подсеть в каноническом виде: 1.2.3.4, 2001:db8::/32
    std::string reason;
    std::string rule_id;  // для автоблокировки — правило алерта
    uint64_t alert_id = 0;
    std::string by;       // "auto" или имя ключа того, кто заблокировал
    int64_t created = 0;
    int64_t expires = 0;  // 0 — бессрочно
    uint64_t hits = 1;    // сколько раз продлевалась
};

struct AutoBlockPolicy {
    bool enabled = true;
    Severity min_severity = Severity::Critical;
    std::vector<std::string> rules;  // эти правила блокируют при любой важности
    int64_t duration_ms = 3600000;   // 0 — бессрочно
    std::vector<Cidr> allowlist;     // никогда не блокировать
    bool block_private = false;
    int max_per_minute = 60;
};

struct BlockStats {
    size_t active = 0;
    uint64_t auto_added = 0;
    uint64_t manual_added = 0;
    uint64_t skipped_allowlist = 0;
    uint64_t skipped_private = 0;
    uint64_t skipped_limit = 0;
    uint64_t expired = 0;
};

class BlockList {
public:
    enum class Result { Added, Extended, Unchanged, Invalid, Allowlisted, Private, Limit, Full };
    static const char* result_text(Result r);

    // path — файл (data/blocks.json). Пустой путь — без сохранения (для тестов).
    bool open(const std::string& path, std::string& error);
    void set_policy(AutoBlockPolicy p);
    AutoBlockPolicy policy() const;

    // Ручная блокировка (адрес или подсеть). duration_ms = 0 — бессрочно.
    Result add_manual(const std::string& ip_or_cidr, int64_t duration_ms, const std::string& reason,
                      const std::string& by, Block* out = nullptr);
    bool remove(const std::string& ip_or_cidr);
    // Автоблокировка по новым алертам. Возвращает адреса, заблокированные (или продлённые) сейчас.
    std::vector<Block> on_alerts(const std::vector<Alert>& alerts);

    // Удалить истёкшие, сохранить изменения на диск (вызывать раз в 1–2 с).
    void tick(int64_t now_ms);
    void flush();

    std::vector<Block> list() const;
    std::optional<Block> find(const std::string& ip) const;  // точное совпадение или подсеть, содержащая адрес
    uint64_t version() const;
    BlockStats stats() const;

    static constexpr size_t kMaxEntries = 100000;

private:
    Result add_locked(const Cidr& c, int64_t duration_ms, const std::string& reason, const std::string& rule_id,
                      uint64_t alert_id, const std::string& by, int64_t now, Block* out);
    bool allowlisted(const Cidr& c) const;
    void save_locked();

    mutable std::mutex mu_;
    std::string path_;
    AutoBlockPolicy policy_;
    std::map<std::string, Block> blocks_;  // ключ — канонический вид
    uint64_t version_ = 1;
    bool dirty_ = false;
    int64_t minute_start_ = 0;
    int minute_count_ = 0;
    BlockStats stats_;
};

}  // namespace sentinel
