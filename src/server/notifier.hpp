// SentinelCore — уведомления об алертах: Telegram, вебхук (Slack / Discord / свой JSON), почта.
//
// Работает в своём потоке, чтобы медленная сеть не тормозила обработку событий:
//   алерты -> очередь -> раз в batch (5 с) отбор -> сообщения -> отправка с повторами.
// Чтобы не утонуть в сообщениях:
//   - уведомляются только алерты не ниже min_severity;
//   - одно и то же (правило + IP) — не чаще cooldown, число пропущенных повторов пишется в следующее;
//   - если за окно набралось больше 3 алертов — уходит одна сводка вместо пачки сообщений.
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "core/event.hpp"
#include "server/blocklist.hpp"
#include "server/config.hpp"
#include "store/incident_store.hpp"

namespace sentinel {

struct ChannelStatus {
    std::string name;    // telegram | webhook | email
    std::string target;  // куда (без секретов): chat id, хост вебхука, адреса почты
    uint64_t sent = 0;
    uint64_t failed = 0;
    int64_t last_ok = 0;
    int64_t last_error_at = 0;
    std::string last_error;
};

struct NotifyStats {
    bool enabled = false;
    Severity min_severity = Severity::High;
    std::string mode = "alerts";
    uint64_t queued = 0;
    uint64_t suppressed = 0;  // склеено по cooldown
    uint64_t dropped = 0;     // очередь переполнена
    uint64_t digests = 0;
    std::vector<ChannelStatus> channels;
};

struct ChannelResult {
    std::string name;
    bool ok = false;
    std::string error;
};

class Notifier {
public:
    explicit Notifier(NotifyConfig cfg);
    ~Notifier();

    void start();
    void stop();  // отправит то, что уже в очереди (одна попытка), и остановится

    // Вызывается после сохранения алертов (номера уже есть). blocked — что заблокировано автоматически.
    void enqueue(const std::vector<Alert>& alerts, const std::vector<Block>& blocked);
    // Режим notify.mode: incidents — сообщение только о новом инциденте или когда он стал серьёзнее.
    void enqueue_incidents(const std::vector<IncidentNotice>& notices, const std::vector<Block>& blocked);
    // Отправить тестовое сообщение во все каналы сразу (из панели), с результатом по каждому.
    std::vector<ChannelResult> send_test(const std::string& who);

    NotifyStats stats() const;

    // Тексты сообщений — отдельно, чтобы проверять тестами.
    struct Item {
        Alert alert;
        uint64_t repeats = 0;     // сколько похожих было подавлено с прошлого уведомления
        int64_t blocked_until = -1;  // -1 — не блокировался; 0 — бессрочно; иначе время
        // для режима инцидентов
        uint64_t incident_id = 0;
        std::string incident_title;
        Severity incident_severity = Severity::Info;
        uint64_t incident_alerts = 0;
        bool incident_new = false;
    };
    std::string format_text(const Item& it, bool html) const;
    std::string format_digest(const std::vector<Item>& items, bool html) const;
    std::string subject(const Item& it) const;
    std::string digest_subject(const std::vector<Item>& items) const;

private:
    struct Message {
        std::string subject;
        std::string text;   // обычный текст (почта, вебхук)
        std::string html;   // для Telegram
        const Alert* alert = nullptr;  // для вебхука в формате json (одиночный алерт)
        const Item* item = nullptr;
    };
    void loop();
    void process(std::vector<Item>& items, bool final_pass);
    bool deliver(size_t ch, const Message& m, std::string& error);
    bool send_telegram(const Message& m, std::string& error);
    bool send_webhook(const Message& m, std::string& error);
    bool send_email(const Message& m, std::string& error);
    std::string alert_url(uint64_t id) const;
    std::string incident_url(uint64_t id) const;
    std::string format_incident(const Item& it, bool html) const;

    NotifyConfig cfg_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<Item> queue_;
    std::unordered_map<std::string, std::pair<int64_t, uint64_t>> cooldown_;  // ключ -> (до какого времени, подавлено)
    std::vector<ChannelStatus> channels_;
    std::unordered_map<std::string, int64_t> blocked_;  // ip -> до какого времени (из последних автоблокировок)
    uint64_t suppressed_ = 0, dropped_ = 0, digests_ = 0;
    std::atomic<bool> stop_{false};
    std::thread th_;

    static constexpr size_t kMaxQueue = 10000;
};

}  // namespace sentinel
