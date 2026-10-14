// SentinelCore — конвейер обработки:
//   HTTP-потоки (разбор) -> очередь пачек -> потоки обнаружения -> поток записи.
//
// Обнаружение идёт в нескольких потоках. События делятся между ними по IP источника
// (все события одного адреса — в одном потоке), а правила, которые считают по другим полям,
// проверяет отдельный «общий» поток (см. detect/partition.hpp). Каждая пачка проходит все
// потоки обнаружения независимо, а записываются пачки строго в порядке поступления.
//
// Очередь ограничена: если сервер не успевает, приём отвечает 503 и агент
// повторит отправку позже (данные не теряются молча).
#pragma once

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "core/event.hpp"
#include "detect/engine.hpp"
#include "server/live_stats.hpp"
#include "store/alert_store.hpp"
#include "store/event_store.hpp"

namespace sentinel {

struct PipelineStats {
    uint64_t accepted = 0;
    uint64_t rejected = 0;  // отклонено из-за переполнения очереди
    uint64_t queued = 0;
    EngineStats engine;
    int detect_threads = 1;      // потоков, делящих события по IP
    bool global_thread = false;  // есть ли отдельный поток для правил «не по IP»
    size_t sharded_rules = 0;
    size_t global_rules = 0;
    std::vector<uint64_t> shard_events;  // сколько событий обработал каждый поток (равномерность)
};

class Pipeline {
public:
    Pipeline(EventStore& events, AlertStore& alerts, LiveStats& stats, size_t max_queued_events);
    ~Pipeline();

    // Сколько потоков обнаружения (0 — по числу ядер). Задать до start().
    void set_detect_threads(int n) { threads_opt_ = n; }
    static int auto_threads();

    // Правила берутся из движка; при нескольких потоках движки собираются заново под каждый поток.
    void start(std::unique_ptr<DetectionEngine> engine);
    void stop();  // дождаться обработки очереди и остановиться

    // Назначает id событиям и ставит в очередь. false — очередь переполнена.
    bool submit(std::vector<Event>&& batch);
    // Подменить правила на лету (без остановки приёма). Пачки, принятые до вызова,
    // доделываются старыми правилами, после — новыми.
    void replace_engine(std::unique_ptr<DetectionEngine> engine);

    PipelineStats stats() const;

    // Вызывается потоком записи после обработки пачки (алерты уже с номерами). Задать до start().
    using StoredHook = std::function<void(const std::vector<Event>&, const std::vector<Alert>&)>;
    void set_on_stored(StoredHook hook) { on_stored_ = std::move(hook); }

private:
    struct EngineSet;
    struct Job;
    std::shared_ptr<EngineSet> make_set(std::unique_ptr<DetectionEngine> engine) const;
    void worker_loop(size_t w);
    void store_loop();

    EventStore& events_;
    AlertStore& alerts_;
    LiveStats& stats_;
    const size_t max_queued_;
    int threads_opt_ = 0;
    size_t shards_ = 1;   // потоков по IP
    size_t workers_ = 1;  // всего потоков обнаружения (shards_ или shards_ + 1 общий)

    std::atomic<uint64_t> next_id_{1};
    std::atomic<uint64_t> accepted_{0}, rejected_{0};

    mutable std::mutex mu_;
    std::condition_variable work_cv_, done_cv_;
    std::deque<std::shared_ptr<Job>> pending_;  // в порядке поступления
    uint64_t front_seq_ = 0;                    // номер пачки pending_.front()
    uint64_t next_seq_ = 0;                     // номер следующей пачки
    std::vector<uint64_t> cursor_;              // какую пачку берёт каждый поток
    size_t queued_events_ = 0;
    std::shared_ptr<EngineSet> current_;
    bool stopping_ = false;

    mutable std::mutex stats_mu_;
    std::vector<EngineStats> worker_stats_;
    std::vector<uint64_t> worker_events_;

    StoredHook on_stored_;
    std::vector<std::thread> worker_th_;
    std::thread store_th_;
};

}  // namespace sentinel
