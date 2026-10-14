#include "server/pipeline.hpp"

#include <algorithm>

#include "core/log.hpp"
#include "core/util.hpp"
#include "detect/partition.hpp"

namespace sentinel {

// Движки одного набора правил: по одному на каждый поток обнаружения.
// Каждый движок трогает только «свой» поток — блокировки при проверке событий не нужны.
struct Pipeline::EngineSet {
    std::vector<std::unique_ptr<DetectionEngine>> eng;  // [0..shards) — по IP, [shards] — общий; может быть null
    size_t sharded_rules = 0;
    size_t global_rules = 0;
};

struct Pipeline::Job {
    std::vector<Event> events;
    std::vector<uint32_t> shard;  // поток для каждого события (пусто, если поток один)
    std::shared_ptr<EngineSet> set;
    std::vector<std::vector<Alert>> alerts;  // по потокам
    std::atomic<size_t> remaining{0};
};

Pipeline::Pipeline(EventStore& events, AlertStore& alerts, LiveStats& stats, size_t max_queued_events)
    : events_(events), alerts_(alerts), stats_(stats), max_queued_(max_queued_events ? max_queued_events : 1) {}

Pipeline::~Pipeline() { stop(); }

int Pipeline::auto_threads() {
    unsigned hw = std::thread::hardware_concurrency();
    if (hw <= 2) return 1;  // на 1–2 ядрах лишние потоки только мешают разбору и записи
    return int(std::min<unsigned>(hw / 2, 8));
}

std::shared_ptr<Pipeline::EngineSet> Pipeline::make_set(std::unique_ptr<DetectionEngine> engine) const {
    auto set = std::make_shared<EngineSet>();
    set->eng.resize(workers_);
    if (!engine) return set;
    if (workers_ == 1) {
        set->sharded_rules = engine->rules().size();
        set->eng[0] = std::move(engine);
        return set;
    }
    RulePartition part = partition_rules(engine->rules());
    std::string err;
    bool ok = true;
    if (!part.sharded.empty()) {
        for (size_t i = 0; i < shards_ && ok; ++i) {
            auto e = std::make_unique<DetectionEngine>();
            ok = e->load(part.sharded, err);
            set->eng[i] = std::move(e);
        }
    }
    if (ok && !part.global.empty()) {
        auto e = std::make_unique<DetectionEngine>();
        ok = e->load(part.global, err);
        set->eng[shards_] = std::move(e);
    }
    if (!ok) {
        // не должно случаться (правила уже проверены) — тогда всё в общий поток, результат тот же
        log::error("pipeline: cannot split rules between threads (", err, "), using one thread for detection");
        for (auto& e : set->eng) e.reset();
        set->global_rules = engine->rules().size();
        set->eng[shards_] = std::move(engine);
        return set;
    }
    set->sharded_rules = part.sharded.size();
    set->global_rules = part.global.size();
    return set;
}

void Pipeline::start(std::unique_ptr<DetectionEngine> engine) {
    if (!worker_th_.empty()) return;
    int t = threads_opt_ > 0 ? threads_opt_ : auto_threads();
    shards_ = size_t(std::clamp(t, 1, 64));
    workers_ = shards_ == 1 ? 1 : shards_ + 1;
    next_id_.store(events_.max_id() + 1);
    {
        std::lock_guard<std::mutex> lock(mu_);
        stopping_ = false;
        current_ = make_set(std::move(engine));
        cursor_.assign(workers_, next_seq_);
    }
    {
        std::lock_guard<std::mutex> lock(stats_mu_);
        worker_stats_.assign(workers_, EngineStats{});
        worker_events_.assign(workers_, 0);
    }
    if (workers_ > 1)
        log::info("pipeline: detection in ", shards_, " threads by source IP + 1 for other rules (",
                  current_->sharded_rules, " / ", current_->global_rules, " rules)");
    for (size_t w = 0; w < workers_; ++w) worker_th_.emplace_back([this, w] { worker_loop(w); });
    store_th_ = std::thread([this] { store_loop(); });
}

void Pipeline::stop() {
    if (worker_th_.empty()) return;
    {
        std::lock_guard<std::mutex> lock(mu_);
        stopping_ = true;
    }
    work_cv_.notify_all();
    done_cv_.notify_all();
    for (auto& t : worker_th_) t.join();
    worker_th_.clear();
    store_th_.join();
    events_.flush();
}

bool Pipeline::submit(std::vector<Event>&& batch) {
    if (batch.empty()) return true;
    auto job = std::make_shared<Job>();
    job->alerts.resize(workers_);
    job->remaining.store(workers_);
    if (shards_ > 1) {  // делим по IP до блокировки — HTTP-потоки делают это параллельно
        job->shard.resize(batch.size());
        for (size_t i = 0; i < batch.size(); ++i)
            job->shard[i] = uint32_t(shard_of(batch[i][Field::SrcIp], shards_));
    }
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (queued_events_ + batch.size() > max_queued_ || stopping_ || worker_th_.empty()) {
            rejected_ += batch.size();
            return false;
        }
        uint64_t first = next_id_.fetch_add(batch.size());
        for (size_t i = 0; i < batch.size(); ++i) batch[i].id = first + i;
        queued_events_ += batch.size();
        accepted_ += batch.size();
        job->events = std::move(batch);
        job->set = current_;
        pending_.push_back(std::move(job));
        ++next_seq_;
    }
    work_cv_.notify_all();
    return true;
}

void Pipeline::replace_engine(std::unique_ptr<DetectionEngine> engine) {
    size_t n = engine ? engine->rules().size() : 0;
    auto set = make_set(std::move(engine));  // компиляция — вне блокировки, приём не ждёт
    {
        std::lock_guard<std::mutex> lock(mu_);
        current_ = std::move(set);
    }
    log::info("pipeline: detection rules reloaded (", n, " rules)");
}

void Pipeline::worker_loop(size_t w) {
    uint64_t seen_events = 0;
    while (true) {
        std::shared_ptr<Job> job;
        {
            std::unique_lock<std::mutex> lock(mu_);
            work_cv_.wait(lock, [&] { return cursor_[w] < next_seq_ || stopping_; });
            if (cursor_[w] >= next_seq_) break;  // остановка, очередь разобрана
            job = pending_[size_t(cursor_[w] - front_seq_)];
            ++cursor_[w];
        }
        DetectionEngine* eng = job->set->eng[w].get();
        if (eng) {
            auto& out = job->alerts[w];
            const bool shard_worker = w < shards_ && shards_ > 1;
            for (size_t i = 0; i < job->events.size(); ++i) {
                if (shard_worker && job->shard[i] != w) continue;
                eng->process(job->events[i], out);
                ++seen_events;
            }
            std::lock_guard<std::mutex> lock(stats_mu_);
            worker_stats_[w] = eng->stats();
            worker_events_[w] = seen_events;
        } else {
            std::lock_guard<std::mutex> lock(stats_mu_);
            worker_stats_[w] = EngineStats{};
        }
        if (job->remaining.fetch_sub(1) == 1) {
            std::lock_guard<std::mutex> lock(mu_);  // под блокировкой — чтобы поток записи не пропустил сигнал
            done_cv_.notify_all();
        }
    }
}

void Pipeline::store_loop() {
    int64_t last_tick = 0;
    while (true) {
        std::shared_ptr<Job> job;
        {
            std::unique_lock<std::mutex> lock(mu_);
            done_cv_.wait_for(lock, std::chrono::milliseconds(200), [&] {
                return (!pending_.empty() && pending_.front()->remaining.load() == 0) || (stopping_ && pending_.empty());
            });
            if (!pending_.empty() && pending_.front()->remaining.load() == 0) {
                job = std::move(pending_.front());
                pending_.pop_front();
                ++front_seq_;
                queued_events_ -= job->events.size();
            } else if (stopping_ && pending_.empty()) {
                break;
            }
        }
        if (job) {
            std::vector<Alert> alerts;
            if (job->alerts.size() == 1) {
                alerts = std::move(job->alerts[0]);
            } else {
                for (auto& v : job->alerts)
                    for (auto& a : v) alerts.push_back(std::move(a));
                // по порядку событий, вызвавших алерт (как при одном потоке)
                std::stable_sort(alerts.begin(), alerts.end(), [](const Alert& a, const Alert& b) {
                    uint64_t x = a.event_ids.empty() ? 0 : a.event_ids.back();
                    uint64_t y = b.event_ids.empty() ? 0 : b.event_ids.back();
                    return x < y;
                });
            }
            const int64_t now = now_ms();
            stats_.add_events(job->events, now);
            if (!alerts.empty()) {
                alerts_.add(alerts);
                stats_.add_alerts(alerts, now);
                for (auto& a : alerts)
                    log::info("ALERT #", a.id, " [", severity_name(a.severity), "] ", a.rule_id, ": ", a.message);
            }
            if (on_stored_) on_stored_(job->events, alerts);
            events_.append(job->events);
        }
        int64_t now = now_ms();
        if (now - last_tick >= 200) {
            events_.tick(now);
            last_tick = now;
        }
    }
}

PipelineStats Pipeline::stats() const {
    PipelineStats s;
    s.accepted = accepted_.load();
    s.rejected = rejected_.load();
    {
        std::lock_guard<std::mutex> lock(mu_);
        s.queued = queued_events_;
        if (current_) {
            s.sharded_rules = current_->sharded_rules;
            s.global_rules = current_->global_rules;
        }
    }
    s.detect_threads = int(shards_);
    s.global_thread = workers_ > shards_;
    std::lock_guard<std::mutex> lock(stats_mu_);
    for (size_t w = 0; w < worker_stats_.size(); ++w) {
        const EngineStats& e = worker_stats_[w];
        if (w < shards_) s.engine.events += e.events;  // общий поток видит те же события ещё раз
        s.engine.alerts += e.alerts;
        s.engine.suppressed += e.suppressed;
        s.engine.state_keys += e.state_keys;
        if (w < shards_) s.shard_events.push_back(worker_events_[w]);
    }
    if (shards_ > 1 && worker_stats_.size() > shards_ && s.engine.events == 0) s.engine.events = worker_stats_[shards_].events;
    return s;
}

}  // namespace sentinel
