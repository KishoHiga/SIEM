// SentinelCore — собственное хранилище событий.
//
// Устройство:
//   data/events/seg-<время>-<номер>.sntl — сегменты (новый каждый час или при 256 МБ);
//   сегмент = заголовок + блоки; блок = до N событий, сжатых своим LZ;
//   у каждого блока заголовок с CRC, диапазоном времени и id, и bloom-фильтром по
//   IP/пользователю/хосту — при поиске "что делал IP X" лишние блоки даже не читаются.
// Восстановление после сбоя: при старте недописанный хвост последнего сегмента отрезается.
// Старые сегменты удаляются по сроку хранения (retention).
//
// Запись — из одного потока (append/tick/flush). Чтение (query/get) — из любых потоков.
// Подготовка блоков (кодирование, bloom-фильтр, сжатие) идёт в нескольких потоках,
// а на диск блоки пишутся строго по порядку. Пока блок готовится, его события видны поиску.
#pragma once

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <thread>
#include <optional>
#include <string>
#include <vector>

#include "core/event.hpp"
#include "store/file.hpp"

namespace sentinel {

struct StoreOptions {
    std::string dir;                              // каталог данных
    int64_t retention_ms = 90LL * 86400 * 1000;   // срок хранения
    size_t block_events = 2048;                   // событий в блоке
    int64_t flush_interval_ms = 1000;             // максимум задержки записи на диск
    uint64_t segment_max_bytes = 256ull << 20;
    int64_t segment_max_age_ms = 3600 * 1000;
    bool fsync = true;
    int compress_threads = -1;                    // потоков сжатия: -1 — по числу ядер, 0 — сжимать в потоке записи
};

struct EventQuery {
    int64_t from = std::numeric_limits<int64_t>::min();
    int64_t to = std::numeric_limits<int64_t>::max();
    std::vector<std::pair<std::string, std::string>> equals;  // поле = значение (без учёта регистра)
    std::string text;                                         // подстрока в message/raw
    size_t limit = 100;
    uint64_t before_id = 0;                                   // для постраничного вывода
};

struct StoreStats {
    uint64_t events = 0;
    uint64_t blocks = 0;
    uint64_t segments = 0;
    uint64_t bytes_on_disk = 0;
    uint64_t raw_bytes = 0;
    uint64_t pending = 0;
    uint64_t corrupt_blocks = 0;
};

class EventStore {
public:
    EventStore();
    ~EventStore();

    bool open(const StoreOptions& opt, std::string& error);
    void close();

    // Поток записи
    void append(std::vector<Event>& batch);
    void tick(int64_t now_ms);  // сброс по таймеру, ротация, удаление старого
    void flush();

    // Любые потоки
    std::vector<Event> query(const EventQuery& q) const;
    // То же без сбора в память: fn получает подходящие события (сначала свежие); false — стоп.
    // q.limit = 0 — без ограничения. Возвращает, сколько событий передано.
    size_t visit(const EventQuery& q, const std::function<bool(Event&&)>& fn) const;
    std::optional<Event> get(uint64_t id) const;
    // Пройти события периода от старых к новым (не больше max самых свежих), по одному блоку в памяти.
    // fn вернул false — остановиться. Возвращает, сколько событий передано.
    size_t scan(int64_t from, int64_t to, size_t max, const std::function<bool(const Event&)>& fn) const;
    uint64_t max_id() const;
    StoreStats stats() const;

private:
    struct BlockMeta;
    struct Segment;

    struct Prepared;
    static void prepare_block(Prepared& p);
    void cut_block_locked(size_t n);
    void write_ready(bool all);
    bool write_prepared(Prepared& p);
    void write_failed();
    void worker();
    bool open_new_segment(int64_t now);
    bool read_block(const Segment& seg, const BlockMeta& b, std::vector<Event>& out) const;
    void apply_retention(int64_t now);

    StoreOptions opt_;
    std::string events_dir_;
    mutable std::mutex mu_;
    std::vector<std::shared_ptr<Segment>> segments_;  // по возрастанию времени
    std::vector<Event> pending_;
    std::deque<std::shared_ptr<Prepared>> inflight_;  // блоки в подготовке/ожидании записи (по порядку)
    std::deque<std::shared_ptr<Prepared>> work_;      // очередь для потоков сжатия
    std::condition_variable work_cv_, ready_cv_;
    std::vector<std::thread> pool_;
    bool pool_stop_ = false;
    std::unique_ptr<File> writer_;
    std::shared_ptr<Segment> current_;
    int64_t last_flush_ = 0;
    int64_t last_sync_ = 0;
    int64_t last_retention_ = 0;
    uint64_t max_id_ = 0;
    uint64_t seg_counter_ = 0;
    mutable uint64_t corrupt_blocks_ = 0;
    bool open_ = false;
};

}  // namespace sentinel
