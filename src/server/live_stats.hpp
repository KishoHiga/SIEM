// SentinelCore — счётчики для панели: события/алерты по минутам за сутки,
// по часам за 32 дня (для отчётов): число событий и алертов, самые частые IP, источники, типы, страны.
// Часы старше суток хранят только самые частые значения. Всё в памяти, обновляется потоком записи.
#pragma once

#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "core/event.hpp"

namespace sentinel {

class LiveStats {
public:
    void add_events(const std::vector<Event>& events, int64_t now_ms);
    void add_alerts(const std::vector<Alert>& alerts, int64_t now_ms);

    struct Snapshot {
        uint64_t events_total = 0;     // с момента запуска
        uint64_t events_24h = 0;
        uint64_t alerts_24h = 0;
        double events_per_sec_1m = 0;
        std::vector<std::pair<int64_t, uint64_t>> events_per_minute;  // (начало минуты, кол-во), последние N минут
        std::vector<std::pair<int64_t, uint64_t>> alerts_per_minute;
        std::vector<std::pair<std::string, uint64_t>> top_ips;
        std::vector<std::pair<std::string, uint64_t>> top_sources;
        std::vector<std::pair<std::string, uint64_t>> by_type;
        std::vector<std::pair<std::string, uint64_t>> top_countries;
    };
    Snapshot snapshot(int64_t now_ms, int minutes, size_t top_n) const;

    // Сводка за период (для отчётов): по часам, самые частые значения.
    struct Period {
        uint64_t events = 0;
        uint64_t alerts = 0;
        int64_t data_from = 0;  // самый ранний час, за который есть данные (0 — нет данных)
        std::vector<std::pair<int64_t, std::pair<uint64_t, uint64_t>>> hours;  // (начало часа, (событий, алертов))
        std::vector<std::pair<std::string, uint64_t>> top_ips, top_sources, by_type, top_countries;
    };
    Period period(int64_t from_ms, int64_t to_ms, size_t top_n) const;

    // Сохранение между перезапусками (data/stats.bin). load() при повреждённом файле ничего не меняет.
    bool save(const std::string& path) const;
    bool load(const std::string& path);

private:
    static constexpr int kMinutes = 1440;
    static constexpr int kHours = 24 * 32;
    static constexpr int kDashHours = 24;
    static constexpr size_t kKeepOldHour = 300;  // часы старше суток: столько самых частых значений
    static constexpr size_t kMaxKeysPerHour = 50000;

    struct MinuteBucket {
        int64_t minute = -1;
        uint64_t events = 0;
        uint64_t alerts = 0;
    };
    struct HourBucket {
        int64_t hour = -1;
        uint64_t events = 0;
        uint64_t alerts = 0;
        bool compact = false;
        std::unordered_map<std::string, uint64_t> ips;
        std::unordered_map<std::string, uint64_t> sources;
        std::unordered_map<std::string, uint64_t> types;
        std::unordered_map<std::string, uint64_t> countries;
    };
    MinuteBucket& minute(int64_t m);
    HourBucket& hour(int64_t h);

    mutable std::mutex mu_;
    std::array<MinuteBucket, kMinutes> minutes_{};
    std::array<HourBucket, kHours> hours_{};
    uint64_t total_ = 0;
};

}  // namespace sentinel
