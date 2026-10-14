// SentinelCore — списки плохих адресов (threat intelligence): FireHOL, Spamhaus DROP, выходные узлы Tor,
// свои файлы. Сервер сам скачивает списки по расписанию (своим HTTP-клиентом), хранит копию на диске
// (работает и без интернета после перезапуска) и помечает события: ti.listed = true, ti.lists = имена.
#pragma once

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "core/ip.hpp"

namespace sentinel {

struct ThreatListConfig {
    std::string name;  // латиница, цифры, - и _
    std::string url;   // откуда скачивать (http/https)
    std::string file;  // или локальный файл
};

struct ThreatConfig {
    std::vector<ThreatListConfig> lists;
    int64_t refresh_ms = 6 * 3600 * 1000LL;
    std::string ca_file;  // свой корневой сертификат для скачивания (необязательно)
    bool any() const { return !lists.empty(); }
};

// Неизменяемый набор списков (меняется целиком, атомарно).
class ThreatSet {
public:
    void add(const std::string& name, const std::vector<Cidr>& entries);  // до 64 списков
    uint64_t match(const IpAddr& ip) const;                                // биты списков
    std::string names_of(uint64_t mask) const;                             // "firehol,tor"
    const std::vector<std::string>& names() const { return names_; }
    size_t entries(size_t i) const { return counts_[i]; }

private:
    struct V4 {
        uint32_t start, end;
    };
    struct V6 {
        std::array<uint8_t, 16> start, end;
    };
    std::vector<std::string> names_;
    std::vector<size_t> counts_;
    std::vector<std::vector<V4>> v4_;
    std::vector<std::vector<V6>> v6_;
};

// Разбор текста списка: по адресу или подсети в строке, комментарии # и ;
// ("1.2.3.0/24 ; SBL123", "1.2.3.4", "2001:db8::/32"). Подсети шире /8 (v4) и /16 (v6) пропускаются.
std::vector<Cidr> parse_threat_list(std::string_view text, size_t* bad_lines = nullptr);

struct ThreatListStatus {
    std::string name, source;
    size_t entries = 0;
    int64_t updated = 0;      // когда список последний раз успешно загружен
    int64_t last_try = 0;
    bool cached = false;      // загружена копия с диска (свежая ещё не скачана)
    std::string last_error;
};

class ThreatFeeds {
public:
    using OnUpdate = std::function<void(std::shared_ptr<const ThreatSet>)>;
    ThreatFeeds(ThreatConfig cfg, std::string cache_dir, OnUpdate on_update);
    ~ThreatFeeds();

    // Загрузить копии с диска (быстро, при старте), затем фоновое обновление.
    void start();
    void stop();
    // Обновить все списки сейчас (в вызывающем потоке). true — хоть что-то изменилось.
    bool refresh_all();
    std::vector<ThreatListStatus> status() const;

private:
    bool fetch(size_t i, std::string& text, std::string& error);
    void rebuild();
    void loop();

    ThreatConfig cfg_;
    std::string cache_dir_;
    OnUpdate on_update_;
    mutable std::mutex mu_;
    std::vector<ThreatListStatus> status_;
    std::vector<std::vector<Cidr>> data_;
    std::condition_variable cv_;
    bool stop_ = false;
    std::thread th_;
};

}  // namespace sentinel
