// SentinelCore — живая лента для панели (через WebSocket).
// Раз в секунду отправляет: сколько событий пришло, последние события (до 30) и новые алерты.
// Так браузер не захлёбывается даже при сотнях тысяч событий в секунду.
#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "core/event.hpp"

namespace sentinel {

class LiveFeed {
public:
    using Sink = std::function<void(const std::string&)>;

    void set_sink(Sink sink);
    // Вызывается потоком записи после сохранения пачки (алерты уже с номерами).
    void on_stored(const std::vector<Event>& events, const std::vector<Alert>& alerts);
    // Собрать и разослать сообщение (раз в секунду).
    void tick(int64_t now_ms);

private:
    static constexpr size_t kRecent = 30;
    std::mutex mu_;
    Sink sink_;
    std::deque<std::string> recent_;
    std::vector<std::string> alerts_;
    uint64_t count_ = 0;
    int64_t last_sent_ = 0;
};

}  // namespace sentinel
