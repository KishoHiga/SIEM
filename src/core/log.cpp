#include "core/log.hpp"

#include <atomic>
#include <cstdio>
#include <mutex>

#include "core/util.hpp"

namespace sentinel::log {

static std::atomic<int> g_level{int(Level::Info)};
static std::mutex g_mutex;

void set_level(Level l) { g_level.store(int(l)); }
Level level() { return Level(g_level.load(std::memory_order_relaxed)); }

void write(Level l, const std::string& msg) {
    static const char* names[] = {"DEBUG", "INFO ", "WARN ", "ERROR"};
    std::string line = format_iso8601(now_ms());
    line += ' ';
    line += names[int(l) < 4 ? int(l) : 3];
    line += ' ';
    line += msg;
    line += '\n';
    std::lock_guard<std::mutex> lock(g_mutex);
    std::fwrite(line.data(), 1, line.size(), stderr);
    std::fflush(stderr);
}

}  // namespace sentinel::log
