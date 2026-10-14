// SentinelCore — простой потокобезопасный логгер в stderr.
#pragma once

#include <sstream>
#include <string>

namespace sentinel::log {

enum class Level { Debug = 0, Info = 1, Warn = 2, Error = 3, Off = 4 };

void set_level(Level l);
Level level();
void write(Level l, const std::string& msg);

namespace detail {
inline void append(std::ostringstream&) {}
template <class T, class... Rest>
void append(std::ostringstream& os, const T& v, const Rest&... rest) {
    os << v;
    append(os, rest...);
}
}  // namespace detail

template <class... Args>
void msg(Level l, const Args&... args) {
    if (l < level()) return;
    std::ostringstream os;
    detail::append(os, args...);
    write(l, os.str());
}

template <class... Args> void debug(const Args&... a) { msg(Level::Debug, a...); }
template <class... Args> void info(const Args&... a) { msg(Level::Info, a...); }
template <class... Args> void warn(const Args&... a) { msg(Level::Warn, a...); }
template <class... Args> void error(const Args&... a) { msg(Level::Error, a...); }

}  // namespace sentinel::log
