// SentinelCore — разбор строк логов в нормализованные события.
// Все парсеры написаны вручную (без регулярных выражений) ради скорости.
#pragma once

#include <string_view>

#include "core/event.hpp"
#include "core/json.hpp"

namespace sentinel {

enum class LogFormat { Auto, Json, Nginx, Syslog, KeyValue, Plain };

LogFormat log_format_from_name(std::string_view name);
const char* log_format_name(LogFormat f);

struct ParseContext {
    int64_t now_ms = 0;            // текущее время (для года в syslog и событий без времени)
    int tz_offset_minutes = 0;     // часовой пояс источника для времени без зоны (syslog, nginx без зоны)
    std::string_view source_hint;  // имя источника от агента (nginx, auth.log...)
    std::string_view host_hint;    // имя хоста от агента
};

// Разобрать одну строку. false — строка пустая/не распознана как событие.
bool parse_line(std::string_view line, LogFormat fmt, const ParseContext& ctx, Event& ev);

// Отдельные парсеры (false — формат не подходит)
bool parse_nginx(std::string_view line, const ParseContext& ctx, Event& ev);
bool parse_syslog(std::string_view line, const ParseContext& ctx, Event& ev);
bool parse_keyvalue(std::string_view line, const ParseContext& ctx, Event& ev);
bool parse_json_line(std::string_view line, const ParseContext& ctx, Event& ev);

// JSON-объект -> событие (известные поля и синонимы, вложенные объекты разворачиваются через точку).
bool event_from_json(const JValue& obj, const ParseContext& ctx, Event& ev);

// Обогащение по содержимому: sshd, sudo, su, брандмауэр (UFW/iptables).
void enrich_event(Event& ev);

// Время из nginx: "10/Oct/2000:13:55:36 -0700"
bool parse_clf_time(std::string_view s, int64_t& out_ms);

}  // namespace sentinel
