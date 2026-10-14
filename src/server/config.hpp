// SentinelCore — конфигурация сервера и ключи доступа.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/event.hpp"
#include "core/ip.hpp"
#include "enrich/threat.hpp"

namespace sentinel {

enum class Role { Ingest, Read, Analyst, Admin };
const char* role_name(Role r);
bool role_from_name(const std::string& s, Role& out);
// Может ли роль выполнять действие
bool role_can_ingest(Role r);
bool role_can_read(Role r);
bool role_can_change_alerts(Role r);

struct ApiKey {
    std::string name;
    Role role = Role::Read;
    std::string sha256;  // хеш ключа в hex (сам ключ нигде не хранится)
};

// Уведомления об алертах (раздел notify: в sentinel.yaml).
struct NotifyConfig {
    Severity min_severity = Severity::High;
    int64_t cooldown_ms = 10 * 60000;  // одно и то же (правило + IP) не чаще
    int64_t batch_ms = 5000;           // окно склейки: больше 3 алертов за окно -> одна сводка
    std::string panel_url;             // для ссылок на алерты (по умолчанию public_url)
    std::string ca_file;               // свой корневой сертификат для каналов (если нужен)
    std::string pin;                   // или закреплённый отпечаток sha256:...
    std::string mode = "alerts";       // alerts — по каждому алерту; incidents — только новый/усилившийся инцидент
    bool incidents() const { return mode == "incidents"; }

    struct Telegram {
        std::string bot_token, chat_id;
        std::string api_url = "https://api.telegram.org";
        bool enabled() const { return !bot_token.empty() && !chat_id.empty(); }
    } telegram;
    struct Webhook {
        std::string url;
        std::string format = "json";  // json | slack | discord
        bool enabled() const { return !url.empty(); }
    } webhook;
    struct Email {
        std::string host;
        uint16_t port = 587;
        std::string tls = "auto";  // auto (465 -> сразу TLS, иначе STARTTLS) | starttls | tls | none
        std::string username, password, from;
        std::vector<std::string> to;
        bool enabled() const { return !host.empty() && !from.empty() && !to.empty(); }
    } email;

    bool any() const { return telegram.enabled() || webhook.enabled() || email.enabled(); }
};

// Автоблокировка (раздел response: в sentinel.yaml).
struct ResponseConfig {
    bool auto_block = true;
    Severity min_severity = Severity::Critical;
    std::vector<std::string> rules;
    int64_t duration_ms = 3600000;
    std::vector<Cidr> allowlist;
    bool block_private = false;
    int max_per_minute = 60;
};

// Еженедельный отчёт на почту (раздел reports: в sentinel.yaml). Письмо уходит через notify.email.
struct ReportConfig {
    bool weekly = false;
    int weekday = 1;            // 0 — воскресенье, 1 — понедельник, …
    int minute_of_day = 9 * 60; // местное время сервера
    std::vector<std::string> to;  // пусто — адреса из notify.email.to
};

struct Config {
    std::string listen_host = "127.0.0.1";
    uint16_t listen_port = 8080;
    std::string data_dir = "./data";
    std::string rules_dir = "./rules";
    std::string keys_file;  // по умолчанию <data_dir>/keys.yaml
    int retention_days = 90;
    int workers = 4;
    size_t max_body_mb = 32;
    size_t queue_events = 1'000'000;
    int detect_threads = 0;  // потоков обнаружения: 0 — по числу ядер
    int store_threads = -1;  // потоков сжатия при записи: -1 — по числу ядер, 0 — без отдельных потоков
    bool fsync = true;
    std::string log_level = "info";
    std::string tls_cert;    // путь к сертификату (PEM). Если задан — сервер работает по HTTPS
    std::string tls_key;     // путь к закрытому ключу (PEM)
    std::string public_url;  // адрес сервера для агентов, например https://siem.example.com:8443
    std::string web_dir = "./web/dist";  // собранная панель (npm run build); пусто — панель отключена
    std::vector<ApiKey> keys;  // ключи из самого конфига (api_keys)
    NotifyConfig notify;
    ResponseConfig response;
    std::string geo_db;       // база стран и сетей (geo-import); по умолчанию <data_dir>/geo/geo.bin
    ThreatConfig threat;      // списки плохих адресов
    int64_t incident_window_ms = 3600000;
    ReportConfig reports;  // алерты одного IP в пределах окна — один инцидент

    std::string source;  // откуда загружен
};

// Загрузить конфиг (если файла нет — значения по умолчанию, это не ошибка).
bool load_config(const std::string& path, Config& cfg, std::string& error);
// Загрузить ключи из файла ключей и добавить к cfg.keys.
bool load_keys_file(Config& cfg, std::string& error);
// Прочитать ключи из файла (файла нет — не ошибка).
bool read_keys_file(const std::string& path, std::vector<ApiKey>& out, std::string& error);
// Дописать ключ в файл ключей (создаёт файл с правами только для владельца).
bool append_key_file(const std::string& path, const ApiKey& key, std::string& error);
// Проверка имени ключа: буквы, цифры, - _ .
bool valid_key_name(const std::string& name);
// Адрес, который агенты используют для подключения (public_url или из listen).
std::string agent_server_url(const Config& cfg);
// Создать новый ключ: дописывает запись в файл ключей, возвращает секрет (показать один раз).
bool create_key(Config& cfg, const std::string& name, Role role, std::string& secret, std::string& error);

}  // namespace sentinel
