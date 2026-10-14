// SentinelCore — HTTP API:
//   GET  /health
//   POST /api/v1/ingest                  приём логов (роль ingest/admin)
//   GET  /api/v1/events                  поиск событий
//   GET  /api/v1/events/{id}
//   GET  /api/v1/alerts                  список алертов
//   GET  /api/v1/alerts/{id}             алерт + связанные события
//   POST /api/v1/alerts/{id}/status      смена статуса (analyst/admin)
//   GET  /api/v1/stats                   цифры для панели
//   GET  /api/v1/rules                   правила, сколько алертов дали за сутки, ошибки файлов
//   GET  /api/v1/rules/{id}              правило и текст его файла
//   POST /api/v1/rules                   новое правило {source} (admin)
//   PUT  /api/v1/rules/{id}              сохранить текст {source} (admin)
//   DELETE /api/v1/rules/{id}            удалить (admin)
//   POST /api/v1/rules/{id}/enabled      включить/выключить {enabled} (admin)
//   GET  /api/v1/rules/{id}/history[/{version}]  версии файла правила
//   POST /api/v1/rules/check             проверить текст, не сохраняя {source, id?} (analyst/admin)
//   POST /api/v1/rules/try               пробный запуск на строках логов {source, lines, format?}
//   POST /api/v1/rules/try-history       пробный запуск на сохранённых событиях {source, hours, max_events}
//   GET  /api/v1/whoami                  кто я (имя ключа и роль)
//   GET  /api/v1/agents                  подключённые агенты/источники и когда были на связи
//   POST /api/v1/enroll                  подключение агента по одноразовому токену (без ключа)
//   POST /api/v1/enroll-tokens           создать токен подключения агента (admin, из панели)
//   POST /api/v1/login | /logout, GET /api/v1/me   вход в панель по ключу (сессия в HttpOnly-cookie)
//   GET  /api/v1/blocks[?ip=]            заблокированные IP и политика автоблокировки
//   POST /api/v1/blocks                  заблокировать вручную {ip, duration, reason} (analyst/admin)
//   DELETE /api/v1/blocks?ip=...         разблокировать (analyst/admin)
//   GET  /api/v1/agent/blocks?version=N  список для брандмауэра агента (роль ingest)
//   GET  /api/v1/notify                  каналы уведомлений и их состояние
//   POST /api/v1/notify/test             тестовое уведомление во все каналы (admin)
//   GET  /api/v1/ip/{адрес}              карточка IP: страна, сеть, чёрные списки, блокировка, активность
//   GET  /api/v1/threat                  чёрные списки: сколько адресов, когда обновлены, ошибки
//   GET  /api/v1/incidents               инциденты (?status=&active=1&severity=&q=&assignee=&limit=&before_id=)
//   GET  /api/v1/incidents/{id}          инцидент: алерты, заметки, история, сведения об IP
//   POST /api/v1/incidents/{id}/status   {status, close_alerts?} (analyst/admin)
//   POST /api/v1/incidents/{id}/assign   {assignee: "me" | "" | имя} (analyst/admin)
//   POST /api/v1/incidents/{id}/notes    {text} (analyst/admin)
//   POST /api/v1/incidents/{id}/merge    {into} — перенести алерты в другой инцидент (analyst/admin)
//   GET  /api/v1/export/{events|alerts|incidents}?format=csv|excel|json|ndjson&...фильтры  выгрузка файлом
//   GET  /api/v1/report?from=&to=        отчёт за период (по умолчанию 7 дней)
//   POST /api/v1/report/send             отправить отчёт письмом сейчас (admin)
//   WS   /ws/live                        живая лента (см. LiveFeed)
// Авторизация: заголовок "Authorization: Bearer <ключ>", "X-API-Key: <ключ>" или cookie сессии панели.
// Для изменяющих запросов с cookie нужен заголовок "X-Requested-With: sentinel" (защита от CSRF).
#pragma once

#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/json.hpp"
#include "detect/rules.hpp"
#include "net/http.hpp"
#include "server/access.hpp"
#include "server/blocklist.hpp"
#include "server/config.hpp"
#include "server/live_stats.hpp"
#include "server/notifier.hpp"
#include "server/pipeline.hpp"
#include "server/report.hpp"
#include "enrich/enricher.hpp"
#include "server/rule_manager.hpp"
#include "server/web.hpp"
#include "store/alert_store.hpp"
#include "store/event_store.hpp"
#include "store/incident_store.hpp"

namespace sentinel {

void write_block(JsonWriter& w, const Block& b);
void write_incident(JsonWriter& w, const Incident& i, bool full);
std::optional<int64_t> parse_time_param(std::string_view v);
// Разбор фильтров из адреса запроса (общий для списков и выгрузок). false — error заполнен.
bool parse_event_query(const net::HttpRequest& req, EventQuery& q, std::string& error);
bool parse_alert_query(const net::HttpRequest& req, AlertQuery& q, std::string& error);
bool parse_incident_query(const net::HttpRequest& req, IncidentQuery& q, std::string& error);

class Api {
public:
    Api(const Config& cfg, EventStore& events, AlertStore& alerts, LiveStats& stats, Pipeline& pipeline);

    void handle(const net::HttpRequest& req, net::HttpResponse& resp);
    void set_rules(const std::vector<Rule>& rules);
    // Управление правилами из панели (без него — правила только для чтения).
    void set_rule_manager(RuleManager* m) { rule_mgr_ = m; }
    // Обогащение событий при приёме (страна, сеть, чёрные списки) и сведения для карточки IP.
    void set_enrichment(Enricher* e, ThreatFeeds* feeds) {
        enricher_ = e;
        feeds_ = feeds;
    }
    KeyStore& keys() { return keys_; }
    EnrollStore& enroll_store() { return enroll_; }

    // Проверка доступа к WebSocket-ленте (сессия панели или ключ с правом чтения).
    bool ws_accept(const net::HttpRequest& req);
    void set_web(std::shared_ptr<WebFiles> web) { web_ = std::move(web); }
    void set_response(BlockList* blocks, Notifier* notifier) {
        blocks_ = blocks;
        notifier_ = notifier;
    }
    void set_incidents(IncidentStore* s) { incidents_ = s; }
    void set_report_mailer(ReportMailer* m) { mailer_ = m; }
    // Список серверов (агентов) переживает перезапуск: сохраняется в data/agents.json.
    void load_agents();
    void save_agents();
    // Адрес сервера и отпечаток сертификата — для готовой команды подключения агента.
    void set_agent_info(std::string url, std::string fingerprint) {
        agent_url_ = std::move(url);
        agent_pin_ = std::move(fingerprint);
    }

private:
    std::optional<ApiKey> authenticate(const net::HttpRequest& req, net::HttpResponse& resp, bool& via_cookie);
    std::optional<ApiKey> session_from_cookie(const net::HttpRequest& req);
    void login(const net::HttpRequest& req, net::HttpResponse& resp);
    void logout(const net::HttpRequest& req, net::HttpResponse& resp);
    void create_enroll_token(const net::HttpRequest& req, net::HttpResponse& resp);
    void enroll(const net::HttpRequest& req, net::HttpResponse& resp);
    void agents(net::HttpResponse& resp);
    void touch_agent(const ApiKey& key, const net::HttpRequest& req, size_t events);
    bool auth_blocked(const std::string& ip);
    void auth_failed(const std::string& ip);

    void ingest(const net::HttpRequest& req, net::HttpResponse& resp, const ApiKey& key);
    void list_events(const net::HttpRequest& req, net::HttpResponse& resp);
    void get_event(uint64_t id, net::HttpResponse& resp);
    void list_alerts(const net::HttpRequest& req, net::HttpResponse& resp);
    void get_alert(uint64_t id, net::HttpResponse& resp);
    void set_alert_status(uint64_t id, const net::HttpRequest& req, net::HttpResponse& resp);
    void stats(const net::HttpRequest& req, net::HttpResponse& resp);
    void rules(net::HttpResponse& resp);
    void rules_route(const net::HttpRequest& req, net::HttpResponse& resp, const ApiKey& key,
                     const std::vector<std::string_view>& parts);
    void rule_get(const std::string& id, net::HttpResponse& resp);
    void rule_save(const std::string& id, const net::HttpRequest& req, net::HttpResponse& resp, const ApiKey& key);
    void rule_delete(const std::string& id, net::HttpResponse& resp, const ApiKey& key);
    void rule_enabled(const std::string& id, const net::HttpRequest& req, net::HttpResponse& resp, const ApiKey& key);
    void rule_history(const std::string& id, const std::string& version, net::HttpResponse& resp);
    void rule_check(const net::HttpRequest& req, net::HttpResponse& resp);
    void rule_try(const net::HttpRequest& req, net::HttpResponse& resp, bool history);
    void list_blocks(const net::HttpRequest& req, net::HttpResponse& resp);
    void add_block(const net::HttpRequest& req, net::HttpResponse& resp, const ApiKey& key);
    void remove_block(const net::HttpRequest& req, net::HttpResponse& resp, const ApiKey& key);
    void agent_blocks(const net::HttpRequest& req, net::HttpResponse& resp, const ApiKey& key);
    void notify_status(net::HttpResponse& resp);
    void notify_test(net::HttpResponse& resp, const ApiKey& key);
    void ip_card(const std::string& ip, const net::HttpRequest& req, net::HttpResponse& resp);
    void threat_status(net::HttpResponse& resp);
    void incidents_route(const net::HttpRequest& req, net::HttpResponse& resp, const ApiKey& key,
                         const std::vector<std::string_view>& parts);
    void list_incidents(const net::HttpRequest& req, net::HttpResponse& resp);
    void get_incident(uint64_t id, net::HttpResponse& resp);
    void incident_action(uint64_t id, std::string_view action, const net::HttpRequest& req, net::HttpResponse& resp,
                         const ApiKey& key);
    void export_data(std::string_view what, const net::HttpRequest& req, net::HttpResponse& resp);
    void report(const net::HttpRequest& req, net::HttpResponse& resp);
    void report_send(const net::HttpRequest& req, net::HttpResponse& resp, const ApiKey& key);
    uint64_t incident_of(uint64_t alert_id) const { return incidents_ ? incidents_->incident_of_alert(alert_id) : 0; }

    EventStore& events_;
    AlertStore& alerts_;
    LiveStats& live_;
    Pipeline& pipeline_;
    int64_t started_ms_;

    std::mutex rules_mu_;
    std::vector<Rule> rules_list_;
    RuleManager* rule_mgr_ = nullptr;
    Enricher* enricher_ = nullptr;
    ThreatFeeds* feeds_ = nullptr;
    std::mutex try_mu_;  // одна пробная проверка на истории за раз

    struct AuthFail {
        int64_t window_start = 0;
        int count = 0;
        int64_t blocked_until = 0;
    };
    std::mutex auth_mu_;
    std::unordered_map<std::string, AuthFail> auth_fail_;

    KeyStore keys_;
    EnrollStore enroll_;

    struct AgentInfo {
        std::string host;
        std::string version;
        std::string remote_addr;
        int64_t first_seen = 0;
        int64_t last_seen = 0;
        uint64_t events = 0;
        uint64_t requests = 0;
        std::string firewall;  // что агент сообщил о брандмауэре: "nftables; applied=12" и т.п.
        int64_t blocks_synced = 0;
    };
    std::mutex agents_mu_;
    std::unordered_map<std::string, AgentInfo> agents_;  // по имени ключа

    struct Session {
        std::string key_hash;  // ключ, которым вошли (роль берём из него при каждом запросе)
        int64_t expires = 0;
    };
    std::mutex sessions_mu_;
    std::unordered_map<std::string, Session> sessions_;  // id сессии -> кто вошёл
    // Одноразовые билеты для живой ленты: Safari не всегда передаёт cookie в WebSocket,
    // поэтому панель сначала берёт билет обычным запросом и подключается с ним (живёт 60 с).
    std::unordered_map<std::string, Session> ws_tickets_;  // под sessions_mu_
    void ws_ticket(const net::HttpRequest& req, net::HttpResponse& resp, const ApiKey& key);

    std::shared_ptr<WebFiles> web_;
    BlockList* blocks_ = nullptr;
    Notifier* notifier_ = nullptr;
    IncidentStore* incidents_ = nullptr;
    ReportMailer* mailer_ = nullptr;
    std::string tmp_dir_;      // временные файлы выгрузок (data/tmp)
    std::mutex export_mu_;     // одна выгрузка за раз
    std::string agents_file_;
    bool agents_dirty_ = false;
    std::string agent_url_, agent_pin_;
};

}  // namespace sentinel
