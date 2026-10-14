// SentinelCore Agent — сбор логов и надёжная доставка на сервер.
//
// Принцип надёжности: позиция чтения файла подтверждается ТОЛЬКО после того, как сервер
// принял данные (HTTP 202). Если сервер недоступен, агент ждёт и повторяет —
// сами файлы логов служат буфером, ничего не теряется. Позиции сохраняются на диск,
// после перезапуска агент продолжает с того же места.
#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "agent/agent_config.hpp"
#include "agent/files.hpp"
#include "agent/winevent.hpp"
#include "net/client.hpp"

namespace sentinel::agent {

extern const char* kAgentVersion;

struct AgentStats {
    uint64_t lines_sent = 0;
    uint64_t bytes_sent = 0;
    uint64_t batches = 0;
    uint64_t send_errors = 0;
    uint64_t dropped = 0;  // потеряно из буфера команд при долгой недоступности сервера
    std::string last_error;
};

class Agent {
public:
    explicit Agent(AgentConfig cfg);
    ~Agent();

    bool init(std::string& error);
    // Одна итерация: найти файлы, прочитать новое, отправить. Возвращает отправленные строки.
    size_t step();
    void run(const std::atomic<bool>& stop);
    void shutdown();

    AgentStats stats() const { return stats_; }
    std::vector<SourceSpec> sources() const { return sources_; }

    // Блокировки: получить список с сервера и применить в брандмауэре (если firewall включён).
    bool sync_blocks(std::string& error);
    // Убрать из брандмауэра всё, что добавил агент.
    bool firewall_clear(std::string& error);
    // "none" | "nftables; applied=12" | "nftables; error=..." — показывается в панели.
    std::string firewall_status() const { return fw_status_; }
    // Для тестов: подменить запуск nft/iptables/... (вызывать до init).
    void set_firewall_runner(Runner r) { fw_runner_ = std::move(r); }

    // Проверка связи и ключа: вернёт имя ключа и роль.
    bool test_connection(std::string& info, std::string& error);

    // Подключение по одноразовому токену: получает личный ключ и записывает конфиг.
    static bool enroll(AgentConfig& cfg, const std::string& token, std::string& error, std::string& info);

private:
    struct FileSource {
        SourceSpec spec;
        std::map<std::string, std::unique_ptr<FileTailer>> tailers;
        struct Draining {
            std::unique_ptr<FileTailer> t;
            int64_t until;
        };
        std::vector<Draining> draining;
    };
    struct CommandSource;
    struct WinSource {
        SourceSpec spec;
        std::unique_ptr<WinEventReader> reader;
    };
    struct SavedFile {
        uint64_t dev = 0, ino = 0, offset = 0;
    };

    void rescan(int64_t now);
    bool send_lines(const SourceSpec& spec, const std::vector<std::string>& lines, bool json_array);
    bool drain_tailer(FileSource& fs, FileTailer& t, size_t& sent);
    void load_state();
    void save_state();

    std::vector<std::pair<std::string, std::string>> base_headers() const;

    AgentConfig cfg_;
    std::unique_ptr<net::HttpClient> http_;
    std::unique_ptr<Firewall> fw_;
    Runner fw_runner_;
    std::string fw_status_ = "none";
    std::vector<Cidr> fw_allow_;  // allowlist + адреса самого SIEM (иначе агент отрежет себе связь)
    uint64_t blocks_version_ = 0;
    bool blocks_applied_ = false;
    int64_t last_block_sync_ = 0;
    int64_t last_block_warn_ = 0;
    std::vector<SourceSpec> sources_;
    std::vector<std::unique_ptr<FileSource>> files_;
    std::vector<std::unique_ptr<CommandSource>> commands_;
    std::vector<std::unique_ptr<WinSource>> windows_;
    std::map<std::string, SavedFile> saved_;
    std::map<std::string, std::string> saved_bookmarks_;
    bool first_scan_ = true;
    bool state_dirty_ = false;
    int64_t last_rescan_ = 0;
    int64_t last_save_ = 0;
    int64_t backoff_until_ = 0;
    int64_t backoff_ms_ = 0;
    int64_t last_report_ = 0;
    int tz_minutes_ = 0;
    AgentStats stats_;
};

// Смещение местного часового пояса от UTC в минутах (для логов без зоны, например syslog).
int local_utc_offset_minutes();
// Строка `log stream --style syslog` (macOS) -> вид, понятный разбору syslog на сервере.
bool convert_macos_log_line(std::string& line);

}  // namespace sentinel::agent
