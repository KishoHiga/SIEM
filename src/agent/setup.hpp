// SentinelCore Agent — простая настройка без ручной правки файлов:
//   sentinel-agent add <файл>       добавить журнал сайта в agent.yaml
//   sentinel-agent remove <файл>    убрать
//   sentinel-agent sources          что читается сейчас
//   sentinel-agent service install  работать в фоне (launchd / systemd / служба Windows)
#pragma once

#include <string>
#include <vector>

#include "agent/agent_config.hpp"

namespace sentinel::agent {

// --- agent.yaml как текст: комментарии и остальные настройки сохраняются ---

// Добавить файл в раздел sources (раздел создаётся, если его нет).
std::string yaml_add_source(const std::string& text, const SourceSpec& s);
// Убрать источник с этим путём. false — такого нет.
bool yaml_remove_source(const std::string& text, const std::string& path, std::string& out);

// Метка источника по пути: /Users/me/SupSearch/server/logs/access.log -> "supsearch".
std::string guess_source_name(const std::string& path);

// Формат по последним строкам файла.
struct FormatGuess {
    std::string format = "auto";  // nginx | json | syslog | kv | auto
    int checked = 0;              // сколько строк посмотрели
    int recognized = 0;           // сколько из них подошли
    std::string example;          // как SIEM поймёт последнюю строку
};
FormatGuess guess_log_format(const std::vector<std::string>& lines);
// Последние строки файла (до max_lines, читает не больше 64 КБ с конца).
std::vector<std::string> tail_lines(const std::string& path, size_t max_lines);

// Записать файл целиком через временный (права исходного файла сохраняются).
bool write_file_atomic(const std::string& path, const std::string& text, std::string& error);

// --- фоновая служба ---

struct ServiceInfo {
    std::string kind;     // launchd-user | launchd-system | systemd | windows
    std::string file;     // plist / unit (пусто для Windows)
    std::string log_hint; // где смотреть журнал агента
};

ServiceInfo service_info();
// exe и config — абсолютные пути. В out — что сделано (для человека).
bool service_install(const std::string& exe, const std::string& config, std::string& out, std::string& error);
bool service_uninstall(std::string& out, std::string& error);
// running: работает ли сейчас; installed: установлена ли.
void service_status(bool& installed, bool& running, std::string& details);

// Текст файла службы (для проверки и для команды 'service print').
std::string launchd_plist(const std::string& exe, const std::string& config, const std::string& log_file);
std::string systemd_unit(const std::string& exe, const std::string& config);

// Полный путь к запущенной программе.
std::string executable_path(const char* argv0);

}  // namespace sentinel::agent
