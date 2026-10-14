// SentinelCore Agent — настройки агента (agent.yaml).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "agent/firewall.hpp"

namespace sentinel::agent {

// Источник логов.
struct SourceSpec {
    std::string kind = "file";  // file | command | windows_event
    std::string path;           // файл/маска (file), команда (command), канал (windows_event)
    std::string format = "auto";
    std::string source;         // имя источника на сервере: nginx, auth, syslog, docker...
    bool from_beginning = false;  // читать файл с начала при первом обнаружении
    std::string note;           // пояснение (для discover)
};

struct AgentConfig {
    std::string server;       // https://siem.example.com:8443
    std::string key;          // ключ с ролью ingest (выдаётся при enroll)
    std::string pin;          // sha256:... отпечаток сертификата сервера
    std::string ca_file;      // либо свой корневой сертификат
    bool insecure = false;    // не проверять сертификат (только отладка)
    std::string host;         // имя этого хоста (по умолчанию — системное)
    std::string state_dir;    // где хранить позиции чтения (по умолчанию рядом с конфигом)
    bool autodiscover = true;
    std::string start_at = "end";  // end | beginning — для файлов, найденных при первом запуске
    size_t batch_bytes = 1 << 20;
    int flush_ms = 1000;
    int scan_ms = 250;
    std::vector<SourceSpec> sources;   // заданные вручную
    std::vector<std::string> exclude;  // пути, которые не читать
    FirewallConfig firewall;           // блокировка адресов на этом сервере (по умолчанию выключена)

    std::string path;  // откуда загружен
};

bool load_agent_config(const std::string& path, AgentConfig& cfg, std::string& error);
bool save_agent_config(const AgentConfig& cfg, std::string& error);
std::string default_host_name();

}  // namespace sentinel::agent
