// SentinelCore Agent — автопоиск источников логов на этом компьютере.
#pragma once

#include <string>
#include <vector>

#include "agent/agent_config.hpp"

namespace sentinel::agent {

struct DiscoveryResult {
    std::vector<SourceSpec> sources;   // что будем читать
    std::vector<std::string> warnings; // найдено, но нет прав / не поддерживается
};

// Linux: nginx, apache, auth.log/secure, syslog/messages, docker, journald (если нет auth.log).
// macOS: nginx (Homebrew), apache, системный журнал (sshd, sudo, su) через `log stream`.
// Windows: журнал безопасности (входы, блокировки, создание пользователей).
DiscoveryResult discover_sources();

// Итоговый список: найденные автоматически + заданные вручную, минус исключения.
std::vector<SourceSpec> effective_sources(const AgentConfig& cfg, std::vector<std::string>* warnings);

}  // namespace sentinel::agent
