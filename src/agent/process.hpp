// SentinelCore Agent — запуск внешних программ (nft, iptables, pfctl, netsh, nginx) без оболочки:
// аргументы передаются списком, поэтому подставить в команду что-то лишнее нельзя.
#pragma once

#include <string>
#include <vector>

namespace sentinel::agent {

struct ProcResult {
    bool started = false;
    bool timed_out = false;
    int exit_code = -1;
    std::string output;  // stdout + stderr

    bool ok() const { return started && !timed_out && exit_code == 0; }
};

ProcResult run_process(const std::vector<std::string>& argv, const std::string& stdin_data, int timeout_ms = 30000);

// Найти программу в PATH и в /usr/sbin, /sbin, /usr/local/sbin (там лежат nft и iptables).
bool find_executable(const std::string& name, std::string& path);

}  // namespace sentinel::agent
