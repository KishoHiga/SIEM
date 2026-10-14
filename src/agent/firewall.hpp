// SentinelCore Agent — применение списка блокировок в брандмауэре этого сервера.
//
// Поддерживается:
//   nftables  (Linux)   — своя таблица inet sentinel, наборы адресов, отбрасывание до маршрутизации
//                         (работает и для портов Docker); список заменяется атомарно одной командой
//   iptables  (Linux)   — своя цепочка SENTINEL в таблице raw, замена через iptables-restore
//   pf        (macOS)   — якорь com.apple/sentinel со своей таблицей адресов
//   windows             — правила брандмауэра Windows "SentinelCore Block"
//   nginx               — файл с "deny <ip>;" и мягкая перезагрузка nginx (не нужен root на брандмауэр)
//   command             — своя программа: получает путь к файлу со списком адресов
// Агент трогает ТОЛЬКО свои таблицы/цепочки/правила — чужие правила не изменяются.
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "agent/process.hpp"
#include "core/ip.hpp"

namespace sentinel::agent {

struct FirewallConfig {
    std::string mode = "none";  // none | auto | nftables | iptables | pf | windows | nginx | command
    std::string nginx_file = "/etc/nginx/conf.d/sentinel-blocklist.conf";
    std::string nginx_bin = "nginx";
    std::string command;    // для mode: command
    std::string list_file;  // файл со списком для command (по умолчанию state/blocklist.txt)
    std::vector<std::string> allowlist;  // никогда не блокировать на этом сервере
    int sync_seconds = 15;
};

// Запуск программы (подменяется в тестах).
using Runner = std::function<ProcResult(const std::vector<std::string>& argv, const std::string& stdin_data)>;
Runner default_runner();

class Firewall {
public:
    virtual ~Firewall() = default;
    virtual const char* name() const = 0;
    // Привести брандмауэр к списку (полная замена). false — ошибка (список будет применён позже снова).
    virtual bool apply(const std::vector<Cidr>& v4, const std::vector<Cidr>& v6, std::string& error) = 0;
    // Убрать всё, что добавил агент.
    virtual bool clear(std::string& error) = 0;

    // nullptr и пустая ошибка — mode: none.
    static std::unique_ptr<Firewall> create(const FirewallConfig& cfg, const std::string& state_dir, Runner runner,
                                            std::string& error);
    // Какой брандмауэр выберет mode: auto на этой системе.
    static std::string detect_auto();
};

// Тексты команд — отдельно, чтобы проверять тестами на любой ОС.
std::string nft_script(const std::vector<Cidr>& v4, const std::vector<Cidr>& v6);
std::string iptables_restore_script(const std::vector<Cidr>& list);
std::string pf_rules(const std::vector<Cidr>& v4, const std::vector<Cidr>& v6);
std::vector<std::string> windows_remoteip_chunks(const std::vector<Cidr>& all, size_t per_rule = 200);
std::string nginx_deny_file(const std::vector<Cidr>& all);

}  // namespace sentinel::agent
