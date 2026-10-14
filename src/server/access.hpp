// SentinelCore — доступ: ключи API (с перечитыванием без перезапуска)
// и одноразовые токены подключения агентов.
//
// Как подключается агент:
//   1) администратор: sentinel-server enroll-token        -> токен sne_... (живёт 24 ч)
//   2) на сервере с сайтом: sentinel-agent enroll --server https://... --token sne_... --pin sha256:...
//   3) сервер проверяет токен и выдаёт агенту ЛИЧНЫЙ ключ с ролью ingest (только отправка логов).
#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

#include "server/config.hpp"

namespace sentinel {

class KeyStore {
public:
    // static_keys — ключи из конфига; file — файл ключей (keygen / enroll дописывают туда).
    void init(std::vector<ApiKey> static_keys, std::string file);
    bool reload(std::string& error);
    // Перечитать файл, если он изменился (вызывать раз в несколько секунд).
    void reload_if_changed();

    std::optional<ApiKey> find_by_secret(std::string_view secret) const;
    // Найти ключ по его хешу (для сессий панели: если ключ удалили — сессия тоже перестаёт работать).
    std::optional<ApiKey> find_by_hash(const std::string& sha256) const;
    bool has_name(const std::string& name) const;
    size_t size() const;
    // Создать ключ: запись в файл + сразу в память. secret показывается один раз.
    bool add(const std::string& name, Role role, std::string& secret, std::string& error);

private:
    mutable std::shared_mutex mu_;
    std::vector<ApiKey> static_keys_;
    std::vector<ApiKey> keys_;
    std::string file_;
    int64_t file_stamp_ = -1;
};

class EnrollStore {
public:
    explicit EnrollStore(std::string file = "") : file_(std::move(file)) {}
    void set_file(std::string file) { file_ = std::move(file); }

    // Создать токен (секрет sne_... возвращается один раз).
    bool create(int64_t ttl_ms, int uses, const std::string& label, std::string& secret, std::string& error);

    enum class Result { Ok, Invalid, Expired };
    // Проверить и "погасить" одно использование токена.
    Result consume(std::string_view secret);

private:
    struct Token {
        std::string sha256;
        int64_t expires = 0;
        int uses = 1;
        std::string label;
    };
    bool load(std::vector<Token>& out, std::string& error) const;
    bool save(const std::vector<Token>& tokens, std::string& error) const;

    std::mutex mu_;
    std::string file_;
};

}  // namespace sentinel
