// SentinelCore — раздача собранной панели (React) прямо из сервера.
// Одна точка входа: и API, и страница на одном адресе — не нужен отдельный веб-сервер и CORS.
#pragma once

#include <string>

#include "net/http.hpp"

namespace sentinel {

class WebFiles {
public:
    explicit WebFiles(std::string dir) : dir_(std::move(dir)) {}
    bool available() const;
    const std::string& dir() const { return dir_; }
    // true — запрос обработан (файл, index.html для SPA или 404).
    bool serve(const net::HttpRequest& req, net::HttpResponse& resp) const;
    // Заголовки безопасности для страниц панели (CSP и др.).
    static void security_headers(const net::HttpRequest& req, net::HttpResponse& resp);

private:
    std::string dir_;
};

}  // namespace sentinel
