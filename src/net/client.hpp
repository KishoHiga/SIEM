// SentinelCore — простой HTTP/1.1 клиент (с TLS через net/tls) для агента и проверок.
// Блокирующий, держит соединение открытым (keep-alive), переподключается при обрыве.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "net/socket.hpp"
#include "net/tls.hpp"

namespace sentinel::net {

struct Url {
    bool https = false;
    std::string host;
    uint16_t port = 0;
    std::string path;  // базовый путь (обычно пусто)
};

bool parse_url(const std::string& s, Url& out, std::string& error);

struct ClientResponse {
    int status = 0;
    std::vector<std::pair<std::string, std::string>> headers;  // имена в нижнем регистре
    std::string body;
    std::string header(const std::string& name) const;
};

class HttpClient {
public:
    HttpClient(Url url, ClientTlsOptions tls, int timeout_ms = 15000);
    ~HttpClient();

    // false — сетевая ошибка (error заполнен). HTTP-ошибки (4xx/5xx) — это true + status.
    bool request(const std::string& method, const std::string& path,
                 const std::vector<std::pair<std::string, std::string>>& headers, const std::string& body,
                 ClientResponse& resp, std::string& error);
    void close();
    void set_max_response(size_t n) { max_response_ = n; }
    // Отпечаток сертификата сервера последнего соединения (для показа пользователю).
    std::string server_fingerprint() const { return fingerprint_; }

private:
    bool connect(std::string& error);
    bool send_all(const char* data, size_t n);
    long recv_some(char* buf, size_t n);
    bool exchange(const std::string& req, ClientResponse& resp, std::string& error);

    Url url_;
    ClientTlsOptions tls_opt_;
    int timeout_ms_;
    socket_t fd_ = kInvalidSocket;
    std::unique_ptr<TlsContext> ctx_;
    std::unique_ptr<TlsConn> tls_;
    std::string fingerprint_;
    size_t max_response_ = 64u << 20;
};

// Скачать по ссылке (GET) с переходами по redirect (не с https на http). Понимает ответы частями (chunked).
bool http_get(const std::string& url, const ClientTlsOptions& tls, int timeout_ms, ClientResponse& resp,
              std::string& error, size_t max_bytes = 64u << 20, int max_redirects = 3);

}  // namespace sentinel::net
