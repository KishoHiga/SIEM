// SentinelCore — многопоточный HTTP-сервер на событиях (без сторонних библиотек).
//
// Один поток принимает соединения и раздаёт их рабочим потокам по кругу.
// Каждый рабочий поток ведёт свои соединения в цикле epoll/poll: читает,
// разбирает запросы (с поддержкой keep-alive и конвейера), вызывает обработчик,
// отправляет ответ. Простаивающие соединения закрываются по таймауту.
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "net/http.hpp"
#include "net/socket.hpp"
#include "net/tls.hpp"

namespace sentinel::net {

// WebSocket (RFC 6455): сервер только рассылает сообщения подписчикам (живая лента панели).
struct WsOptions {
    std::string path;                                 // например "/ws/live"; пусто — выключено
    std::function<bool(const HttpRequest&)> accept;   // проверка доступа при подключении
    int ping_interval_ms = 25000;
};

struct ServerOptions {
    std::string host = "127.0.0.1";
    uint16_t port = 8080;
    int workers = 4;
    size_t max_body_bytes = 32 * 1024 * 1024;
    int idle_timeout_ms = 60000;
    size_t max_connections_per_worker = 10000;
    std::shared_ptr<TlsContext> tls;  // если задан — сервер принимает только HTTPS
    WsOptions ws;
};

using Handler = std::function<void(const HttpRequest&, HttpResponse&)>;

class HttpServer {
public:
    HttpServer(ServerOptions opt, Handler handler);
    ~HttpServer();

    bool start(std::string& error);
    void stop();
    uint16_t port() const { return bound_port_; }

    // Разослать текстовое сообщение всем WebSocket-подписчикам (потокобезопасно).
    void broadcast(const std::string& text);
    size_t ws_clients() const { return ws_clients_.load(); }

private:
    struct Worker;
    void accept_loop();

    ServerOptions opt_;
    Handler handler_;
    socket_t listen_ = kInvalidSocket;
    uint16_t bound_port_ = 0;
    std::atomic<bool> running_{false};
    std::atomic<size_t> ws_clients_{0};
    std::thread acceptor_;
    std::vector<std::unique_ptr<Worker>> workers_;
    std::mutex workers_mu_;  // broadcast() из других потоков против stop()
};

}  // namespace sentinel::net
