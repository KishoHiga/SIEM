// SentinelCore — тонкая переносимая обёртка над сокетами и ожиданием событий.
// Linux: epoll. macOS/BSD: poll. Windows: WSAPoll.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

namespace sentinel::net {

#ifdef _WIN32
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
#endif

bool init();  // WSAStartup на Windows, игнор SIGPIPE на POSIX
void close_socket(socket_t s);
bool set_nonblocking(socket_t s);
void set_nodelay(socket_t s);
int last_error();
bool would_block(int err);
bool interrupted(int err);
std::string error_text(int err);

// Открыть слушающий TCP-сокет. host: "127.0.0.1", "0.0.0.0", "::"
socket_t listen_tcp(const std::string& host, uint16_t port, std::string& error);
// Пара связанных сокетов для пробуждения потоков.
bool make_wake_pair(socket_t& read_end, socket_t& write_end);
std::string peer_address(socket_t s);
// Все адреса имени (IPv4 и IPv6) в текстовом виде; пусто — не удалось.
std::vector<std::string> resolve_host(const std::string& host);

// Подключение (для клиента/тестов): блокирующее.
socket_t connect_tcp(const std::string& host, uint16_t port, std::string& error);
// То же с ограничением времени на установку соединения; возвращает блокирующий сокет
// с таймаутами чтения/записи timeout_ms.
socket_t connect_tcp_timeout(const std::string& host, uint16_t port, int timeout_ms, std::string& error);
// Отправить всё / прочитать сколько есть (блокирующие помощники).
bool send_all(socket_t s, const char* data, size_t n);
long recv_some(socket_t s, char* buf, size_t n);

struct PollEvent {
    socket_t fd;
    bool readable;
    bool writable;
    bool error;
};

class Poller {
public:
    static std::unique_ptr<Poller> create();
    virtual ~Poller() = default;
    virtual bool add(socket_t fd, bool want_write) = 0;
    virtual bool modify(socket_t fd, bool want_write) = 0;
    virtual void remove(socket_t fd) = 0;
    virtual int wait(int timeout_ms, std::vector<PollEvent>& out) = 0;
};

}  // namespace sentinel::net
