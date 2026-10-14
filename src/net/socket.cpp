#include "net/socket.hpp"

#include <cstdlib>
#include <cstring>
#include <unordered_map>

#ifdef _WIN32
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#else
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#ifdef __linux__
#include <sys/epoll.h>
#endif

namespace sentinel::net {

bool init() {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#else
    std::signal(SIGPIPE, SIG_IGN);
    return true;
#endif
}

void close_socket(socket_t s) {
    if (s == kInvalidSocket) return;
#ifdef _WIN32
    closesocket(s);
#else
    ::close(s);
#endif
}

bool set_nonblocking(socket_t s) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(s, F_GETFL, 0);
    return flags >= 0 && fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

void set_nodelay(socket_t s) {
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
}

int last_error() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

bool would_block(int err) {
#ifdef _WIN32
    return err == WSAEWOULDBLOCK;
#else
    return err == EAGAIN || err == EWOULDBLOCK;
#endif
}

bool interrupted(int err) {
#ifdef _WIN32
    return err == WSAEINTR;
#else
    return err == EINTR;
#endif
}

std::string error_text(int err) {
#ifdef _WIN32
    return "socket error " + std::to_string(err);
#else
    return std::strerror(err);
#endif
}

socket_t listen_tcp(const std::string& host, uint16_t port, std::string& error) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    addrinfo* res = nullptr;
    std::string port_s = std::to_string(port);
    int rc = getaddrinfo(host.empty() ? nullptr : host.c_str(), port_s.c_str(), &hints, &res);
    if (rc != 0 || !res) {
        error = "cannot resolve listen address " + host;
        return kInvalidSocket;
    }
    socket_t s = kInvalidSocket;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == kInvalidSocket) continue;
        int one = 1;
#ifdef _WIN32
        setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&one), sizeof(one));
#else
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif
        if (::bind(s, ai->ai_addr, socklen_t(ai->ai_addrlen)) == 0 && ::listen(s, 1024) == 0) break;
        error = "cannot listen on " + host + ":" + port_s + ": " + error_text(last_error());
        close_socket(s);
        s = kInvalidSocket;
    }
    freeaddrinfo(res);
    return s;
}

socket_t connect_tcp(const std::string& host, uint16_t port, std::string& error) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    std::string port_s = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res) != 0 || !res) {
        error = "cannot resolve " + host;
        return kInvalidSocket;
    }
    socket_t s = kInvalidSocket;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == kInvalidSocket) continue;
        if (::connect(s, ai->ai_addr, socklen_t(ai->ai_addrlen)) == 0) break;
        close_socket(s);
        s = kInvalidSocket;
    }
    freeaddrinfo(res);
    if (s == kInvalidSocket) error = "cannot connect to " + host + ":" + port_s;
    return s;
}

static bool set_blocking(socket_t s) {
#ifdef _WIN32
    u_long mode = 0;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(s, F_GETFL, 0);
    return flags >= 0 && fcntl(s, F_SETFL, flags & ~O_NONBLOCK) == 0;
#endif
}

socket_t connect_tcp_timeout(const std::string& host, uint16_t port, int timeout_ms, std::string& error) {
    init();
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    std::string port_s = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res) != 0 || !res) {
        error = "cannot resolve " + host;
        return kInvalidSocket;
    }
    socket_t s = kInvalidSocket;
    error = "cannot connect to " + host + ":" + port_s;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == kInvalidSocket) continue;
        set_nonblocking(s);
        int rc = ::connect(s, ai->ai_addr, socklen_t(ai->ai_addrlen));
        bool ok = rc == 0;
        if (!ok) {
            int e = last_error();
#ifdef _WIN32
            bool pending = e == WSAEWOULDBLOCK || e == WSAEINPROGRESS;
#else
            bool pending = e == EINPROGRESS || e == EINTR;
#endif
            if (pending) {
                fd_set wr, ex;
                FD_ZERO(&wr);
                FD_ZERO(&ex);
                FD_SET(s, &wr);
                FD_SET(s, &ex);
                timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
                int n = ::select(int(s + 1), nullptr, &wr, &ex, &tv);
                if (n > 0 && FD_ISSET(s, &wr)) {
                    int so = 0;
                    socklen_t len = sizeof(so);
                    getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so), &len);
                    ok = so == 0;
                    if (!ok) error = "cannot connect to " + host + ":" + port_s + ": " + error_text(so);
                } else if (n == 0) {
                    error = "connection to " + host + ":" + port_s + " timed out";
                }
            } else {
                error = "cannot connect to " + host + ":" + port_s + ": " + error_text(e);
            }
        }
        if (ok) {
            set_blocking(s);
#ifdef _WIN32
            DWORD tv = DWORD(timeout_ms);
#else
            timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
#endif
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
            break;
        }
        close_socket(s);
        s = kInvalidSocket;
    }
    freeaddrinfo(res);
    if (s != kInvalidSocket) error.clear();
    return s;
}

bool send_all(socket_t s, const char* data, size_t n) {
    while (n > 0) {
#ifdef _WIN32
        int k = ::send(s, data, int(n > 1 << 30 ? 1 << 30 : n), 0);
#else
        ssize_t k = ::send(s, data, n, 0);
#endif
        if (k < 0) {
            if (interrupted(last_error())) continue;
            return false;
        }
        data += k;
        n -= size_t(k);
    }
    return true;
}

long recv_some(socket_t s, char* buf, size_t n) {
#ifdef _WIN32
    return ::recv(s, buf, int(n), 0);
#else
    return long(::recv(s, buf, n, 0));
#endif
}

bool make_wake_pair(socket_t& r, socket_t& w) {
#ifdef _WIN32
    // На Windows нет socketpair: соединяем два TCP-сокета через loopback.
    std::string err;
    socket_t l = listen_tcp("127.0.0.1", 0, err);
    if (l == kInvalidSocket) return false;
    sockaddr_in addr{};
    int len = sizeof(addr);
    getsockname(l, reinterpret_cast<sockaddr*>(&addr), &len);
    w = ::socket(AF_INET, SOCK_STREAM, 0);
    if (::connect(w, reinterpret_cast<sockaddr*>(&addr), len) != 0) {
        close_socket(l);
        return false;
    }
    r = ::accept(l, nullptr, nullptr);
    close_socket(l);
    if (r == kInvalidSocket) return false;
    set_nonblocking(r);
    set_nonblocking(w);
    return true;
#else
    int fds[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return false;
    r = fds[0];
    w = fds[1];
    set_nonblocking(r);
    set_nonblocking(w);
    return true;
#endif
}

std::vector<std::string> resolve_host(const std::string& host) {
    std::vector<std::string> out;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return out;
    for (addrinfo* p = res; p; p = p->ai_next) {
        char buf[INET6_ADDRSTRLEN] = {};
        if (p->ai_family == AF_INET)
            inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(p->ai_addr)->sin_addr, buf, sizeof(buf));
        else if (p->ai_family == AF_INET6)
            inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(p->ai_addr)->sin6_addr, buf, sizeof(buf));
        else
            continue;
        std::string a = buf;
        bool dup = false;
        for (auto& x : out) dup |= x == a;
        if (!a.empty() && !dup) out.push_back(a);
    }
    freeaddrinfo(res);
    return out;
}

std::string peer_address(socket_t s) {
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (getpeername(s, reinterpret_cast<sockaddr*>(&ss), &len) != 0) return "";
    char buf[INET6_ADDRSTRLEN] = {};
    if (ss.ss_family == AF_INET) {
        auto* a = reinterpret_cast<sockaddr_in*>(&ss);
        inet_ntop(AF_INET, &a->sin_addr, buf, sizeof(buf));
    } else if (ss.ss_family == AF_INET6) {
        auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
        inet_ntop(AF_INET6, &a->sin6_addr, buf, sizeof(buf));
    } else {
        return "local";
    }
    return buf;
}

// ---------------- Poller ----------------

namespace {

#ifdef __linux__
class EpollPoller : public Poller {
public:
    EpollPoller() { ep_ = epoll_create1(EPOLL_CLOEXEC); }
    ~EpollPoller() override {
        if (ep_ >= 0) ::close(ep_);
    }
    bool add(socket_t fd, bool want_write) override { return ctl(EPOLL_CTL_ADD, fd, want_write); }
    bool modify(socket_t fd, bool want_write) override { return ctl(EPOLL_CTL_MOD, fd, want_write); }
    void remove(socket_t fd) override { epoll_ctl(ep_, EPOLL_CTL_DEL, fd, nullptr); }
    int wait(int timeout_ms, std::vector<PollEvent>& out) override {
        out.clear();
        epoll_event evs[256];
        int n = epoll_wait(ep_, evs, 256, timeout_ms);
        for (int i = 0; i < n; ++i) {
            PollEvent pe;
            pe.fd = evs[i].data.fd;
            pe.readable = evs[i].events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP);
            pe.writable = evs[i].events & EPOLLOUT;
            pe.error = evs[i].events & EPOLLERR;
            out.push_back(pe);
        }
        return n;
    }

private:
    bool ctl(int op, socket_t fd, bool want_write) {
        epoll_event ev{};
        ev.events = uint32_t(EPOLLIN | EPOLLRDHUP) | (want_write ? uint32_t(EPOLLOUT) : 0u);
        ev.data.fd = fd;
        return epoll_ctl(ep_, op, fd, &ev) == 0;
    }
    int ep_ = -1;
};
#endif

class PollPoller : public Poller {
public:
    bool add(socket_t fd, bool want_write) override {
        if (index_.count(fd)) return false;
#ifdef _WIN32
        WSAPOLLFD p{};
#else
        pollfd p{};
#endif
        p.fd = fd;
        p.events = short(POLLIN | (want_write ? POLLOUT : 0));
        index_[fd] = fds_.size();
        fds_.push_back(p);
        return true;
    }
    bool modify(socket_t fd, bool want_write) override {
        auto it = index_.find(fd);
        if (it == index_.end()) return false;
        fds_[it->second].events = short(POLLIN | (want_write ? POLLOUT : 0));
        return true;
    }
    void remove(socket_t fd) override {
        auto it = index_.find(fd);
        if (it == index_.end()) return;
        size_t i = it->second;
        index_.erase(it);
        if (i != fds_.size() - 1) {
            fds_[i] = fds_.back();
            index_[fds_[i].fd] = i;
        }
        fds_.pop_back();
    }
    int wait(int timeout_ms, std::vector<PollEvent>& out) override {
        out.clear();
        if (fds_.empty()) return 0;
#ifdef _WIN32
        int n = WSAPoll(fds_.data(), ULONG(fds_.size()), timeout_ms);
#else
        int n = ::poll(fds_.data(), nfds_t(fds_.size()), timeout_ms);
#endif
        if (n <= 0) return n;
        for (auto& p : fds_) {
            if (!p.revents) continue;
            PollEvent pe;
            pe.fd = p.fd;
            pe.readable = p.revents & (POLLIN | POLLHUP);
            pe.writable = p.revents & POLLOUT;
            pe.error = p.revents & (POLLERR | POLLNVAL);
            out.push_back(pe);
        }
        return int(out.size());
    }

private:
#ifdef _WIN32
    std::vector<WSAPOLLFD> fds_;
#else
    std::vector<pollfd> fds_;
#endif
    std::unordered_map<socket_t, size_t> index_;
};

}  // namespace

std::unique_ptr<Poller> Poller::create() {
#ifdef __linux__
    // SENTINEL_POLLER=poll — принудительно poll() (для проверки ветки macOS на Linux)
    const char* force = std::getenv("SENTINEL_POLLER");
    if (force && std::strcmp(force, "poll") == 0) return std::make_unique<PollPoller>();
    return std::make_unique<EpollPoller>();
#else
    return std::make_unique<PollPoller>();
#endif
}

}  // namespace sentinel::net
