#include "net/server.hpp"

#include <cstdio>

#include <chrono>
#include <mutex>
#include <unordered_map>

#include "core/crypto.hpp"
#include "core/log.hpp"
#include "core/util.hpp"

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace sentinel::net {

namespace {
uint16_t local_port(socket_t s) {
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&ss), &len) != 0) return 0;
    if (ss.ss_family == AF_INET) return ntohs(reinterpret_cast<sockaddr_in*>(&ss)->sin_port);
    if (ss.ss_family == AF_INET6) return ntohs(reinterpret_cast<sockaddr_in6*>(&ss)->sin6_port);
    return 0;
}

// Кадр WebSocket от сервера (без маски).
std::string ws_frame(uint8_t opcode, std::string_view payload) {
    std::string f;
    f.push_back(char(0x80 | opcode));
    size_t n = payload.size();
    if (n < 126) {
        f.push_back(char(n));
    } else if (n <= 0xFFFF) {
        f.push_back(char(126));
        f.push_back(char(n >> 8));
        f.push_back(char(n & 0xFF));
    } else {
        f.push_back(char(127));
        for (int i = 7; i >= 0; --i) f.push_back(char((uint64_t(n) >> (8 * i)) & 0xFF));
    }
    f.append(payload.data(), payload.size());
    return f;
}

int64_t mono_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}
}  // namespace

struct HttpServer::Worker {
    struct Conn {
        socket_t fd = kInvalidSocket;
        std::string in;
        std::string out;
        size_t out_off = 0;
        int64_t last = 0;
        bool close_after = false;
        bool continue_sent = false;
        bool want_write = false;
        bool peer_closed = false;
        bool handshaking = false;
        bool websocket = false;
        int64_t last_ping = 0;
        std::unique_ptr<TlsConn> tls;
        std::string addr;
        // тело ответа из файла: отправляется частями (пока идёт — следующие запросы ждут)
        std::FILE* src = nullptr;
        uint64_t src_left = 0;
        std::string src_path;
        bool src_remove = false;

        void close_src() {
            if (src) std::fclose(src);
            src = nullptr;
            src_left = 0;
            if (src_remove && !src_path.empty()) std::remove(src_path.c_str());
            src_path.clear();
            src_remove = false;
        }
        Conn() = default;
        Conn(const Conn&) = delete;
        Conn& operator=(const Conn&) = delete;
        ~Conn() { close_src(); }
    };
    static constexpr size_t kFileChunk = 256 * 1024;
    static constexpr size_t kMaxWsBacklog = 8u << 20;  // медленный клиент — отключаем

    enum class R { Ok, WaitRead, WaitWrite, Closed, Fail };

    static R from_tls(TlsConn::Io io) {
        switch (io) {
            case TlsConn::Io::Ok: return R::Ok;
            case TlsConn::Io::WantRead: return R::WaitRead;
            case TlsConn::Io::WantWrite: return R::WaitWrite;
            case TlsConn::Io::Closed: return R::Closed;
            default: return R::Fail;
        }
    }

    R do_recv(Conn& c, char* buf, size_t n, size_t& got) {
        got = 0;
        if (c.tls) return from_tls(c.tls->read(buf, n, got));
        while (true) {
            long k = recv_some(c.fd, buf, n);
            if (k > 0) {
                got = size_t(k);
                return R::Ok;
            }
            if (k == 0) return R::Closed;
            int err = last_error();
            if (interrupted(err)) continue;
            return would_block(err) ? R::WaitRead : R::Fail;
        }
    }

    R do_send(Conn& c, const char* data, size_t n, size_t& wrote) {
        wrote = 0;
        if (c.tls) return from_tls(c.tls->write(data, n, wrote));
        while (true) {
#ifdef _WIN32
            int k = ::send(c.fd, data, int(n), 0);
#else
            ssize_t k = ::send(c.fd, data, n, 0);
#endif
            if (k > 0) {
                wrote = size_t(k);
                return R::Ok;
            }
            int err = last_error();
            if (k < 0 && interrupted(err)) continue;
            if (k < 0 && would_block(err)) return R::WaitWrite;
            return R::Fail;
        }
    }

    void want_write(Conn& c, bool on) {
        if (c.want_write != on) {
            poller->modify(c.fd, on);
            c.want_write = on;
        }
    }

    // Продвинуть TLS-рукопожатие. false — соединение закрыто.
    bool advance_handshake(Conn& c) {
        TlsConn::Io io = c.tls->handshake();
        if (io == TlsConn::Io::Ok) {
            c.handshaking = false;
            if (c.out.empty()) want_write(c, false);
            return true;
        }
        if (io == TlsConn::Io::WantRead) {
            want_write(c, false);
            return true;
        }
        if (io == TlsConn::Io::WantWrite) {
            want_write(c, true);
            return true;
        }
        log::debug("tls: handshake failed from ", c.addr, ": ", c.tls->last_error());
        drop(c);
        return false;
    }

    HttpServer* srv = nullptr;
    std::thread th;
    std::unique_ptr<Poller> poller;
    socket_t wake_r = kInvalidSocket, wake_w = kInvalidSocket;
    std::mutex mu;
    std::vector<socket_t> inbox;
    std::vector<std::shared_ptr<const std::string>> ws_out;  // кадры для рассылки
    std::unordered_map<socket_t, std::unique_ptr<Conn>> conns;
    ParseLimits limits;

    ~Worker() {
        close_socket(wake_r);
        close_socket(wake_w);
    }

    void wake() {
        char b = 1;
        ::send(wake_w, &b, 1, 0);
    }

    void push(socket_t fd) {
        {
            std::lock_guard<std::mutex> lock(mu);
            inbox.push_back(fd);
        }
        wake();
    }

    void push_frame(std::shared_ptr<const std::string> frame) {
        {
            std::lock_guard<std::mutex> lock(mu);
            ws_out.push_back(std::move(frame));
        }
        wake();
    }

    void drop(Conn& c) {
        if (c.websocket) srv->ws_clients_.fetch_sub(1);
        poller->remove(c.fd);
        close_socket(c.fd);
        socket_t fd = c.fd;
        conns.erase(fd);  // c больше не валиден
    }

    // Возвращает false, если соединение закрыто.
    bool flush_out(Conn& c) {
        if (c.handshaking) return true;
        while (true) {
            if (c.out_off >= c.out.size()) {
                if (c.src && c.src_left > 0) {
                    // следующая часть файла
                    c.out.clear();
                    c.out_off = 0;
                    size_t want = size_t(std::min<uint64_t>(c.src_left, kFileChunk));
                    c.out.resize(want);
                    size_t got = std::fread(c.out.data(), 1, want, c.src);
                    c.out.resize(got);
                    if (got == 0) {  // файл стал короче — ответ уже не исправить, закрываем
                        c.close_src();
                        drop(c);
                        return false;
                    }
                    c.src_left -= got;
                } else if (c.src) {
                    c.close_src();
                    c.out.clear();
                    c.out_off = 0;
                    if (!c.in.empty() && !c.close_after) process(c);  // запросы, пришедшие следом
                    if (c.out.empty()) break;
                } else {
                    break;
                }
            }
            size_t wrote = 0;
            R r = do_send(c, c.out.data() + c.out_off, c.out.size() - c.out_off, wrote);
            if (r == R::Ok) {
                c.out_off += wrote;
                c.last = mono_ms();
                continue;
            }
            if (r == R::WaitWrite) {
                want_write(c, true);
                return true;
            }
            if (r == R::WaitRead) return true;  // TLS ждёт данных от клиента
            drop(c);
            return false;
        }
        c.out.clear();
        c.out_off = 0;
        want_write(c, false);
        if (c.close_after || c.peer_closed) {
            drop(c);
            return false;
        }
        return true;
    }

    // Разбор кадров от клиента WebSocket: ping -> pong, close -> закрыть, остальное игнорируем.
    void process_ws(Conn& c) {
        while (c.in.size() >= 2 && !c.close_after) {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(c.in.data());
            uint8_t opcode = p[0] & 0x0F;
            bool masked = p[1] & 0x80;
            uint64_t len = p[1] & 0x7F;
            size_t pos = 2;
            if (len == 126) {
                if (c.in.size() < 4) return;
                len = (uint64_t(p[2]) << 8) | p[3];
                pos = 4;
            } else if (len == 127) {
                if (c.in.size() < 10) return;
                len = 0;
                for (int i = 0; i < 8; ++i) len = (len << 8) | p[2 + i];
                pos = 10;
            }
            if (!masked || len > 65536) {  // клиент обязан маскировать; большие кадры не нужны
                c.out += ws_frame(8, std::string("\x03\xEA", 2));  // 1002 protocol error
                c.close_after = true;
                return;
            }
            if (c.in.size() < pos + 4 + len) return;
            const uint8_t* mask = p + pos;
            std::string payload(size_t(len), '\0');
            for (size_t i = 0; i < len; ++i) payload[i] = char(p[pos + 4 + i] ^ mask[i & 3]);
            c.in.erase(0, pos + 4 + size_t(len));
            if (opcode == 8) {  // close
                c.out += ws_frame(8, payload.substr(0, 2));
                c.close_after = true;
            } else if (opcode == 9) {  // ping
                c.out += ws_frame(10, payload);
            }
            // pong (10), текст (1) и прочее — просто отметка активности
        }
    }

    bool try_upgrade(Conn& c, const HttpRequest& req) {
        const WsOptions& ws = srv->opt_.ws;
        if (ws.path.empty() || req.path != ws.path) return false;
        if (!iequals(req.header("upgrade"), "websocket")) return false;
        std::string_view key = req.header("sec-websocket-key");
        HttpResponse resp;
        if (req.method != "GET" || key.empty() || req.header("sec-websocket-version") != "13") {
            resp.error(400, "bad websocket handshake");
        } else if (ws.accept && !ws.accept(req)) {
            resp.error(401, "not authorized");
        } else {
            std::string accept_src = std::string(key) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            auto digest = sha1(accept_src);
            c.out += "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     "Sec-WebSocket-Accept: " + base64_encode(digest.data(), digest.size()) + "\r\n\r\n";
            c.websocket = true;
            c.last_ping = mono_ms();
            srv->ws_clients_.fetch_add(1);
            return true;
        }
        serialize_response(resp, false, c.out);
        c.close_after = true;
        return true;
    }

    void process(Conn& c) {
        if (c.websocket) return process_ws(c);
        while (!c.in.empty() && !c.close_after && !c.src) {
            HttpRequest req;
            size_t consumed = 0;
            int err = 400;
            bool cont = false, headers_done = false;
            ParseResult r = parse_request(c.in, limits, req, consumed, err, cont, headers_done);
            if (r == ParseResult::Incomplete) {
                if (cont && headers_done && !c.continue_sent) {
                    c.out += "HTTP/1.1 100 Continue\r\n\r\n";
                    c.continue_sent = true;
                }
                break;
            }
            HttpResponse resp;
            if (r == ParseResult::Error) {
                resp.error(err, status_text(err));
                serialize_response(resp, false, c.out);
                c.close_after = true;
                c.in.clear();
                break;
            }
            c.in.erase(0, consumed);
            c.continue_sent = false;
            req.remote_addr = c.addr;
            req.tls = c.tls != nullptr;
            if (try_upgrade(c, req)) {
                if (c.websocket) process_ws(c);
                return;
            }
            try {
                srv->handler_(req, resp);
            } catch (const std::exception& e) {
                log::error("http: handler exception: ", e.what());
                resp = HttpResponse{};
                resp.error(500, "internal error");
            }
            bool ka = req.keep_alive && !resp.close;
            if (!resp.file.empty()) {
                std::FILE* f = std::fopen(resp.file.c_str(), "rb");
                if (!f) {
                    if (resp.file_remove) std::remove(resp.file.c_str());
                    HttpResponse e;
                    e.error(500, "cannot open response file");
                    resp = std::move(e);
                } else {
                    c.src = f;
                    c.src_left = resp.file_size;
                    c.src_path = resp.file;
                    c.src_remove = resp.file_remove;
                }
            }
            serialize_response(resp, ka, c.out);
            if (c.src && c.src_left == 0) c.close_src();
            if (!ka) {
                c.close_after = true;
                break;
            }
        }
    }

    void on_read(Conn& c) {
        if (c.handshaking) {
            if (!advance_handshake(c)) return;
            if (c.handshaking) return;
        }
        char buf[64 * 1024];
        const size_t cap = limits.max_header_bytes + limits.max_body_bytes + 4096;
        while (true) {
            size_t got = 0;
            R r = do_recv(c, buf, sizeof(buf), got);
            if (r == R::Ok) {
                c.in.append(buf, got);
                if (c.in.size() > cap) break;  // parse_request вернёт 413/431
                continue;
            }
            if (r == R::WaitRead) break;
            if (r == R::WaitWrite) {
                want_write(c, true);
                break;
            }
            if (r == R::Closed) {
                c.peer_closed = true;
                break;
            }
            drop(c);
            return;
        }
        c.last = mono_ms();
        process(c);
        if (!c.out.empty() || c.peer_closed || c.close_after) flush_out(c);
    }

    void deliver(const std::vector<std::shared_ptr<const std::string>>& frames) {
        std::vector<socket_t> targets;
        for (auto& kv : conns)
            if (kv.second->websocket && !kv.second->close_after) targets.push_back(kv.first);
        for (socket_t fd : targets) {
            auto it = conns.find(fd);
            if (it == conns.end()) continue;
            Conn& c = *it->second;
            for (auto& f : frames) c.out += *f;
            if (c.out.size() - c.out_off > kMaxWsBacklog) {
                drop(c);  // клиент не успевает читать
                continue;
            }
            flush_out(c);
        }
    }

    void run() {
        poller->add(wake_r, false);
        std::vector<PollEvent> evs;
        int64_t last_sweep = mono_ms();
        while (srv->running_.load()) {
            poller->wait(500, evs);
            for (auto& ev : evs) {
                if (ev.fd == wake_r) {
                    char tmp[256];
                    while (recv_some(wake_r, tmp, sizeof(tmp)) > 0) {
                    }
                    std::vector<socket_t> fresh;
                    std::vector<std::shared_ptr<const std::string>> frames;
                    {
                        std::lock_guard<std::mutex> lock(mu);
                        fresh.swap(inbox);
                        frames.swap(ws_out);
                    }
                    if (!frames.empty()) deliver(frames);
                    for (socket_t fd : fresh) {
                        if (conns.size() >= srv->opt_.max_connections_per_worker) {
                            close_socket(fd);
                            continue;
                        }
                        set_nonblocking(fd);
                        set_nodelay(fd);
                        auto c = std::make_unique<Conn>();
                        c->fd = fd;
                        c->last = mono_ms();
                        c->addr = peer_address(fd);
                        if (srv->opt_.tls) {
                            c->tls = TlsConn::create(*srv->opt_.tls, fd, "");
                            c->handshaking = true;
                            if (!c->tls) {
                                close_socket(fd);
                                continue;
                            }
                        }
                        if (!poller->add(fd, false)) {
                            close_socket(fd);
                            continue;
                        }
                        conns.emplace(fd, std::move(c));
                    }
                    continue;
                }
                auto it = conns.find(ev.fd);
                if (it == conns.end()) continue;
                Conn& c = *it->second;
                if (ev.readable || ev.error) {
                    on_read(c);
                    if (!conns.count(ev.fd)) continue;
                }
                if (ev.writable) {
                    if (c.handshaking) {
                        if (advance_handshake(c) && !c.handshaking) on_read(c);
                    } else {
                        flush_out(c);
                    }
                }
            }
            int64_t now = mono_ms();
            if (now - last_sweep >= 1000) {
                last_sweep = now;
                std::vector<socket_t> idle, ping;
                const int64_t ws_ping = srv->opt_.ws.ping_interval_ms;
                for (auto& kv : conns) {
                    Conn& c = *kv.second;
                    if (c.websocket) {
                        if (now - c.last > 3 * ws_ping) idle.push_back(kv.first);
                        else if (now - c.last_ping >= ws_ping) ping.push_back(kv.first);
                    } else if (now - c.last > srv->opt_.idle_timeout_ms) {
                        idle.push_back(kv.first);
                    }
                }
                for (socket_t fd : ping) {
                    auto it = conns.find(fd);
                    if (it == conns.end()) continue;
                    it->second->last_ping = now;
                    it->second->out += ws_frame(9, "");
                    flush_out(*it->second);
                }
                for (socket_t fd : idle) {
                    auto it = conns.find(fd);
                    if (it != conns.end()) drop(*it->second);
                }
            }
        }
        for (auto& kv : conns) close_socket(kv.first);
        conns.clear();
        std::lock_guard<std::mutex> lock(mu);
        for (socket_t fd : inbox) close_socket(fd);
        inbox.clear();
    }
};

HttpServer::HttpServer(ServerOptions opt, Handler handler) : opt_(std::move(opt)), handler_(std::move(handler)) {}

HttpServer::~HttpServer() { stop(); }

bool HttpServer::start(std::string& error) {
    if (!init()) {
        error = "network init failed";
        return false;
    }
    listen_ = listen_tcp(opt_.host, opt_.port, error);
    if (listen_ == kInvalidSocket) return false;
    bound_port_ = local_port(listen_);
    running_.store(true);
    int n = opt_.workers > 0 ? opt_.workers : 1;
    for (int i = 0; i < n; ++i) {
        auto w = std::make_unique<Worker>();
        w->srv = this;
        w->poller = Poller::create();
        w->limits.max_body_bytes = opt_.max_body_bytes;
        if (!make_wake_pair(w->wake_r, w->wake_w)) {
            error = "cannot create wake socket pair";
            stop();
            return false;
        }
        workers_.push_back(std::move(w));
    }
    for (auto& w : workers_) w->th = std::thread([wp = w.get()] { wp->run(); });
    acceptor_ = std::thread([this] { accept_loop(); });
    return true;
}

void HttpServer::accept_loop() {
    auto poller = Poller::create();
    poller->add(listen_, false);
    std::vector<PollEvent> evs;
    size_t rr = 0;
    while (running_.load()) {
        poller->wait(300, evs);
        if (evs.empty()) continue;
        while (running_.load()) {
            set_nonblocking(listen_);
            socket_t fd = ::accept(listen_, nullptr, nullptr);
            if (fd == kInvalidSocket) break;
            workers_[rr++ % workers_.size()]->push(fd);
        }
    }
}

void HttpServer::broadcast(const std::string& text) {
    if (ws_clients_.load() == 0 || !running_.load()) return;
    auto frame = std::make_shared<const std::string>(ws_frame(1, text));
    std::lock_guard<std::mutex> lock(workers_mu_);
    for (auto& w : workers_) w->push_frame(frame);
}

void HttpServer::stop() {
    if (!running_.exchange(false)) {
        if (listen_ != kInvalidSocket) {
            close_socket(listen_);
            listen_ = kInvalidSocket;
        }
        return;
    }
    if (acceptor_.joinable()) acceptor_.join();
    for (auto& w : workers_) w->wake();
    for (auto& w : workers_)
        if (w->th.joinable()) w->th.join();
    std::lock_guard<std::mutex> lock(workers_mu_);
    workers_.clear();
    close_socket(listen_);
    listen_ = kInvalidSocket;
}

}  // namespace sentinel::net
