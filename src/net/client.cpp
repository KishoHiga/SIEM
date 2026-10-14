#include "net/client.hpp"

#include <cstdlib>

#include "core/util.hpp"

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/time.h>
#endif

namespace sentinel::net {

bool parse_url(const std::string& s, Url& out, std::string& error) {
    out = Url{};
    std::string_view v = s;
    if (starts_with(v, "https://")) {
        out.https = true;
        v.remove_prefix(8);
    } else if (starts_with(v, "http://")) {
        v.remove_prefix(7);
    } else {
        error = "URL must start with http:// or https://";
        return false;
    }
    size_t slash = v.find('/');
    std::string_view hostport = v.substr(0, slash);
    if (slash != std::string_view::npos) out.path = std::string(v.substr(slash));
    while (!out.path.empty() && out.path.back() == '/') out.path.pop_back();
    if (!hostport.empty() && hostport[0] == '[') {  // [IPv6]:port
        size_t close = hostport.find(']');
        if (close == std::string_view::npos) {
            error = "bad IPv6 address in URL";
            return false;
        }
        out.host = std::string(hostport.substr(1, close - 1));
        hostport.remove_prefix(close + 1);
        if (starts_with(hostport, ":")) {
            auto p = parse_uint(hostport.substr(1));
            if (!p || *p > 65535) {
                error = "bad port in URL";
                return false;
            }
            out.port = uint16_t(*p);
        }
    } else {
        size_t colon = hostport.rfind(':');
        out.host = std::string(hostport.substr(0, colon));
        if (colon != std::string_view::npos) {
            auto p = parse_uint(hostport.substr(colon + 1));
            if (!p || *p > 65535) {
                error = "bad port in URL";
                return false;
            }
            out.port = uint16_t(*p);
        }
    }
    if (out.host.empty()) {
        error = "URL has no host";
        return false;
    }
    if (out.port == 0) out.port = out.https ? 443 : 80;
    return true;
}

std::string ClientResponse::header(const std::string& name) const {
    for (auto& h : headers)
        if (h.first == name) return h.second;
    return "";
}

HttpClient::HttpClient(Url url, ClientTlsOptions tls, int timeout_ms)
    : url_(std::move(url)), tls_opt_(std::move(tls)), timeout_ms_(timeout_ms) {
    init();
}

HttpClient::~HttpClient() { close(); }

void HttpClient::close() {
    if (tls_) {
        tls_->shutdown();
        tls_.reset();
    }
    if (fd_ != kInvalidSocket) {
        close_socket(fd_);
        fd_ = kInvalidSocket;
    }
}

bool HttpClient::connect(std::string& error) {
    close();
    fd_ = connect_tcp_timeout(url_.host, url_.port, timeout_ms_, error);
    if (fd_ == kInvalidSocket) return false;
    set_nodelay(fd_);
    if (url_.https) {
        if (!ctx_) {
            ctx_ = TlsContext::client(tls_opt_, error);
            if (!ctx_) {
                close();
                return false;
            }
        }
        tls_ = TlsConn::create(*ctx_, fd_, url_.host);
        if (!tls_) {
            error = "cannot create TLS connection";
            close();
            return false;
        }
        TlsConn::Io io = tls_->handshake();
        if (io != TlsConn::Io::Ok) {
            error = "TLS handshake with " + url_.host + " failed: " + tls_->last_error();
            close();
            return false;
        }
        fingerprint_ = tls_->peer_fingerprint();
        if (!tls_->verify_pin(error)) {
            close();
            return false;
        }
    }
    return true;
}

bool HttpClient::send_all(const char* data, size_t n) {
    if (!tls_) return net::send_all(fd_, data, n);
    while (n > 0) {
        size_t w = 0;
        if (tls_->write(data, n, w) != TlsConn::Io::Ok) return false;
        data += w;
        n -= w;
    }
    return true;
}

long HttpClient::recv_some(char* buf, size_t n) {
    if (!tls_) return net::recv_some(fd_, buf, n);
    size_t got = 0;
    TlsConn::Io io = tls_->read(buf, n, got);
    if (io == TlsConn::Io::Ok) return long(got);
    if (io == TlsConn::Io::Closed) return 0;
    return -1;
}

bool HttpClient::exchange(const std::string& req, ClientResponse& resp, std::string& error) {
    if (!send_all(req.data(), req.size())) {
        error = "send failed";
        return false;
    }
    std::string buf;
    char tmp[16384];
    size_t header_end = std::string::npos;
    size_t content_length = 0;
    while (true) {
        if (header_end == std::string::npos) {
            header_end = buf.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                resp = ClientResponse{};
                std::string_view head(buf.data(), header_end);
                size_t le = head.find("\r\n");
                std::string_view status_line = head.substr(0, le);
                if (status_line.size() < 12 || !starts_with(status_line, "HTTP/1.")) {
                    error = "bad HTTP response";
                    return false;
                }
                resp.status = int(parse_int(status_line.substr(9, 3)).value_or(0));
                size_t pos = le == std::string_view::npos ? head.size() : le + 2;
                while (pos < head.size()) {
                    size_t e = head.find("\r\n", pos);
                    if (e == std::string_view::npos) e = head.size();
                    std::string_view line = head.substr(pos, e - pos);
                    pos = e + 2;
                    size_t c = line.find(':');
                    if (c == std::string_view::npos) continue;
                    resp.headers.emplace_back(to_lower(trim(line.substr(0, c))), std::string(trim(line.substr(c + 1))));
                }
                content_length = size_t(parse_uint(resp.header("content-length")).value_or(0));
                if (resp.status == 100) {  // промежуточный ответ — ждём настоящий
                    buf.erase(0, header_end + 4);
                    header_end = std::string::npos;
                    continue;
                }
            }
        }
        if (header_end != std::string::npos) {
            const bool chunked = to_lower(resp.header("transfer-encoding")).find("chunked") != std::string::npos;
            const bool has_len = !resp.header("content-length").empty();
            if (chunked) {
                // тело частями: <размер в hex>\r\n<данные>\r\n ... 0\r\n\r\n
                std::string body;
                size_t pos = header_end + 4;
                bool done = false, bad = false;
                while (true) {
                    size_t le = buf.find("\r\n", pos);
                    if (le == std::string::npos) break;
                    std::string_view sz(buf.data() + pos, le - pos);
                    if (size_t semi = sz.find(';'); semi != std::string_view::npos) sz = sz.substr(0, semi);
                    sz = trim(sz);
                    uint64_t n = 0;
                    if (sz.empty() || sz.size() > 15) {
                        bad = true;
                        break;
                    }
                    for (char c : sz) {
                        int d = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
                        if (d < 0) {
                            bad = true;
                            break;
                        }
                        n = n * 16 + uint64_t(d);
                    }
                    if (bad) break;
                    if (n == 0) {  // последняя часть, за ней необязательные trailer-строки и пустая строка
                        done = buf.find("\r\n\r\n", le) != std::string::npos;
                        break;
                    }
                    if (buf.size() < le + 2 + n + 2) break;  // часть ещё не пришла целиком
                    body.append(buf, le + 2, size_t(n));
                    pos = le + 2 + size_t(n) + 2;
                }
                if (bad) {
                    error = "bad chunked response";
                    return false;
                }
                if (done) {
                    resp.body = std::move(body);
                    if (iequals(resp.header("connection"), "close")) close();
                    return true;
                }
            } else if (has_len || resp.status == 204 || resp.status == 304 || resp.status / 100 == 1) {
                if (buf.size() >= header_end + 4 + content_length) {
                    resp.body = buf.substr(header_end + 4, content_length);
                    if (iequals(resp.header("connection"), "close")) close();
                    return true;
                }
            }
        }
        long n = recv_some(tmp, sizeof(tmp));
        if (n == 0 && header_end != std::string::npos && resp.header("content-length").empty() &&
            to_lower(resp.header("transfer-encoding")).find("chunked") == std::string::npos) {
            resp.body = buf.substr(header_end + 4);  // тело до закрытия соединения
            close();
            return true;
        }
        if (n <= 0) {
            error = n == 0 ? "connection closed by server" : "receive failed or timed out";
            return false;
        }
        buf.append(tmp, size_t(n));
        if (buf.size() > max_response_) {
            error = "response too large";
            return false;
        }
    }
}

bool HttpClient::request(const std::string& method, const std::string& path,
                         const std::vector<std::pair<std::string, std::string>>& headers, const std::string& body,
                         ClientResponse& resp, std::string& error) {
    std::string req = method + " " + url_.path + path + " HTTP/1.1\r\nHost: " + url_.host + "\r\n";
    for (auto& h : headers) req += h.first + ": " + h.second + "\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
    req += body;
    // Если старое соединение оборвалось сервером — одна повторная попытка с новым.
    for (int attempt = 0; attempt < 2; ++attempt) {
        bool fresh = false;
        if (fd_ == kInvalidSocket) {
            if (!connect(error)) return false;
            fresh = true;
        }
        if (exchange(req, resp, error)) return true;
        close();
        if (fresh) return false;
    }
    return false;
}

}  // namespace sentinel::net

namespace sentinel::net {

bool http_get(const std::string& url, const ClientTlsOptions& tls, int timeout_ms, ClientResponse& resp,
              std::string& error, size_t max_bytes, int max_redirects) {
    std::string cur = url;
    for (int hop = 0; hop <= max_redirects; ++hop) {
        Url u;
        if (!parse_url(cur, u, error)) return false;
        std::string path = u.path.empty() ? "/" : u.path;
        // parse_url отрезает завершающий '/', а для запроса нужен исходный путь
        if (size_t p = cur.find("://"); p != std::string::npos) {
            size_t slash = cur.find('/', p + 3);
            path = slash == std::string::npos ? "/" : cur.substr(slash);
        }
        u.path.clear();
        if (u.https && !tls_available()) {
            error = "https:// requires a build with OpenSSL";
            return false;
        }
        HttpClient c(u, tls, timeout_ms);
        c.set_max_response(max_bytes);
        if (!c.request("GET", path, {{"User-Agent", "SentinelCore"}, {"Accept", "*/*"}, {"Connection", "close"}}, "", resp,
                       error))
            return false;
        if (resp.status == 301 || resp.status == 302 || resp.status == 303 || resp.status == 307 || resp.status == 308) {
            std::string loc = resp.header("location");
            if (loc.empty()) return true;
            if (starts_with(loc, "/")) {
                std::string base = cur.substr(0, cur.find('/', cur.find("://") + 3));
                loc = base + loc;
            } else if (!starts_with(loc, "http://") && !starts_with(loc, "https://")) {
                error = "unsupported redirect: " + loc;
                return false;
            }
            if (starts_with(cur, "https://") && starts_with(loc, "http://")) {
                error = "refusing redirect from https to http";
                return false;
            }
            cur = loc;
            continue;
        }
        return true;
    }
    error = "too many redirects";
    return false;
}

}  // namespace sentinel::net
