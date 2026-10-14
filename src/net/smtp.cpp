#include "net/smtp.hpp"

#include <algorithm>
#include <cstdio>
#include <memory>

#include "core/crypto.hpp"
#include "core/util.hpp"
#include "net/socket.hpp"

namespace sentinel::net {

namespace {

bool is_ascii_printable(const std::string& s) {
    for (unsigned char c : s)
        if (c < 0x20 || c > 0x7E) return false;
    return true;
}

std::string b64(std::string_view s) { return base64_encode(reinterpret_cast<const uint8_t*>(s.data()), s.size()); }

// Соединение: обычный сокет, при необходимости — поверх TLS.
class Conn {
public:
    ~Conn() {
        if (tls_) tls_->shutdown();
        tls_.reset();
        close_socket(fd_);
    }

    bool connect(const SmtpOptions& o, std::string& err) {
        fd_ = connect_tcp_timeout(o.host, o.port, o.timeout_ms, err);
        return fd_ != kInvalidSocket;
    }

    bool start_tls(const SmtpOptions& o, std::string& err) {
        ctx_ = TlsContext::client(o.tls_opt, err);
        if (!ctx_) return false;
        tls_ = TlsConn::create(*ctx_, fd_, o.host);
        if (!tls_) {
            err = "cannot create TLS connection";
            return false;
        }
        if (tls_->handshake() != TlsConn::Io::Ok) {
            err = "TLS handshake with " + o.host + " failed: " + tls_->last_error();
            return false;
        }
        if (!tls_->verify_pin(err)) return false;
        buf_.clear();
        return true;
    }

    bool send(const std::string& s) {
        if (!tls_) return send_all(fd_, s.data(), s.size());
        size_t off = 0;
        while (off < s.size()) {
            size_t w = 0;
            if (tls_->write(s.data() + off, s.size() - off, w) != TlsConn::Io::Ok) return false;
            off += w;
        }
        return true;
    }

    // Ответ сервера: код и все строки текста (многострочный ответ "250-...").
    bool reply(int& code, std::string& text, std::string& err) {
        text.clear();
        while (true) {
            size_t nl;
            while ((nl = buf_.find("\r\n")) == std::string::npos) {
                if (buf_.size() > 64 * 1024) {
                    err = "SMTP reply too long";
                    return false;
                }
                char tmp[4096];
                long n;
                if (tls_) {
                    size_t got = 0;
                    TlsConn::Io io = tls_->read(tmp, sizeof(tmp), got);
                    n = io == TlsConn::Io::Ok ? long(got) : (io == TlsConn::Io::Closed ? 0 : -1);
                } else {
                    n = recv_some(fd_, tmp, sizeof(tmp));
                }
                if (n <= 0) {
                    err = n == 0 ? "SMTP server closed the connection" : "SMTP server did not answer (timeout)";
                    return false;
                }
                buf_.append(tmp, size_t(n));
            }
            std::string line = buf_.substr(0, nl);
            buf_.erase(0, nl + 2);
            if (line.size() < 3 || !is_digit(line[0]) || !is_digit(line[1]) || !is_digit(line[2])) {
                err = "bad SMTP reply: " + line.substr(0, 100);
                return false;
            }
            code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
            if (!text.empty()) text += "\n";
            text += line.size() > 4 ? line.substr(4) : "";
            if (line.size() == 3 || line[3] == ' ') return true;
        }
    }

    // Команда и ожидаемый класс ответа (2 = 2xx, 3 = 3xx).
    bool cmd(const std::string& line, int expect_class, std::string& text, std::string& err,
             const std::string& shown = "") {
        if (!send(line + "\r\n")) {
            err = "SMTP send failed";
            return false;
        }
        int code = 0;
        if (!reply(code, text, err)) return false;
        if (code / 100 != expect_class) {
            std::string what = shown.empty() ? line.substr(0, line.find(' ')) : shown;
            err = "SMTP " + what + " rejected: " + std::to_string(code) + " " + text.substr(0, 200);
            return false;
        }
        return true;
    }

private:
    socket_t fd_ = kInvalidSocket;
    std::unique_ptr<TlsContext> ctx_;
    std::unique_ptr<TlsConn> tls_;
    std::string buf_;
};

bool has_cap(const std::string& ehlo, const std::string& cap) {
    for (auto line : split(ehlo, '\n')) {
        line = trim(line);
        if (iequals(line.substr(0, cap.size()), cap) && (line.size() == cap.size() || line[cap.size()] == ' ' || line[cap.size()] == '='))
            return true;
    }
    return false;
}

bool auth_supports(const std::string& ehlo, const std::string& mech) {
    for (auto line : split(ehlo, '\n')) {
        line = trim(line);
        if (!iequals(line.substr(0, 5), "AUTH ") && !iequals(line.substr(0, 5), "AUTH=")) continue;
        for (auto m : split(line.substr(5), ' '))
            if (iequals(trim(m), mech)) return true;
    }
    return false;
}

}  // namespace

std::string encode_header_utf8(const std::string& text) {
    if (is_ascii_printable(text) && text.size() <= 70) return text;
    std::string out;
    size_t i = 0;
    while (i < text.size()) {
        size_t end = std::min(text.size(), i + 45);
        // не разрывать многобайтный символ UTF-8
        while (end < text.size() && end > i && (uint8_t(text[end]) & 0xC0) == 0x80) --end;
        if (!out.empty()) out += "\r\n ";
        out += "=?UTF-8?B?" + b64(std::string_view(text).substr(i, end - i)) + "?=";
        i = end;
    }
    return out;
}

std::string rfc5322_date(int64_t now_ms) {
    static const char* wd[] = {"Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"};  // 1970-01-01 — четверг
    static const char* mn[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    int64_t secs = now_ms / 1000;
    int64_t days = secs / 86400;
    int64_t rem = secs % 86400;
    int64_t y;
    unsigned m, d;
    civil_from_days(days, y, m, d);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s, %02u %s %04lld %02d:%02d:%02d +0000", wd[days % 7], d, mn[m - 1], (long long)y,
                  int(rem / 3600), int(rem / 60 % 60), int(rem % 60));
    return buf;
}

std::string build_mime_message(const SmtpMessage& msg, int64_t now_ms, const std::string& message_id) {
    std::string to;
    for (auto& t : msg.to) {
        if (!to.empty()) to += ", ";
        to += t;
    }
    std::string m;
    m += "From: SentinelCore <" + msg.from + ">\r\n";
    m += "To: " + to + "\r\n";
    m += "Subject: " + encode_header_utf8(msg.subject) + "\r\n";
    m += "Date: " + rfc5322_date(now_ms) + "\r\n";
    m += "Message-ID: <" + message_id + ">\r\n";
    m += "MIME-Version: 1.0\r\n";
    // части в base64 по 76 символов: в них нет строк, начинающихся с ".", и нет 8-битных символов
    auto part = [](const std::string& text) {
        std::string normalized, out;
        for (size_t i = 0; i < text.size(); ++i) {
            if (text[i] == '\n' && (i == 0 || text[i - 1] != '\r')) normalized += "\r\n";
            else normalized.push_back(text[i]);
        }
        std::string enc = b64(normalized);
        for (size_t i = 0; i < enc.size(); i += 76) out += enc.substr(i, 76) + "\r\n";
        return out;
    };
    if (msg.html.empty()) {
        m += "Content-Type: text/plain; charset=UTF-8\r\n";
        m += "Content-Transfer-Encoding: base64\r\n";
        m += "X-Mailer: SentinelCore\r\n\r\n";
        m += part(msg.body);
        return m;
    }
    // граница не может встретиться внутри частей: они в base64 (там нет "=_")
    const std::string boundary = "=_sentinel_" + message_id.substr(0, std::min<size_t>(message_id.find('@'), 32));
    m += "Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n";
    m += "X-Mailer: SentinelCore\r\n\r\n";
    m += "--" + boundary + "\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n";
    m += part(msg.body);
    m += "--" + boundary + "\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n";
    m += part(msg.html);
    m += "--" + boundary + "--\r\n";
    return m;
}

bool smtp_send(const SmtpOptions& o, const SmtpMessage& msg, std::string& error) {
    auto bad = [](const std::string& s) { return s.find_first_of("\r\n<>") != std::string::npos || s.empty(); };
    if (bad(msg.from) || msg.to.empty()) {
        error = "bad sender or no recipients";
        return false;
    }
    for (auto& t : msg.to)
        if (bad(t)) {
            error = "bad recipient address";
            return false;
        }
    if (o.username.find_first_of("\r\n") != std::string::npos || o.password.find_first_of("\r\n") != std::string::npos) {
        error = "bad SMTP credentials";
        return false;
    }
    std::string mode = o.tls;
    if (mode == "auto") mode = o.port == 465 ? "tls" : "starttls";
    if ((mode == "tls" || mode == "starttls") && !tls_available()) {
        error = "SMTP over TLS needs a build with OpenSSL";
        return false;
    }

    Conn c;
    if (!c.connect(o, error)) return false;
    if (mode == "tls" && !c.start_tls(o, error)) return false;
    int code = 0;
    std::string text;
    if (!c.reply(code, text, error)) return false;
    if (code != 220) {
        error = "SMTP server refused the connection: " + std::to_string(code) + " " + text.substr(0, 200);
        return false;
    }
    std::string ehlo;
    if (!c.cmd("EHLO " + o.helo, 2, ehlo, error)) return false;
    if (mode == "starttls") {
        if (!has_cap(ehlo, "STARTTLS")) {
            error = "SMTP server does not support STARTTLS (set tls: none only for a trusted local relay)";
            return false;
        }
        if (!c.cmd("STARTTLS", 2, text, error)) return false;
        if (!c.start_tls(o, error)) return false;
        if (!c.cmd("EHLO " + o.helo, 2, ehlo, error)) return false;
    }
    if (!o.username.empty()) {
        if (auth_supports(ehlo, "PLAIN") || !auth_supports(ehlo, "LOGIN")) {
            std::string cred = std::string(1, '\0') + o.username + std::string(1, '\0') + o.password;
            if (!c.cmd("AUTH PLAIN " + b64(cred), 2, text, error, "AUTH")) return false;
        } else {
            if (!c.cmd("AUTH LOGIN", 3, text, error)) return false;
            if (!c.cmd(b64(o.username), 3, text, error, "AUTH user")) return false;
            if (!c.cmd(b64(o.password), 2, text, error, "AUTH")) return false;
        }
    }
    if (!c.cmd("MAIL FROM:<" + msg.from + ">", 2, text, error)) return false;
    for (auto& t : msg.to)
        if (!c.cmd("RCPT TO:<" + t + ">", 2, text, error)) return false;
    if (!c.cmd("DATA", 3, text, error)) return false;
    std::string id = random_hex(12) + "@sentinel";
    std::string body = build_mime_message(msg, now_ms(), id) + ".";
    if (!c.cmd(body, 2, text, error, "message")) return false;
    c.cmd("QUIT", 2, text, error);
    error.clear();
    return true;
}

}  // namespace sentinel::net
