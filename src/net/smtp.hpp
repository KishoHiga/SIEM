// SentinelCore — собственный SMTP-клиент для отправки уведомлений на почту.
// Поддерживает STARTTLS (порт 587), сразу TLS (порт 465), вход AUTH PLAIN / LOGIN.
// Письмо — текст (и, если задан, HTML) в UTF-8 (тема и тело в base64, поэтому русский текст доходит без искажений).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "net/tls.hpp"

namespace sentinel::net {

struct SmtpOptions {
    std::string host;
    uint16_t port = 587;
    std::string tls = "auto";  // auto | starttls | tls | none
    std::string username, password;
    ClientTlsOptions tls_opt;
    int timeout_ms = 15000;
    std::string helo = "sentinel.local";
};

struct SmtpMessage {
    std::string from;
    std::vector<std::string> to;
    std::string subject;
    std::string body;  // обычный текст UTF-8
    std::string html;  // если задан — письмо из двух частей: текст и HTML (почта покажет HTML)
};

bool smtp_send(const SmtpOptions& opt, const SmtpMessage& msg, std::string& error);

// Письмо целиком (заголовки + тело) — отдельно, чтобы проверять тестами.
std::string build_mime_message(const SmtpMessage& msg, int64_t now_ms, const std::string& message_id);
// "=?UTF-8?B?...?=" с разбиением длинной темы на части по 45 байт (не разрывая символы UTF-8).
std::string encode_header_utf8(const std::string& text);
// Дата в формате писем: "Mon, 12 Oct 2026 20:21:00 +0000"
std::string rfc5322_date(int64_t now_ms);

}  // namespace sentinel::net
