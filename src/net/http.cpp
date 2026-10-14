#include "net/http.hpp"

#include "core/json.hpp"
#include "core/util.hpp"

namespace sentinel::net {

std::string_view HttpRequest::header(std::string_view name) const {
    for (auto& h : headers)
        if (h.first == name) return h.second;
    return {};
}

std::string_view HttpRequest::param(std::string_view name) const {
    for (auto& p : query)
        if (p.first == name) return p.second;
    return {};
}

bool HttpRequest::has_param(std::string_view name) const {
    for (auto& p : query)
        if (p.first == name) return true;
    return false;
}

void HttpResponse::error(int code, std::string_view message) {
    status = code;
    content_type = "application/json; charset=utf-8";
    body.clear();
    JsonWriter w(body);
    w.begin_object().kv("error", message).kv("status", code).end_object();
}

const char* status_text(int code) {
    switch (code) {
        case 100: return "Continue";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 411: return "Length Required";
        case 413: return "Payload Too Large";
        case 415: return "Unsupported Media Type";
        case 429: return "Too Many Requests";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 503: return "Service Unavailable";
        default: return "Unknown";
    }
}

std::string url_decode_component(std::string_view s, bool plus_as_space) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '%' && i + 2 < s.size()) {
            auto hv = [](char h) {
                return (h >= '0' && h <= '9') ? h - '0'
                       : (h >= 'a' && h <= 'f') ? h - 'a' + 10
                       : (h >= 'A' && h <= 'F') ? h - 'A' + 10
                                                : -1;
            };
            int a = hv(s[i + 1]), b = hv(s[i + 2]);
            if (a >= 0 && b >= 0) {
                out.push_back(char(a * 16 + b));
                i += 2;
                continue;
            }
        }
        out.push_back(plus_as_space && c == '+' ? ' ' : c);
    }
    return out;
}

ParseResult parse_request(std::string_view buf, const ParseLimits& lim, HttpRequest& req, size_t& consumed,
                          int& err_status, bool& expects_continue, bool& headers_done) {
    expects_continue = false;
    headers_done = false;
    size_t hend = buf.find("\r\n\r\n");
    if (hend == std::string_view::npos) {
        if (buf.size() > lim.max_header_bytes) {
            err_status = 431;
            return ParseResult::Error;
        }
        return ParseResult::Incomplete;
    }
    if (hend > lim.max_header_bytes) {
        err_status = 431;
        return ParseResult::Error;
    }
    req = HttpRequest{};
    std::string_view head = buf.substr(0, hend);
    size_t line_end = head.find("\r\n");
    std::string_view rl = head.substr(0, line_end);
    size_t sp1 = rl.find(' ');
    size_t sp2 = sp1 == std::string_view::npos ? std::string_view::npos : rl.find(' ', sp1 + 1);
    if (sp1 == std::string_view::npos || sp2 == std::string_view::npos) {
        err_status = 400;
        return ParseResult::Error;
    }
    req.method.assign(rl.substr(0, sp1));
    req.target.assign(rl.substr(sp1 + 1, sp2 - sp1 - 1));
    std::string_view version = rl.substr(sp2 + 1);
    if (version != "HTTP/1.1" && version != "HTTP/1.0") {
        err_status = 400;
        return ParseResult::Error;
    }
    req.keep_alive = version == "HTTP/1.1";
    if (req.target.empty() || req.target[0] != '/') {
        err_status = 400;
        return ParseResult::Error;
    }

    size_t content_length = 0;
    bool has_length = false;
    size_t pos = line_end == std::string_view::npos ? head.size() : line_end + 2;
    while (pos < head.size()) {
        size_t e = head.find("\r\n", pos);
        if (e == std::string_view::npos) e = head.size();
        std::string_view line = head.substr(pos, e - pos);
        pos = e + 2;
        size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0) {
            err_status = 400;
            return ParseResult::Error;
        }
        std::string name = to_lower(trim(line.substr(0, colon)));
        std::string value(trim(line.substr(colon + 1)));
        if (name == "content-length") {
            auto n = parse_uint(value);
            if (!n || (has_length && *n != content_length)) {
                err_status = 400;
                return ParseResult::Error;
            }
            content_length = size_t(*n);
            has_length = true;
        } else if (name == "transfer-encoding") {
            if (!iequals(value, "identity")) {
                err_status = 501;  // chunked не поддерживается: агенты шлют Content-Length
                return ParseResult::Error;
            }
        } else if (name == "connection") {
            if (iequals(value, "close")) req.keep_alive = false;
            else if (iequals(value, "keep-alive")) req.keep_alive = true;
        } else if (name == "expect") {
            if (iequals(value, "100-continue")) expects_continue = true;
        }
        req.headers.emplace_back(std::move(name), std::move(value));
    }
    if (content_length > lim.max_body_bytes) {
        err_status = 413;
        return ParseResult::Error;
    }
    headers_done = true;
    size_t total = hend + 4 + content_length;
    if (buf.size() < total) return ParseResult::Incomplete;
    req.body.assign(buf.substr(hend + 4, content_length));
    consumed = total;

    // путь и параметры
    std::string_view t = req.target;
    size_t q = t.find('?');
    req.path = url_decode_component(t.substr(0, q), false);
    if (q != std::string_view::npos) {
        for (auto part : split(t.substr(q + 1), '&')) {
            if (part.empty()) continue;
            size_t eq = part.find('=');
            std::string k = url_decode_component(part.substr(0, eq), true);
            std::string v = eq == std::string_view::npos ? std::string() : url_decode_component(part.substr(eq + 1), true);
            req.query.emplace_back(std::move(k), std::move(v));
        }
    }
    return ParseResult::Complete;
}

void serialize_response(const HttpResponse& resp, bool keep_alive, std::string& out) {
    out += "HTTP/1.1 ";
    out += std::to_string(resp.status);
    out += ' ';
    out += status_text(resp.status);
    out += "\r\nContent-Type: ";
    out += resp.content_type;
    out += "\r\nContent-Length: ";
    out += std::to_string(resp.file.empty() ? uint64_t(resp.body.size()) : resp.file_size);
    out += "\r\nX-Content-Type-Options: nosniff\r\n";
    bool has_cache = false;
    for (auto& h : resp.headers)
        if (iequals(h.first, "Cache-Control")) has_cache = true;
    if (!has_cache) out += "Cache-Control: no-store\r\n";
    out += keep_alive ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
    for (auto& h : resp.headers) {
        out += h.first;
        out += ": ";
        out += h.second;
        out += "\r\n";
    }
    out += "\r\n";
    if (resp.file.empty()) out += resp.body;
}

}  // namespace sentinel::net
