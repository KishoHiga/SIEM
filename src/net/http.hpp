// SentinelCore — собственный HTTP/1.1: разбор запросов и сборка ответов.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sentinel::net {

struct HttpRequest {
    std::string method;
    std::string target;  // как пришло: /path?query
    std::string path;    // раскодированный путь без query
    std::vector<std::pair<std::string, std::string>> query;
    std::vector<std::pair<std::string, std::string>> headers;  // имена в нижнем регистре
    std::string body;
    std::string remote_addr;
    bool keep_alive = true;
    bool tls = false;  // запрос пришёл по HTTPS

    std::string_view header(std::string_view name) const;  // name в нижнем регистре
    std::string_view param(std::string_view name) const;
    bool has_param(std::string_view name) const;
};

struct HttpResponse {
    int status = 200;
    std::string content_type = "application/json; charset=utf-8";
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    bool close = false;
    // Тело из файла (большие выгрузки): сервер отдаёт его частями, не читая целиком в память.
    std::string file;
    uint64_t file_size = 0;
    bool file_remove = false;  // удалить файл после отправки (временный)

    void send_file(std::string path, uint64_t size, bool remove_after) {
        file = std::move(path);
        file_size = size;
        file_remove = remove_after;
        body.clear();
    }

    void json(int code, std::string b) {
        status = code;
        content_type = "application/json; charset=utf-8";
        body = std::move(b);
    }
    void error(int code, std::string_view message);
};

const char* status_text(int code);

enum class ParseResult { Incomplete, Complete, Error };

struct ParseLimits {
    size_t max_header_bytes = 32 * 1024;
    size_t max_body_bytes = 32 * 1024 * 1024;
};

// Пытается разобрать запрос из начала buf. При Complete consumed — сколько байт занял.
// Error: err_status — код ответа (400/413/431/501).
ParseResult parse_request(std::string_view buf, const ParseLimits& lim, HttpRequest& req, size_t& consumed,
                          int& err_status, bool& expects_continue, bool& headers_done);

void serialize_response(const HttpResponse& resp, bool keep_alive, std::string& out);

std::string url_decode_component(std::string_view s, bool plus_as_space);

}  // namespace sentinel::net
