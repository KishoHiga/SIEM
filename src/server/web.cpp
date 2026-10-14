#include "server/web.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

#include "core/util.hpp"

namespace fs = std::filesystem;

namespace sentinel {

static const char* mime_type(const std::string& ext) {
    static const struct {
        const char* ext;
        const char* type;
    } types[] = {
        {".html", "text/html; charset=utf-8"}, {".js", "text/javascript; charset=utf-8"},
        {".mjs", "text/javascript; charset=utf-8"}, {".css", "text/css; charset=utf-8"},
        {".json", "application/json"}, {".svg", "image/svg+xml"}, {".png", "image/png"},
        {".jpg", "image/jpeg"}, {".ico", "image/x-icon"}, {".woff2", "font/woff2"},
        {".woff", "font/woff"}, {".txt", "text/plain; charset=utf-8"}, {".map", "application/json"},
    };
    for (auto& t : types)
        if (ext == t.ext) return t.type;
    return "application/octet-stream";
}

bool WebFiles::available() const {
    std::error_code ec;
    return !dir_.empty() && fs::is_regular_file(fs::path(dir_) / "index.html", ec);
}

void WebFiles::security_headers(const net::HttpRequest& req, net::HttpResponse& resp) {
    std::string host(req.header("host"));
    for (char c : host)
        if (!(is_alpha(c) || is_digit(c) || c == '.' || c == ':' || c == '-' || c == '[' || c == ']')) {
            host.clear();
            break;
        }
    std::string connect = "'self'";
    if (!host.empty()) connect += " wss://" + host + " ws://" + host;
    resp.headers.emplace_back("Content-Security-Policy",
                              "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                              "img-src 'self' data:; font-src 'self' data:; connect-src " + connect +
                                  "; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'");
    resp.headers.emplace_back("X-Frame-Options", "DENY");
    resp.headers.emplace_back("Referrer-Policy", "no-referrer");
    if (req.tls) resp.headers.emplace_back("Strict-Transport-Security", "max-age=31536000");
}

bool WebFiles::serve(const net::HttpRequest& req, net::HttpResponse& resp) const {
    if (req.method != "GET" || !available()) return false;
    std::string rel = req.path;
    // защита от выхода за каталог: никаких "..", "\\" и нулевых байтов
    if (rel.find("..") != std::string::npos || rel.find('\\') != std::string::npos ||
        rel.find('\0') != std::string::npos)
        return resp.error(400, "bad path"), true;
    if (rel.empty() || rel == "/") rel = "/index.html";
    fs::path p = fs::path(dir_) / rel.substr(1);
    std::error_code ec;
    bool is_file = fs::is_regular_file(p, ec);
    std::string ext = p.extension().string();
    if (!is_file) {
        // «файл» с расширением, которого нет, — 404; но /ip/1.2.3.4 и подобные маршруты панели — это не файлы
        bool spa_route = starts_with(rel, "/ip/") || starts_with(rel, "/rules/") || starts_with(rel, "/incidents/");
        if (!ext.empty() && ext != ".html" && !spa_route) {
            resp.error(404, "not found");
            return true;
        }
        p = fs::path(dir_) / "index.html";  // маршруты SPA (/alerts, /events/...) отдаёт сама панель
        ext = ".html";
    }
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        resp.error(404, "not found");
        return true;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    resp.status = 200;
    resp.body = ss.str();
    resp.content_type = mime_type(ext);
    // Файлы сборки с хешем в имени (assets/...) кэшируются надолго, index.html — нет
    if (starts_with(rel, "/assets/")) resp.headers.emplace_back("Cache-Control", "public, max-age=31536000, immutable");
    if (ext == ".html") security_headers(req, resp);
    return true;
}

}  // namespace sentinel
