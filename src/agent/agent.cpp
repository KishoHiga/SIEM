#include "agent/agent.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "agent/discover.hpp"
#include "core/json.hpp"
#include "core/log.hpp"
#include "core/util.hpp"
#include "net/socket.hpp"

#ifndef _WIN32
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace sentinel::agent {

const char* kAgentVersion = "0.6.1";

static const char* os_name() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#else
    return "linux";
#endif
}

int local_utc_offset_minutes() {
    std::time_t t = std::time(nullptr);
    std::tm lt{}, gt{};
#ifdef _WIN32
    localtime_s(&lt, &t);
    gmtime_s(&gt, &t);
#else
    localtime_r(&t, &lt);
    gmtime_r(&t, &gt);
#endif
    gt.tm_isdst = lt.tm_isdst;
    std::time_t as_local = std::mktime(&gt);
    return int(std::difftime(t, as_local) / 60);
}

bool convert_macos_log_line(std::string& line) {
    // "2026-10-12 18:01:02.123456+0300  localhost sshd[123]: msg"
    if (line.size() < 20 || !is_digit(line[0]) || line[4] != '-' || line[10] != ' ') return false;
    line[10] = 'T';
    size_t sp = line.find(' ', 11);
    if (sp == std::string::npos) return false;
    size_t e = sp;
    while (e < line.size() && line[e] == ' ') ++e;
    line.replace(sp, e - sp, " ");
    return true;
}

// ---------------- Источник-команда (journalctl, log stream) ----------------

struct Agent::CommandSource {
    SourceSpec spec;
    std::thread th;
    std::mutex mu;
    std::deque<std::string> lines;
    size_t bytes = 0;
    uint64_t dropped = 0;
    std::atomic<bool> stop{false};
#ifndef _WIN32
    pid_t pid = -1;
#endif
    static constexpr size_t kMaxBuffered = 64u << 20;

    void push(std::string line) {
        std::lock_guard<std::mutex> lock(mu);
        bytes += line.size();
        lines.push_back(std::move(line));
        while (bytes > kMaxBuffered && !lines.empty()) {  // сервер долго недоступен — старое выбрасываем
            bytes -= lines.front().size();
            lines.pop_front();
            ++dropped;
        }
    }

    void loop() {
#ifdef _WIN32
        log::warn("agent: command sources are not supported on Windows: ", spec.path);
#else
        while (!stop.load()) {
            int fds[2];
            if (pipe(fds) != 0) return;
            pid_t p = fork();
            if (p == 0) {
                dup2(fds[1], 1);
                ::close(fds[0]);
                ::close(fds[1]);
                execl("/bin/sh", "sh", "-c", spec.path.c_str(), static_cast<char*>(nullptr));
                _exit(127);
            }
            ::close(fds[1]);
            if (p < 0) {
                ::close(fds[0]);
                return;
            }
            {
                std::lock_guard<std::mutex> lock(mu);
                pid = p;
            }
            log::info("agent: started '", spec.path, "'");
            std::FILE* f = fdopen(fds[0], "r");
            std::string line;
            char buf[8192];
            while (f && std::fgets(buf, sizeof(buf), f)) {
                line += buf;
                if (line.empty() || line.back() != '\n') {
                    if (line.size() > 256 * 1024) line.clear();
                    continue;
                }
                line.pop_back();
                if (!line.empty() && line.back() == '\r') line.pop_back();
                bool keep = !line.empty() && !starts_with(line, "-- ");
                if (keep && spec.format == "macos_log") keep = convert_macos_log_line(line);
                if (keep) push(std::move(line));
                line.clear();
            }
            if (f) std::fclose(f);
            int status = 0;
            waitpid(p, &status, 0);
            {
                std::lock_guard<std::mutex> lock(mu);
                pid = -1;
            }
            if (stop.load()) break;
            log::warn("agent: command exited, restarting in 5 s: ", spec.path);
            for (int i = 0; i < 50 && !stop.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
#endif
    }

    void start() {
        th = std::thread([this] { loop(); });
    }

    void shutdown() {
        stop.store(true);
#ifndef _WIN32
        {
            std::lock_guard<std::mutex> lock(mu);
            if (pid > 0) kill(pid, SIGTERM);
        }
#endif
        if (th.joinable()) th.join();
    }
};

// ---------------- Агент ----------------

Agent::Agent(AgentConfig cfg) : cfg_(std::move(cfg)) {}

Agent::~Agent() { shutdown(); }

void Agent::shutdown() {
    for (auto& c : commands_) c->shutdown();
    commands_.clear();
    if (state_dirty_) save_state();
}

bool Agent::init(std::string& error) {
    if (cfg_.server.empty() || cfg_.key.empty()) {
        error = "agent is not connected: run 'sentinel-agent enroll --server URL --token TOKEN' first";
        return false;
    }
    net::Url url;
    if (!net::parse_url(cfg_.server, url, error)) return false;
    net::ClientTlsOptions tls;
    tls.pin_sha256 = cfg_.pin;
    tls.ca_file = cfg_.ca_file;
    tls.insecure = cfg_.insecure;
    if (url.https && !net::tls_available()) {
        error = "server URL is https:// but the agent was built without OpenSSL";
        return false;
    }
    if (!url.https) log::warn("agent: server URL is http:// — logs and the key travel UNENCRYPTED");
    http_ = std::make_unique<net::HttpClient>(url, tls, 30000);
    tz_minutes_ = local_utc_offset_minutes();

    std::error_code ec;
    fs::create_directories(cfg_.state_dir, ec);
    load_state();

    std::vector<std::string> warnings;
    sources_ = effective_sources(cfg_, &warnings);
    for (auto& w : warnings) log::warn("agent: ", w);
    for (auto& s : sources_) {
        if (s.kind == "file") {
            auto f = std::make_unique<FileSource>();
            f->spec = s;
            files_.push_back(std::move(f));
        } else if (s.kind == "command") {
            auto c = std::make_unique<CommandSource>();
            c->spec = s;
            c->start();
            commands_.push_back(std::move(c));
        } else if (s.kind == "windows_event") {
            auto w = std::make_unique<WinSource>();
            w->spec = s;
            w->reader = std::make_unique<WinEventReader>(s.path, saved_bookmarks_[s.path]);
            windows_.push_back(std::move(w));
        }
        log::info("agent: source [", s.source, "] ", s.kind, " ", s.path);
    }
    if (sources_.empty()) log::warn("agent: no log sources found. Add them under 'sources:' in ", cfg_.path);

    std::string fw_err;
    fw_ = Firewall::create(cfg_.firewall, cfg_.state_dir, fw_runner_, fw_err);
    if (!fw_err.empty()) {
        log::error("agent: firewall: ", fw_err);
        fw_status_ = cfg_.firewall.mode + "; error=" + fw_err;
    } else if (fw_) {
        fw_status_ = std::string(fw_->name()) + "; waiting";
        for (auto& a : cfg_.firewall.allowlist)
            if (auto c = parse_cidr(a)) fw_allow_.push_back(*c);
        // Сам SIEM блокировать нельзя: ответы сервера тоже проходят через брандмауэр.
        std::vector<std::string> server_ips = net::resolve_host(url.host);
        if (auto ip = parse_ip(url.host)) server_ips.push_back(format_ip(*ip));
        for (auto& ip : server_ips)
            if (auto c = parse_cidr(ip)) fw_allow_.push_back(*c);
        log::info("agent: firewall ", fw_->name(), " enabled, block list sync every ", cfg_.firewall.sync_seconds, " s");
    }
    return true;
}

std::vector<std::pair<std::string, std::string>> Agent::base_headers() const {
    return {
        {"Authorization", "Bearer " + cfg_.key},
        {"X-Sentinel-Host", cfg_.host},
        {"X-Sentinel-Agent", std::string("sentinel-agent/") + kAgentVersion + " (" + os_name() + ")"},
        {"X-Sentinel-Firewall", fw_status_},
    };
}

static bool overlaps(const Cidr& a, const Cidr& b) {
    if (a.net.v6 != b.net.v6) return false;
    return a.contains(b.net) || b.contains(a.net);
}

bool Agent::sync_blocks(std::string& error) {
    if (!fw_) {
        error = "firewall is not enabled in " + cfg_.path;
        return false;
    }
    last_block_sync_ = now_ms();
    std::string path = "/api/v1/agent/blocks";
    if (blocks_applied_) path += "?version=" + std::to_string(blocks_version_);
    net::ClientResponse resp;
    if (!http_->request("GET", path, base_headers(), "", resp, error)) return false;
    if (resp.status != 200) {
        error = "server answered HTTP " + std::to_string(resp.status);
        return false;
    }
    JValue v;
    std::string perr;
    if (!json_parse(resp.body, v, perr) || !v.is_object()) {
        error = "bad block list from server";
        return false;
    }
    const JValue* changed = v.get("changed");
    const JValue* ver = v.get("version");
    if (changed && changed->is_bool() && !changed->b) return true;
    const JValue* list = v.get("blocks");
    if (!list || !list->is_array()) {
        error = "bad block list from server";
        return false;
    }
    std::vector<Cidr> v4, v6;
    size_t skipped = 0;
    for (auto& item : list->arr) {
        if (!item.is_string()) continue;
        auto c = parse_cidr(item.s);
        if (!c) {
            ++skipped;
            continue;
        }
        bool allowed = false;
        for (auto& a : fw_allow_) allowed |= overlaps(*c, a);
        if (allowed) {
            ++skipped;
            log::debug("agent: firewall: ", item.s, " is in the allowlist, not blocked here");
            continue;
        }
        (c->net.v6 ? v6 : v4).push_back(*c);
    }
    // Убрать подсети, которые уже покрыты более широкими (nft не любит пересекающиеся интервалы)
    auto reduce = [](std::vector<Cidr>& l) {
        std::sort(l.begin(), l.end(), [](const Cidr& a, const Cidr& b) { return a.prefix < b.prefix; });
        std::vector<Cidr> out;
        for (auto& c : l) {
            bool covered = false;
            for (auto& o : out) covered |= o.contains(c.net);
            if (!covered) out.push_back(c);
        }
        l.swap(out);
    };
    reduce(v4);
    reduce(v6);
    std::string ferr;
    if (!fw_->apply(v4, v6, ferr)) {
        fw_status_ = std::string(fw_->name()) + "; error=" + ferr;
        error = "firewall: " + ferr;
        return false;  // версию не запоминаем — применим снова при следующей синхронизации
    }
    bool first = !blocks_applied_;
    blocks_applied_ = true;
    blocks_version_ = ver && ver->is_number() ? uint64_t(ver->i) : 0;
    fw_status_ = std::string(fw_->name()) + "; applied=" + std::to_string(v4.size() + v6.size());
    if (skipped) fw_status_ += "; skipped=" + std::to_string(skipped);
    log::info("agent: firewall ", fw_->name(), first ? " loaded " : " updated: ", v4.size() + v6.size(),
              " blocked addresses");
    return true;
}

bool Agent::firewall_clear(std::string& error) {
    if (!fw_) {
        error = "firewall is not enabled in " + cfg_.path;
        return false;
    }
    if (!fw_->clear(error)) return false;
    blocks_applied_ = false;
    fw_status_ = std::string(fw_->name()) + "; cleared";
    return true;
}

void Agent::load_state() {
    std::ifstream in(cfg_.state_dir + "/state.json", std::ios::binary);
    if (!in) return;
    std::stringstream ss;
    ss << in.rdbuf();
    JValue v;
    std::string err;
    if (!json_parse(ss.str(), v, err)) {
        log::warn("agent: state file is damaged, starting fresh: ", err);
        return;
    }
    if (const JValue* files = v.get("files"); files && files->is_array()) {
        for (auto& f : files->arr) {
            const JValue* p = f.get("path");
            if (!p || !p->is_string()) continue;
            SavedFile s;
            if (auto* d = f.get("dev")) s.dev = uint64_t(d->i);
            if (auto* i = f.get("ino")) s.ino = uint64_t(i->i);
            if (auto* o = f.get("offset")) s.offset = uint64_t(o->i);
            saved_[p->s] = s;
        }
    }
    if (const JValue* w = v.get("windows"); w && w->is_object())
        for (auto& kv : w->obj)
            if (kv.second.is_string()) saved_bookmarks_[kv.first] = kv.second.s;
    first_scan_ = saved_.empty() && saved_bookmarks_.empty();
    // Если состояние есть, файлы без записи (появились, пока агент был выключен) читаем с начала.
}

void Agent::save_state() {
    std::string out;
    JsonWriter w(out);
    w.begin_object().key("files").begin_array();
    for (auto& f : files_) {
        for (auto& kv : f->tailers) {
            FileId id = kv.second->id();
            w.begin_object().kv("path", kv.first).kv("dev", id.dev).kv("ino", id.ino).kv("offset", kv.second->committed());
            w.end_object();
        }
    }
    w.end_array().key("windows").begin_object();
    for (auto& ws : windows_) w.kv(ws->spec.path, ws->reader->committed_bookmark());
    w.end_object().kv("saved_at", format_iso8601(now_ms())).end_object();
    std::string path = cfg_.state_dir + "/state.json", tmp = path + ".tmp";
    {
        std::ofstream o(tmp, std::ios::binary | std::ios::trunc);
        o << out;
        if (!o) {
            log::error("agent: cannot write ", tmp);
            return;
        }
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) {
        fs::remove(path, ec);
        fs::rename(tmp, path, ec);
    }
    state_dirty_ = false;
}

void Agent::rescan(int64_t now) {
    for (auto& fsrc : files_) {
        std::vector<std::string> paths = expand_glob(fsrc->spec.path);
        paths.erase(std::remove_if(paths.begin(), paths.end(),
                                   [&](const std::string& p) {
                                       return ends_with(p, ".gz") ||
                                              std::find(cfg_.exclude.begin(), cfg_.exclude.end(), p) != cfg_.exclude.end();
                                   }),
                    paths.end());
        if (fsrc->spec.format == "nginx" && fsrc->spec.path.find('*') != std::string::npos) {
            // в масках nginx/apache берём только access-логи
            paths.erase(std::remove_if(paths.begin(), paths.end(),
                                       [](const std::string& p) {
                                           return fs::path(p).filename().string().find("access") == std::string::npos;
                                       }),
                        paths.end());
        }
        for (auto& p : paths) {
            FileId id = file_id_of_path(p);
            auto it = fsrc->tailers.find(p);
            if (it == fsrc->tailers.end()) {
                uint64_t offset = 0;
                auto sv = saved_.find(p);
                std::error_code ec;
                uint64_t size = fs::file_size(p, ec);
                if (sv != saved_.end() && sv->second.dev == id.dev && sv->second.ino == id.ino && sv->second.offset <= size) {
                    offset = sv->second.offset;  // продолжаем с того же места
                } else if (first_scan_ && !fsrc->spec.from_beginning && cfg_.start_at != "beginning") {
                    offset = size;  // первый запуск: только новые записи
                }
                auto t = std::make_unique<FileTailer>(p, offset);
                if (!t->open()) {
                    log::warn("agent: cannot open ", p);
                    continue;
                }
                log::info("agent: watching ", p, " from offset ", offset);
                fsrc->tailers.emplace(p, std::move(t));
                state_dirty_ = true;
            } else if (id.valid && it->second->id().valid && id != it->second->id()) {
                // Ротация: старый файл дочитываем, новый читаем с начала
                log::info("agent: rotation detected for ", p);
                fsrc->draining.push_back({std::move(it->second), now + 10000});
                auto t = std::make_unique<FileTailer>(p, 0);
                if (t->open()) it->second = std::move(t);
                else fsrc->tailers.erase(it);
                state_dirty_ = true;
            }
        }
        // Файлы, которые исчезли под старым именем
        for (auto it = fsrc->tailers.begin(); it != fsrc->tailers.end();) {
            if (std::find(paths.begin(), paths.end(), it->first) == paths.end()) {
                fsrc->draining.push_back({std::move(it->second), now + 10000});
                it = fsrc->tailers.erase(it);
                state_dirty_ = true;
            } else {
                ++it;
            }
        }
    }
    first_scan_ = false;
}

bool Agent::send_lines(const SourceSpec& spec, const std::vector<std::string>& lines, bool json_array) {
    if (lines.empty()) return true;
    std::string body;
    size_t total = 0;
    for (auto& l : lines) total += l.size() + 1;
    body.reserve(total + 2);
    if (json_array) body.push_back('[');
    for (size_t i = 0; i < lines.size(); ++i) {
        if (json_array && i) body.push_back(',');
        body += lines[i];
        if (!json_array) body.push_back('\n');
    }
    if (json_array) body.push_back(']');

    std::string format = spec.format == "macos_log" ? "syslog" : spec.format;
    std::vector<std::pair<std::string, std::string>> headers = base_headers();
    headers.insert(headers.end(), {
                                      {"Content-Type", json_array ? "application/json" : "text/plain"},
                                      {"X-Sentinel-Source", spec.source},
                                      {"X-Sentinel-Format", format},
                                      {"X-Sentinel-TZ", std::to_string(tz_minutes_)},
                                  });
    net::ClientResponse resp;
    std::string err;
    auto fail = [&](const std::string& why, int64_t min_backoff) {
        ++stats_.send_errors;
        stats_.last_error = why;
        backoff_ms_ = std::clamp<int64_t>(backoff_ms_ ? backoff_ms_ * 2 : 1000, min_backoff, 60000);
        backoff_until_ = now_ms() + backoff_ms_;
        log::warn("agent: send failed (", why, "), retry in ", backoff_ms_ / 1000, " s");
        return false;
    };
    if (!http_->request("POST", "/api/v1/ingest", headers, body, resp, err)) return fail(err, 1000);
    if (resp.status == 202) {
        backoff_ms_ = 0;
        stats_.lines_sent += lines.size();
        stats_.bytes_sent += body.size();
        ++stats_.batches;
        return true;
    }
    if (resp.status == 401 || resp.status == 403)
        return fail("server rejected the agent key (HTTP " + std::to_string(resp.status) + "), re-enroll the agent", 60000);
    if (resp.status == 400 || resp.status == 413) {
        // Данные не принимаются в принципе — повторять бессмысленно, пропускаем пакет
        log::error("agent: server refused a batch from ", spec.source, " (HTTP ", resp.status, "): ", resp.body);
        ++stats_.send_errors;
        return true;
    }
    return fail("HTTP " + std::to_string(resp.status), resp.status == 429 ? 30000 : 1000);
}

bool Agent::drain_tailer(FileSource& fsrc, FileTailer& t, size_t& sent) {
    for (int rounds = 0; rounds < 64; ++rounds) {
        std::vector<std::string> lines;
        size_t n = t.read_lines(lines, cfg_.batch_bytes);
        if (lines.empty()) return true;
        if (!send_lines(fsrc.spec, lines, false)) {
            t.rewind();
            return false;
        }
        t.commit(t.pending_offset());
        state_dirty_ = true;
        sent += lines.size();
        if (n < cfg_.batch_bytes) return true;
    }
    return true;
}

size_t Agent::step() {
    const int64_t now = now_ms();
    if (now < backoff_until_) return 0;
    const int64_t sync_ms = int64_t(cfg_.firewall.sync_seconds) * 1000;
    if (fw_ && now - last_block_sync_ >= sync_ms) {
        std::string err, before = fw_status_;
        if (!sync_blocks(err) && now - last_block_warn_ >= 60000) {
            last_block_warn_ = now;
            log::warn("agent: block list sync failed: ", err);
        }
        // Новое состояние брандмауэра сообщаем серверу почти сразу, а не через sync_seconds
        if (fw_status_ != before) last_block_sync_ = now - sync_ms + 1000;
    }
    if (now - last_rescan_ >= 2000 || first_scan_) {
        rescan(now);
        last_rescan_ = now;
    }
    size_t sent = 0;
    for (auto& fsrc : files_) {
        for (auto it = fsrc->draining.begin(); it != fsrc->draining.end();) {
            if (!drain_tailer(*fsrc, *it->t, sent)) return sent;
            if (now > it->until) it = fsrc->draining.erase(it);
            else ++it;
        }
        for (auto& kv : fsrc->tailers)
            if (!drain_tailer(*fsrc, *kv.second, sent)) return sent;
    }
    for (auto& c : commands_) {
        std::vector<std::string> batch;
        size_t bytes = 0;
        {
            std::lock_guard<std::mutex> lock(c->mu);
            while (!c->lines.empty() && bytes < cfg_.batch_bytes) {
                bytes += c->lines.front().size();
                batch.push_back(std::move(c->lines.front()));
                c->lines.pop_front();
            }
            c->bytes -= bytes;
            stats_.dropped = c->dropped;
        }
        if (batch.empty()) continue;
        if (!send_lines(c->spec, batch, false)) {
            std::lock_guard<std::mutex> lock(c->mu);  // вернуть в начало очереди
            for (auto it = batch.rbegin(); it != batch.rend(); ++it) {
                c->bytes += it->size();
                c->lines.push_front(std::move(*it));
            }
            return sent;
        }
        sent += batch.size();
    }
    for (auto& w : windows_) {
        std::vector<std::string> events;
        std::string err;
        if (!w->reader->read(events, 2000, err)) {
            log::warn("agent: windows event log: ", err);
            continue;
        }
        if (!events.empty() && !send_lines(w->spec, events, true)) {
            w->reader->rewind();
            return sent;
        }
        if (w->reader->pending_bookmark() != w->reader->committed_bookmark()) {
            w->reader->commit();
            state_dirty_ = true;
        }
        sent += events.size();
    }
    if (state_dirty_ && now - last_save_ >= 2000) {
        save_state();
        last_save_ = now;
    }
    if (now - last_report_ >= 60000) {
        last_report_ = now;
        log::info("agent: sent ", stats_.lines_sent, " lines in ", stats_.batches, " batches, errors ",
                  stats_.send_errors, stats_.dropped ? ", dropped " + std::to_string(stats_.dropped) : "");
    }
    return sent;
}

void Agent::run(const std::atomic<bool>& stop) {
    last_report_ = now_ms();
    while (!stop.load()) {
        size_t n = step();
        if (n == 0) {
            // нечего отправлять (или ждём сервер) — короткая пауза
            for (int i = 0; i < cfg_.scan_ms / 50 && !stop.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    save_state();
}

bool Agent::test_connection(std::string& info, std::string& error) {
    net::ClientResponse resp;
    if (!http_->request("GET", "/api/v1/whoami", {{"Authorization", "Bearer " + cfg_.key}}, "", resp, error))
        return false;
    if (resp.status != 200) {
        error = "server answered HTTP " + std::to_string(resp.status) + ": " + resp.body;
        return false;
    }
    info = resp.body;
    if (!http_->server_fingerprint().empty()) info += "  (server certificate " + http_->server_fingerprint() + ")";
    return true;
}

bool Agent::enroll(AgentConfig& cfg, const std::string& token, std::string& error, std::string& info) {
    net::Url url;
    if (!net::parse_url(cfg.server, url, error)) return false;
    if (url.https && !net::tls_available()) {
        error = "https:// requires an agent built with OpenSSL";
        return false;
    }
    net::ClientTlsOptions tls;
    tls.pin_sha256 = cfg.pin;
    tls.ca_file = cfg.ca_file;
    tls.insecure = cfg.insecure;
    net::HttpClient http(url, tls, 30000);
    std::string body;
    JsonWriter(body).begin_object().kv("token", token).kv("host", cfg.host).kv("os", os_name()).kv("agent", kAgentVersion).end_object();
    net::ClientResponse resp;
    if (!http.request("POST", "/api/v1/enroll", {{"Content-Type", "application/json"}}, body, resp, error)) {
        if (url.https && cfg.pin.empty() && cfg.ca_file.empty())
            error += ". If the server uses a self-signed certificate, pass --pin sha256:... "
                     "(printed by 'sentinel-server enroll-token')";
        return false;
    }
    if (resp.status != 201) {
        JValue v;
        std::string perr;
        std::string msg = resp.body;
        if (json_parse(resp.body, v, perr) && v.get("error")) msg = v.get("error")->s;
        error = "enroll failed (HTTP " + std::to_string(resp.status) + "): " + msg;
        return false;
    }
    JValue v;
    std::string perr;
    if (!json_parse(resp.body, v, perr) || !v.get("key") || !v.get("key")->is_string()) {
        error = "bad answer from server";
        return false;
    }
    cfg.key = v.get("key")->s;
    if (!save_agent_config(cfg, error)) return false;
    info = v.get("name") ? v.get("name")->s : "";
    return true;
}

}  // namespace sentinel::agent
