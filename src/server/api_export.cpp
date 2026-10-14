// SentinelCore — HTTP API: выгрузка событий, алертов и инцидентов файлом (CSV, CSV для Excel, JSON, NDJSON).
//
// Строки пишутся во временный файл data/tmp/… по мере чтения хранилища, а сервер отдаёт файл частями —
// даже выгрузка миллиона событий не держит всё в памяти. Файл удаляется сразу после отправки.
#include <algorithm>
#include <cstdio>
#include <filesystem>

#include "core/crypto.hpp"
#include "core/json.hpp"
#include "core/log.hpp"
#include "core/util.hpp"
#include "server/api.hpp"
#include "server/json_out.hpp"

namespace sentinel {

using net::HttpRequest;
using net::HttpResponse;

namespace {

enum class Fmt { Csv, Excel, Json, Ndjson };

class ExportFile {
public:
    ExportFile(Fmt fmt, std::vector<std::string> columns) : fmt_(fmt), cols_(std::move(columns)) {
        sep_ = fmt == Fmt::Excel ? ';' : ',';
    }
    ~ExportFile() {
        if (f_) std::fclose(f_);
        if (!kept_ && !path_.empty()) std::remove(path_.c_str());
    }
    bool open(const std::string& dir, std::string& error) {
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        path_ = dir + "/export-" + random_hex(8) + ".tmp";
        f_ = std::fopen(path_.c_str(), "wb");
        if (!f_) {
            error = "cannot create " + path_;
            return false;
        }
        std::setvbuf(f_, nullptr, _IOFBF, 1 << 20);
        if (fmt_ == Fmt::Excel) put("\xEF\xBB\xBF");  // BOM: Excel узнаёт UTF-8 и не ломает кириллицу
        if (fmt_ == Fmt::Csv || fmt_ == Fmt::Excel) {
            buf_.clear();
            for (size_t i = 0; i < cols_.size(); ++i) {
                if (i) buf_.push_back(sep_);
                cell(cols_[i]);
            }
            buf_ += "\r\n";
            put(buf_);
        } else if (fmt_ == Fmt::Json) {
            put("[");
        }
        return true;
    }
    bool csv() const { return fmt_ == Fmt::Csv || fmt_ == Fmt::Excel; }

    void csv_row(const std::vector<std::string>& v) {
        buf_.clear();
        for (size_t i = 0; i < v.size(); ++i) {
            if (i) buf_.push_back(sep_);
            cell(v[i]);
        }
        buf_ += "\r\n";
        put(buf_);
        ++rows_;
    }
    // json — один объект
    void json_row(const std::string& obj) {
        if (fmt_ == Fmt::Json) put(rows_ ? ",\n" : "\n");
        put(obj);
        if (fmt_ == Fmt::Ndjson) put("\n");
        ++rows_;
    }
    bool finish(uint64_t& size, std::string& error) {
        if (fmt_ == Fmt::Json) put(rows_ ? "\n]\n" : "]\n");
        bool ok = !failed_ && std::fflush(f_) == 0;
        std::fclose(f_);
        f_ = nullptr;
        if (!ok) {
            error = "cannot write export file (disk full?)";
            return false;
        }
        std::error_code ec;
        size = std::filesystem::file_size(path_, ec);
        if (ec) {
            error = "cannot stat export file";
            return false;
        }
        kept_ = true;
        return true;
    }
    const std::string& path() const { return path_; }
    uint64_t rows() const { return rows_; }

private:
    void put(std::string_view s) {
        if (!failed_ && std::fwrite(s.data(), 1, s.size(), f_) != s.size()) failed_ = true;
    }
    // Ячейка CSV: кавычки при необходимости; формулы (=, +, -, @) обезвреживаются апострофом,
    // чтобы открытая в Excel выгрузка не выполнила чужую «формулу» из лога.
    void cell(std::string_view v) {
        bool formula = v.size() > 1 && (v[0] == '=' || v[0] == '+' || v[0] == '-' || v[0] == '@' || v[0] == '\t' ||
                                        v[0] == '\r');
        if (formula) {
            // числа вида -5 оставляем как есть
            bool number = v.size() > 1 && v[0] == '-' &&
                          std::all_of(v.begin() + 1, v.end(), [](char c) { return (c >= '0' && c <= '9') || c == '.'; });
            if (number) formula = false;
        }
        bool quote = formula || v.find_first_of(std::string_view("\"\r\n,;")) != std::string_view::npos;
        if (!quote) {
            buf_.append(v);
            return;
        }
        buf_.push_back('"');
        if (formula) buf_.push_back('\'');
        for (char c : v) {
            if (c == '"') buf_.push_back('"');
            buf_.push_back(c);
        }
        buf_.push_back('"');
    }

    Fmt fmt_;
    std::vector<std::string> cols_;
    char sep_ = ',';
    std::FILE* f_ = nullptr;
    std::string path_, buf_;
    uint64_t rows_ = 0;
    bool failed_ = false, kept_ = false;
};

// Время в выгрузке: ISO-8601 UTC, а с tz=<минуты> — местное «2026-10-13 18:20:13» (так его понимает Excel).
struct TimeFmt {
    bool local = false;
    int64_t offset_ms = 0;
    std::string operator()(int64_t ms) const {
        if (!ms) return "";
        if (!local) return format_iso8601(ms);
        std::string s = format_iso8601(ms + offset_ms);
        s[10] = ' ';
        return s.substr(0, 19);
    }
};

std::string join(const std::vector<std::string>& v, const char* sep) {
    std::string out;
    for (auto& x : v) {
        if (!out.empty()) out += sep;
        out += x;
    }
    return out;
}

std::string extra_of(const Event& e, std::string_view k) {
    const std::string* v = e.extra_get(k);
    return v ? *v : std::string();
}

std::string field_of(const Alert& a, const char* k) {
    for (auto& kv : a.fields)
        if (kv.first == k) return kv.second;
    return "";
}

}  // namespace

void Api::export_data(std::string_view what, const HttpRequest& req, HttpResponse& resp) {
    std::string fmt_name = to_lower(req.param("format"));
    Fmt fmt = Fmt::Csv;
    if (fmt_name.empty() || fmt_name == "csv") fmt = Fmt::Csv;
    else if (fmt_name == "excel") fmt = Fmt::Excel;
    else if (fmt_name == "json") fmt = Fmt::Json;
    else if (fmt_name == "ndjson") fmt = Fmt::Ndjson;
    else return resp.error(400, "bad format (csv|excel|json|ndjson)");
    if (what != "events" && what != "alerts" && what != "incidents") return resp.error(404, "not found");
    if (what == "incidents" && !incidents_) return resp.error(503, "incidents are not enabled");

    TimeFmt tf;
    if (!req.param("tz").empty()) {
        auto tz = parse_int(req.param("tz"));
        if (!tz || *tz < -24 * 60 || *tz > 24 * 60) return resp.error(400, "bad tz (minutes east of UTC)");
        tf.local = true;
        tf.offset_ms = *tz * 60000;
    }
    const bool raw = req.param("raw") == "1";
    std::string err;
    EventQuery eq;
    AlertQuery aq;
    IncidentQuery iq;
    uint64_t limit = 0;
    // разбор до блокировки — плохой запрос не занимает очередь
    if (what == "events") {
        if (!parse_event_query(req, eq, err)) return resp.error(400, err);
        limit = 100000;
        if (auto l = parse_uint(req.param("limit"))) limit = std::clamp<uint64_t>(*l, 1, 1000000);
    } else if (what == "alerts") {
        if (!parse_alert_query(req, aq, err)) return resp.error(400, err);
        limit = 100000;
        if (auto l = parse_uint(req.param("limit"))) limit = std::clamp<uint64_t>(*l, 1, 1000000);
    } else {
        if (!parse_incident_query(req, iq, err)) return resp.error(400, err);
        limit = 100000;
        if (auto l = parse_uint(req.param("limit"))) limit = std::clamp<uint64_t>(*l, 1, 100000);
    }

    std::unique_lock<std::mutex> lock(export_mu_, std::try_to_lock);
    if (!lock.owns_lock()) {
        resp.headers.emplace_back("Retry-After", "5");
        return resp.error(429, "another export is running, try again in a few seconds");
    }

    static const std::vector<std::string> ev_cols = {
        "id",     "time",       "received",  "source",      "type",        "host",           "process",
        "src_ip", "src_port",   "dst_ip",    "dst_port",    "proto",       "user",           "action",
        "outcome", "http.method", "http.path", "http.status", "http.user_agent", "bytes",      "geo.country",
        "geo.org", "ti.lists",  "message"};
    static const std::vector<std::string> al_cols = {"id",      "created", "time",    "severity", "status",
                                                     "rule_id", "rule_name", "src_ip", "user",     "host",
                                                     "message", "count",   "incident_id", "geo.country", "ti.lists"};
    static const std::vector<std::string> in_cols = {"id",        "title",      "severity",   "status",      "assignee",
                                                     "src_ip",    "user",       "host",       "created",     "first_alert",
                                                     "last_alert", "alert_count", "rules",     "hosts",       "notes",
                                                     "merged_into"};
    std::vector<std::string> cols = what == "events" ? ev_cols : what == "alerts" ? al_cols : in_cols;
    if (what == "events" && raw) cols.push_back("raw");
    ExportFile out(fmt, cols);
    if (!out.open(tmp_dir_, err)) return resp.error(500, err);

    const int64_t started = now_ms();
    bool truncated = false;
    std::string js;
    if (what == "events") {
        eq.limit = size_t(limit) + 1;  // +1 — узнать, что упёрлись в предел
        events_.visit(eq, [&](Event&& e) {
            if (out.rows() >= limit) {
                truncated = true;
                return false;
            }
            if (out.csv()) {
                std::vector<std::string> v = {std::to_string(e.id), tf(e.time()), tf(e.received)};
                for (Field f : {Field::Source, Field::Type, Field::Host, Field::Process, Field::SrcIp, Field::SrcPort,
                                Field::DstIp, Field::DstPort, Field::Proto, Field::User, Field::Action, Field::Outcome,
                                Field::HttpMethod, Field::HttpPath, Field::HttpStatus, Field::HttpUserAgent, Field::Bytes})
                    v.push_back(e[f]);
                v.push_back(extra_of(e, "geo.country"));
                v.push_back(extra_of(e, "geo.org"));
                v.push_back(extra_of(e, "ti.lists"));
                v.push_back(e[Field::Message]);
                if (raw) v.push_back(e[Field::Raw]);
                out.csv_row(v);
            } else {
                if (!raw) e[Field::Raw].clear();
                js.clear();
                JsonWriter w(js);
                write_event(w, e);
                out.json_row(js);
            }
            return true;
        });
    } else if (what == "alerts") {
        aq.limit = size_t(limit) + 1;
        auto list = alerts_.query(aq);
        if (list.size() > limit) {
            truncated = true;
            list.resize(size_t(limit));
        }
        for (auto& a : list) {
            uint64_t inc = incident_of(a.id);
            if (out.csv()) {
                out.csv_row({std::to_string(a.id), tf(a.created), tf(a.ts), severity_name(a.severity),
                             alert_status_name(a.status), a.rule_id, a.rule_name, a.src_ip, a.user, a.host, a.message,
                             std::to_string(a.count), inc ? std::to_string(inc) : "", field_of(a, "geo.country"),
                             field_of(a, "ti.lists")});
            } else {
                js.clear();
                JsonWriter w(js);
                write_alert(w, a, inc);
                out.json_row(js);
            }
        }
    } else {
        iq.limit = size_t(limit) + 1;
        auto list = incidents_->list(iq);
        if (list.size() > limit) {
            truncated = true;
            list.resize(size_t(limit));
        }
        for (auto& i : list) {
            if (out.csv()) {
                std::vector<std::string> rules;
                for (auto& r : i.rules) rules.push_back(r.rule_id + " (" + std::to_string(r.count) + ")");
                out.csv_row({std::to_string(i.id), i.title(), severity_name(i.severity), incident_status_name(i.status),
                             i.assignee, i.src_ip, i.user, i.host, tf(i.created), tf(i.first_alert), tf(i.last_alert),
                             std::to_string(i.alert_count), join(rules, ", "), join(i.hosts, ", "),
                             std::to_string(i.notes.size()), i.merged_into ? std::to_string(i.merged_into) : ""});
            } else {
                js.clear();
                JsonWriter w(js);
                write_incident(w, i, true);
                out.json_row(js);
            }
        }
    }
    uint64_t size = 0;
    if (!out.finish(size, err)) return resp.error(500, err);
    log::info("export: ", what, " ", out.rows(), " rows, ", size / 1024, " KiB in ", now_ms() - started, " ms",
              truncated ? " (limit reached)" : "");

    // имя файла: sentinel-events-20261013-1820.csv
    std::string stamp = tf.local ? tf(now_ms()) : format_iso8601(now_ms());
    std::string name = "sentinel-" + std::string(what) + "-" + stamp.substr(0, 4) + stamp.substr(5, 2) + stamp.substr(8, 2) +
                       "-" + stamp.substr(11, 2) + stamp.substr(14, 2);
    const char* ext = fmt == Fmt::Json ? ".json" : fmt == Fmt::Ndjson ? ".ndjson" : ".csv";
    resp.status = 200;
    resp.content_type = fmt == Fmt::Json     ? "application/json; charset=utf-8"
                        : fmt == Fmt::Ndjson ? "application/x-ndjson; charset=utf-8"
                                             : "text/csv; charset=utf-8";
    resp.headers.emplace_back("Content-Disposition", "attachment; filename=\"" + name + ext + "\"");
    resp.headers.emplace_back("X-Export-Rows", std::to_string(out.rows()));
    if (truncated) resp.headers.emplace_back("X-Export-Truncated", "true");
    resp.send_file(out.path(), size, true);
}

// ---------------- отчёт за период ----------------

void Api::report(const HttpRequest& req, HttpResponse& resp) {
    const int64_t now = now_ms();
    int64_t to = now, from = 0;
    if (!req.param("to").empty()) {
        auto t = parse_time_param(req.param("to"));
        if (!t) return resp.error(400, "bad 'to' (ISO-8601 or ms)");
        to = *t;
    }
    if (!req.param("from").empty()) {
        auto t = parse_time_param(req.param("from"));
        if (!t) return resp.error(400, "bad 'from' (ISO-8601 or ms)");
        from = *t;
    } else {
        from = to - 7 * 86400000LL;
    }
    if (from >= to) return resp.error(400, "'from' must be before 'to'");
    if (to - from > 400 * 86400000LL) return resp.error(400, "period is too long (max 400 days)");
    int tz = local_utc_offset_minutes_now();
    if (!req.param("tz").empty()) {
        auto t = parse_int(req.param("tz"));
        if (!t || *t < -24 * 60 || *t > 24 * 60) return resp.error(400, "bad tz (minutes east of UTC)");
        tz = int(*t);
    }
    ReportSources src;
    src.events = &events_;
    src.alerts = &alerts_;
    src.incidents = incidents_;
    src.blocks = blocks_;
    src.live = &live_;
    src.enricher = enricher_;
    ReportData r = build_report(src, from, to, tz);
    std::string b;
    JsonWriter w(b);
    w.begin_object().key("report");
    write_report_json(w, r);
    w.key("mail").begin_object();
    w.kv("enabled", mailer_ && mailer_->enabled());
    if (mailer_ && mailer_->enabled()) {
        int64_t next = mailer_->next_at(now);
        w.kv("next", next ? format_iso8601(next) : std::string());
        w.kv("last_sent", mailer_->last_sent() ? format_iso8601(mailer_->last_sent()) : std::string());
        w.kv("recipients", uint64_t(mailer_->recipients().size()));
        w.kv("last_error", mailer_->last_error());
    }
    w.end_object();
    w.end_object();
    resp.json(200, std::move(b));
}

void Api::report_send(const HttpRequest&, HttpResponse& resp, const ApiKey& key) {
    if (!mailer_) return resp.error(503, "reports are not configured");
    std::string err = mailer_->send_now(key.name);
    if (!err.empty()) return resp.error(502, "cannot send: " + err);
    std::string b;
    JsonWriter(b).begin_object().kv("ok", true).kv("recipients", uint64_t(mailer_->recipients().size())).end_object();
    resp.json(200, std::move(b));
}

}  // namespace sentinel
