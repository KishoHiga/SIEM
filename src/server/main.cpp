// SentinelCore — сервер SIEM.
//
//   sentinel-server [run] [-c sentinel.yaml]             запустить сервер
//   sentinel-server gen-cert [--names a,b] [--days N]    создать сертификат для HTTPS
//   sentinel-server enroll-token [--ttl 24h] [--uses N]  токен для подключения агента
//   sentinel-server keygen --name web-01 --role ingest   создать ключ доступа вручную
//   sentinel-server test-rules [--rules DIR]             проверить правила на их примерах
//   sentinel-server version
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <thread>

#include "core/log.hpp"
#include "core/util.hpp"
#include "detect/engine.hpp"
#include "detect/rule_tests.hpp"
#include "detect/rules.hpp"
#include "net/server.hpp"
#include "net/tls.hpp"
#include "server/access.hpp"
#include "server/api.hpp"
#include "server/blocklist.hpp"
#include "server/config.hpp"
#include "server/live_feed.hpp"
#include "server/live_stats.hpp"
#include "server/notifier.hpp"
#include "store/incident_store.hpp"

#if defined(__GLIBC__)
#include <malloc.h>
#endif
#include "server/pipeline.hpp"
#include "server/rule_manager.hpp"
#include "enrich/enricher.hpp"
#include "server/web.hpp"
#include "store/alert_store.hpp"
#include "store/event_store.hpp"

using namespace sentinel;
namespace fs = std::filesystem;

static std::atomic<bool> g_stop{false};
static void on_signal(int) { g_stop.store(true); }

static const char* kVersion = "0.6.0";

static void usage() {
    std::cout << "SentinelCore SIEM server " << kVersion << "\n\n"
              << "Usage:\n"
              << "  sentinel-server [run] [-c sentinel.yaml]\n"
              << "  sentinel-server gen-cert [--names host1,10.0.0.5] [--days 825] [-c sentinel.yaml]\n"
              << "  sentinel-server enroll-token [--ttl 24h] [--uses 1] [--label text] [-c sentinel.yaml]\n"
              << "  sentinel-server keygen --name NAME --role ingest|read|analyst|admin [-c sentinel.yaml]\n"
              << "  sentinel-server test-rules [--rules DIR] [-c sentinel.yaml]\n"
              << "  sentinel-server geo-import FILE.csv [FILE2.csv...] [-c sentinel.yaml]   country/ASN/city database\n"
              << "  sentinel-server geo-lookup IP [-c sentinel.yaml]\n"
              << "  sentinel-server version\n";
}

struct Args {
    std::string cmd = "run";
    std::string config = "sentinel.yaml";
    std::string name, role, rules, names, days, ttl, uses, label;
    std::vector<std::string> files;  // geo-import: входные файлы; geo-lookup: адрес
};

static bool parse_args(int argc, char** argv, Args& a) {
    int i = 1;
    if (i < argc && argv[i][0] != '-') a.cmd = argv[i++];
    for (; i < argc; ++i) {
        std::string k = argv[i];
        auto next = [&](std::string& out) {
            if (i + 1 >= argc) return false;
            out = argv[++i];
            return true;
        };
        if ((k == "-c" || k == "--config") && next(a.config)) continue;
        if (k == "--name" && next(a.name)) continue;
        if (k == "--role" && next(a.role)) continue;
        if (k == "--rules" && next(a.rules)) continue;
        if (k == "--names" && next(a.names)) continue;
        if (k == "--days" && next(a.days)) continue;
        if (k == "--ttl" && next(a.ttl)) continue;
        if (k == "--uses" && next(a.uses)) continue;
        if (k == "--label" && next(a.label)) continue;
        if (k == "-h" || k == "--help") return false;
        if ((a.cmd == "geo-import" || a.cmd == "geo-lookup") && !k.empty() && k[0] != '-') {
            a.files.push_back(k);
            continue;
        }
        std::cerr << "unknown argument: " << k << "\n";
        return false;
    }
    return true;
}

static int cmd_geo_import(const Config& cfg, const Args& a) {
    if (a.files.empty()) {
        std::cerr << "usage: sentinel-server geo-import dbip-country-lite.csv [dbip-asn-lite.csv] [-c sentinel.yaml]\n"
                  << "Free databases: https://db-ip.com/db/lite.php (CC BY 4.0), https://iptoasn.com\n";
        return 2;
    }
    GeoImportStats st;
    std::string err;
    std::cout << "Importing " << a.files.size() << " file(s)...\n";
    if (!GeoDb::import_files(a.files, cfg.geo_db, st, err)) {
        std::cerr << "error: " << err << "\n";
        return 1;
    }
    std::cout << "Saved " << cfg.geo_db << ": " << st.country_ranges << " country, " << st.city_ranges << " city, "
              << st.asn_ranges << " network (ASN) ranges";
    if (st.skipped_lines) std::cout << ", skipped lines: " << st.skipped_lines;
    std::cout << "\nA running server picks the new database up within a few seconds.\n";
    return 0;
}

static int cmd_geo_lookup(const Config& cfg, const Args& a) {
    if (a.files.empty()) {
        std::cerr << "usage: sentinel-server geo-lookup 8.8.8.8\n";
        return 2;
    }
    GeoDb db;
    std::string err;
    if (!db.load(cfg.geo_db, err)) {
        std::cerr << "error: " << err << "\n";
        return 1;
    }
    for (auto& s : a.files) {
        auto ip = parse_ip(s);
        if (!ip) {
            std::cout << s << ": not an IP address\n";
            continue;
        }
        GeoInfo g = db.lookup(*ip);
        std::cout << format_ip(*ip) << ": " << (g.country.empty() ? "?" : std::string(g.country));
        if (!g.city.empty()) std::cout << ", " << g.city;
        if (!g.asn.empty()) std::cout << ", AS" << g.asn;
        if (!g.org.empty()) std::cout << " " << g.org;
        if (is_private_or_special(*ip)) std::cout << " (internal network)";
        std::cout << "\n";
    }
    return 0;
}

static int64_t parse_ttl(const std::string& s, int64_t def) {
    if (s.empty()) return def;
    std::string v = s;
    int64_t mult = 3600000;  // по умолчанию часы
    char u = v.back();
    if (u == 'm') { mult = 60000; v.pop_back(); }
    else if (u == 'h') { mult = 3600000; v.pop_back(); }
    else if (u == 'd') { mult = 86400000; v.pop_back(); }
    auto n = parse_int(v);
    return n && *n > 0 ? *n * mult : def;
}

static std::string tls_fingerprint(const Config& cfg) {
    if (cfg.tls_cert.empty()) return "";
    std::string fp, err;
    if (!net::cert_file_fingerprint(cfg.tls_cert, fp, err)) return "";
    return fp;
}

static int cmd_test_rules(const Config& cfg, const std::string& dir_arg) {
    std::string dir = dir_arg.empty() ? cfg.rules_dir : dir_arg;
    auto res = load_rules_dir(dir);
    for (auto& e : res.errors) std::cout << "ERROR  " << e << "\n";
    auto rep = run_rule_tests(res.rules);
    for (auto& e : rep.errors) std::cout << "ERROR  " << e << "\n";
    for (auto& f : rep.failures)
        std::cout << "FAIL   " << f.rule_id << " (" << f.file << "): "
                  << (f.expected_alert ? "expected alert, got none: " : "unexpected alert: ") << f.line << "\n";
    std::cout << "\nrules: " << res.rules.size() << ", with tests: " << rep.rules_with_tests << ", cases: " << rep.cases
              << ", failed: " << rep.failures.size() << ", load errors: " << res.errors.size() + rep.errors.size()
              << "\n";
    return (res.errors.empty() && rep.errors.empty() && rep.failures.empty()) ? 0 : 1;
}

static int cmd_keygen(Config& cfg, const Args& a) {
    Role role;
    if (a.name.empty() || !role_from_name(a.role.empty() ? "ingest" : a.role, role)) {
        std::cerr << "usage: sentinel-server keygen --name NAME --role ingest|read|analyst|admin\n";
        return 2;
    }
    std::string err;
    if (!load_keys_file(cfg, err)) {
        std::cerr << "error: " << err << "\n";
        return 1;
    }
    std::string secret;
    if (!create_key(cfg, a.name, role, secret, err)) {
        std::cerr << "error: " << err << "\n";
        return 1;
    }
    std::cout << "Created key '" << a.name << "' (role: " << role_name(role) << ")\n"
              << "Saved hash to: " << cfg.keys_file << " (a running server picks it up within 2 seconds)\n\n"
              << "  " << secret << "\n\n"
              << "Copy it now: the key itself is not stored anywhere and cannot be shown again.\n";
    return 0;
}

static int cmd_gen_cert(const Config& cfg, const Args& a) {
    std::vector<std::string> names;
    for (auto n : split(a.names, ','))
        if (!trim(n).empty()) names.emplace_back(trim(n));
    if (names.empty()) names = {"localhost", "127.0.0.1"};
    int days = int(parse_int(a.days).value_or(825));
    std::string cert = cfg.tls_cert.empty() ? cfg.data_dir + "/tls/server.crt" : cfg.tls_cert;
    std::string key = cfg.tls_key.empty() ? cfg.data_dir + "/tls/server.key" : cfg.tls_key;
    std::string fp, err;
    if (!net::generate_self_signed(cert, key, names, days, fp, err)) {
        std::cerr << "error: " << err << "\n";
        return 1;
    }
    std::cout << "Certificate: " << cert << "\nPrivate key: " << key << " (keep it secret)\n"
              << "Valid for " << days << " days, names: " << a.names << (a.names.empty() ? "localhost,127.0.0.1" : "")
              << "\n\nFingerprint (agents use it to trust this server):\n  " << fp << "\n\n";
    if (cfg.tls_cert.empty())
        std::cout << "Add to " << (cfg.source.empty() ? "sentinel.yaml" : cfg.source) << ":\n\n"
                  << "tls:\n  cert: " << cert << "\n  key: " << key << "\n\n";
    std::cout << "Then restart the server.\n";
    return 0;
}

static int cmd_enroll_token(const Config& cfg, const Args& a) {
    EnrollStore store(cfg.data_dir + "/enroll_tokens.yaml");
    int64_t ttl = parse_ttl(a.ttl, 24 * 3600000LL);
    int uses = int(parse_int(a.uses).value_or(1));
    std::string secret, err;
    if (!store.create(ttl, uses, a.label, secret, err)) {
        std::cerr << "error: " << err << "\n";
        return 1;
    }
    std::string fp = tls_fingerprint(cfg);
    std::cout << "Enroll token (valid " << ttl / 3600000 << " h, " << uses << " use(s)):\n\n  " << secret << "\n\n"
              << "On the server you want to protect, run:\n\n"
              << "  sentinel-agent enroll --server " << agent_server_url(cfg) << " --token " << secret;
    if (!fp.empty()) std::cout << " \\\n      --pin " << fp;
    std::cout << "\n  sentinel-agent run\n\n";
    if (cfg.tls_cert.empty())
        std::cout << "WARNING: the server has no TLS configured, the key would travel unencrypted.\n"
                     "Run 'sentinel-server gen-cert' first (or put nginx with HTTPS in front).\n";
    return 0;
}

static int cmd_run(Config& cfg) {
    log::info("SentinelCore ", kVersion, " starting",
              cfg.source.empty() ? " (default config)" : " with config " + cfg.source);

    std::shared_ptr<net::TlsContext> tls;
    std::string err;
    if (!cfg.tls_cert.empty()) {
        tls = net::TlsContext::server(cfg.tls_cert, cfg.tls_key, err);
        if (!tls) {
            log::error("tls: ", err);
            return 1;
        }
        log::info("tls: enabled (", net::tls_library_version(), "), certificate fingerprint ", tls_fingerprint(cfg));
    }

    EventStore events;
    StoreOptions so;
    so.dir = cfg.data_dir;
    so.retention_ms = int64_t(cfg.retention_days) * 86400000LL;
    so.fsync = cfg.fsync;
    so.compress_threads = cfg.store_threads;
    if (!events.open(so, err)) {
        log::error(err);
        return 1;
    }
    AlertStore alerts;
    if (!alerts.open(cfg.data_dir, so.retention_ms, err)) {
        log::error(err);
        return 1;
    }

    // Инциденты: алерты одной атаки в одной карточке
    IncidentStore incidents;
    incidents.set_window(cfg.incident_window_ms);
    if (!incidents.open(cfg.data_dir, so.retention_ms, err)) {
        log::error(err);
        return 1;
    }

    // Правила: загрузка, правка из панели (с историей версий в data/rules-history) и подхват ручных правок
    RuleManager rule_mgr(cfg.rules_dir, cfg.data_dir + "/rules-history");
    std::unique_ptr<DetectionEngine> engine;
    std::vector<Rule> rules;
    rule_mgr.set_apply([&](std::unique_ptr<DetectionEngine> e, const std::vector<Rule>& r) {
        engine = std::move(e);
        rules = r;
    });
    if (!rule_mgr.reload(err)) {
        log::error("rules: ", err);
        return 1;
    }

    // Реагирование: список блокировок и уведомления
    BlockList blocks;
    if (!blocks.open(cfg.data_dir + "/blocks.json", err)) {
        log::error(err);
        return 1;
    }
    {
        AutoBlockPolicy p;
        p.enabled = cfg.response.auto_block;
        p.min_severity = cfg.response.min_severity;
        p.rules = cfg.response.rules;
        p.duration_ms = cfg.response.duration_ms;
        p.allowlist = cfg.response.allowlist;
        p.block_private = cfg.response.block_private;
        p.max_per_minute = cfg.response.max_per_minute;
        blocks.set_policy(p);
        if (p.enabled)
            log::info("response: auto-block for '", severity_name(p.min_severity), "' alerts",
                      p.rules.empty() ? "" : " and " + std::to_string(p.rules.size()) + " listed rules", ", for ",
                      p.duration_ms ? std::to_string(p.duration_ms / 60000) + " min" : std::string("ever"),
                      " (agents apply it when 'firewall:' is set in agent.yaml)");
        else
            log::info("response: auto-block is off (manual blocking from the panel still works)");
    }
    NotifyConfig ncfg = cfg.notify;
    if (ncfg.panel_url.empty()) ncfg.panel_url = cfg.public_url;
    Notifier notifier(ncfg);
    notifier.start();
    if (!ncfg.any()) log::info("notify: no channels configured (see 'notify:' in sentinel.yaml)");

    // Обогащение: страна и сеть по IP (geo-import), списки плохих адресов
    Enricher enricher;
    if (!enricher.reload_geo_if_changed(cfg.geo_db))
        log::info("geo: no country database (", cfg.geo_db, "); import one with 'sentinel-server geo-import'");
    ThreatFeeds feeds(cfg.threat, cfg.data_dir + "/threat", [&enricher](std::shared_ptr<const ThreatSet> set) {
        size_t n = 0;
        for (size_t i = 0; i < set->names().size(); ++i) n += set->entries(i);
        log::info("threat: ", set->names().size(), " lists active, ", n, " entries");
        enricher.set_threat(std::move(set));
    });
    feeds.start();

    LiveStats live;
    if (live.load(cfg.data_dir + "/stats.bin")) log::info("stats: restored dashboard counters");
    LiveFeed feed;
    Pipeline pipeline(events, alerts, live, cfg.queue_events);
    pipeline.set_detect_threads(cfg.detect_threads);
    const bool notify_incidents = ncfg.incidents();
    pipeline.set_on_stored([&feed, &blocks, &notifier, &incidents, notify_incidents](const std::vector<Event>& ev,
                                                                                     const std::vector<Alert>& al) {
        feed.on_stored(ev, al);
        if (al.empty()) return;
        auto notices = incidents.on_alerts(al);
        auto auto_blocked = blocks.on_alerts(al);
        if (notify_incidents) notifier.enqueue_incidents(notices, auto_blocked);
        else notifier.enqueue(al, auto_blocked);
    });
    pipeline.start(std::move(engine));

    Api api(cfg, events, alerts, live, pipeline);
    api.set_rules(rules);
    api.set_rule_manager(&rule_mgr);
    api.set_enrichment(&enricher, &feeds);
    rule_mgr.set_apply([&pipeline, &api](std::unique_ptr<DetectionEngine> e, const std::vector<Rule>& r) {
        pipeline.replace_engine(std::move(e));
        api.set_rules(r);
    });
    api.set_agent_info(agent_server_url(cfg), tls ? tls_fingerprint(cfg) : std::string());
    auto web = std::make_shared<WebFiles>(cfg.web_dir);
    api.set_web(web);
    api.set_response(&blocks, &notifier);
    api.set_incidents(&incidents);
    ReportSources rsrc;
    rsrc.events = &events;
    rsrc.alerts = &alerts;
    rsrc.incidents = &incidents;
    rsrc.blocks = &blocks;
    rsrc.live = &live;
    rsrc.enricher = &enricher;
    ReportMailer mailer(cfg.reports, ncfg, rsrc, cfg.data_dir + "/reports.json");
    api.set_report_mailer(&mailer);
    if (mailer.enabled()) {
        static const char* days[] = {"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"};
        log::info("reports: weekly e-mail on ", days[cfg.reports.weekday], " at ", cfg.reports.minute_of_day / 60, ":",
                  cfg.reports.minute_of_day % 60 < 10 ? "0" : "", cfg.reports.minute_of_day % 60, " (server time) to ",
                  mailer.recipients().size(), " address(es)");
    }
    api.load_agents();

    if (api.keys().size() == 0) {
        std::string secret;
        if (!api.keys().add("admin", Role::Admin, secret, err)) {
            log::error("cannot create initial admin key: ", err);
            pipeline.stop();
            return 1;
        }
        std::cout << "\n=====================================================================\n"
                  << " First start: created ADMIN key (shown only once, save it now):\n\n"
                  << "   " << secret << "\n\n"
                  << " Use it as:  Authorization: Bearer <key>\n"
                  << " Connect an agent:  sentinel-server enroll-token\n"
                  << "=====================================================================\n"
                  << std::endl;
    }

    net::ServerOptions sopt;
    sopt.host = cfg.listen_host;
    sopt.port = cfg.listen_port;
    sopt.workers = cfg.workers;
    sopt.max_body_bytes = cfg.max_body_mb * 1024 * 1024;
    sopt.tls = tls;
    sopt.ws.path = "/ws/live";
    sopt.ws.accept = [&api](const net::HttpRequest& rq) { return api.ws_accept(rq); };
    net::HttpServer server(sopt, [&api](const net::HttpRequest& rq, net::HttpResponse& rs) { api.handle(rq, rs); });
    if (!server.start(err)) {
        log::error(err);
        pipeline.stop();
        return 1;
    }
    log::info("listening on ", tls ? "https://" : "http://", cfg.listen_host, ":", server.port(), " (", cfg.workers,
              " workers), data in ", cfg.data_dir);
    feed.set_sink([&server](const std::string& msg) { server.broadcast(msg); });
    if (web->available())
        log::info("web panel: ", tls ? "https://" : "http://", cfg.listen_host, ":", server.port(), "/ (files from ",
                  cfg.web_dir, ")");
    else
        log::info("web panel: not built (", cfg.web_dir, "/index.html missing) — run 'npm run build' in web/");
    bool local = cfg.listen_host == "127.0.0.1" || cfg.listen_host == "localhost" || cfg.listen_host == "::1";
    if (!local && !tls)
        log::warn("listening on a non-local address WITHOUT encryption. Run 'sentinel-server gen-cert' and set tls: "
                  "in the config, or put nginx with HTTPS in front.");

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    int64_t last_check = now_ms();
    int64_t last_tick = now_ms();
    int64_t last_save = now_ms();
    int64_t last_maintain = now_ms();
    [[maybe_unused]] uint64_t trimmed_at = 0;
    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (now_ms() - last_tick >= 1000) {
            last_tick = now_ms();
            feed.tick(last_tick);
            blocks.tick(last_tick);
        }
        if (now_ms() - last_save >= 30000) {
            last_save = now_ms();
            live.save(cfg.data_dir + "/stats.bin");
            api.save_agents();
#if defined(__GLIBC__)
            // после большой пачки очередь пуста, а память осталась у malloc — вернуть её системе
            auto ps = pipeline.stats();
            if (ps.queued == 0 && ps.accepted - trimmed_at >= 100000) {
                trimmed_at = ps.accepted;
                malloc_trim(0);
            }
#endif
        }
        if (now_ms() - last_maintain >= 3600000) {
            last_maintain = now_ms();
            incidents.maintain();  // старые инциденты и сжатие журнала
        }
        if (now_ms() - last_check < 2000) continue;
        last_check = now_ms();
        api.keys().reload_if_changed();
        rule_mgr.reload_if_changed();  // правила изменили вручную в папке rules
        enricher.reload_geo_if_changed(cfg.geo_db);  // новая база после geo-import
        mailer.tick(now_ms());                         // еженедельный отчёт на почту
    }
    log::info("shutting down...");
    feed.set_sink(nullptr);
    server.stop();
    pipeline.stop();
    feeds.stop();
    mailer.stop();
    notifier.stop();
    blocks.flush();
    live.save(cfg.data_dir + "/stats.bin");
    api.save_agents();
    events.close();
    alerts.close();
    incidents.close();
    log::info("stopped cleanly");
    return 0;
}

int main(int argc, char** argv) {
    Args a;
    if (!parse_args(argc, argv, a)) {
        usage();
        return 2;
    }
    if (a.cmd == "version") {
        std::cout << "SentinelCore " << kVersion << " (TLS: " << net::tls_library_version() << ")\n";
        return 0;
    }
    if (a.cmd == "help") {
        usage();
        return 0;
    }
    Config cfg;
    std::string err;
    if (!load_config(a.config, cfg, err)) {
        std::cerr << "config error: " << err << "\n";
        return 1;
    }
    if (cfg.log_level == "debug") log::set_level(log::Level::Debug);
    else if (cfg.log_level == "warn") log::set_level(log::Level::Warn);
    else if (cfg.log_level == "error") log::set_level(log::Level::Error);

    if (a.cmd == "test-rules") return cmd_test_rules(cfg, a.rules);
    if (a.cmd == "geo-import") return cmd_geo_import(cfg, a);
    if (a.cmd == "geo-lookup") return cmd_geo_lookup(cfg, a);
    if (a.cmd == "keygen") return cmd_keygen(cfg, a);
    if (a.cmd == "gen-cert") return cmd_gen_cert(cfg, a);
    if (a.cmd == "enroll-token") return cmd_enroll_token(cfg, a);
    if (a.cmd == "run") return cmd_run(cfg);
    usage();
    return 2;
}
