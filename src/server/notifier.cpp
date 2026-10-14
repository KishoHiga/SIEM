#include "server/notifier.hpp"

#include <algorithm>
#include <chrono>

#include "core/json.hpp"
#include "core/log.hpp"
#include "core/util.hpp"
#include "net/client.hpp"
#include "net/smtp.hpp"
#include "server/json_out.hpp"

namespace sentinel {

namespace {

const char* sev_ru(Severity s) {
    switch (s) {
        case Severity::Critical: return "Критический";
        case Severity::High: return "Высокий";
        case Severity::Medium: return "Средний";
        case Severity::Low: return "Низкий";
        default: return "Инфо";
    }
}

const char* sev_icon(Severity s) {
    switch (s) {
        case Severity::Critical: return "\xF0\x9F\x94\xB4";  // красный круг
        case Severity::High: return "\xF0\x9F\x9F\xA0";      // оранжевый
        case Severity::Medium: return "\xF0\x9F\x9F\xA1";    // жёлтый
        case Severity::Low: return "\xF0\x9F\x94\xB5";       // синий
        default: return "\xE2\x9A\xAA";                      // белый
    }
}

std::string html_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        if (c == '<') out += "&lt;";
        else if (c == '>') out += "&gt;";
        else if (c == '&') out += "&amp;";
        else if (c == '"') out += "&quot;";
        else out.push_back(c);
    }
    return out;
}

// Обрезать по границе символа UTF-8.
std::string clip_utf8(const std::string& s, size_t max) {
    if (s.size() <= max) return s;
    size_t end = max;
    while (end > 0 && (uint8_t(s[end]) & 0xC0) == 0x80) --end;
    return s.substr(0, end) + "…";
}

std::string ru_duration(int64_t ms) {
    int64_t m = (ms + 59999) / 60000;
    if (m < 60) return std::to_string(m) + " мин";
    int64_t h = (m + 59) / 60;
    if (h < 48) return std::to_string(h) + " ч";
    return std::to_string((h + 23) / 24) + " дн";
}

std::string plural_alerts(size_t n) {
    size_t d10 = n % 10, d100 = n % 100;
    const char* w = (d10 == 1 && d100 != 11) ? "новый алерт"
                    : (d10 >= 2 && d10 <= 4 && (d100 < 12 || d100 > 14)) ? "новых алерта"
                                                                          : "новых алертов";
    return std::to_string(n) + " " + w;
}

std::string host_of(const std::string& url) {
    net::Url u;
    std::string err;
    if (!net::parse_url(url, u, err)) return "?";
    return u.host;
}

}  // namespace

Notifier::Notifier(NotifyConfig cfg) : cfg_(std::move(cfg)) {
    while (!cfg_.panel_url.empty() && cfg_.panel_url.back() == '/') cfg_.panel_url.pop_back();
    auto add = [&](const char* name, std::string target) {
        ChannelStatus c;
        c.name = name;
        c.target = std::move(target);
        channels_.push_back(std::move(c));
    };
    if (cfg_.telegram.enabled()) add("telegram", "чат " + cfg_.telegram.chat_id);
    if (cfg_.webhook.enabled()) add("webhook", cfg_.webhook.format + " → " + host_of(cfg_.webhook.url));
    if (cfg_.email.enabled()) {
        std::string to;
        for (auto& t : cfg_.email.to) to += (to.empty() ? "" : ", ") + t;
        add("email", to + " через " + cfg_.email.host + ":" + std::to_string(cfg_.email.port));
    }
}

Notifier::~Notifier() { stop(); }

void Notifier::start() {
    if (channels_.empty() || th_.joinable()) return;
    stop_.store(false);
    th_ = std::thread([this] { loop(); });
    std::string names;
    for (auto& c : channels_) names += (names.empty() ? "" : ", ") + c.name;
    log::info("notify: channels ", names, cfg_.incidents() ? ", new/escalated incidents from '" : ", alerts from '",
              severity_name(cfg_.min_severity), "' and above");
}

void Notifier::stop() {
    if (!th_.joinable()) return;
    stop_.store(true);
    cv_.notify_all();
    th_.join();
}

std::string Notifier::alert_url(uint64_t id) const {
    if (cfg_.panel_url.empty()) return "";
    return cfg_.panel_url + "/alerts/" + std::to_string(id);
}

std::string Notifier::incident_url(uint64_t id) const {
    if (cfg_.panel_url.empty()) return "";
    return cfg_.panel_url + "/incidents/" + std::to_string(id);
}

void Notifier::enqueue_incidents(const std::vector<IncidentNotice>& notices, const std::vector<Block>& blocked) {
    if (channels_.empty()) return;
    bool any = false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& b : blocked) blocked_[b.ip] = b.expires;
        if (blocked_.size() > 10000) blocked_.clear();
        for (const IncidentNotice& n : notices) {
            // повторы не нужны: об инциденте пишем, когда он появился или стал серьёзнее
            if (n.severity < cfg_.min_severity) continue;
            if (!n.is_new && !n.escalated) {
                ++suppressed_;
                continue;
            }
            Item it;
            it.alert = n.alert;
            it.incident_id = n.id;
            it.incident_title = n.title;
            it.incident_severity = n.severity;
            it.incident_alerts = n.alert_count;
            // новый, но важность ниже порога была раньше — для человека это всё равно «новый»
            it.incident_new = n.is_new;
            auto bit = blocked_.find(n.alert.src_ip);
            if (bit != blocked_.end()) it.blocked_until = bit->second;
            if (queue_.size() >= kMaxQueue) {
                queue_.pop_front();
                ++dropped_;
            }
            queue_.push_back(std::move(it));
            any = true;
        }
    }
    if (any) cv_.notify_one();
}

void Notifier::enqueue(const std::vector<Alert>& alerts, const std::vector<Block>& blocked) {
    if (channels_.empty()) return;
    const int64_t now = now_ms();
    bool any = false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& b : blocked) blocked_[b.ip] = b.expires;
        if (blocked_.size() > 10000) blocked_.clear();
        for (const Alert& a : alerts) {
            if (a.severity < cfg_.min_severity) continue;
            std::string key = a.rule_id + "|" + a.src_ip;
            auto& cd = cooldown_[key];
            if (now < cd.first) {
                ++cd.second;
                ++suppressed_;
                continue;
            }
            Item it;
            it.alert = a;
            it.repeats = cd.second;
            cd = {now + cfg_.cooldown_ms, 0};
            auto bit = blocked_.find(a.src_ip);
            if (bit != blocked_.end()) it.blocked_until = bit->second;
            if (queue_.size() >= kMaxQueue) {
                queue_.pop_front();
                ++dropped_;
            }
            queue_.push_back(std::move(it));
            any = true;
        }
        if (cooldown_.size() > 50000) {  // чистка старых ключей
            for (auto it = cooldown_.begin(); it != cooldown_.end();)
                it = it->second.first < now ? cooldown_.erase(it) : std::next(it);
        }
    }
    if (any) cv_.notify_one();
}

std::string Notifier::subject(const Item& it) const {
    if (it.incident_id) {
        std::string s = "[Sentinel] ";
        s += it.incident_new ? "Новый инцидент #" : "Инцидент стал серьёзнее #";
        s += std::to_string(it.incident_id) + " (" + sev_ru(it.incident_severity) + "): " + it.incident_title;
        return clip_utf8(s, 200);
    }
    std::string s = "[Sentinel] " + std::string(sev_ru(it.alert.severity)) + ": " + it.alert.rule_name;
    if (!it.alert.src_ip.empty()) s += " (" + it.alert.src_ip + ")";
    return s;
}

std::string Notifier::digest_subject(const std::vector<Item>& items) const {
    if (!items.empty() && items[0].incident_id) return "[Sentinel] Инцидентов: " + std::to_string(items.size());
    return "[Sentinel] " + plural_alerts(items.size());
}

std::string Notifier::format_incident(const Item& it, bool html) const {
    const Alert& a = it.alert;
    auto esc = [&](std::string_view s) { return html ? html_escape(s) : std::string(s); };
    std::string head = std::string(it.incident_new ? "Новый инцидент #" : "Инцидент стал серьёзнее #") +
                       std::to_string(it.incident_id) + " · " + sev_ru(it.incident_severity);
    std::string out = std::string(sev_icon(it.incident_severity)) + " " + (html ? "<b>" + esc(head) + "</b>" : head);
    out += "\n" + esc(clip_utf8(it.incident_title, 300));
    out += "\nПоследний алерт: " + esc(a.rule_name) + " — " + esc(clip_utf8(a.message, 400));
    std::string who;
    if (!a.src_ip.empty()) who += "IP: " + (html ? "<code>" + esc(a.src_ip) + "</code>" : a.src_ip);
    if (!a.user.empty()) who += std::string(who.empty() ? "" : " · ") + "пользователь: " + esc(a.user);
    if (!a.host.empty()) who += std::string(who.empty() ? "" : " · ") + "сервер: " + esc(a.host);
    if (!who.empty()) out += "\n" + who;
    out += "\nАлертов в инциденте: " + std::to_string(it.incident_alerts);
    if (it.blocked_until == 0) out += "\n\xF0\x9F\x9A\xAB IP заблокирован бессрочно";
    else if (it.blocked_until > 0)
        out += "\n\xF0\x9F\x9A\xAB IP заблокирован на " + ru_duration(std::max<int64_t>(0, it.blocked_until - now_ms()));
    std::string url = incident_url(it.incident_id);
    std::string label = "Инцидент #" + std::to_string(it.incident_id);
    if (!url.empty()) out += "\n" + (html ? "<a href=\"" + esc(url) + "\">" + label + "</a>" : label + ": " + url);
    else out += "\n" + label;
    return out;
}

std::string Notifier::format_text(const Item& it, bool html) const {
    if (it.incident_id) return format_incident(it, html);
    const Alert& a = it.alert;
    auto esc = [&](std::string_view s) { return html ? html_escape(s) : std::string(s); };
    std::string out = std::string(sev_icon(a.severity)) + " ";
    out += html ? "<b>" + esc(sev_ru(a.severity)) + " · " + esc(a.rule_name) + "</b>"
                : std::string(sev_ru(a.severity)) + " · " + a.rule_name;
    out += "\n" + esc(clip_utf8(a.message, 600));
    std::string who;
    if (!a.src_ip.empty()) who += "IP: " + (html ? "<code>" + esc(a.src_ip) + "</code>" : a.src_ip);
    if (!a.user.empty()) who += std::string(who.empty() ? "" : " · ") + "пользователь: " + esc(a.user);
    if (!a.host.empty()) who += std::string(who.empty() ? "" : " · ") + "сервер: " + esc(a.host);
    if (!who.empty()) out += "\n" + who;
    if (it.repeats) out += "\n(ещё " + std::to_string(it.repeats) + " похожих с прошлого уведомления)";
    if (it.blocked_until == 0) out += "\n\xF0\x9F\x9A\xAB IP заблокирован бессрочно";
    else if (it.blocked_until > 0)
        out += "\n\xF0\x9F\x9A\xAB IP заблокирован на " + ru_duration(std::max<int64_t>(0, it.blocked_until - now_ms()));
    std::string url = alert_url(a.id);
    std::string label = "Алерт #" + std::to_string(a.id);
    if (!url.empty()) out += "\n" + (html ? "<a href=\"" + esc(url) + "\">" + label + "</a>" : label + ": " + url);
    else out += "\n" + label;
    return out;
}

std::string Notifier::format_digest(const std::vector<Item>& items, bool html) const {
    auto esc = [&](std::string_view s) { return html ? html_escape(s) : std::string(s); };
    const bool inc = !items.empty() && items[0].incident_id;
    auto sev_of = [&](const Item& it) { return inc ? it.incident_severity : it.alert.severity; };
    size_t by_sev[5] = {0, 0, 0, 0, 0};
    size_t blocked = 0;
    for (auto& it : items) {
        ++by_sev[size_t(sev_of(it))];
        if (it.blocked_until >= 0) ++blocked;
    }
    std::string head = "\xE2\x9A\xA0\xEF\xB8\x8F " +
                       (inc ? "Новых или усилившихся инцидентов: " + std::to_string(items.size()) : plural_alerts(items.size()));
    std::string out = html ? "<b>" + head + "</b>" : head;
    std::string counts;
    static const char* names[] = {"инфо", "низких", "средних", "высоких", "критических"};
    for (int s = 4; s >= 0; --s)
        if (by_sev[s]) counts += std::string(counts.empty() ? "" : ", ") + names[s] + ": " + std::to_string(by_sev[s]);
    out += "\n" + counts;
    if (blocked) out += "\n\xF0\x9F\x9A\xAB автоматически заблокировано IP: " + std::to_string(blocked);
    out += "\n";
    std::vector<const Item*> sorted;
    for (auto& it : items) sorted.push_back(&it);
    std::stable_sort(sorted.begin(), sorted.end(), [&](const Item* x, const Item* y) { return sev_of(*x) > sev_of(*y); });
    size_t shown = 0;
    for (auto* it : sorted) {
        if (shown == 10) break;
        const Alert& a = it->alert;
        if (inc) {
            out += "\n" + std::string(sev_icon(it->incident_severity)) + " #" + std::to_string(it->incident_id) + " " +
                   esc(clip_utf8(it->incident_title, 200));
            ++shown;
            continue;
        }
        out += "\n" + std::string(sev_icon(a.severity)) + " " + esc(a.rule_name);
        if (!a.src_ip.empty()) out += " — " + esc(a.src_ip);
        if (!a.host.empty()) out += " (" + esc(a.host) + ")";
        ++shown;
    }
    if (items.size() > shown) out += "\n…и ещё " + std::to_string(items.size() - shown);
    if (!cfg_.panel_url.empty()) {
        std::string url = cfg_.panel_url + (inc ? "/incidents" : "/alerts?status=new");
        const char* label = inc ? "Открыть инциденты" : "Открыть алерты";
        out += "\n\n" + (html ? "<a href=\"" + esc(url) + "\">" + label + "</a>" : std::string(label) + ": " + url);
    }
    return out;
}

void Notifier::loop() {
    while (true) {
        std::vector<Item> items;
        {
            std::unique_lock<std::mutex> lock(mu_);
            cv_.wait(lock, [&] { return stop_.load() || !queue_.empty(); });
            if (!stop_.load()) {
                // окно склейки: ждём, не придут ли ещё алерты
                cv_.wait_for(lock, std::chrono::milliseconds(cfg_.batch_ms), [&] { return stop_.load(); });
            }
            items.assign(std::make_move_iterator(queue_.begin()), std::make_move_iterator(queue_.end()));
            queue_.clear();
        }
        if (!items.empty()) process(items, stop_.load());
        if (stop_.load()) {
            std::lock_guard<std::mutex> lock(mu_);
            if (queue_.empty()) break;
        }
    }
}

void Notifier::process(std::vector<Item>& items, bool final_pass) {
    std::vector<Message> msgs;
    if (items.size() <= 3) {
        for (auto& it : items)
            msgs.push_back({subject(it), format_text(it, false), format_text(it, true), &it.alert, &it});
    } else {
        msgs.push_back({digest_subject(items), format_digest(items, false), format_digest(items, true), nullptr, nullptr});
        std::lock_guard<std::mutex> lock(mu_);
        ++digests_;
    }
    for (size_t ch = 0; ch < channels_.size(); ++ch) {
        for (auto& m : msgs) {
            std::string err;
            bool ok = false;
            int attempts = final_pass ? 1 : 3;
            for (int a = 0; a < attempts && !ok; ++a) {
                if (a > 0) {
                    for (int w = 0; w < (a == 1 ? 10 : 30) && !stop_.load(); ++w)
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                ok = deliver(ch, m, err);
            }
            std::lock_guard<std::mutex> lock(mu_);
            ChannelStatus& st = channels_[ch];
            if (ok) {
                ++st.sent;
                st.last_ok = now_ms();
            } else {
                ++st.failed;
                st.last_error = err;
                st.last_error_at = now_ms();
                log::warn("notify: ", st.name, " failed: ", err);
            }
        }
    }
}

bool Notifier::deliver(size_t ch, const Message& m, std::string& error) {
    const std::string& name = channels_[ch].name;
    if (name == "telegram") return send_telegram(m, error);
    if (name == "webhook") return send_webhook(m, error);
    if (name == "email") return send_email(m, error);
    error = "unknown channel";
    return false;
}

static bool post_json(const std::string& url, const std::string& path_suffix, const std::string& body,
                      const NotifyConfig& cfg, std::string& response, std::string& error) {
    net::Url u;
    if (!net::parse_url(url, u, error)) return false;
    net::ClientTlsOptions tls;
    tls.ca_file = cfg.ca_file;
    tls.pin_sha256 = cfg.pin;
    net::HttpClient c(u, tls, 10000);
    net::ClientResponse r;
    if (!c.request("POST", path_suffix, {{"Content-Type", "application/json"}, {"User-Agent", "SentinelCore"}}, body,
                   r, error))
        return false;
    response = r.body;
    if (r.status / 100 != 2) {
        error = "HTTP " + std::to_string(r.status) + ": " + clip_utf8(r.body, 200);
        return false;
    }
    return true;
}

bool Notifier::send_telegram(const Message& m, std::string& error) {
    std::string body;
    JsonWriter(body)
        .begin_object()
        .kv("chat_id", cfg_.telegram.chat_id)
        .kv("text", clip_utf8(m.html, 3900))
        .kv("parse_mode", "HTML")
        .kv("disable_web_page_preview", true)
        .end_object();
    std::string resp;
    // токен бота — в адресе запроса; в ошибки он не попадает (там только хост и код ответа)
    return post_json(cfg_.telegram.api_url, "/bot" + cfg_.telegram.bot_token + "/sendMessage", body, cfg_, resp, error);
}

bool Notifier::send_webhook(const Message& m, std::string& error) {
    std::string body;
    JsonWriter w(body);
    w.begin_object();
    if (cfg_.webhook.format == "slack") {
        w.kv("text", m.text);
    } else if (cfg_.webhook.format == "discord") {
        w.kv("content", clip_utf8(m.text, 1900));
    } else {
        w.kv("source", "sentinel").kv("subject", m.subject).kv("text", m.text);
        if (m.item && m.item->incident_id) {
            w.key("incident").begin_object();
            w.kv("id", m.item->incident_id)
                .kv("title", m.item->incident_title)
                .kv("severity", severity_name(m.item->incident_severity))
                .kv("new", m.item->incident_new)
                .kv("alert_count", m.item->incident_alerts);
            if (std::string u = incident_url(m.item->incident_id); !u.empty()) w.kv("url", u);
            w.end_object();
        }
        if (m.alert) {
            w.key("alert");
            write_alert(w, *m.alert);
        }
    }
    w.end_object();
    std::string resp;
    return post_json(cfg_.webhook.url, "", body, cfg_, resp, error);
}

bool Notifier::send_email(const Message& m, std::string& error) {
    net::SmtpOptions o;
    o.host = cfg_.email.host;
    o.port = cfg_.email.port;
    o.tls = cfg_.email.tls;
    o.username = cfg_.email.username;
    o.password = cfg_.email.password;
    o.tls_opt.ca_file = cfg_.ca_file;
    o.tls_opt.pin_sha256 = cfg_.pin;
    net::SmtpMessage msg{cfg_.email.from, cfg_.email.to, m.subject, m.text + "\n\n— SentinelCore SIEM\n", ""};
    return net::smtp_send(o, msg, error);
}

std::vector<ChannelResult> Notifier::send_test(const std::string& who) {
    std::vector<ChannelResult> out;
    std::string text = "Проверка уведомлений SentinelCore.\nЕсли вы это читаете — канал работает.\nОтправил: " + who +
                       "\nВремя: " + format_iso8601(now_ms());
    Message m{"[Sentinel] Тестовое уведомление", "\xE2\x9C\x85 " + text, "\xE2\x9C\x85 " + html_escape(text), nullptr,
              nullptr};
    for (size_t ch = 0; ch < channels_.size(); ++ch) {
        ChannelResult r;
        r.name = channels_[ch].name;
        r.ok = deliver(ch, m, r.error);
        std::lock_guard<std::mutex> lock(mu_);
        ChannelStatus& st = channels_[ch];
        if (r.ok) {
            ++st.sent;
            st.last_ok = now_ms();
        } else {
            ++st.failed;
            st.last_error = r.error;
            st.last_error_at = now_ms();
        }
        out.push_back(r);
    }
    return out;
}

NotifyStats Notifier::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    NotifyStats s;
    s.enabled = !channels_.empty();
    s.min_severity = cfg_.min_severity;
    s.mode = cfg_.mode;
    s.queued = queue_.size();
    s.suppressed = suppressed_;
    s.dropped = dropped_;
    s.digests = digests_;
    s.channels = channels_;
    return s;
}

}  // namespace sentinel
