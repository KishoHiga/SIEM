#include "server/live_feed.hpp"

#include "core/json.hpp"
#include "core/util.hpp"
#include "server/json_out.hpp"

namespace sentinel {

void LiveFeed::set_sink(Sink sink) {
    std::lock_guard<std::mutex> lock(mu_);
    sink_ = std::move(sink);
}

void LiveFeed::on_stored(const std::vector<Event>& events, const std::vector<Alert>& alerts) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!sink_) return;
    count_ += events.size();
    size_t from = events.size() > kRecent ? events.size() - kRecent : 0;
    for (size_t i = from; i < events.size(); ++i) {
        std::string js;
        JsonWriter w(js);
        write_event_summary(w, events[i]);
        recent_.push_back(std::move(js));
        if (recent_.size() > kRecent) recent_.pop_front();
    }
    for (auto& a : alerts) {
        if (alerts_.size() >= 200) break;  // лавина алертов — остальное видно на странице алертов
        std::string js;
        JsonWriter w(js);
        write_alert(w, a);
        alerts_.push_back(std::move(js));
    }
}

void LiveFeed::tick(int64_t now) {
    std::string msg;
    Sink sink;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!sink_) return;
        bool idle = count_ == 0 && alerts_.empty();
        if (idle && now - last_sent_ < 5000) return;  // пульс раз в 5 с, чтобы панель видела связь
        JsonWriter w(msg);
        w.begin_object().kv("type", "tick").kv("t", format_iso8601(now)).kv("events", count_);
        w.key("recent").begin_array();
        for (auto& r : recent_) w.raw(r);
        w.end_array().key("alerts").begin_array();
        for (auto& a : alerts_) w.raw(a);
        w.end_array().end_object();
        recent_.clear();
        alerts_.clear();
        count_ = 0;
        last_sent_ = now;
        sink = sink_;
    }
    sink(msg);
}

}  // namespace sentinel
