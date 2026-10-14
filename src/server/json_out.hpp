// SentinelCore — единый JSON-вид событий и алертов для API и живой ленты.
#pragma once

#include "core/event.hpp"
#include "core/json.hpp"

namespace sentinel {

void write_event(JsonWriter& w, const Event& e);
// incident_id — номер инцидента, в который попал алерт (0 — не писать).
void write_alert(JsonWriter& w, const Alert& a, uint64_t incident_id = 0);
// Короткая сводка события для живой ленты.
void write_event_summary(JsonWriter& w, const Event& e);

}  // namespace sentinel
