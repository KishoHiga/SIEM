// SentinelCore — компактная двоичная запись событий и алертов.
#pragma once

#include <string>
#include <string_view>

#include "core/event.hpp"
#include "core/util.hpp"

namespace sentinel {

void encode_event(const Event& ev, std::string& out);
bool decode_event(Reader& r, Event& ev);

void encode_alert(const Alert& a, std::string& out);
bool decode_alert(Reader& r, Alert& a);

}  // namespace sentinel
