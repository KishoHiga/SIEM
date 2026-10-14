// SentinelCore — деление правил между потоками обнаружения.
//
// События делятся между потоками по значению одного поля (по умолчанию src_ip): все события
// одного адреса всегда попадают в один и тот же поток. Поэтому правило, которое считает
// «по адресу» (group_by содержит src_ip), можно проверять в каждом потоке на его доле событий —
// результат будет точно таким же, как в одном потоке.
//
// Правила, которые считают по другим полям (например, [user, host]), отдаются отдельному
// «общему» потоку, который видит все события. Цепочки (sequence) и правила, на которые они
// ссылаются, всегда остаются вместе.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "core/event.hpp"
#include "detect/rules.hpp"

namespace sentinel {

struct RulePartition {
    std::vector<Rule> sharded;  // проверяются в каждом потоке на его доле событий
    std::vector<Rule> global;   // проверяются одним потоком на всех событиях
};

// Отключённые правила пропускаются.
RulePartition partition_rules(const std::vector<Rule>& rules, Field key = Field::SrcIp);

// Номер потока для значения ключа (одинаковое значение -> один и тот же поток).
inline size_t shard_of(std::string_view key, size_t shards) {
    uint64_t h = 1469598103934665603ull;  // FNV-1a
    for (unsigned char c : key) {
        h ^= c;
        h *= 1099511628211ull;
    }
    h ^= h >> 29;
    return shards <= 1 ? 0 : size_t(h % shards);
}

}  // namespace sentinel
