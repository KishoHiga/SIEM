#include "detect/partition.hpp"

#include <numeric>
#include <unordered_map>

namespace sentinel {

namespace {
bool keyed_by(const Rule& r, Field key) {
    for (auto& f : r.group_by)
        if (f.known && f.field == key) return true;
    return false;
}
}  // namespace

RulePartition partition_rules(const std::vector<Rule>& rules, Field key) {
    std::vector<const Rule*> on;
    for (auto& r : rules)
        if (r.enabled) on.push_back(&r);
    std::unordered_map<std::string, size_t> idx;
    for (size_t i = 0; i < on.size(); ++i) idx.emplace(on[i]->id, i);

    // Компоненты связности: цепочка + правила, на которые она ссылается
    std::vector<size_t> parent(on.size());
    std::iota(parent.begin(), parent.end(), size_t(0));
    auto find = [&](size_t x) {
        while (parent[x] != x) x = parent[x] = parent[parent[x]];
        return x;
    };
    for (size_t i = 0; i < on.size(); ++i)
        for (auto& s : on[i]->steps)
            if (!s.rule_id.empty())
                if (auto it = idx.find(s.rule_id); it != idx.end()) parent[find(i)] = find(it->second);

    std::vector<bool> comp_ok(on.size(), true);
    for (size_t i = 0; i < on.size(); ++i)
        if (!keyed_by(*on[i], key)) comp_ok[find(i)] = false;

    RulePartition p;
    for (size_t i = 0; i < on.size(); ++i) (comp_ok[find(i)] ? p.sharded : p.global).push_back(*on[i]);
    return p;
}

}  // namespace sentinel
