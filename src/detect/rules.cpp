#include "detect/rules.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

#include "core/util.hpp"
#include "detect/transform.hpp"
#include "regex/regex.hpp"

namespace sentinel {

FieldRef make_field_ref(std::string_view name) {
    FieldRef r;
    r.name.assign(name);
    if (auto f = field_from_name(name)) {
        r.known = true;
        r.field = *f;
    } else {
        r.known = false;
        r.extra.assign(starts_with(name, "extra.") ? name.substr(6) : name);
    }
    return r;
}

const char* rule_kind_name(Rule::Kind k) {
    switch (k) {
        case Rule::Kind::Match: return "match";
        case Rule::Kind::Threshold: return "threshold";
        case Rule::Kind::Sequence: return "sequence";
    }
    return "match";
}

namespace {

bool parse_transforms(const YNode* n, uint32_t& mask, std::string& err) {
    mask = 0;
    if (!n) return true;
    for (auto& name : n->as_strings()) {
        auto t = transform_from_name(name);
        if (!t) {
            err = "unknown transform '" + name + "'";
            return false;
        }
        mask |= *t;
    }
    return true;
}

bool parse_duration(const YNode& rule, std::string_view key, int64_t& out_ms, std::string& err) {
    const YNode* n = rule.get(key);
    if (!n) return true;
    if (!n->is_scalar()) {
        err = std::string(key) + " must be a number of seconds (or 30s/5m/1h)";
        return false;
    }
    std::string v = n->scalar;
    int64_t mult = 1000;
    if (!v.empty()) {
        char u = v.back();
        if (u == 's') v.pop_back();
        else if (u == 'm') { mult = 60000; v.pop_back(); }
        else if (u == 'h') { mult = 3600000; v.pop_back(); }
        else if (u == 'd') { mult = 86400000; v.pop_back(); }
    }
    auto num = parse_int(v);
    if (!num || *num < 0) {
        err = std::string(key) + ": bad duration '" + n->scalar + "'";
        return false;
    }
    out_ms = *num * mult;
    return true;
}

bool parse_conditions(const YNode* where, std::vector<Condition>& out, std::string& err) {
    if (!where) return true;
    if (!where->is_map()) {
        err = "'where' must be a map of field: condition";
        return false;
    }
    for (auto& kv : where->map) {
        const std::string& fname = kv.first;
        const YNode& v = kv.second;
        if (v.is_scalar() || v.is_seq()) {
            Condition c;
            c.field = make_field_ref(fname);
            c.op = Condition::Op::In;
            c.values = v.as_strings();
            if (c.values.empty()) {
                err = "field '" + fname + "': empty value list";
                return false;
            }
            out.push_back(std::move(c));
            continue;
        }
        if (!v.is_map()) {
            err = "field '" + fname + "': bad condition";
            return false;
        }
        uint32_t tmask = 0;
        if (!parse_transforms(v.get("transform"), tmask, err)) return false;
        bool any = false;
        for (auto& op : v.map) {
            const std::string& o = op.first;
            if (o == "transform") continue;
            Condition c;
            c.field = make_field_ref(fname);
            c.transforms = tmask;
            any = true;
            if (o == "eq" || o == "in" || o == "any") {
                c.op = Condition::Op::In;
                c.values = op.second.as_strings();
            } else if (o == "not" || o == "not_in" || o == "ne") {
                c.op = Condition::Op::NotIn;
                c.values = op.second.as_strings();
            } else if (o == "regex") {
                c.op = Condition::Op::Regex;
                c.values = op.second.as_strings();
            } else if (o == "not_regex") {
                c.op = Condition::Op::NotRegex;
                c.values = op.second.as_strings();
            } else if (o == "contains") {
                c.op = Condition::Op::Contains;
                c.values = op.second.as_strings();
            } else if (o == "exists") {
                std::string b = to_lower(op.second.scalar);
                c.op = (b == "false" || b == "no") ? Condition::Op::Missing : Condition::Op::Exists;
            } else if (o == "gte" || o == "lte" || o == "gt" || o == "lt") {
                auto d = parse_double(op.second.scalar);
                if (!d) {
                    err = "field '" + fname + "': " + o + " needs a number";
                    return false;
                }
                c.number = *d;
                c.op = o == "gte" ? Condition::Op::Gte : o == "lte" ? Condition::Op::Lte
                       : o == "gt" ? Condition::Op::Gt : Condition::Op::Lt;
            } else {
                err = "field '" + fname + "': unknown operator '" + o + "'";
                return false;
            }
            if ((c.op == Condition::Op::In || c.op == Condition::Op::NotIn || c.op == Condition::Op::Regex ||
                 c.op == Condition::Op::NotRegex || c.op == Condition::Op::Contains) &&
                c.values.empty()) {
                err = "field '" + fname + "': operator '" + o + "' needs values";
                return false;
            }
            if (c.op == Condition::Op::Contains && (tmask & T_Lowercase))
                for (auto& s : c.values) s = to_lower(s);
            out.push_back(std::move(c));
        }
        if (!any) {
            err = "field '" + fname + "': no operator";
            return false;
        }
    }
    return true;
}

bool parse_one_rule(const YNode& n, const std::string& file, Rule& r, std::string& err) {
    if (!n.is_map()) {
        err = "rule must be a map";
        return false;
    }
    static const std::set<std::string> known = {
        "id", "name", "description", "severity", "type", "enabled", "tags", "where", "field", "patterns",
        "transform", "group_by", "cooldown", "threshold", "window", "distinct", "steps", "within",
        "message", "tests", "references", "author"};
    for (auto& kv : n.map) {
        if (!known.count(kv.first)) {
            err = "unknown key '" + kv.first + "'";
            return false;
        }
    }
    r.file = file;
    r.id = n.str("id");
    if (r.id.empty()) {
        err = "missing 'id'";
        return false;
    }
    auto fail = [&](const std::string& m) {
        err = "rule " + r.id + ": " + m;
        return false;
    };
    r.name = n.str("name", r.id);
    r.description = n.str("description");
    r.message = n.str("message");
    if (auto s = severity_from_name(n.str("severity", "medium"))) r.severity = *s;
    else return fail("bad severity (info|low|medium|high|critical)");
    if (auto e = n.boolean("enabled")) r.enabled = *e;
    r.tags = n.strings("tags");

    std::string type = to_lower(n.str("type", "match"));
    if (type == "match" || type == "pattern") r.kind = Rule::Kind::Match;
    else if (type == "threshold") r.kind = Rule::Kind::Threshold;
    else if (type == "sequence" || type == "correlation") r.kind = Rule::Kind::Sequence;
    else return fail("bad type '" + type + "' (match|threshold|sequence)");

    if (!parse_conditions(n.get("where"), r.where, err)) return fail(err);

    // Сокращение: patterns + field + transform == условие regex
    if (const YNode* pats = n.get("patterns")) {
        Condition c;
        c.field = make_field_ref(n.str("field", "message"));
        c.op = Condition::Op::Regex;
        c.values = pats->as_strings();
        if (c.values.empty()) return fail("'patterns' is empty");
        if (!parse_transforms(n.get("transform"), c.transforms, err)) return fail(err);
        r.where.push_back(std::move(c));
    } else if (n.get("field") || n.get("transform")) {
        return fail("'field'/'transform' are used together with 'patterns'");
    }

    for (auto& g : n.strings("group_by")) r.group_by.push_back(make_field_ref(g));
    if (r.group_by.empty()) r.group_by.push_back(make_field_ref("src_ip"));

    if (!parse_duration(n, "cooldown", r.cooldown_ms, err)) return fail(err);

    if (r.kind == Rule::Kind::Threshold) {
        auto t = n.integer("threshold");
        if (!t || *t < 1) return fail("threshold rule needs 'threshold' >= 1");
        r.threshold = uint32_t(*t);
        if (!parse_duration(n, "window", r.window_ms, err)) return fail(err);
        if (r.window_ms <= 0) return fail("threshold rule needs 'window' (seconds)");
        std::string d = n.str("distinct");
        if (!d.empty()) r.distinct = make_field_ref(d);
    }

    if (r.kind == Rule::Kind::Sequence) {
        const YNode* steps = n.get("steps");
        if (!steps || !steps->is_seq() || steps->seq.size() < 2) return fail("sequence rule needs 'steps' (2 or more)");
        for (auto& s : steps->seq) {
            Rule::Step st;
            if (s.is_map() && s.get("rule")) {
                st.rule_id = s.str("rule");
            } else if (s.is_map() && s.get("where")) {
                if (!parse_conditions(s.get("where"), st.where, err)) return fail(err);
            } else {
                return fail("each step needs 'rule: ID' or 'where: {...}'");
            }
            r.steps.push_back(std::move(st));
        }
        if (!parse_duration(n, "within", r.within_ms, err)) return fail(err);
        if (r.within_ms <= 0) return fail("sequence rule needs 'within' (seconds)");
    }

    if (r.kind == Rule::Kind::Match && r.where.empty()) return fail("match rule needs 'where' or 'patterns'");
    if (r.kind == Rule::Kind::Threshold && r.where.empty()) return fail("threshold rule needs 'where'");

    if (const YNode* t = n.get("tests")) {
        r.tests.match = t->strings("match");
        r.tests.no_match = t->strings("no_match");
        if (auto rep = t->integer("repeat")) r.tests.repeat = int(*rep);
    }
    return true;
}

}  // namespace

bool parse_rules_yaml(std::string_view text, const std::string& file, std::vector<Rule>& out, std::string& error) {
    YNode root;
    if (!parse_yaml(text, root, error)) return false;
    if (root.is_null()) return true;
    if (root.is_seq()) {
        for (auto& item : root.seq) {
            Rule r;
            if (!parse_one_rule(item, file, r, error)) return false;
            out.push_back(std::move(r));
        }
        return true;
    }
    if (const YNode* list = root.get("rules"); list && root.map.size() == 1) {
        for (auto& item : list->seq) {
            Rule r;
            if (!parse_one_rule(item, file, r, error)) return false;
            out.push_back(std::move(r));
        }
        return true;
    }
    Rule r;
    if (!parse_one_rule(root, file, r, error)) return false;
    out.push_back(std::move(r));
    return true;
}

void validate_rules(std::vector<Rule>& rules, std::vector<std::string>& errors) {
    std::set<std::string> ids;
    std::vector<Rule> ok;
    // id уникальны
    for (auto& r : rules) {
        if (!ids.insert(r.id).second) {
            errors.push_back(r.file + ": duplicate rule id " + r.id);
            continue;
        }
        // синтаксис регулярок
        bool good = true;
        auto check = [&](const std::vector<Condition>& conds) {
            for (auto& c : conds) {
                if (c.op != Condition::Op::Regex && c.op != Condition::Op::NotRegex) continue;
                for (auto& p : c.values) {
                    std::string e;
                    if (!rx::validate(p, &e)) {
                        errors.push_back(r.file + ": rule " + r.id + ": bad regex '" + p + "': " + e);
                        good = false;
                    }
                }
            }
        };
        check(r.where);
        for (auto& s : r.steps) check(s.where);
        if (good) ok.push_back(std::move(r));
    }
    // ссылки в sequence
    std::set<std::string> present;
    for (auto& r : ok) present.insert(r.id);
    std::vector<Rule> final_rules;
    for (auto& r : ok) {
        bool good = true;
        for (auto& s : r.steps) {
            if (s.rule_id.empty()) continue;
            if (s.rule_id == r.id || !present.count(s.rule_id)) {
                errors.push_back(r.file + ": rule " + r.id + ": step refers to unknown rule " + s.rule_id);
                good = false;
            }
        }
        if (good) final_rules.push_back(std::move(r));
    }
    rules.swap(final_rules);
}

RuleLoadResult load_rules_dir(const std::string& dir) {
    namespace fs = std::filesystem;
    RuleLoadResult res;
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) {
        res.errors.push_back(dir + ": rules directory not found");
        return res;
    }
    std::vector<fs::path> files;
    for (auto& e : fs::directory_iterator(dir, ec)) {
        auto ext = e.path().extension().string();
        if (e.is_regular_file() && (ext == ".yml" || ext == ".yaml")) files.push_back(e.path());
    }
    std::sort(files.begin(), files.end());
    for (auto& p : files) {
        std::ifstream in(p, std::ios::binary);
        std::stringstream ss;
        ss << in.rdbuf();
        std::string err;
        std::vector<Rule> rules;
        if (!parse_rules_yaml(ss.str(), p.filename().string(), rules, err)) {
            res.errors.push_back(p.filename().string() + ": " + err);
            continue;
        }
        for (auto& r : rules) res.rules.push_back(std::move(r));
    }
    validate_rules(res.rules, res.errors);
    return res;
}

}  // namespace sentinel
