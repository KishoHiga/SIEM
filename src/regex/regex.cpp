#include "regex/regex.hpp"

#include <algorithm>
#include <cstring>
#include <map>
#include <array>

namespace sentinel::rx {

namespace {

constexpr int kMaxRepeat = 1000;
constexpr size_t kMaxNfaStates = 250000;
constexpr int kMaxDepth = 200;
constexpr size_t kMaxTransitionCells = 1u << 20;  // ~4 МБ таблицы переходов на автомат

inline bool is_digit_c(char c) { return c >= '0' && c <= '9'; }
inline bool is_alpha_c(uint8_t c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
inline bool is_alnum_c(uint8_t c) { return is_alpha_c(c) || (c >= '0' && c <= '9'); }
inline uint8_t other_case(uint8_t c) {
    if (c >= 'a' && c <= 'z') return uint8_t(c - 32);
    if (c >= 'A' && c <= 'Z') return uint8_t(c + 32);
    return c;
}

// ---------------- Дерево разбора ----------------

enum class NK : uint8_t { Empty, Set, Cat, Alt, Rep, Bol, Eol };

struct Node {
    NK k = NK::Empty;
    ByteSet set;
    std::vector<int> kids;
    int min = 0, max = 0;  // для Rep; max = -1 означает бесконечность
};

ByteSet class_digit() {
    ByteSet s;
    s.set_range('0', '9');
    return s;
}
ByteSet class_word() {
    ByteSet s;
    s.set_range('a', 'z');
    s.set_range('A', 'Z');
    s.set_range('0', '9');
    s.set('_');
    return s;
}
ByteSet class_space() {
    ByteSet s;
    for (uint8_t c : {' ', '\t', '\n', '\r', '\f', '\v'}) s.set(c);
    return s;
}

class PatternParser {
public:
    PatternParser(std::string_view p, std::vector<Node>& pool) : p_(p), pool_(pool) {}

    bool parse(int& root, std::string& err) {
        root = parse_alt();
        if (!failed_ && pos_ < p_.size()) fail("unmatched ')'");
        if (failed_) {
            err = err_;
            return false;
        }
        return true;
    }

private:
    std::string_view p_;
    size_t pos_ = 0;
    std::vector<Node>& pool_;
    bool ci_ = false;
    bool dotall_ = false;
    bool failed_ = false;
    std::string err_;
    int depth_ = 0;

    int add(Node n) {
        pool_.push_back(std::move(n));
        return int(pool_.size() - 1);
    }
    int add_kind(NK k) {
        Node n;
        n.k = k;
        return add(std::move(n));
    }
    int fail(const std::string& m) {
        if (!failed_) {
            failed_ = true;
            err_ = m + " (position " + std::to_string(pos_) + ")";
        }
        return add_kind(NK::Empty);
    }

    void add_byte(ByteSet& s, uint8_t c) const {
        s.set(c);
        if (ci_ && is_alpha_c(c)) s.set(other_case(c));
    }

    int literal(uint8_t c) {
        Node n;
        n.k = NK::Set;
        add_byte(n.set, c);
        return add(std::move(n));
    }

    int parse_alt() {
        if (++depth_ > kMaxDepth) return fail("pattern nesting too deep");
        std::vector<int> alts;
        alts.push_back(parse_cat());
        while (!failed_ && pos_ < p_.size() && p_[pos_] == '|') {
            ++pos_;
            alts.push_back(parse_cat());
        }
        --depth_;
        if (alts.size() == 1) return alts[0];
        Node n;
        n.k = NK::Alt;
        n.kids = std::move(alts);
        return add(std::move(n));
    }

    int parse_cat() {
        std::vector<int> items;
        while (!failed_ && pos_ < p_.size() && p_[pos_] != '|' && p_[pos_] != ')') {
            int a = parse_repeat();
            if (a >= 0) items.push_back(a);
        }
        if (items.empty()) return add_kind(NK::Empty);
        if (items.size() == 1) return items[0];
        Node n;
        n.k = NK::Cat;
        n.kids = std::move(items);
        return add(std::move(n));
    }

    bool parse_number(size_t& p, int& out) const {
        size_t st = p;
        long v = 0;
        while (p < p_.size() && is_digit_c(p_[p])) {
            v = v * 10 + (p_[p] - '0');
            if (v > 100000) v = 100000;
            ++p;
        }
        if (p == st) return false;
        out = int(v);
        return true;
    }

    // На '{'. false — это не квантификатор (тогда '{' — обычный символ).
    bool parse_braces(int& mn, int& mx) {
        size_t p = pos_ + 1;
        if (!parse_number(p, mn)) return false;
        if (p < p_.size() && p_[p] == '}') {
            mx = mn;
        } else if (p < p_.size() && p_[p] == ',') {
            ++p;
            if (p < p_.size() && p_[p] == '}') {
                mx = -1;
            } else if (!parse_number(p, mx)) {
                return false;
            }
        } else {
            return false;
        }
        if (p >= p_.size() || p_[p] != '}') return false;
        pos_ = p + 1;
        if (mn > kMaxRepeat || mx > kMaxRepeat) fail("repeat count too large (max 1000)");
        else if (mx != -1 && mx < mn) fail("bad repeat range");
        return true;
    }

    int parse_repeat() {
        int atom = parse_atom();
        if (atom < 0 || failed_) return atom;
        while (pos_ < p_.size()) {
            char c = p_[pos_];
            int mn, mx;
            if (c == '*') {
                mn = 0;
                mx = -1;
                ++pos_;
            } else if (c == '+') {
                mn = 1;
                mx = -1;
                ++pos_;
            } else if (c == '?') {
                mn = 0;
                mx = 1;
                ++pos_;
            } else if (c == '{') {
                if (!parse_braces(mn, mx)) break;
                if (failed_) return atom;
            } else {
                break;
            }
            if (pos_ < p_.size() && p_[pos_] == '?') {
                ++pos_;  // ленивый квантификатор: для ответа "есть/нет совпадения" не важен
            } else if (pos_ < p_.size() && p_[pos_] == '+') {
                return fail("possessive quantifiers are not supported");
            }
            NK ak = pool_[size_t(atom)].k;
            if (ak == NK::Bol || ak == NK::Eol) return fail("quantifier after anchor");
            Node n;
            n.k = NK::Rep;
            n.kids = {atom};
            n.min = mn;
            n.max = mx;
            atom = add(std::move(n));
        }
        return atom;
    }

    // После '\'. Возвращает байт (0..255), -1 если это класс (заполнен out), -2 при ошибке.
    int escape(ByteSet& out) {
        if (pos_ >= p_.size()) {
            fail("trailing backslash");
            return -2;
        }
        uint8_t c = uint8_t(p_[pos_++]);
        switch (c) {
            case 'd': out = class_digit(); return -1;
            case 'D': out = class_digit(); out.invert(); return -1;
            case 'w': out = class_word(); return -1;
            case 'W': out = class_word(); out.invert(); return -1;
            case 's': out = class_space(); return -1;
            case 'S': out = class_space(); out.invert(); return -1;
            case 'n': return '\n';
            case 't': return '\t';
            case 'r': return '\r';
            case 'f': return '\f';
            case 'v': return '\v';
            case 'e': return 0x1b;
            case '0': return 0;
            case 'x': {
                int v = 0;
                for (int k = 0; k < 2; ++k) {
                    if (pos_ >= p_.size()) {
                        fail("bad \\x escape");
                        return -2;
                    }
                    char h = p_[pos_++];
                    int d = (h >= '0' && h <= '9') ? h - '0'
                            : (h >= 'a' && h <= 'f') ? h - 'a' + 10
                            : (h >= 'A' && h <= 'F') ? h - 'A' + 10
                                                     : -1;
                    if (d < 0) {
                        fail("bad \\x escape");
                        return -2;
                    }
                    v = v * 16 + d;
                }
                return v;
            }
            default:
                if (is_alnum_c(c)) {
                    --pos_;
                    fail(std::string("unsupported escape \\") + char(c) +
                         " (\\b, backreferences and \\p are not supported)");
                    return -2;
                }
                return c;  // \. \\ \/ \- \[ и т.п.
        }
    }

    int parse_escape_atom() {
        ++pos_;  // '\'
        ByteSet s;
        int r = escape(s);
        if (r == -2) return add_kind(NK::Empty);
        if (r == -1) {
            Node n;
            n.k = NK::Set;
            n.set = s;
            return add(std::move(n));
        }
        return literal(uint8_t(r));
    }

    void add_range(ByteSet& s, int lo, int hi) const {
        for (int c = lo; c <= hi; ++c) add_byte(s, uint8_t(c));
    }

    bool posix_class(ByteSet& s) {
        // на "[:"
        size_t end = p_.find(":]", pos_ + 2);
        if (end == std::string_view::npos) return false;
        std::string_view name = p_.substr(pos_ + 2, end - pos_ - 2);
        ByteSet t;
        if (name == "alpha") {
            t.set_range('a', 'z');
            t.set_range('A', 'Z');
        } else if (name == "digit") {
            t = class_digit();
        } else if (name == "alnum") {
            t.set_range('a', 'z');
            t.set_range('A', 'Z');
            t.set_range('0', '9');
        } else if (name == "space") {
            t = class_space();
        } else if (name == "upper") {
            t.set_range('A', 'Z');
        } else if (name == "lower") {
            t.set_range('a', 'z');
        } else if (name == "xdigit") {
            t.set_range('0', '9');
            t.set_range('a', 'f');
            t.set_range('A', 'F');
        } else if (name == "word") {
            t = class_word();
        } else if (name == "punct") {
            for (int c = 33; c < 127; ++c)
                if (!is_alnum_c(uint8_t(c))) t.set(uint8_t(c));
        } else {
            return false;
        }
        for (int c = 0; c < 256; ++c)
            if (t.has(uint8_t(c))) add_byte(s, uint8_t(c));
        pos_ = end + 2;
        return true;
    }

    int parse_class() {
        ++pos_;  // '['
        ByteSet s;
        bool neg = false;
        if (pos_ < p_.size() && p_[pos_] == '^') {
            neg = true;
            ++pos_;
        }
        bool first = true;
        while (true) {
            if (pos_ >= p_.size()) return fail("unterminated character class");
            char c = p_[pos_];
            if (c == ']' && !first) {
                ++pos_;
                break;
            }
            first = false;
            int lo;
            if (c == '[' && pos_ + 1 < p_.size() && p_[pos_ + 1] == ':') {
                if (posix_class(s)) continue;
                lo = '[';
                ++pos_;
            } else if (c == '\\') {
                ++pos_;
                ByteSet t;
                int r = escape(t);
                if (r == -2) return add_kind(NK::Empty);
                if (r == -1) {
                    for (int b = 0; b < 256; ++b)
                        if (t.has(uint8_t(b))) s.set(uint8_t(b));
                    continue;
                }
                lo = r;
            } else {
                lo = uint8_t(c);
                ++pos_;
            }
            if (pos_ + 1 < p_.size() && p_[pos_] == '-' && p_[pos_ + 1] != ']') {
                ++pos_;
                int hi;
                if (p_[pos_] == '\\') {
                    ++pos_;
                    ByteSet t;
                    int r = escape(t);
                    if (r < 0) return fail("bad character range");
                    hi = r;
                } else {
                    hi = uint8_t(p_[pos_]);
                    ++pos_;
                }
                if (hi < lo) return fail("bad character range");
                add_range(s, lo, hi);
            } else {
                add_range(s, lo, lo);
            }
        }
        if (neg) s.invert();
        Node n;
        n.k = NK::Set;
        n.set = s;
        return add(std::move(n));
    }

    int parse_group() {
        ++pos_;  // '('
        const bool saved_ci = ci_, saved_dot = dotall_;
        if (pos_ < p_.size() && p_[pos_] == '?') {
            ++pos_;
            bool on = true, any = false;
            bool new_ci = ci_, new_dot = dotall_;
            while (pos_ < p_.size()) {
                char f = p_[pos_];
                if (f == 'i') {
                    new_ci = on;
                    any = true;
                } else if (f == 's') {
                    new_dot = on;
                    any = true;
                } else if (f == 'm') {
                    any = true;  // многострочный режим: строки событий однострочные, игнорируем
                } else if (f == '-') {
                    on = false;
                } else {
                    break;
                }
                ++pos_;
            }
            if (pos_ >= p_.size()) return fail("unterminated group");
            char f = p_[pos_];
            if (f == ')' && (any || !on)) {
                ++pos_;
                ci_ = new_ci;
                dotall_ = new_dot;
                return -1;  // флаги действуют до конца объемлющей группы
            }
            if (f == ':') {
                ++pos_;
                ci_ = new_ci;
                dotall_ = new_dot;
            } else if (!any && on && (f == '=' || f == '!')) {
                return fail("lookahead is not supported");
            } else if (!any && on && f == '<' && pos_ + 1 < p_.size() &&
                       (p_[pos_ + 1] == '=' || p_[pos_ + 1] == '!')) {
                return fail("lookbehind is not supported");
            } else if (!any && on && (f == '<' || (f == 'P' && pos_ + 1 < p_.size() && p_[pos_ + 1] == '<'))) {
                // именованная группа: имя пропускаем
                size_t close = p_.find('>', pos_);
                if (close == std::string_view::npos) return fail("bad named group");
                pos_ = close + 1;
            } else {
                return fail("unknown group syntax");
            }
        }
        int r = parse_alt();
        if (failed_) return r;
        if (pos_ >= p_.size() || p_[pos_] != ')') return fail("missing ')'");
        ++pos_;
        ci_ = saved_ci;
        dotall_ = saved_dot;
        return r;
    }

    int parse_atom() {
        char c = p_[pos_];
        switch (c) {
            case '(': return parse_group();
            case '[': return parse_class();
            case '.': {
                ++pos_;
                Node n;
                n.k = NK::Set;
                n.set.invert();
                if (!dotall_) n.set.w[0] &= ~(uint64_t(1) << '\n');
                return add(std::move(n));
            }
            case '^': ++pos_; return add_kind(NK::Bol);
            case '$': ++pos_; return add_kind(NK::Eol);
            case '\\': return parse_escape_atom();
            case '*':
            case '+':
            case '?': return fail("nothing to repeat");
            default: ++pos_; return literal(uint8_t(c));
        }
    }
};

// ---------------- NFA ----------------

enum : uint8_t { S_BYTE, S_SPLIT, S_EPS, S_MATCH, S_BOL, S_EOL };

struct NState {
    uint8_t kind = S_EPS;
    int32_t out = -1;
    int32_t out1 = -1;
    uint32_t arg = 0;  // BYTE: номер набора байтов; MATCH: номер шаблона
};

struct Frag {
    int32_t start = -1;
    std::vector<std::pair<int32_t, bool>> outs;  // (состояние, это out1?)
};

}  // namespace

// ---------------- Реализация MultiMatcher ----------------

struct MultiMatcher::Impl {
    std::vector<std::string> patterns;
    std::vector<Node> pool;
    std::vector<int> roots;
    bool compiled = false;

    std::vector<NState> st;
    std::vector<ByteSet> sets;
    std::map<std::array<uint64_t, 4>, uint32_t> set_index;
    std::vector<int32_t> starts;
    std::string build_error;

    uint8_t eq[256] = {};
    int ncls = 1;
    std::vector<uint8_t> rep;

    struct DState {
        std::vector<int32_t> nfa;
        std::vector<uint32_t> matches;
        bool has_eol = false;
    };
    std::vector<DState> ds;
    std::vector<uint8_t> has_match;  // быстрый флаг "в состоянии есть совпадения"
    std::vector<int32_t> trans;
    std::unordered_map<std::string, int32_t> index;
    int32_t start_state = -1;
    size_t max_states = 4096;
    uint64_t resets = 0;

    // Рабочие буферы
    std::vector<uint32_t> mark;
    uint32_t gen = 0;
    std::vector<int32_t> stack, seeds, tmp_set;
    std::vector<uint32_t> tmp_matches;
    bool tmp_eol = false;
    std::vector<uint8_t> seen;
    std::string key;

    // ---- построение NFA ----
    int32_t new_state(uint8_t kind) {
        if (st.size() >= kMaxNfaStates) {
            if (build_error.empty()) build_error = "pattern set is too large";
            if (!st.empty()) return 0;
        }
        NState s;
        s.kind = kind;
        st.push_back(s);
        return int32_t(st.size() - 1);
    }

    void patch(const std::vector<std::pair<int32_t, bool>>& outs, int32_t target) {
        for (auto& o : outs) {
            if (o.second)
                st[size_t(o.first)].out1 = target;
            else
                st[size_t(o.first)].out = target;
        }
    }

    uint32_t intern_set(const ByteSet& s) {
        std::array<uint64_t, 4> k{s.w[0], s.w[1], s.w[2], s.w[3]};
        auto it = set_index.find(k);
        if (it != set_index.end()) return it->second;
        uint32_t id = uint32_t(sets.size());
        sets.push_back(s);
        set_index.emplace(k, id);
        return id;
    }

    Frag single(uint8_t kind, uint32_t arg = 0) {
        int32_t s = new_state(kind);
        st[size_t(s)].arg = arg;
        return Frag{s, {{s, false}}};
    }

    Frag build(int ni) {
        if (!build_error.empty()) return single(S_EPS);
        const Node& n = pool[size_t(ni)];
        switch (n.k) {
            case NK::Empty: return single(S_EPS);
            case NK::Set: return single(S_BYTE, intern_set(n.set));
            case NK::Bol: return single(S_BOL);
            case NK::Eol: return single(S_EOL);
            case NK::Cat: {
                Frag f = build(n.kids[0]);
                for (size_t i = 1; i < n.kids.size(); ++i) {
                    Frag g = build(n.kids[i]);
                    patch(f.outs, g.start);
                    f.outs = std::move(g.outs);
                }
                return f;
            }
            case NK::Alt: {
                std::vector<Frag> fr;
                fr.reserve(n.kids.size());
                for (int k : n.kids) fr.push_back(build(k));
                Frag res;
                int32_t next = fr.back().start;
                for (size_t i = fr.size() - 1; i-- > 0;) {
                    int32_t s = new_state(S_SPLIT);
                    st[size_t(s)].out = fr[i].start;
                    st[size_t(s)].out1 = next;
                    next = s;
                }
                res.start = next;
                for (auto& f : fr) res.outs.insert(res.outs.end(), f.outs.begin(), f.outs.end());
                return res;
            }
            case NK::Rep: {
                const int x = n.kids[0];
                const int mn = n.min, mx = n.max;
                if (mn == 0 && mx == 0) return single(S_EPS);
                Frag result;
                bool have = false;
                auto append = [&](Frag g) {
                    if (!have) {
                        result = std::move(g);
                        have = true;
                    } else {
                        patch(result.outs, g.start);
                        result.outs = std::move(g.outs);
                    }
                };
                for (int i = 0; i < mn; ++i) {
                    Frag g = build(x);
                    if (i == mn - 1 && mx == -1) {
                        int32_t loop = new_state(S_SPLIT);
                        st[size_t(loop)].out = g.start;
                        patch(g.outs, loop);
                        append(Frag{g.start, {{loop, true}}});
                    } else {
                        append(std::move(g));
                    }
                    if (!build_error.empty()) return single(S_EPS);
                }
                if (mx == -1 && mn == 0) {
                    Frag g = build(x);
                    int32_t s = new_state(S_SPLIT);
                    st[size_t(s)].out = g.start;
                    patch(g.outs, s);
                    append(Frag{s, {{s, true}}});
                } else if (mx > mn) {
                    for (int i = mn; i < mx; ++i) {
                        Frag g = build(x);
                        int32_t s = new_state(S_SPLIT);
                        st[size_t(s)].out = g.start;
                        Frag of{s, std::move(g.outs)};
                        of.outs.push_back({s, true});
                        append(std::move(of));
                        if (!build_error.empty()) return single(S_EPS);
                    }
                }
                return result;
            }
        }
        return single(S_EPS);
    }

    void compute_byte_classes() {
        uint16_t cls[256] = {};
        int n = 1;
        for (auto& s : sets) {
            std::vector<int> map_in(size_t(n), -1), map_out(size_t(n), -1);
            int nn = 0;
            uint16_t ncl[256];
            for (int b = 0; b < 256; ++b) {
                int o = cls[b];
                int& m = s.has(uint8_t(b)) ? map_in[size_t(o)] : map_out[size_t(o)];
                if (m < 0) m = nn++;
                ncl[b] = uint16_t(m);
            }
            std::memcpy(cls, ncl, sizeof(cls));
            n = nn;
        }
        ncls = n;
        rep.assign(size_t(n), 0);
        std::vector<bool> got(size_t(n), false);
        for (int b = 0; b < 256; ++b) {
            eq[b] = uint8_t(cls[b]);
            if (!got[cls[b]]) {
                got[cls[b]] = true;
                rep[cls[b]] = uint8_t(b);
            }
        }
    }

    // ---- ленивый DFA ----

    void closure(bool at_begin, bool at_end) {
        if (++gen == 0) {
            std::fill(mark.begin(), mark.end(), 0);
            gen = 1;
        }
        tmp_set.clear();
        tmp_matches.clear();
        tmp_eol = false;
        stack.assign(seeds.begin(), seeds.end());
        while (!stack.empty()) {
            int32_t s = stack.back();
            stack.pop_back();
            if (s < 0 || mark[size_t(s)] == gen) continue;
            mark[size_t(s)] = gen;
            const NState& x = st[size_t(s)];
            switch (x.kind) {
                case S_BYTE: tmp_set.push_back(s); break;
                case S_MATCH: tmp_matches.push_back(x.arg); break;
                case S_SPLIT:
                    stack.push_back(x.out1);
                    stack.push_back(x.out);
                    break;
                case S_EPS: stack.push_back(x.out); break;
                case S_BOL:
                    if (at_begin) stack.push_back(x.out);
                    break;
                case S_EOL:
                    if (at_end) {
                        stack.push_back(x.out);
                    } else {
                        tmp_set.push_back(s);
                        tmp_eol = true;
                    }
                    break;
            }
        }
        std::sort(tmp_set.begin(), tmp_set.end());
        std::sort(tmp_matches.begin(), tmp_matches.end());
        tmp_matches.erase(std::unique(tmp_matches.begin(), tmp_matches.end()), tmp_matches.end());
    }

    int32_t intern() {
        key.assign(reinterpret_cast<const char*>(tmp_set.data()), tmp_set.size() * sizeof(int32_t));
        key.push_back('|');
        key.append(reinterpret_cast<const char*>(tmp_matches.data()), tmp_matches.size() * sizeof(uint32_t));
        auto it = index.find(key);
        if (it != index.end()) return it->second;
        int32_t id = int32_t(ds.size());
        DState d;
        d.nfa = tmp_set;
        d.matches = tmp_matches;
        d.has_eol = tmp_eol;
        has_match.push_back(d.matches.empty() ? 0 : 1);
        ds.push_back(std::move(d));
        trans.resize(ds.size() * size_t(ncls), -1);
        index.emplace(key, id);
        return id;
    }

    void build_start() {
        seeds.assign(starts.begin(), starts.end());
        closure(true, false);
        start_state = intern();
    }

    void reset_cache() {
        ++resets;
        ds.clear();
        has_match.clear();
        trans.clear();
        index.clear();
        start_state = -1;
    }

    // Вычислить переход; reset=true если кэш был сброшен (номер s больше недействителен).
    int32_t compute_next(int32_t s, int c, bool& reset) {
        reset = false;
        seeds.clear();
        const uint8_t b = rep[size_t(c)];
        for (int32_t x : ds[size_t(s)].nfa) {
            const NState& n = st[size_t(x)];
            if (n.kind == S_BYTE && sets[n.arg].has(b)) seeds.push_back(n.out);
        }
        seeds.insert(seeds.end(), starts.begin(), starts.end());  // поиск в любом месте строки
        closure(false, false);
        if (ds.size() >= max_states) {
            std::vector<int32_t> keep_set = tmp_set;
            std::vector<uint32_t> keep_m = tmp_matches;
            bool keep_eol = tmp_eol;
            reset_cache();
            build_start();
            tmp_set = std::move(keep_set);
            tmp_matches = std::move(keep_m);
            tmp_eol = keep_eol;
            reset = true;
        }
        return intern();
    }

    bool record(const std::vector<uint32_t>& ms, std::vector<uint32_t>* out, size_t& found) {
        bool any = false;
        for (uint32_t id : ms) {
            if (!seen[id]) {
                seen[id] = 1;
                ++found;
                any = true;
                if (out) out->push_back(id);
            }
        }
        return any;
    }

    bool run(std::string_view text, std::vector<uint32_t>* out, bool stop_first) {
        if (starts.empty()) return false;
        if (start_state < 0) build_start();
        const size_t total = patterns.size();
        size_t found = 0;
        std::vector<uint32_t> local;
        std::vector<uint32_t>* sink = out ? out : &local;
        const size_t base = sink->size();

        int32_t s = start_state;
        if (!ds[size_t(s)].matches.empty()) {
            record(ds[size_t(s)].matches, sink, found);
            if (stop_first || found == total) goto done;
        }
        {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(text.data());
            const uint8_t* e = p + text.size();
            const size_t nc = size_t(ncls);
            for (; p < e; ++p) {
                const int c = eq[*p];
                int32_t nx = trans[size_t(s) * nc + size_t(c)];
                if (nx < 0) {
                    bool reset;
                    nx = compute_next(s, c, reset);
                    if (!reset) trans[size_t(s) * nc + size_t(c)] = nx;
                }
                s = nx;
                if (has_match[size_t(s)] && record(ds[size_t(s)].matches, sink, found)) {
                    if (stop_first || found == total) goto done;
                }
            }
        }
        if (ds[size_t(s)].has_eol) {
            seeds.clear();
            for (int32_t x : ds[size_t(s)].nfa)
                if (st[size_t(x)].kind == S_EOL) seeds.push_back(st[size_t(x)].out);
            closure(text.empty(), true);
            record(tmp_matches, sink, found);
        }
    done:
        for (size_t i = base; i < sink->size(); ++i) seen[(*sink)[i]] = 0;
        return found > 0;
    }
};

MultiMatcher::MultiMatcher() : impl_(std::make_unique<Impl>()) {}
MultiMatcher::~MultiMatcher() = default;
MultiMatcher::MultiMatcher(MultiMatcher&&) noexcept = default;
MultiMatcher& MultiMatcher::operator=(MultiMatcher&&) noexcept = default;

int MultiMatcher::add(std::string_view pattern, std::string* error) {
    if (impl_->compiled) {
        if (error) *error = "matcher already compiled";
        return -1;
    }
    int root;
    std::string err;
    PatternParser p(pattern, impl_->pool);
    if (!p.parse(root, err)) {
        if (error) *error = err;
        return -1;
    }
    impl_->patterns.emplace_back(pattern);
    impl_->roots.push_back(root);
    return int(impl_->patterns.size() - 1);
}

bool MultiMatcher::compile(std::string* error) {
    Impl& m = *impl_;
    if (m.compiled) return true;
    for (size_t i = 0; i < m.roots.size(); ++i) {
        Frag f = m.build(m.roots[i]);
        int32_t ms = m.new_state(S_MATCH);
        m.st[size_t(ms)].arg = uint32_t(i);
        m.patch(f.outs, ms);
        m.starts.push_back(f.start);
        if (!m.build_error.empty()) {
            if (error) *error = m.build_error;
            return false;
        }
    }
    m.pool.clear();
    m.pool.shrink_to_fit();
    m.compute_byte_classes();
    m.max_states = std::max<size_t>(64, kMaxTransitionCells / size_t(m.ncls));
    m.mark.assign(m.st.size(), 0);
    m.seen.assign(m.patterns.size(), 0);
    m.compiled = true;
    return true;
}

size_t MultiMatcher::pattern_count() const { return impl_->patterns.size(); }
bool MultiMatcher::compiled() const { return impl_->compiled; }

bool MultiMatcher::scan(std::string_view text, std::vector<uint32_t>& out) {
    if (!impl_->compiled) return false;
    return impl_->run(text, &out, false);
}

bool MultiMatcher::any(std::string_view text) {
    if (!impl_->compiled) return false;
    return impl_->run(text, nullptr, true);
}

size_t MultiMatcher::dfa_state_count() const { return impl_->ds.size(); }
size_t MultiMatcher::nfa_state_count() const { return impl_->st.size(); }
size_t MultiMatcher::byte_class_count() const { return size_t(impl_->ncls); }
uint64_t MultiMatcher::cache_resets() const { return impl_->resets; }

bool validate(std::string_view pattern, std::string* error) {
    std::vector<Node> pool;
    int root;
    std::string err;
    PatternParser p(pattern, pool);
    if (!p.parse(root, err)) {
        if (error) *error = err;
        return false;
    }
    return true;
}

bool Regex::compile(std::string_view pattern, std::string* error) {
    m_ = MultiMatcher();
    if (m_.add(pattern, error) < 0) return false;
    return m_.compile(error);
}

}  // namespace sentinel::rx
