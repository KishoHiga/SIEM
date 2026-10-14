#include <functional>
#include <random>
#include <regex>

#include "regex/regex.hpp"
#include "testing.hpp"

using namespace sentinel::rx;

static bool m(const char* pat, const char* text) {
    Regex r;
    std::string err;
    if (!r.compile(pat, &err)) {
        std::cerr << "compile error for " << pat << ": " << err << "\n";
        return false;
    }
    return r.search(text);
}

TEST("regex: basics") {
    CHECK(m("abc", "xxabcxx"));
    CHECK(!m("abd", "xxabcxx"));
    CHECK(m("a.c", "abc"));
    CHECK(!m("a.c", "a\nc"));
    CHECK(m("(?s)a.c", "a\nc"));
    CHECK(m("^abc", "abcdef"));
    CHECK(!m("^abc", "xabc"));
    CHECK(m("def$", "abcdef"));
    CHECK(!m("def$", "defx"));
    CHECK(m("^$", ""));
    CHECK(!m("^$", "a"));
    CHECK(m("colou?r", "color"));
    CHECK(m("colou?r", "colour"));
    CHECK(m("ab+c", "abbbc"));
    CHECK(!m("ab+c", "ac"));
    CHECK(m("ab*c", "ac"));
    CHECK(m("a{3}", "caaab"));
    CHECK(!m("^a{3}$", "aa"));
    CHECK(m("^a{2,4}$", "aaaa"));
    CHECK(!m("^a{2,4}$", "aaaaa"));
    CHECK(m("^a{2,}$", "aaaaaaa"));
    CHECK(m("x{,3}", "x{,3}"));  // не квантификатор -> литерал
    CHECK(m("cat|dog", "hotdog"));
    CHECK(m("gr(a|e)y", "grey"));
    CHECK(m("(?:ab)+$", "xxababab"));
}

TEST("regex: classes and escapes") {
    CHECK(m("[a-c]+x", "zzbcax"));
    CHECK(!m("^[^0-9]+$", "abc1"));
    CHECK(m("\\d{4}-\\d{2}", "on 2026-10 we"));
    CHECK(m("\\w+@\\w+\\.com", "mail: ivan@site.com"));
    CHECK(m("a\\s+b", "a \t b"));
    CHECK(m("\\.\\./", "/../etc"));
    CHECK(!m("\\.\\./", "/./etc"));
    CHECK(m("[\\d.]+", "1.2"));
    CHECK(m("[[:alpha:]]+", "abc"));
    CHECK(m("\\x41", "A"));
    CHECK(m("[-a]", "-"));
    CHECK(m("[a-]", "-"));
    CHECK(m("[]a]", "]"));
}

TEST("regex: case insensitive") {
    CHECK(m("(?i)union\\s+select", "1 UNION   SeLeCt *"));
    CHECK(!m("union\\s+select", "1 UNION SELECT"));
    CHECK(m("(?i)[a-c]x", "BX"));
    CHECK(m("a(?i:B)c", "abc"));
    CHECK(!m("a(?i:B)c", "abC"));
    CHECK(m("(?i)<script", "<ScRiPt>"));
    CHECK(!m("(?i)[^a]", "A"));
}

TEST("regex: errors are reported, not crashes") {
    Regex r;
    std::string err;
    CHECK(!r.compile("(abc", &err));
    CHECK(!r.compile("abc)", &err));
    CHECK(!r.compile("*a", &err));
    CHECK(!r.compile("[abc", &err));
    CHECK(!r.compile("a\\b", &err));
    CHECK(!r.compile("(?=a)", &err));
    CHECK(!r.compile("(?<=a)b", &err));
    CHECK(!r.compile("a{5000}", &err));
    CHECK(!r.compile("[z-a]", &err));
    CHECK(!r.compile("\\1", &err));
    CHECK(r.compile("(?<name>abc)", &err));
    CHECK(!validate("a++", &err));
}

TEST("regex: multi matcher reports all matches") {
    MultiMatcher mm;
    CHECK_EQ(mm.add("(?i)union\\s+select"), 0);
    CHECK_EQ(mm.add("<script"), 1);
    CHECK_EQ(mm.add("\\.\\./"), 2);
    CHECK_EQ(mm.add("^GET "), 3);
    REQUIRE(mm.compile());
    std::vector<uint32_t> out;
    CHECK(mm.scan("GET /a/../b?q=<script>&id=1 union select 2", out));
    std::sort(out.begin(), out.end());
    REQUIRE(out.size() == 4);
    CHECK_EQ(out[0], 0u);
    CHECK_EQ(out[3], 3u);
    out.clear();
    CHECK(!mm.scan("POST /normal/page", out));
    CHECK(out.empty());
    out.clear();
    CHECK(mm.scan("POST /../", out));
    CHECK(out.size() == 1 && out[0] == 2);
}

TEST("regex: linear time on evil patterns") {
    // Классический пример, который "вешает" движки с откатом: (a+)+$ на aaaa...b
    Regex r;
    REQUIRE(r.compile("(a+)+$"));
    std::string text(100000, 'a');
    text += 'b';
    CHECK(!r.search(text));
    Regex r2;
    REQUIRE(r2.compile("(x+x+)+y"));
    CHECK(!r2.search(std::string(50000, 'x')));
}

TEST("regex: dfa cache reset keeps results correct") {
    // Шаблон с экспоненциальным числом DFA-состояний: (a|b)*a(a|b){12}
    Regex r;
    REQUIRE(r.compile("a[ab]{12}c"));
    std::mt19937 rng(7);
    std::string text;
    for (int i = 0; i < 200000; ++i) text.push_back("ab"[rng() & 1]);
    CHECK(!r.search(text));
    text += "c";
    // последние 13 символов перед c: нужен 'a' на позиции -13
    text[text.size() - 14] = 'a';
    CHECK(r.search(text));
}

// Дифференциальный тест против std::regex (стандартная библиотека как эталон).
static std::string random_pattern(std::mt19937& rng, int depth) {
    auto pick = [&](int n) { return int(rng() % unsigned(n)); };
    std::string p;
    int items = 1 + pick(4);
    for (int i = 0; i < items; ++i) {
        std::string atom;
        int kind = pick(depth > 2 ? 6 : 8);
        switch (kind) {
            case 0: case 1: case 2: atom = std::string(1, "abc"[pick(3)]); break;
            case 3: atom = "."; break;
            case 4: atom = pick(2) ? "[ab]" : "[^a]"; break;
            case 5: atom = pick(2) ? "\\n" : "b"; break;
            case 6: atom = "(" + random_pattern(rng, depth + 1) + ")"; break;
            case 7: atom = "(" + random_pattern(rng, depth + 1) + "|" + random_pattern(rng, depth + 1) + ")"; break;
        }
        int q = pick(9);
        if (q == 0) atom += "*";
        else if (q == 1) atom += "+";
        else if (q == 2) atom += "?";
        else if (q == 3) atom += "{1,2}";
        p += atom;
    }
    if (depth == 0) {
        if (pick(5) == 0) p = "^" + p;
        if (pick(5) == 0) p += "$";
    }
    return p;
}

// Эталон для случайных проверок: простейший перебор с возвратами для того же подмножества синтаксиса,
// что выдаёт random_pattern (a b c . [ab] [^a] \n, группы, |, * + ? {1,2}, ^ $). Медленный, но очевидно верный
// и одинаковый на всех платформах (std::regex в libc++ у Apple ошибается, например, на «b?$» и «cac»).
namespace refrx {

struct Item;
using Seq = std::vector<Item>;
struct Node {
    enum Kind { Char, Any, Set, Group, Bol, Eol } kind = Char;
    char c = 0;
    bool neg = false;
    std::string set;
    std::vector<Seq> alts;  // для Group
};
struct Item {
    Node node;
    int min = 1, max = 1;  // max = -1 — без ограничения
};

struct Parser {
    const std::string& p;
    size_t i = 0;
    std::vector<Seq> alts() {
        std::vector<Seq> out(1);
        while (i < p.size() && p[i] != ')') {
            if (p[i] == '|') {
                ++i;
                out.emplace_back();
                continue;
            }
            out.back().push_back(item());
        }
        return out;
    }
    Item item() {
        Item it;
        char ch = p[i++];
        if (ch == '(') {
            it.node.kind = Node::Group;
            it.node.alts = alts();
            ++i;  // ')'
        } else if (ch == '.') {
            it.node.kind = Node::Any;
        } else if (ch == '^') {
            it.node.kind = Node::Bol;
        } else if (ch == '$') {
            it.node.kind = Node::Eol;
        } else if (ch == '[') {
            it.node.kind = Node::Set;
            if (p[i] == '^') {
                it.node.neg = true;
                ++i;
            }
            while (p[i] != ']') it.node.set.push_back(p[i++]);
            ++i;
        } else if (ch == '\\') {
            char e = p[i++];
            it.node.c = e == 'n' ? '\n' : e;
        } else {
            it.node.c = ch;
        }
        if (i < p.size()) {
            if (p[i] == '*') it.min = 0, it.max = -1, ++i;
            else if (p[i] == '+') it.min = 1, it.max = -1, ++i;
            else if (p[i] == '?') it.min = 0, it.max = 1, ++i;
            else if (p[i] == '{') {  // только {1,2}
                it.min = p[i + 1] - '0';
                it.max = p[i + 3] - '0';
                i += 5;
            }
        }
        return it;
    }
};

using Cont = std::function<bool(size_t)>;
struct Matcher {
    const std::string& t;
    bool seq(const Seq& s, size_t idx, size_t pos, const Cont& k) const {
        if (idx == s.size()) return k(pos);
        return item(s[idx], pos, 0, [&](size_t p2) { return seq(s, idx + 1, p2, k); });
    }
    bool item(const Item& it, size_t pos, int count, const Cont& k) const {
        if (count >= it.min && k(pos)) return true;
        if (it.max != -1 && count >= it.max) return false;
        return atom(it.node, pos, [&](size_t p2) {
            if (p2 == pos && count >= it.min) return false;  // пустой повтор ничего не даёт (и не зацикливает)
            return item(it, p2, count + 1, k);
        });
    }
    bool atom(const Node& n, size_t pos, const Cont& k) const {
        switch (n.kind) {
            case Node::Bol: return pos == 0 && k(pos);
            case Node::Eol: return pos == t.size() && k(pos);
            case Node::Group:
                for (auto& a : n.alts)
                    if (seq(a, 0, pos, k)) return true;
                return false;
            default: break;
        }
        if (pos >= t.size()) return false;
        char ch = t[pos];
        bool ok = n.kind == Node::Any ? ch != '\n'
                  : n.kind == Node::Set ? (n.set.find(ch) != std::string::npos) != n.neg
                                        : ch == n.c;
        return ok && k(pos + 1);
    }
};

bool search(const std::string& pat, const std::string& text) {
    Parser ps{pat};
    std::vector<Seq> top = ps.alts();
    Matcher m{text};
    for (size_t start = 0; start <= text.size(); ++start)
        for (auto& a : top)
            if (m.seq(a, 0, start, [](size_t) { return true; })) return true;
    return false;
}

}  // namespace refrx

// std::regex как второй эталон — только там, где он надёжен (libstdc++).
#if defined(__GLIBCXX__)
constexpr bool kStdRegexReference = true;
#else
constexpr bool kStdRegexReference = false;
#endif

TEST("regex: reference matcher agrees with known answers") {
    CHECK(refrx::search("b?$", "cac"));
    CHECK(refrx::search("(b*){1,2}$", "ba"));
    CHECK(!refrx::search("^b", "ab"));
    CHECK(refrx::search("a(b|c)+$", "xabcb"));
    CHECK(!refrx::search("a.c", "a\nc"));
    CHECK(refrx::search("[^a]", "\n"));
    CHECK(!refrx::search("^(a|b){1,2}$", "abc"));
    CHECK(refrx::search("^(a|b){1,2}$", "ab"));
}

TEST("regex: differential fuzz vs std::regex") {
    std::mt19937 rng(12345);
    int compared = 0, mismatches = 0;
    for (int iter = 0; iter < 1500; ++iter) {
        std::string pat = random_pattern(rng, 0);
        Regex mine;
        std::string err;
        if (!mine.compile(pat, &err)) {
            std::cerr << "unexpected compile failure: " << pat << " : " << err << "\n";
            ++mismatches;
            continue;
        }
        std::regex ref;
        if (kStdRegexReference) ref = std::regex(pat, std::regex::ECMAScript);
        for (int t = 0; t < 8; ++t) {
            std::string text;
            int len = int(rng() % 12);
            for (int k = 0; k < len; ++k) text.push_back("abc\n"[rng() % 4]);
            bool a = mine.search(text);
            bool b = refrx::search(pat, text);
            if (kStdRegexReference) {
                try {
                    if (std::regex_search(text, ref) != b) {
                        std::cerr << "reference disagreement pat=[" << pat << "]\n";
                        ++mismatches;
                    }
                } catch (const std::regex_error&) {
                }
            }
            ++compared;
            if (a != b) {
                ++mismatches;
                if (mismatches < 6) {
                    std::string shown;
                    for (char ch : text) shown += ch == '\n' ? std::string("\\n") : std::string(1, ch);
                    std::cerr << "mismatch pat=[" << pat << "] text=[" << shown << "] mine=" << a << " ref=" << b << "\n";
                }
            }
        }
    }
    CHECK_EQ(mismatches, 0);
    CHECK(compared > 10000);
}

TEST("regex: multi matcher equals individual matching (fuzz)") {
    std::mt19937 rng(999);
    int mismatches = 0;
    for (int round = 0; round < 30; ++round) {
        std::vector<std::string> pats;
        MultiMatcher mm;
        for (int i = 0; i < 25; ++i) {
            std::string p = random_pattern(rng, 0);
            if (mm.add(p) < 0) continue;
            pats.push_back(p);
        }
        REQUIRE(mm.compile());
        for (int t = 0; t < 40; ++t) {
            std::string text;
            int len = int(rng() % 10);
            for (int k = 0; k < len; ++k) text.push_back("abc\n"[rng() % 4]);
            std::vector<uint32_t> got;
            mm.scan(text, got);
            std::vector<bool> g(pats.size(), false);
            for (auto id : got) g[id] = true;
            for (size_t i = 0; i < pats.size(); ++i) {
                {
                    bool ref = refrx::search(pats[i], text);
                    if (g[i] != ref) {
                        ++mismatches;
                        if (mismatches < 6) {
                            std::string shown;
                            for (char ch : text) shown += ch == '\n' ? std::string("\\n") : std::string(1, ch);
                            std::cerr << "mismatch(multi) pat=[" << pats[i] << "] text=[" << shown << "] mine=" << g[i]
                                      << " ref=" << ref << "\n";
                        }
                    }
                }
            }
        }
    }
    CHECK_EQ(mismatches, 0);
}
