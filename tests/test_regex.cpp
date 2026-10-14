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
        std::regex ref(pat, std::regex::ECMAScript);
        for (int t = 0; t < 8; ++t) {
            std::string text;
            int len = int(rng() % 12);
            for (int k = 0; k < len; ++k) text.push_back("abc\n"[rng() % 4]);
            bool a = mine.search(text);
            bool b;
            try {
                b = std::regex_search(text, ref);
            } catch (const std::regex_error&) {
                continue;  // эталонный std::regex сдался (возврат слишком сложный) — пропускаем
            }
            ++compared;
            if (a != b) {
                ++mismatches;
                if (mismatches < 5)
                    std::cerr << "mismatch pat=[" << pat << "] text=[" << text << "] mine=" << a << " ref=" << b << "\n";
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
        std::vector<std::regex> refs;
        MultiMatcher mm;
        for (int i = 0; i < 25; ++i) {
            std::string p = random_pattern(rng, 0);
            if (mm.add(p) < 0) continue;
            pats.push_back(p);
            refs.emplace_back(p, std::regex::ECMAScript);
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
                try {
                    if (g[i] != std::regex_search(text, refs[i])) ++mismatches;
                } catch (const std::regex_error&) {
                }
            }
        }
    }
    CHECK_EQ(mismatches, 0);
}
