#include "detect/transform.hpp"

#include "core/util.hpp"

namespace sentinel {

std::optional<uint32_t> transform_from_name(std::string_view n) {
    if (n == "unescape") return T_Unescape;
    if (n == "url_decode" || n == "urldecode") return T_UrlDecode;
    if (n == "html_decode" || n == "htmldecode") return T_HtmlDecode;
    if (n == "remove_sql_comments" || n == "sql_comments") return T_RemoveSqlComments;
    if (n == "compress_space" || n == "compress_whitespace") return T_CompressSpace;
    if (n == "lowercase" || n == "lower") return T_Lowercase;
    return std::nullopt;
}

std::string transform_names(uint32_t mask) {
    std::string r;
    auto add = [&](uint32_t bit, const char* name) {
        if (mask & bit) {
            if (!r.empty()) r += ',';
            r += name;
        }
    };
    add(T_Unescape, "unescape");
    add(T_UrlDecode, "url_decode");
    add(T_HtmlDecode, "html_decode");
    add(T_RemoveSqlComments, "remove_sql_comments");
    add(T_CompressSpace, "compress_space");
    add(T_Lowercase, "lowercase");
    return r;
}

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void url_decode_once(std::string_view s, std::string& out) {
    out.resize(s.size());
    char* o = out.data();
    size_t w = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '%') {
            if (i + 2 < s.size()) {
                int a = hexv(s[i + 1]), b = hexv(s[i + 2]);
                if (a >= 0 && b >= 0) {
                    o[w++] = char(a * 16 + b);
                    i += 2;
                    continue;
                }
            }
            if (i + 5 < s.size() && (s[i + 1] == 'u' || s[i + 1] == 'U')) {
                int v = 0;
                bool ok = true;
                for (int k = 2; k < 6; ++k) {
                    int h = hexv(s[i + size_t(k)]);
                    if (h < 0) {
                        ok = false;
                        break;
                    }
                    v = v * 16 + h;
                }
                if (ok) {
                    // %uFF1C и подобные "полноширинные" символы приводим к ASCII
                    if (v >= 0xFF01 && v <= 0xFF5E) v -= 0xFEE0;
                    o[w++] = v < 0x80 ? char(v) : '?';
                    i += 5;
                    continue;
                }
            }
        }
        o[w++] = c == '+' ? ' ' : c;
    }
    out.resize(w);
}

std::string url_decode(std::string_view s) {
    std::string a, b;
    url_decode_once(s, a);
    if (a.find('%') == std::string::npos) return a;
    url_decode_once(a, b);
    return b;
}

static void html_decode_into(std::string_view s, std::string& out) {
    out.clear();
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '&') {
            out.push_back(s[i]);
            continue;
        }
        // &name; или &#NN; или &#xHH; (точка с запятой может отсутствовать)
        size_t j = i + 1;
        if (j < s.size() && s[j] == '#') {
            ++j;
            bool hex = j < s.size() && (s[j] == 'x' || s[j] == 'X');
            if (hex) ++j;
            uint32_t v = 0;
            size_t st = j;
            while (j < s.size() && j - st < 8) {
                int h = hex ? hexv(s[j]) : (is_digit(s[j]) ? s[j] - '0' : -1);
                if (h < 0) break;
                v = v * (hex ? 16 : 10) + uint32_t(h);
                ++j;
            }
            if (j > st) {
                if (j < s.size() && s[j] == ';') ++j;
                out.push_back(v < 0x80 ? char(v) : '?');
                i = j - 1;
                continue;
            }
            out.push_back('&');
            continue;
        }
        static const struct {
            const char* name;
            char c;
        } ents[] = {{"lt", '<'}, {"gt", '>'}, {"amp", '&'}, {"quot", '"'}, {"apos", '\''},
                    {"sol", '/'}, {"lpar", '('}, {"rpar", ')'}, {"colon", ':'}, {"tab", '\t'}, {"newline", '\n'}};
        bool done = false;
        for (auto& e : ents) {
            size_t n = std::char_traits<char>::length(e.name);
            if (s.size() - j >= n && iequals(s.substr(j, n), e.name)) {
                size_t k = j + n;
                if (k < s.size() && s[k] == ';') ++k;
                out.push_back(e.c);
                i = k - 1;
                done = true;
                break;
            }
        }
        if (!done) out.push_back('&');
    }
}

std::string html_decode(std::string_view s) {
    std::string out;
    html_decode_into(s, out);
    return out;
}

static void unescape_into(std::string_view s, std::string& out) {
    out.clear();
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char n = s[i + 1];
            if ((n == 'x' || n == 'X') && i + 3 < s.size()) {
                int a = hexv(s[i + 2]), b = hexv(s[i + 3]);
                if (a >= 0 && b >= 0) {
                    out.push_back(char(a * 16 + b));
                    i += 3;
                    continue;
                }
            }
            if (n == '"' || n == '\\' || n == '\'') {
                out.push_back(n);
                ++i;
                continue;
            }
        }
        out.push_back(s[i]);
    }
}

void apply_transforms(std::string_view in, uint32_t mask, std::string& out) {
    if (mask == 0) {
        out.assign(in.data(), in.size());
        return;
    }
    // Каждый шаг выполняется только если в строке есть что преобразовывать:
    // обычные запросы без %, & и \ почти ничего не стоят.
    thread_local std::string a, b;
    a.assign(in.data(), in.size());
    if ((mask & T_Unescape) && a.find('\\') != std::string::npos) {
        unescape_into(a, b);
        a.swap(b);
    }
    if ((mask & T_UrlDecode) && (a.find('%') != std::string::npos || a.find('+') != std::string::npos)) {
        url_decode_once(a, b);
        a.swap(b);
        if (a.find('%') != std::string::npos) {
            url_decode_once(a, b);
            a.swap(b);
        }
    }
    if ((mask & T_HtmlDecode) && a.find('&') != std::string::npos) {
        html_decode_into(a, b);
        a.swap(b);
    }
    if ((mask & T_RemoveSqlComments) && a.find("/*") != std::string::npos) {
        b.clear();
        b.reserve(a.size());
        for (size_t i = 0; i < a.size(); ++i) {
            if (a[i] == '/' && i + 1 < a.size() && a[i + 1] == '*') {
                size_t e = a.find("*/", i + 2);
                b.push_back(' ');
                if (e == std::string::npos) break;
                i = e + 1;
                continue;
            }
            b.push_back(a[i]);
        }
        a.swap(b);
    }
    if (mask & T_CompressSpace) {
        size_t w = 0;
        bool sp = false;
        for (size_t i = 0; i < a.size(); ++i) {
            char c = a[i];
            if (is_space(c)) {
                if (!sp) a[w++] = ' ';
                sp = true;
            } else {
                a[w++] = c;
                sp = false;
            }
        }
        a.resize(w);
    }
    if (mask & T_Lowercase)
        for (char& c : a) c = to_lower_ascii(c);
    out.assign(a);
}

}  // namespace sentinel
