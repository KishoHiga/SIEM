#include "core/yaml.hpp"

#include "core/util.hpp"

namespace sentinel {

const YNode* YNode::get(std::string_view key) const {
    if (kind != Kind::Map) return nullptr;
    for (auto& kv : map)
        if (kv.first == key) return &kv.second;
    return nullptr;
}

std::string YNode::str(std::string_view key, std::string_view def) const {
    const YNode* n = get(key);
    if (!n || !n->is_scalar()) return std::string(def);
    return n->scalar;
}

std::optional<int64_t> YNode::integer(std::string_view key) const {
    const YNode* n = get(key);
    if (!n || !n->is_scalar()) return std::nullopt;
    return parse_int(n->scalar);
}

std::optional<bool> YNode::boolean(std::string_view key) const {
    const YNode* n = get(key);
    if (!n || !n->is_scalar()) return std::nullopt;
    std::string v = to_lower(n->scalar);
    if (v == "true" || v == "yes" || v == "on" || v == "1") return true;
    if (v == "false" || v == "no" || v == "off" || v == "0") return false;
    return std::nullopt;
}

std::vector<std::string> YNode::as_strings() const {
    std::vector<std::string> r;
    if (is_scalar()) {
        r.push_back(scalar);
    } else if (is_seq()) {
        for (auto& it : seq)
            if (it.is_scalar()) r.push_back(it.scalar);
    }
    return r;
}

std::vector<std::string> YNode::strings(std::string_view key) const {
    const YNode* n = get(key);
    if (!n) return {};
    return n->as_strings();
}

namespace {

struct Line {
    int indent;
    std::string text;
    int lineno;
};

bool is_token_start(const std::string& s, size_t i) {
    if (i == 0) return true;
    char p = s[i - 1];
    return p == ' ' || p == '\t' || p == '[' || p == '{' || p == ',' || p == ':' || p == '-';
}

// Убирает комментарий, учитывая кавычки.
std::string strip_comment(const std::string& s) {
    char quote = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (quote) {
            if (quote == '"' && c == '\\') {
                ++i;
                continue;
            }
            if (c == quote) {
                if (quote == '\'' && i + 1 < s.size() && s[i + 1] == '\'') {
                    ++i;
                    continue;
                }
                quote = 0;
            }
            continue;
        }
        if ((c == '"' || c == '\'') && is_token_start(s, i)) {
            quote = c;
            continue;
        }
        if (c == '#' && (i == 0 || s[i - 1] == ' ' || s[i - 1] == '\t')) return s.substr(0, i);
    }
    return s;
}

// Ищет ':' разделитель ключа вне кавычек (за ним пробел или конец строки).
size_t find_key_colon(const std::string& s) {
    char quote = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (quote) {
            if (quote == '"' && c == '\\') {
                ++i;
                continue;
            }
            if (c == quote) quote = 0;
            continue;
        }
        if ((c == '"' || c == '\'') && i == 0) {
            quote = c;
            continue;
        }
        if (c == '[' || c == '{') {
            if (i == 0) return std::string::npos;  // flow-значение, не ключ
        }
        if (c == ':' && (i + 1 == s.size() || s[i + 1] == ' ' || s[i + 1] == '\t')) return i;
    }
    return std::string::npos;
}

bool is_seq_item(const std::string& t) { return t == "-" || (t.size() >= 2 && t[0] == '-' && t[1] == ' '); }

class Parser {
public:
    Parser(std::vector<Line> lines) : lines_(std::move(lines)) {}

    bool parse(YNode& out, std::string& err) {
        if (lines_.empty()) {
            out = YNode{};
            return true;
        }
        if (!parse_node(lines_[0].indent, out)) {
            err = err_;
            return false;
        }
        if (i_ < lines_.size()) {
            err = "line " + std::to_string(lines_[i_].lineno) + ": unexpected indentation";
            return false;
        }
        return true;
    }

private:
    std::vector<Line> lines_;
    size_t i_ = 0;
    std::string err_;
    int depth_ = 0;

    bool fail(int lineno, const std::string& m) {
        err_ = "line " + std::to_string(lineno) + ": " + m;
        return false;
    }

    bool parse_node(int indent, YNode& out) {
        if (++depth_ > 64) return fail(lines_[i_].lineno, "nesting too deep");
        bool ok;
        if (is_seq_item(lines_[i_].text))
            ok = parse_seq(indent, out);
        else
            ok = parse_map(indent, out);
        --depth_;
        return ok;
    }

    bool parse_seq(int indent, YNode& out) {
        out = YNode{};
        out.kind = YNode::Kind::Seq;
        out.line = lines_[i_].lineno;
        while (i_ < lines_.size() && lines_[i_].indent == indent && is_seq_item(lines_[i_].text)) {
            Line& ln = lines_[i_];
            std::string rest = ln.text.size() > 1 ? ln.text.substr(2) : std::string();
            size_t lead = 0;
            while (lead < rest.size() && rest[lead] == ' ') ++lead;
            rest = rest.substr(lead);
            YNode item;
            if (rest.empty()) {
                ++i_;
                if (i_ < lines_.size() && lines_[i_].indent > indent) {
                    if (!parse_node(lines_[i_].indent, item)) return false;
                }
            } else if (is_seq_item(rest) || find_key_colon(rest) != std::string::npos) {
                // Вложенный элемент начинается на той же строке: сдвигаем виртуальный отступ.
                ln.indent = indent + 2 + int(lead);
                ln.text = rest;
                if (!parse_node(ln.indent, item)) return false;
            } else {
                if (!parse_scalar(rest, ln.lineno, item)) return false;
                ++i_;
            }
            out.seq.push_back(std::move(item));
        }
        return true;
    }

    bool parse_map(int indent, YNode& out) {
        out = YNode{};
        out.kind = YNode::Kind::Map;
        out.line = lines_[i_].lineno;
        while (i_ < lines_.size() && lines_[i_].indent == indent) {
            const Line ln = lines_[i_];
            if (is_seq_item(ln.text)) return fail(ln.lineno, "unexpected list item");
            size_t colon = find_key_colon(ln.text);
            if (colon == std::string::npos) return fail(ln.lineno, "expected 'key: value'");
            std::string key_raw(trim(std::string_view(ln.text).substr(0, colon)));
            std::string key;
            if (!key_raw.empty() && (key_raw[0] == '"' || key_raw[0] == '\'')) {
                YNode k;
                if (!parse_scalar(key_raw, ln.lineno, k)) return false;
                key = k.scalar;
            } else {
                key = key_raw;
            }
            if (key.empty()) return fail(ln.lineno, "empty key");
            for (auto& kv : out.map)
                if (kv.first == key) return fail(ln.lineno, "duplicate key '" + key + "'");
            std::string value(trim(std::string_view(ln.text).substr(colon + 1)));
            YNode node;
            node.line = ln.lineno;
            ++i_;
            if (!value.empty()) {
                if (!parse_scalar(value, ln.lineno, node)) return false;
            } else if (i_ < lines_.size() && lines_[i_].indent > indent) {
                if (!parse_node(lines_[i_].indent, node)) return false;
            } else if (i_ < lines_.size() && lines_[i_].indent == indent && is_seq_item(lines_[i_].text)) {
                if (!parse_seq(indent, node)) return false;
            }
            out.map.emplace_back(std::move(key), std::move(node));
        }
        return true;
    }

    // Скаляр, "строка", 'строка', [flow, список], {flow: словарь}
    bool parse_scalar(const std::string& s, int lineno, YNode& out) {
        size_t pos = 0;
        if (!parse_flow(s, pos, lineno, out, false)) return false;
        while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
        if (pos != s.size()) return fail(lineno, "unexpected characters after value");
        return true;
    }

    bool parse_flow(const std::string& s, size_t& pos, int lineno, YNode& out, bool in_flow) {
        while (pos < s.size() && s[pos] == ' ') ++pos;
        out = YNode{};
        out.line = lineno;
        if (pos >= s.size()) {
            out.kind = YNode::Kind::Scalar;
            return true;
        }
        char c = s[pos];
        if (c == '|' || c == '>') {
            if (!in_flow && pos + 1 >= s.size()) return fail(lineno, "block scalars (| >) are not supported");
        }
        if (c == '"') return parse_double_quoted(s, pos, lineno, out);
        if (c == '\'') return parse_single_quoted(s, pos, lineno, out);
        if (c == '[') {
            out.kind = YNode::Kind::Seq;
            ++pos;
            while (true) {
                while (pos < s.size() && s[pos] == ' ') ++pos;
                if (pos >= s.size()) return fail(lineno, "unterminated [");
                if (s[pos] == ']') {
                    ++pos;
                    return true;
                }
                YNode item;
                if (!parse_flow(s, pos, lineno, item, true)) return false;
                out.seq.push_back(std::move(item));
                while (pos < s.size() && s[pos] == ' ') ++pos;
                if (pos < s.size() && s[pos] == ',') {
                    ++pos;
                    continue;
                }
                if (pos < s.size() && s[pos] == ']') {
                    ++pos;
                    return true;
                }
                return fail(lineno, "expected , or ] in flow list");
            }
        }
        if (c == '{') {
            out.kind = YNode::Kind::Map;
            ++pos;
            while (true) {
                while (pos < s.size() && s[pos] == ' ') ++pos;
                if (pos >= s.size()) return fail(lineno, "unterminated {");
                if (s[pos] == '}') {
                    ++pos;
                    return true;
                }
                YNode key;
                if (s[pos] == '"' || s[pos] == '\'') {
                    if (!parse_flow(s, pos, lineno, key, true)) return false;
                } else {
                    size_t st = pos;
                    while (pos < s.size() && s[pos] != ':' && s[pos] != ',' && s[pos] != '}') ++pos;
                    key.kind = YNode::Kind::Scalar;
                    key.scalar = std::string(trim(std::string_view(s).substr(st, pos - st)));
                }
                while (pos < s.size() && s[pos] == ' ') ++pos;
                if (pos >= s.size() || s[pos] != ':') return fail(lineno, "expected : in flow map");
                ++pos;
                YNode val;
                if (!parse_flow(s, pos, lineno, val, true)) return false;
                out.map.emplace_back(key.scalar, std::move(val));
                while (pos < s.size() && s[pos] == ' ') ++pos;
                if (pos < s.size() && s[pos] == ',') {
                    ++pos;
                    continue;
                }
                if (pos < s.size() && s[pos] == '}') {
                    ++pos;
                    return true;
                }
                return fail(lineno, "expected , or } in flow map");
            }
        }
        // Простой скаляр
        size_t st = pos;
        if (in_flow) {
            while (pos < s.size() && s[pos] != ',' && s[pos] != ']' && s[pos] != '}') ++pos;
        } else {
            pos = s.size();
        }
        out.kind = YNode::Kind::Scalar;
        out.scalar = std::string(trim(std::string_view(s).substr(st, pos - st)));
        if (out.scalar == "~" || out.scalar == "null") {
            out.kind = YNode::Kind::Null;
            out.scalar.clear();
        }
        return true;
    }

    bool parse_single_quoted(const std::string& s, size_t& pos, int lineno, YNode& out) {
        ++pos;
        out.kind = YNode::Kind::Scalar;
        out.quoted = true;
        while (pos < s.size()) {
            char c = s[pos];
            if (c == '\'') {
                if (pos + 1 < s.size() && s[pos + 1] == '\'') {
                    out.scalar.push_back('\'');
                    pos += 2;
                    continue;
                }
                ++pos;
                return true;
            }
            out.scalar.push_back(c);
            ++pos;
        }
        return fail(lineno, "unterminated single-quoted string");
    }

    static void append_utf8(std::string& out, uint32_t cp) {
        if (cp < 0x80) {
            out.push_back(char(cp));
        } else if (cp < 0x800) {
            out.push_back(char(0xC0 | (cp >> 6)));
            out.push_back(char(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(char(0xE0 | (cp >> 12)));
            out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(char(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(char(0xF0 | (cp >> 18)));
            out.push_back(char(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(char(0x80 | (cp & 0x3F)));
        }
    }

    bool parse_double_quoted(const std::string& s, size_t& pos, int lineno, YNode& out) {
        ++pos;
        out.kind = YNode::Kind::Scalar;
        out.quoted = true;
        while (pos < s.size()) {
            char c = s[pos++];
            if (c == '"') return true;
            if (c != '\\') {
                out.scalar.push_back(c);
                continue;
            }
            if (pos >= s.size()) break;
            char e = s[pos++];
            switch (e) {
                case 'n': out.scalar.push_back('\n'); break;
                case 't': out.scalar.push_back('\t'); break;
                case 'r': out.scalar.push_back('\r'); break;
                case '0': out.scalar.push_back('\0'); break;
                case '"': out.scalar.push_back('"'); break;
                case '\\': out.scalar.push_back('\\'); break;
                case '/': out.scalar.push_back('/'); break;
                case ' ': out.scalar.push_back(' '); break;
                case 'x':
                case 'u': {
                    size_t n = e == 'x' ? 2 : 4;
                    if (pos + n > s.size()) return fail(lineno, "bad escape");
                    std::vector<uint8_t> tmp;
                    uint32_t cp = 0;
                    for (size_t k = 0; k < n; ++k) {
                        char h = s[pos + k];
                        int v = (h >= '0' && h <= '9') ? h - '0'
                                : (h >= 'a' && h <= 'f') ? h - 'a' + 10
                                : (h >= 'A' && h <= 'F') ? h - 'A' + 10
                                                         : -1;
                        if (v < 0) return fail(lineno, "bad escape");
                        cp = cp * 16 + uint32_t(v);
                    }
                    pos += n;
                    if (e == 'x')
                        out.scalar.push_back(char(cp));
                    else
                        append_utf8(out.scalar, cp);
                    break;
                }
                default:
                    return fail(lineno, std::string("unknown escape \\") + e +
                                            " (tip: use 'single quotes' for regex patterns)");
            }
        }
        return fail(lineno, "unterminated double-quoted string");
    }
};

}  // namespace

bool parse_yaml(std::string_view text, YNode& out, std::string& error) {
    std::vector<Line> lines;
    int lineno = 0;
    size_t start = 0;
    while (start <= text.size()) {
        size_t nl = text.find('\n', start);
        if (nl == std::string_view::npos) nl = text.size();
        std::string raw(text.substr(start, nl - start));
        ++lineno;
        start = nl + 1;
        if (!raw.empty() && raw.back() == '\r') raw.pop_back();
        // Отступ — только пробелы
        size_t ind = 0;
        while (ind < raw.size() && raw[ind] == ' ') ++ind;
        if (ind < raw.size() && raw[ind] == '\t') {
            error = "line " + std::to_string(lineno) + ": tabs are not allowed for indentation";
            return false;
        }
        std::string content = strip_comment(raw.substr(ind));
        while (!content.empty() && (content.back() == ' ' || content.back() == '\t')) content.pop_back();
        if (content.empty() || content == "---" || content == "...") {
            if (nl == text.size()) break;
            continue;
        }
        lines.push_back({int(ind), content, lineno});
        if (nl == text.size()) break;
    }
    Parser p(std::move(lines));
    return p.parse(out, error);
}

}  // namespace sentinel
