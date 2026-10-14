#include "core/json.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>

#include "core/util.hpp"

namespace sentinel {

const JValue* JValue::get(std::string_view key) const {
    if (type != Type::Object) return nullptr;
    for (auto& kv : obj)
        if (kv.first == key) return &kv.second;
    return nullptr;
}

std::string JValue::as_text() const {
    switch (type) {
        case Type::Null: return "";
        case Type::Bool: return b ? "true" : "false";
        case Type::String: return s;
        case Type::Number: {
            if (is_int) return std::to_string(i);
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.17g", d);
            return buf;
        }
        default: {
            std::string out;
            json_write_value(out, *this);
            return out;
        }
    }
}

namespace {

class JParser {
public:
    JParser(std::string_view t) : t_(t) {}

    bool parse(JValue& out, std::string& err) {
        skip_ws();
        if (!value(out, 0)) {
            err = err_ + " at offset " + std::to_string(p_);
            return false;
        }
        skip_ws();
        if (p_ != t_.size()) {
            err = "trailing characters at offset " + std::to_string(p_);
            return false;
        }
        return true;
    }

private:
    std::string_view t_;
    size_t p_ = 0;
    std::string err_;

    bool fail(const char* m) {
        err_ = m;
        return false;
    }

    void skip_ws() {
        while (p_ < t_.size() && (t_[p_] == ' ' || t_[p_] == '\t' || t_[p_] == '\n' || t_[p_] == '\r')) ++p_;
    }

    bool literal(const char* lit) {
        size_t n = std::strlen(lit);
        if (t_.substr(p_, n) != lit) return fail("invalid literal");
        p_ += n;
        return true;
    }

    bool value(JValue& v, int depth) {
        if (depth > 64) return fail("nesting too deep");
        if (p_ >= t_.size()) return fail("unexpected end");
        char c = t_[p_];
        switch (c) {
            case '{': return object(v, depth);
            case '[': return array(v, depth);
            case '"':
                v.type = JValue::Type::String;
                return string(v.s);
            case 't':
                v.type = JValue::Type::Bool;
                v.b = true;
                return literal("true");
            case 'f':
                v.type = JValue::Type::Bool;
                v.b = false;
                return literal("false");
            case 'n':
                v.type = JValue::Type::Null;
                return literal("null");
            default:
                if (c == '-' || is_digit(c)) return number(v);
                return fail("unexpected character");
        }
    }

    bool object(JValue& v, int depth) {
        v.type = JValue::Type::Object;
        ++p_;
        skip_ws();
        if (p_ < t_.size() && t_[p_] == '}') {
            ++p_;
            return true;
        }
        while (true) {
            skip_ws();
            if (p_ >= t_.size() || t_[p_] != '"') return fail("expected key");
            std::string key;
            if (!string(key)) return false;
            skip_ws();
            if (p_ >= t_.size() || t_[p_] != ':') return fail("expected ':'");
            ++p_;
            skip_ws();
            JValue child;
            if (!value(child, depth + 1)) return false;
            v.obj.emplace_back(std::move(key), std::move(child));
            skip_ws();
            if (p_ >= t_.size()) return fail("unterminated object");
            if (t_[p_] == ',') {
                ++p_;
                continue;
            }
            if (t_[p_] == '}') {
                ++p_;
                return true;
            }
            return fail("expected ',' or '}'");
        }
    }

    bool array(JValue& v, int depth) {
        v.type = JValue::Type::Array;
        ++p_;
        skip_ws();
        if (p_ < t_.size() && t_[p_] == ']') {
            ++p_;
            return true;
        }
        while (true) {
            skip_ws();
            JValue child;
            if (!value(child, depth + 1)) return false;
            v.arr.push_back(std::move(child));
            skip_ws();
            if (p_ >= t_.size()) return fail("unterminated array");
            if (t_[p_] == ',') {
                ++p_;
                continue;
            }
            if (t_[p_] == ']') {
                ++p_;
                return true;
            }
            return fail("expected ',' or ']'");
        }
    }

    bool number(JValue& v) {
        size_t st = p_;
        if (t_[p_] == '-') ++p_;
        if (p_ >= t_.size() || !is_digit(t_[p_])) return fail("bad number");
        while (p_ < t_.size() && is_digit(t_[p_])) ++p_;
        bool is_int = true;
        if (p_ < t_.size() && t_[p_] == '.') {
            is_int = false;
            ++p_;
            if (p_ >= t_.size() || !is_digit(t_[p_])) return fail("bad number");
            while (p_ < t_.size() && is_digit(t_[p_])) ++p_;
        }
        if (p_ < t_.size() && (t_[p_] == 'e' || t_[p_] == 'E')) {
            is_int = false;
            ++p_;
            if (p_ < t_.size() && (t_[p_] == '+' || t_[p_] == '-')) ++p_;
            if (p_ >= t_.size() || !is_digit(t_[p_])) return fail("bad number");
            while (p_ < t_.size() && is_digit(t_[p_])) ++p_;
        }
        std::string_view num = t_.substr(st, p_ - st);
        v.type = JValue::Type::Number;
        if (is_int) {
            auto iv = parse_int(num);
            if (iv) {
                v.is_int = true;
                v.i = *iv;
                v.d = double(*iv);
                return true;
            }
        }
        auto dv = parse_double(num);
        if (!dv) return fail("bad number");
        v.d = *dv;
        v.is_int = false;
        if (std::isfinite(v.d) && std::fabs(v.d) < 9.2e18 && v.d == std::floor(v.d)) {
            v.i = int64_t(v.d);
        }
        return true;
    }

    static void put_utf8(std::string& out, uint32_t cp) {
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

    bool hex4(uint32_t& out) {
        if (p_ + 4 > t_.size()) return fail("bad \\u escape");
        out = 0;
        for (int k = 0; k < 4; ++k) {
            char h = t_[p_++];
            int v = (h >= '0' && h <= '9') ? h - '0'
                    : (h >= 'a' && h <= 'f') ? h - 'a' + 10
                    : (h >= 'A' && h <= 'F') ? h - 'A' + 10
                                             : -1;
            if (v < 0) return fail("bad \\u escape");
            out = out * 16 + uint32_t(v);
        }
        return true;
    }

    bool string(std::string& out) {
        ++p_;  // "
        while (p_ < t_.size()) {
            // Быстрый путь: копируем кусок без спецсимволов
            size_t st = p_;
            while (p_ < t_.size() && t_[p_] != '"' && t_[p_] != '\\' && uint8_t(t_[p_]) >= 0x20) ++p_;
            out.append(t_.data() + st, p_ - st);
            if (p_ >= t_.size()) break;
            char c = t_[p_];
            if (c == '"') {
                ++p_;
                return true;
            }
            if (uint8_t(c) < 0x20) return fail("control character in string");
            ++p_;  // backslash
            if (p_ >= t_.size()) break;
            char e = t_[p_++];
            switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    uint32_t cp;
                    if (!hex4(cp)) return false;
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        // суррогатная пара
                        if (p_ + 6 <= t_.size() && t_[p_] == '\\' && t_[p_ + 1] == 'u') {
                            p_ += 2;
                            uint32_t lo;
                            if (!hex4(lo)) return false;
                            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            } else {
                                cp = 0xFFFD;
                            }
                        } else {
                            cp = 0xFFFD;
                        }
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        cp = 0xFFFD;
                    }
                    put_utf8(out, cp);
                    break;
                }
                default: return fail("bad escape");
            }
        }
        return fail("unterminated string");
    }
};

}  // namespace

bool json_parse(std::string_view text, JValue& out, std::string& error) {
    out = JValue{};
    JParser p(text);
    return p.parse(out, error);
}

// Длина корректной UTF-8 последовательности, начинающейся в s[i], или 0.
static size_t utf8_seq_len(std::string_view s, size_t i) {
    uint8_t c = uint8_t(s[i]);
    size_t n;
    uint32_t cp;
    if (c < 0x80) return 1;
    if (c >= 0xC2 && c <= 0xDF) {
        n = 2;
        cp = c & 0x1F;
    } else if (c >= 0xE0 && c <= 0xEF) {
        n = 3;
        cp = c & 0x0F;
    } else if (c >= 0xF0 && c <= 0xF4) {
        n = 4;
        cp = c & 0x07;
    } else {
        return 0;
    }
    if (i + n > s.size()) return 0;
    for (size_t k = 1; k < n; ++k) {
        uint8_t cc = uint8_t(s[i + k]);
        if ((cc & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (cc & 0x3F);
    }
    if ((n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)) ||
        (cp >= 0xD800 && cp <= 0xDFFF))
        return 0;
    return n;
}

void json_escape_to(std::string& out, std::string_view s) {
    static const char* hex = "0123456789abcdef";
    out.push_back('"');
    size_t i = 0;
    while (i < s.size()) {
        // Быстрый путь для обычного ASCII
        size_t st = i;
        while (i < s.size()) {
            uint8_t c = uint8_t(s[i]);
            if (c < 0x20 || c == '"' || c == '\\' || c >= 0x80) break;
            ++i;
        }
        out.append(s.data() + st, i - st);
        if (i >= s.size()) break;
        uint8_t c = uint8_t(s[i]);
        if (c >= 0x80) {
            size_t n = utf8_seq_len(s, i);
            if (n == 0) {
                out += "\\ufffd";
                ++i;
            } else {
                out.append(s.data() + i, n);
                i += n;
            }
            continue;
        }
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                out += "\\u00";
                out.push_back(hex[c >> 4]);
                out.push_back(hex[c & 15]);
        }
        ++i;
    }
    out.push_back('"');
}

void JsonWriter::comma() {
    if (after_key_) {
        after_key_ = false;
        return;
    }
    if (!first_.back()) out_.push_back(',');
    first_.back() = false;
}

JsonWriter& JsonWriter::begin_object() {
    comma();
    out_.push_back('{');
    first_.push_back(true);
    return *this;
}
JsonWriter& JsonWriter::end_object() {
    out_.push_back('}');
    first_.pop_back();
    return *this;
}
JsonWriter& JsonWriter::begin_array() {
    comma();
    out_.push_back('[');
    first_.push_back(true);
    return *this;
}
JsonWriter& JsonWriter::end_array() {
    out_.push_back(']');
    first_.pop_back();
    return *this;
}
JsonWriter& JsonWriter::key(std::string_view k) {
    comma();
    json_escape_to(out_, k);
    out_.push_back(':');
    after_key_ = true;
    return *this;
}
JsonWriter& JsonWriter::value(std::string_view v) {
    comma();
    json_escape_to(out_, v);
    return *this;
}
JsonWriter& JsonWriter::value_i64(int64_t v) {
    comma();
    out_ += std::to_string(v);
    return *this;
}
JsonWriter& JsonWriter::value_u64(uint64_t v) {
    comma();
    out_ += std::to_string(v);
    return *this;
}
JsonWriter& JsonWriter::value(double v) {
    comma();
    if (!std::isfinite(v)) {
        out_ += "null";
        return *this;
    }
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.6g", v);
    out_ += buf;
    return *this;
}
JsonWriter& JsonWriter::value(bool v) {
    comma();
    out_ += v ? "true" : "false";
    return *this;
}
JsonWriter& JsonWriter::null() {
    comma();
    out_ += "null";
    return *this;
}
JsonWriter& JsonWriter::raw(std::string_view json) {
    comma();
    out_.append(json.data(), json.size());
    return *this;
}

void json_write_value(std::string& out, const JValue& v) {
    switch (v.type) {
        case JValue::Type::Null: out += "null"; break;
        case JValue::Type::Bool: out += v.b ? "true" : "false"; break;
        case JValue::Type::Number: out += v.as_text(); break;
        case JValue::Type::String: json_escape_to(out, v.s); break;
        case JValue::Type::Array:
            out.push_back('[');
            for (size_t k = 0; k < v.arr.size(); ++k) {
                if (k) out.push_back(',');
                json_write_value(out, v.arr[k]);
            }
            out.push_back(']');
            break;
        case JValue::Type::Object:
            out.push_back('{');
            for (size_t k = 0; k < v.obj.size(); ++k) {
                if (k) out.push_back(',');
                json_escape_to(out, v.obj[k].first);
                out.push_back(':');
                json_write_value(out, v.obj[k].second);
            }
            out.push_back('}');
            break;
    }
}

}  // namespace sentinel
