#include "core/crypto.hpp"
#include "core/json.hpp"
#include "core/util.hpp"
#include "core/yaml.hpp"
#include "testing.hpp"

using namespace sentinel;

TEST("util: iso8601 parse/format") {
    auto t = parse_iso8601("2026-10-12T13:55:36.123Z");
    REQUIRE(t.has_value());
    CHECK_EQ(format_iso8601(*t), std::string("2026-10-12T13:55:36.123Z"));
    auto t2 = parse_iso8601("2026-10-12T16:55:36.123+03:00");
    REQUIRE(t2.has_value());
    CHECK_EQ(*t, *t2);
    CHECK(parse_iso8601("1970-01-01T00:00:00Z").value() == 0);
    CHECK(!parse_iso8601("2026-13-01").has_value());
    CHECK(!parse_iso8601("garbage").has_value());
    CHECK_EQ(format_iso8601(-1), std::string("1969-12-31T23:59:59.999Z"));
}

TEST("util: civil days roundtrip") {
    for (int64_t z = -800000; z < 800000; z += 997) {
        int64_t y;
        unsigned m, d;
        civil_from_days(z, y, m, d);
        CHECK_EQ(days_from_civil(y, m, d), z);
    }
}

TEST("util: varint and reader") {
    std::string buf;
    put_varint(buf, 0);
    put_varint(buf, 127);
    put_varint(buf, 300);
    put_varint(buf, UINT64_MAX);
    put_svarint(buf, -12345);
    put_bytes(buf, "hello");
    put_u32(buf, 0xDEADBEEF);
    Reader r(buf);
    CHECK_EQ(r.varint(), 0u);
    CHECK_EQ(r.varint(), 127u);
    CHECK_EQ(r.varint(), 300u);
    CHECK_EQ(r.varint(), UINT64_MAX);
    CHECK_EQ(r.svarint(), -12345);
    CHECK_EQ(r.bytes(), std::string_view("hello"));
    CHECK_EQ(r.u32(), 0xDEADBEEFu);
    CHECK(r.ok());
    CHECK(r.eof());
    r.u8();
    CHECK(!r.ok());
}

TEST("util: crc32 known value") {
    // Эталон CRC-32 для "123456789" = 0xCBF43926
    CHECK_EQ(crc32("123456789", 9), 0xCBF43926u);
}

TEST("util: ifind and parse") {
    CHECK_EQ(ifind("Hello World", "WORLD"), size_t(6));
    CHECK(ifind("abc", "abcd") == std::string_view::npos);
    CHECK_EQ(parse_int(" 42 ").value(), 42);
    CHECK(!parse_int("4x2").has_value());
    CHECK_EQ(month_from_abbr("Oct"), 10u);
}

TEST("crypto: sha256 test vectors") {
    CHECK_EQ(sha256_hex(""), std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(sha256_hex("abc"), std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_EQ(sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
             std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    std::string million(1000000, 'a');
    CHECK_EQ(sha256_hex(million), std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    CHECK(constant_time_equals("abc", "abc"));
    CHECK(!constant_time_equals("abc", "abd"));
    CHECK_EQ(random_hex(16).size(), size_t(32));
    CHECK(random_hex(16) != random_hex(16));
}

TEST("json: parse and write") {
    JValue v;
    std::string err;
    REQUIRE(json_parse(R"({"a":1,"b":[true,false,null],"c":"x\"y\u00e9\ud83d\ude00","d":-2.5e3})", v, err));
    CHECK_EQ(v.get("a")->i, 1);
    CHECK(v.get("b")->arr.size() == 3);
    CHECK_EQ(v.get("c")->s, std::string("x\"y\xC3\xA9\xF0\x9F\x98\x80"));
    CHECK(v.get("d")->d == -2500.0);
    std::string out;
    json_write_value(out, v);
    JValue v2;
    REQUIRE(json_parse(out, v2, err));
    CHECK_EQ(v2.get("c")->s, v.get("c")->s);
    CHECK(!json_parse("{\"a\":}", v, err));
    CHECK(!json_parse("[1,2", v, err));
    CHECK(!json_parse("{} x", v, err));
    // глубина
    std::string deep(200, '[');
    CHECK(!json_parse(deep, v, err));
}

TEST("json: escaping invalid utf8") {
    std::string out;
    json_escape_to(out, std::string("ok\x01\xff\"", 5));
    CHECK_EQ(out, std::string("\"ok\\u0001\\ufffd\\\"\""));
    std::string w;
    JsonWriter jw(w);
    jw.begin_object().kv("n", size_t(5)).kv("s", "t").key("arr").begin_array().value(int64_t(-1)).value(true).end_array().end_object();
    CHECK_EQ(w, std::string(R"({"n":5,"s":"t","arr":[-1,true]})"));
}

TEST("yaml: rules-like document") {
    const char* text = R"(# comment
id: WEB-SQLI-001
name: "SQL injection: attempt"   # trailing comment
severity: critical
where:
  type: web
  http.status: [200, 500]
patterns:
  - '(?i)union\s+select'
  - "plain \"quoted\""
  - it's plain
tests:
  match:
    - 'line one'
  no_match:
  - 'line two'
steps:
  - rule: A
    within: 30
  - where: {type: auth, outcome: success}
empty:
)";
    YNode n;
    std::string err;
    REQUIRE(parse_yaml(text, n, err));
    CHECK_EQ(n.str("id"), std::string("WEB-SQLI-001"));
    CHECK_EQ(n.str("name"), std::string("SQL injection: attempt"));
    CHECK_EQ(n.get("where")->str("type"), std::string("web"));
    CHECK_EQ(n.get("where")->strings("http.status").size(), size_t(2));
    auto pats = n.strings("patterns");
    REQUIRE(pats.size() == 3);
    CHECK_EQ(pats[0], std::string("(?i)union\\s+select"));
    CHECK_EQ(pats[1], std::string("plain \"quoted\""));
    CHECK_EQ(pats[2], std::string("it's plain"));
    CHECK_EQ(n.get("tests")->get("match")->seq.size(), size_t(1));
    CHECK_EQ(n.get("tests")->get("no_match")->seq.size(), size_t(1));
    auto* steps = n.get("steps");
    REQUIRE(steps && steps->seq.size() == 2);
    CHECK_EQ(steps->seq[0].str("rule"), std::string("A"));
    CHECK_EQ(steps->seq[0].integer("within").value(), 30);
    CHECK_EQ(steps->seq[1].get("where")->str("outcome"), std::string("success"));
    CHECK(n.get("empty")->is_null());
}

TEST("yaml: errors") {
    YNode n;
    std::string err;
    CHECK(!parse_yaml("a: 1\na: 2\n", n, err));
    CHECK(!parse_yaml("a: \"bad \\q\"\n", n, err));
    CHECK(!parse_yaml("just text\n", n, err));
    CHECK(!parse_yaml("a:\n\tb: 1\n", n, err));
}
