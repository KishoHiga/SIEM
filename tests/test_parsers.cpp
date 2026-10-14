#include "core/util.hpp"
#include "parse/parsers.hpp"
#include "testing.hpp"

using namespace sentinel;

static ParseContext ctx_at(const char* iso) {
    ParseContext c;
    c.now_ms = parse_iso8601(iso).value();
    return c;
}

static Event parse(std::string_view line, LogFormat f = LogFormat::Auto) {
    Event ev;
    parse_line(line, f, ctx_at("2026-10-12T12:00:00Z"), ev);
    return ev;
}

TEST("parse: nginx combined") {
    Event ev = parse(R"L(203.0.113.7 - - [12/Oct/2026:13:55:36 +0300] "GET /item?id=1%20UNION%20SELECT HTTP/1.1" 200 512 "https://ref.example/" "Mozilla/5.0 (X11)")L");
    CHECK_EQ(ev[Field::SrcIp], std::string("203.0.113.7"));
    CHECK_EQ(ev[Field::HttpMethod], std::string("GET"));
    CHECK_EQ(ev[Field::HttpPath], std::string("/item?id=1%20UNION%20SELECT"));
    CHECK_EQ(ev[Field::HttpStatus], std::string("200"));
    CHECK_EQ(ev[Field::Bytes], std::string("512"));
    CHECK_EQ(ev[Field::HttpUserAgent], std::string("Mozilla/5.0 (X11)"));
    CHECK_EQ(ev[Field::HttpReferer], std::string("https://ref.example/"));
    CHECK_EQ(ev[Field::Type], std::string("web"));
    CHECK_EQ(ev[Field::Outcome], std::string("success"));
    CHECK_EQ(format_iso8601(ev.ts), std::string("2026-10-12T10:55:36.000Z"));
}

TEST("parse: nginx garbage request and escapes") {
    Event ev = parse(R"L(198.51.100.1 - - [12/Oct/2026:13:55:36 +0000] "\x16\x03\x01" 400 157 "-" "-")L");
    CHECK_EQ(ev[Field::Type], std::string("web"));
    CHECK_EQ(ev[Field::HttpStatus], std::string("400"));
    CHECK_EQ(ev[Field::Outcome], std::string("failure"));
    CHECK(ev[Field::HttpUserAgent].empty());
    Event ev2 = parse(R"L(1.1.1.1 - bob [12/Oct/2026:13:55:36 +0000] "GET /a\"b HTTP/1.1" 404 0 "-" "x \"quoted\" ua")L");
    CHECK_EQ(ev2[Field::HttpPath], std::string("/a\"b"));
    CHECK_EQ(ev2[Field::HttpUserAgent], std::string("x \"quoted\" ua"));
    CHECK_EQ(ev2[Field::User], std::string("bob"));
}

TEST("parse: sshd failed / accepted / invalid user") {
    Event f = parse("Oct 12 11:00:01 web-01 sshd[2211]: Failed password for root from 45.13.10.2 port 51022 ssh2");
    CHECK_EQ(f[Field::Process], std::string("sshd"));
    CHECK_EQ(f[Field::Host], std::string("web-01"));
    CHECK_EQ(f[Field::Type], std::string("auth"));
    CHECK_EQ(f[Field::Action], std::string("login"));
    CHECK_EQ(f[Field::Outcome], std::string("failure"));
    CHECK_EQ(f[Field::User], std::string("root"));
    CHECK_EQ(f[Field::SrcIp], std::string("45.13.10.2"));
    CHECK_EQ(f[Field::SrcPort], std::string("51022"));
    CHECK_EQ(format_iso8601(f.ts), std::string("2026-10-12T11:00:01.000Z"));
    CHECK_EQ(*f.extra_get("pid"), std::string("2211"));

    Event iu = parse("Oct 12 11:00:02 web-01 sshd[2211]: Failed password for invalid user admin from 45.13.10.2 port 51023 ssh2");
    CHECK_EQ(iu[Field::User], std::string("admin"));
    CHECK_EQ(*iu.extra_get("invalid_user"), std::string("true"));

    Event ok = parse("Oct  2 09:15:00 web-01 sshd[3000]: Accepted publickey for ivan from 10.0.0.5 port 40000 ssh2: ED25519 SHA256:abc");
    CHECK_EQ(ok[Field::Outcome], std::string("success"));
    CHECK_EQ(ok[Field::User], std::string("ivan"));
    CHECK_EQ(ok[Field::SrcIp], std::string("10.0.0.5"));
    CHECK_EQ(*ok.extra_get("auth_method"), std::string("publickey"));

    Event inv = parse("Oct 12 11:00:02 web-01 sshd[2211]: Invalid user oracle from 45.13.10.2 port 51023");
    CHECK_EQ(inv[Field::Action], std::string("invalid_user"));
    CHECK_EQ(inv[Field::User], std::string("oracle"));
}

TEST("parse: syslog year rollover") {
    // Запись от 31 декабря, прочитанная 1 января, относится к прошлому году
    Event ev;
    parse_line("Dec 31 23:59:00 h app: x", LogFormat::Auto, ctx_at("2027-01-01T00:05:00Z"), ev);
    CHECK_EQ(format_iso8601(ev.ts), std::string("2026-12-31T23:59:00.000Z"));
}

TEST("parse: sudo and pam") {
    Event s = parse("Oct 12 11:00:05 web-01 sudo:     ivan : TTY=pts/0 ; PWD=/home/ivan ; USER=root ; COMMAND=/usr/bin/id");
    CHECK_EQ(s[Field::Type], std::string("privilege"));
    CHECK_EQ(s[Field::User], std::string("ivan"));
    CHECK_EQ(s[Field::Outcome], std::string("success"));
    CHECK_EQ(*s.extra_get("command"), std::string("/usr/bin/id"));
    Event f = parse("Oct 12 11:00:06 web-01 sudo:     ivan : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/ivan ; USER=root ; COMMAND=/bin/sh");
    CHECK_EQ(f[Field::Outcome], std::string("failure"));
    CHECK_EQ(*f.extra_get("reason"), std::string("3 incorrect password attempts"));
    Event p = parse("Oct 12 11:00:07 web-01 sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=45.13.10.2  user=root");
    CHECK_EQ(p[Field::Action], std::string("pam"));
    CHECK_EQ(p[Field::SrcIp], std::string("45.13.10.2"));
    CHECK_EQ(p[Field::User], std::string("root"));
}

TEST("parse: ufw firewall via kernel") {
    Event ev = parse("Oct 12 11:00:08 web-01 kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb SRC=185.1.2.3 DST=10.0.0.1 LEN=44 PROTO=TCP SPT=40000 DPT=3389 WINDOW=1024");
    CHECK_EQ(ev[Field::Type], std::string("network"));
    CHECK_EQ(ev[Field::Action], std::string("block"));
    CHECK_EQ(ev[Field::SrcIp], std::string("185.1.2.3"));
    CHECK_EQ(ev[Field::DstPort], std::string("3389"));
    CHECK_EQ(ev[Field::Proto], std::string("tcp"));
}

TEST("parse: rfc5424 syslog") {
    Event ev = parse(R"L(<34>1 2026-10-12T11:00:00.123Z host1 myapp 77 ID47 [exampleSDID@32473 iut="3" eventSource="App"] User login failed)L");
    CHECK_EQ(ev[Field::Host], std::string("host1"));
    CHECK_EQ(ev[Field::Process], std::string("myapp"));
    CHECK_EQ(ev[Field::Message], std::string("User login failed"));
    CHECK_EQ(format_iso8601(ev.ts), std::string("2026-10-12T11:00:00.123Z"));
    CHECK_EQ(*ev.extra_get("syslog_severity"), std::string("crit"));
}

TEST("parse: json app event and docker wrapper") {
    Event ev = parse(R"L({"timestamp":"2026-10-12T11:00:00Z","event_type":"auth","result":"failure","username":"ivan","source_ip":"1.2.3.4","http":{"method":"POST"},"custom":{"k":1}})L");
    CHECK_EQ(ev[Field::Type], std::string("auth"));
    CHECK_EQ(ev[Field::Outcome], std::string("failure"));
    CHECK_EQ(ev[Field::User], std::string("ivan"));
    CHECK_EQ(ev[Field::SrcIp], std::string("1.2.3.4"));
    CHECK_EQ(ev[Field::HttpMethod], std::string("POST"));
    CHECK_EQ(*ev.extra_get("custom.k"), std::string("1"));
    CHECK_EQ(format_iso8601(ev.ts), std::string("2026-10-12T11:00:00.000Z"));

    Event d = parse(R"L({"log":"10.1.1.1 - - [12/Oct/2026:11:00:00 +0000] \"GET / HTTP/1.1\" 200 5 \"-\" \"curl\"\n","stream":"stdout","time":"2026-10-12T11:00:00.5Z"})L");
    CHECK_EQ(d[Field::Type], std::string("web"));
    CHECK_EQ(d[Field::SrcIp], std::string("10.1.1.1"));
    CHECK_EQ(*d.extra_get("stream"), std::string("stdout"));
}

TEST("parse: key=value and plain fallback") {
    Event kv = parse("action=deny src=1.2.3.4 dst=10.0.0.1 dport=22 proto=tcp policy=\"block all\"");
    CHECK_EQ(kv[Field::Type], std::string("network"));
    CHECK_EQ(kv[Field::Action], std::string("deny"));
    CHECK_EQ(kv[Field::DstPort], std::string("22"));
    CHECK_EQ(*kv.extra_get("policy"), std::string("block all"));
    Event p = parse("just some text without structure");
    CHECK_EQ(p[Field::Type], std::string("log"));
    CHECK_EQ(p[Field::Message], std::string("just some text without structure"));
    Event e;
    CHECK(!parse_line("   \r\n", LogFormat::Auto, ctx_at("2026-10-12T12:00:00Z"), e));
}

TEST("parse: never crashes on junk (fuzz)") {
    uint64_t x = 88172645463325252ULL;
    auto rnd = [&]() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        return x;
    };
    const char* seeds[] = {
        R"L(1.2.3.4 - - [12/Oct/2026:13:55:36 +0300] "GET / HTTP/1.1" 200 5 "-" "ua")L",
        "Oct 12 11:00:01 web-01 sshd[2211]: Failed password for root from 45.13.10.2 port 51022 ssh2",
        R"L(<34>1 2026-10-12T11:00:00.123Z host1 myapp 77 ID47 [a b="]"] msg)L",
        R"L({"a":{"b":[1,2,{"c":"d"}]},"time":12345})L",
        "x=1 y=\"2 z=3",
    };
    for (int i = 0; i < 20000; ++i) {
        std::string s = seeds[rnd() % 5];
        int muts = int(rnd() % 6);
        for (int k = 0; k < muts && !s.empty(); ++k) {
            size_t pos = rnd() % s.size();
            switch (rnd() % 3) {
                case 0: s[pos] = char(rnd() & 0xFF); break;
                case 1: s.erase(pos, 1 + rnd() % 5); break;
                case 2: s.insert(pos, 1, "[]\"<>{}: =\\"[rnd() % 11]); break;
            }
        }
        Event ev;
        parse_line(s, LogFormat::Auto, ctx_at("2026-10-12T12:00:00Z"), ev);
    }
    CHECK(true);
}
