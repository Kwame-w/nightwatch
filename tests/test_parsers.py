from datetime import datetime

from nightwatch.parsers import parse_auth_line, parse_web_line


def test_failed_password_invalid_user():
    e = parse_auth_line(
        "Oct 12 11:02:03 web01 sshd[2001]: Failed password for invalid user admin from 203.0.113.45 port 50000 ssh2",
        2026,
    )
    assert e.kind == "ssh_failed"
    assert e.user == "admin"
    assert e.ip == "203.0.113.45"
    assert e.method == "password"
    assert e.timestamp == datetime(2026, 10, 12, 11, 2, 3)


def test_accepted_publickey():
    e = parse_auth_line(
        "Oct  2 08:00:00 web01 sshd[10]: Accepted publickey for alice from 192.0.2.10 port 4444 ssh2", 2026
    )
    assert (e.kind, e.user, e.method, e.timestamp.day) == ("ssh_accepted", "alice", "publickey", 2)


def test_invalid_user_line():
    e = parse_auth_line("Oct 12 14:05:01 web01 sshd[9]: Invalid user oracle from 198.51.100.23 port 1", 2026)
    assert (e.kind, e.user, e.ip) == ("ssh_invalid_user", "oracle", "198.51.100.23")


def test_ipv6_source():
    e = parse_auth_line(
        "Oct 12 14:05:01 web01 sshd[9]: Failed password for root from 2001:db8::1 port 22 ssh2", 2026
    )
    assert e.ip == "2001:db8::1"


def test_sudo_to_root_only():
    root = parse_auth_line(
        "Oct 12 09:40:00 web01 sudo:      bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash", 2026
    )
    assert (root.kind, root.user, root.method) == ("sudo", "bob", "/bin/bash")
    other = parse_auth_line(
        "Oct 12 09:40:00 web01 sudo:      bob : TTY=pts/1 ; PWD=/ ; USER=postgres ; COMMAND=/usr/bin/psql", 2026
    )
    assert other is None


def test_irrelevant_and_malformed_auth_lines_are_skipped():
    assert parse_auth_line("Oct 12 12:00:00 web01 CRON[1]: session opened for user root", 2026) is None
    assert parse_auth_line("garbage", 2026) is None
    assert parse_auth_line("Foo 99 12:00:00 web01 sshd[1]: Failed password for x from 1.2.3.4 port 1", 2026) is None


def test_combined_log_line():
    e = parse_web_line(
        '203.0.113.77 - - [12/Oct/2026:12:15:02 +0000] "GET /products?id=1%27 HTTP/1.1" 500 1200 "-" "sqlmap/1.8"'
    )
    assert e.ip == "203.0.113.77"
    assert e.path == "/products?id=1%27"
    assert (e.status, e.size, e.user_agent) == (500, 1200, "sqlmap/1.8")
    assert e.timestamp == datetime(2026, 10, 12, 12, 15, 2)


def test_common_log_format_without_agent_and_dash_size():
    e = parse_web_line('192.0.2.1 - - [12/Oct/2026:12:15:02 +0000] "HEAD / HTTP/1.1" 304 -')
    assert (e.method, e.size, e.user_agent) == ("HEAD", 0, "")


def test_malformed_web_line():
    assert parse_web_line("this is not a log line") is None
