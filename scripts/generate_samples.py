"""Generate realistic sample logs containing benign traffic and staged attacks.

All IPs come from the RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24), so the samples never point at real hosts.

    python scripts/generate_samples.py   # writes samples/auth.log and samples/access.log
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
START = datetime(2026, 10, 12, 8, 0, 0)
HOST = "web01"
rng = random.Random(1337)

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]
PAGES = ["/", "/index.html", "/about", "/blog", "/blog/post-1", "/blog/post-2", "/contact",
         "/static/css/main.css", "/static/js/app.js", "/images/logo.png", "/products?id=12",
         "/products?id=7", "/search?q=shoes", "/login", "/api/v1/status"]
WORDLIST = ["admin", "backup", ".git/config", ".env", "wp-admin", "wp-login.php", "phpmyadmin",
            "config.php", "old", "test", "dev", "db.sql", "server-status", "api/v2", "uploads",
            "private", "secret", "console", "manager/html", "cgi-bin/", "debug", "staging",
            ".htaccess", "backup.zip", "site.tar.gz", "includes", "tmp", "logs", "install.php",
            "setup", "shell.php", "cmd.php", "phpinfo.php", ".DS_Store", "web.config", "admin.php",
            "login.php", "dashboard", "portal", "xmlrpc.php"]


def syslog(ts: datetime, proc: str, pid: int, msg: str) -> str:
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} {proc}[{pid}]: {msg}"


def combined(ts: datetime, ip: str, method: str, path: str, status: int, size: int, ua: str) -> str:
    return f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def auth_log() -> list[tuple[datetime, str]]:
    lines = []
    pid = 2000

    # Normal admin activity across the day.
    for hour in (8, 10, 13, 16):
        ts = START.replace(hour=hour, minute=rng.randint(0, 50))
        pid += 1
        lines.append((ts, syslog(ts, "sshd", pid, f"Accepted publickey for alice from 192.0.2.10 port {rng.randint(40000, 65000)} ssh2")))
    ts = START.replace(hour=9, minute=12)
    lines.append((ts, syslog(ts, "sshd", pid + 1, "Failed password for bob from 192.0.2.11 port 50122 ssh2")))
    ts += timedelta(seconds=9)
    lines.append((ts, syslog(ts, "sshd", pid + 2, "Accepted password for bob from 192.0.2.11 port 50130 ssh2")))
    ts = START.replace(hour=9, minute=40)
    lines.append((ts, syslog(ts, "sudo", 0, "     bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt update")))

    # Attack 1: fast SSH brute force against root/admin.
    ts = START.replace(hour=11, minute=2)
    for _ in range(40):
        ts += timedelta(seconds=rng.randint(1, 4))
        user = rng.choice(["root", "root", "admin"])
        prefix = "" if user == "root" else "invalid user "
        pid += 1
        lines.append((ts, syslog(ts, "sshd", pid, f"Failed password for {prefix}{user} from 203.0.113.45 port {rng.randint(30000, 65000)} ssh2")))

    # Attack 2: password spraying that ends in a successful login.
    ts = START.replace(hour=14, minute=5)
    for user in ["oracle", "postgres", "ubuntu", "test", "git", "jenkins", "ftp", "deploy", "deploy", "deploy"]:
        ts += timedelta(seconds=rng.randint(15, 40))
        pid += 1
        if user in {"deploy", "ubuntu", "git"}:
            lines.append((ts, syslog(ts, "sshd", pid, f"Failed password for {user} from 198.51.100.23 port {rng.randint(30000, 65000)} ssh2")))
        else:
            lines.append((ts, syslog(ts, "sshd", pid, f"Invalid user {user} from 198.51.100.23 port {rng.randint(30000, 65000)}")))
            lines.append((ts, syslog(ts, "sshd", pid, f"Failed password for invalid user {user} from 198.51.100.23 port {rng.randint(30000, 65000)} ssh2")))
    ts += timedelta(seconds=30)
    lines.append((ts, syslog(ts, "sshd", pid + 1, "Accepted password for deploy from 198.51.100.23 port 51999 ssh2")))
    ts += timedelta(minutes=2)
    lines.append((ts, syslog(ts, "sudo", 0, "  deploy : TTY=pts/2 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")))

    # Risky configuration: direct root login.
    ts = START.replace(hour=17, minute=31)
    lines.append((ts, syslog(ts, "sshd", pid + 5, "Accepted password for root from 192.0.2.50 port 41000 ssh2")))

    # Noise the parser should ignore.
    ts = START.replace(hour=12)
    lines.append((ts, syslog(ts, "CRON", 999, "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")))
    return lines


def access_log() -> list[tuple[datetime, str]]:
    lines = []

    # Benign browsing.
    for _ in range(400):
        ts = START + timedelta(seconds=rng.randint(0, 10 * 3600))
        ip = f"192.0.2.{rng.randint(20, 120)}"
        page = rng.choice(PAGES)
        status = 200 if rng.random() > 0.03 else 404
        lines.append((ts, combined(ts, ip, "GET", page, status, rng.randint(300, 30000), rng.choice(BROWSER_UAS))))

    # sqlmap against the product page.
    ts = START.replace(hour=12, minute=15)
    for payload in [
        "/products?id=12%27", "/products?id=12%20OR%201=1", "/products?id=12%27%20OR%20%271%27=%271",
        "/products?id=12%20UNION%20ALL%20SELECT%20NULL,NULL,NULL--",
        "/products?id=12%20AND%20SLEEP(5)", "/products?id=12;SELECT%20table_name%20FROM%20information_schema.tables--",
    ]:
        ts += timedelta(seconds=2)
        lines.append((ts, combined(ts, "203.0.113.77", "GET", payload, rng.choice([200, 500]), 1200, "sqlmap/1.8.4#stable (https://sqlmap.org)")))

    # gobuster wordlist scan.
    ts = START.replace(hour=13, minute=0)
    for word in WORDLIST:
        ts += timedelta(milliseconds=600)
        status = 200 if word == ".env" else 404
        lines.append((ts, combined(ts, "198.51.100.88", "GET", "/" + word, status, 0 if status == 404 else 412, "gobuster/3.6")))

    # Manual path traversal / LFI, one of which "succeeds".
    ts = START.replace(hour=15, minute=42)
    for path, status in [
        ("/download?file=../../../../etc/passwd", 200),
        ("/download?file=..%2f..%2f..%2fetc%2fshadow", 403),
        ("/index.php?page=php://filter/convert.base64-encode/resource=config", 404),
    ]:
        ts += timedelta(seconds=20)
        lines.append((ts, combined(ts, "192.0.2.200", "GET", path, status, 2048, BROWSER_UAS[2])))

    # Reflected XSS probes and command injection.
    ts = START.replace(hour=16, minute=5)
    for path in ["/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "/search?q=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E"]:
        ts += timedelta(seconds=15)
        lines.append((ts, combined(ts, "203.0.113.150", "GET", path, 200, 900, BROWSER_UAS[0])))
    for path in ["/api/v1/ping?host=127.0.0.1;cat%20/etc/passwd", "/api/v1/ping?host=127.0.0.1%7Cid"]:
        ts += timedelta(seconds=15)
        lines.append((ts, combined(ts, "203.0.113.150", "GET", path, 400, 120, "curl/8.5.0")))

    # The SSH brute forcer from auth.log also probes the website (cross-vector activity).
    ts = START.replace(hour=11, minute=20)
    for path in ["/wp-login.php", "/.env", "/admin", "/phpmyadmin/", "/.git/config"]:
        ts += timedelta(seconds=3)
        lines.append((ts, combined(ts, "203.0.113.45", "GET", path, 404, 0, "python-requests/2.32.3")))

    # A malformed line the parser should skip.
    lines.append((START, "this is not a valid access log line"))
    return lines


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, entries in (("auth.log", auth_log()), ("access.log", access_log())):
        entries.sort(key=lambda item: item[0])
        (OUT / name).write_text("\n".join(line for _, line in entries) + "\n", encoding="utf-8")
        print(f"wrote {OUT / name} ({len(entries)} lines)")


if __name__ == "__main__":
    main()
