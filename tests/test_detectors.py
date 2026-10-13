from datetime import datetime, timedelta

from nightwatch.detectors import (
    DetectionConfig,
    detect_directory_bruteforce,
    detect_password_spray,
    detect_root_login,
    detect_scanners,
    detect_ssh_brute_force,
    detect_success_after_failures,
    detect_sudo_shell,
    detect_web_attacks,
    run_all,
)
from nightwatch.models import AuthEvent, Severity, WebEvent

T0 = datetime(2026, 10, 12, 10, 0, 0)
CFG = DetectionConfig()


def auth(kind, user, ip, seconds=0, method="password"):
    return AuthEvent(T0 + timedelta(seconds=seconds), "web01", kind, user, ip, method, raw=f"{kind} {user} {ip}")


def web(path, ip="203.0.113.9", status=200, ua="Mozilla/5.0", seconds=0):
    return WebEvent(T0 + timedelta(seconds=seconds), ip, "GET", path, status, 100, "-", ua, raw=path)


# --- auth ---------------------------------------------------------------------

def test_brute_force_fires_at_threshold():
    events = [auth("ssh_failed", "root", "203.0.113.1", i * 10) for i in range(5)]
    alerts = detect_ssh_brute_force(events, CFG)
    assert len(alerts) == 1
    assert alerts[0].mitre_id == "T1110.001"
    assert alerts[0].count == 5


def test_brute_force_ignores_slow_failures():
    # 5 failures spread over far more than the 300s window
    events = [auth("ssh_failed", "root", "203.0.113.1", i * 200) for i in range(5)]
    assert detect_ssh_brute_force(events, CFG) == []


def test_brute_force_is_per_ip():
    events = [auth("ssh_failed", "root", f"203.0.113.{i}", i) for i in range(10)]
    assert detect_ssh_brute_force(events, CFG) == []


def test_password_spray_counts_distinct_users():
    users = ["oracle", "test", "git", "ftp"]
    events = [auth("ssh_invalid_user", u, "198.51.100.23", i * 30) for i, u in enumerate(users)]
    alerts = detect_password_spray(events, CFG)
    assert len(alerts) == 1
    assert alerts[0].count == 4
    assert alerts[0].mitre_id == "T1110.003"


def test_same_user_repeated_is_not_spray():
    events = [auth("ssh_failed", "root", "198.51.100.23", i) for i in range(20)]
    assert detect_password_spray(events, CFG) == []


def test_success_after_failures_is_critical():
    events = [auth("ssh_failed", "deploy", "198.51.100.23", i * 5) for i in range(6)]
    events.append(auth("ssh_accepted", "deploy", "198.51.100.23", 60))
    alerts = detect_success_after_failures(events, CFG)
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.CRITICAL
    assert alerts[0].user == "deploy"


def test_success_from_clean_ip_is_fine():
    events = [auth("ssh_failed", "bob", "192.0.2.11", 0), auth("ssh_accepted", "bob", "192.0.2.11", 10)]
    assert detect_success_after_failures(events, CFG) == []


def test_root_login_and_sudo_shell():
    assert len(detect_root_login([auth("ssh_accepted", "root", "192.0.2.50")], CFG)) == 1
    shell = AuthEvent(T0, "web01", "sudo", "deploy", None, "/bin/bash")
    apt = AuthEvent(T0, "web01", "sudo", "bob", None, "/usr/bin/apt update")
    alerts = detect_sudo_shell([shell, apt], CFG)
    assert [a.user for a in alerts] == ["deploy"]


# --- web ----------------------------------------------------------------------

def test_sqli_detected_including_url_encoding():
    alerts = detect_web_attacks([web("/p?id=1%20UNION%20ALL%20SELECT%20NULL--", status=500)], CFG)
    assert [a.rule_id for a in alerts] == ["WEB-001"]
    assert alerts[0].severity is Severity.HIGH


def test_double_encoded_traversal_detected():
    alerts = detect_web_attacks([web("/dl?f=..%252f..%252fetc%252fpasswd", status=403)], CFG)
    assert [a.rule_id for a in alerts] == ["WEB-002"]


def test_successful_attack_escalates_severity():
    alerts = detect_web_attacks([web("/dl?f=../../etc/passwd", status=200)], CFG)
    assert alerts[0].severity is Severity.CRITICAL


def test_xss_and_command_injection():
    alerts = detect_web_attacks(
        [web("/s?q=%3Cscript%3Ealert(1)%3C/script%3E", status=400), web("/ping?h=1;whoami", status=400)], CFG
    )
    assert sorted(a.rule_id for a in alerts) == ["WEB-003", "WEB-004"]


def test_benign_requests_do_not_alert():
    benign = [web(p) for p in ["/", "/blog/union-station", "/search?q=select+a+gift", "/products?id=7"]]
    assert detect_web_attacks(benign, CFG) == []


def test_scanner_user_agent():
    alerts = detect_scanners([web("/", ua="Mozilla/5.0 (compatible; Nikto/2.5)")], CFG)
    assert len(alerts) == 1 and "nikto" in alerts[0].description


def test_directory_bruteforce():
    events = [web(f"/w{i}", ip="198.51.100.88", status=404, seconds=i) for i in range(25)]
    alerts = detect_directory_bruteforce(events, CFG)
    assert len(alerts) == 1 and alerts[0].mitre_id == "T1595.003"


def test_run_all_sorts_by_severity():
    events = [auth("ssh_failed", "x", "198.51.100.23", i) for i in range(6)]
    events += [auth("ssh_accepted", "x", "198.51.100.23", 30), auth("ssh_accepted", "root", "192.0.2.50", 40)]
    alerts = run_all(events, [])
    severities = [a.severity for a in alerts]
    assert severities == sorted(severities, reverse=True)
    assert alerts[0].rule_id == "AUTH-003"
