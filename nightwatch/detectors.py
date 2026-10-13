"""Detection rules.

Each detector takes parsed events and returns a list of Alerts. Detectors are
plain functions so they are easy to read, test and extend; ``run_all`` wires
them together using a single ``DetectionConfig``.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import unquote_plus

from .models import Alert, AuthEvent, Severity, WebEvent

MAX_EVIDENCE = 5


@dataclass
class DetectionConfig:
    brute_force_threshold: int = 5        # failed logins from one IP...
    brute_force_window: int = 300         # ...within this many seconds
    spray_user_threshold: int = 4         # distinct usernames from one IP...
    spray_window: int = 600               # ...within this many seconds
    compromise_failure_threshold: int = 5  # failures before a success = likely compromise
    compromise_lookback: int = 3600
    not_found_threshold: int = 20         # 404s from one IP...
    not_found_window: int = 60            # ...within this many seconds


# --- helpers ------------------------------------------------------------------

def _densest_window(times: Sequence[datetime], window: timedelta) -> tuple[int, int]:
    """Return (start, end) indexes of the window holding the most events.

    ``times`` must be sorted. Uses a two-pointer sweep, so it is O(n).
    """
    best = (0, 0)
    left = 0
    for right in range(len(times)):
        while times[right] - times[left] > window:
            left += 1
        if right - left > best[1] - best[0]:
            best = (left, right)
    return best


def _group(events: Iterable, key: Callable) -> dict:
    grouped: dict = defaultdict(list)
    for event in events:
        grouped[key(event)].append(event)
    return grouped


# --- auth.log detectors -------------------------------------------------------

def detect_ssh_brute_force(events: list[AuthEvent], cfg: DetectionConfig) -> list[Alert]:
    # sshd logs both "Invalid user X" and "Failed password for invalid user X" for one
    # attempt, so only "Failed ..." lines are counted to avoid double counting.
    failures = [e for e in events if e.kind == "ssh_failed" and e.ip]
    alerts = []
    window = timedelta(seconds=cfg.brute_force_window)
    for ip, ip_events in _group(failures, lambda e: e.ip).items():
        start, end = _densest_window([e.timestamp for e in ip_events], window)
        burst = ip_events[start : end + 1]
        if len(burst) < cfg.brute_force_threshold:
            continue
        alerts.append(Alert(
            rule_id="AUTH-001",
            title="SSH brute force",
            severity=Severity.HIGH,
            mitre_id="T1110.001",
            mitre_name="Brute Force: Password Guessing",
            description=(
                f"{len(burst)} failed SSH logins from {ip} within "
                f"{cfg.brute_force_window}s ({len(ip_events)} failures total)."
            ),
            ip=ip,
            first_seen=burst[0].timestamp,
            last_seen=burst[-1].timestamp,
            count=len(ip_events),
            evidence=[e.raw for e in burst[:MAX_EVIDENCE]],
        ))
    return alerts


def detect_password_spray(events: list[AuthEvent], cfg: DetectionConfig) -> list[Alert]:
    failures = [e for e in events if e.kind in ("ssh_failed", "ssh_invalid_user") and e.ip and e.user]
    alerts = []
    window = timedelta(seconds=cfg.spray_window)
    for ip, ip_events in _group(failures, lambda e: e.ip).items():
        users: Counter = Counter()
        left = 0
        best_users: set[str] = set()
        best_span = (0, 0)
        for right, event in enumerate(ip_events):
            users[event.user] += 1
            while event.timestamp - ip_events[left].timestamp > window:
                users[ip_events[left].user] -= 1
                if users[ip_events[left].user] == 0:
                    del users[ip_events[left].user]
                left += 1
            if len(users) > len(best_users):
                best_users = set(users)
                best_span = (left, right)
        if len(best_users) < cfg.spray_user_threshold:
            continue
        burst = ip_events[best_span[0] : best_span[1] + 1]
        alerts.append(Alert(
            rule_id="AUTH-002",
            title="Password spraying / username enumeration",
            severity=Severity.HIGH,
            mitre_id="T1110.003",
            mitre_name="Brute Force: Password Spraying",
            description=(
                f"{ip} tried {len(best_users)} different usernames within "
                f"{cfg.spray_window}s: {', '.join(sorted(best_users)[:10])}."
            ),
            ip=ip,
            first_seen=burst[0].timestamp,
            last_seen=burst[-1].timestamp,
            count=len(best_users),
            evidence=[e.raw for e in burst[:MAX_EVIDENCE]],
        ))
    return alerts


def detect_success_after_failures(events: list[AuthEvent], cfg: DetectionConfig) -> list[Alert]:
    """A successful login from an IP that was just failing is a strong compromise signal."""
    alerts = []
    lookback = timedelta(seconds=cfg.compromise_lookback)
    failures_by_ip = _group(
        (e for e in events if e.kind == "ssh_failed" and e.ip),
        lambda e: e.ip,
    )
    for event in events:
        if event.kind != "ssh_accepted" or event.ip not in failures_by_ip:
            continue
        prior = [
            f for f in failures_by_ip[event.ip]
            if event.timestamp - lookback <= f.timestamp < event.timestamp
        ]
        if len(prior) < cfg.compromise_failure_threshold:
            continue
        alerts.append(Alert(
            rule_id="AUTH-003",
            title="Successful login after repeated failures",
            severity=Severity.CRITICAL,
            mitre_id="T1078",
            mitre_name="Valid Accounts",
            description=(
                f"{event.user} logged in from {event.ip} via {event.method} after "
                f"{len(prior)} failed attempts from that IP. Treat the account as compromised."
            ),
            ip=event.ip,
            user=event.user,
            first_seen=prior[0].timestamp,
            last_seen=event.timestamp,
            count=len(prior),
            evidence=[f.raw for f in prior[-(MAX_EVIDENCE - 1):]] + [event.raw],
        ))
    return alerts


def detect_root_login(events: list[AuthEvent], cfg: DetectionConfig) -> list[Alert]:
    alerts = []
    for event in events:
        if event.kind == "ssh_accepted" and event.user == "root":
            alerts.append(Alert(
                rule_id="AUTH-004",
                title="Direct root SSH login",
                severity=Severity.MEDIUM,
                mitre_id="T1078.003",
                mitre_name="Valid Accounts: Local Accounts",
                description=(
                    f"root logged in directly over SSH from {event.ip}. "
                    "Set 'PermitRootLogin no' and use sudo instead."
                ),
                ip=event.ip,
                user="root",
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                evidence=[event.raw],
            ))
    return alerts


_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "su"}


def detect_sudo_shell(events: list[AuthEvent], cfg: DetectionConfig) -> list[Alert]:
    alerts = []
    for event in events:
        if event.kind != "sudo" or not event.method:
            continue
        binary = event.method.split()[0].rsplit("/", 1)[-1]
        if binary not in _SHELLS:
            continue
        alerts.append(Alert(
            rule_id="AUTH-005",
            title="Interactive root shell via sudo",
            severity=Severity.MEDIUM,
            mitre_id="T1548.003",
            mitre_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
            description=f"{event.user} opened a root shell with sudo ({event.method}).",
            user=event.user,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            evidence=[event.raw],
        ))
    return alerts


# --- web access log detectors -------------------------------------------------

@dataclass(frozen=True)
class WebSignature:
    rule_id: str
    title: str
    severity: Severity
    mitre_id: str
    mitre_name: str
    pattern: re.Pattern


WEB_SIGNATURES: tuple[WebSignature, ...] = (
    WebSignature(
        "WEB-001", "SQL injection attempt", Severity.HIGH,
        "T1190", "Exploit Public-Facing Application",
        re.compile(
            r"union(\s|/\*.*?\*/)+(all\s+)?select|'\s*or\s*'?\d+'?\s*=\s*'?\d+|"
            r"\bor\s+1\s*=\s*1\b|information_schema|sleep\s*\(\s*\d+\s*\)|"
            r"benchmark\s*\(|waitfor\s+delay|'\s*;?\s*--",
            re.IGNORECASE,
        ),
    ),
    WebSignature(
        "WEB-002", "Path traversal / local file inclusion", Severity.HIGH,
        "T1190", "Exploit Public-Facing Application",
        re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini|php://filter", re.IGNORECASE),
    ),
    WebSignature(
        "WEB-003", "Cross-site scripting attempt", Severity.MEDIUM,
        "T1189", "Drive-by Compromise",
        re.compile(r"<\s*script|javascript:|on(error|load|mouseover)\s*=|<\s*svg[^>]*onload", re.IGNORECASE),
    ),
    WebSignature(
        "WEB-004", "OS command injection attempt", Severity.HIGH,
        "T1059", "Command and Scripting Interpreter",
        re.compile(
            r"[;|`]\s*(cat|id|whoami|uname|wget|curl|nc|bash|sh)\b|\$\((cat|id|whoami|uname)",
            re.IGNORECASE,
        ),
    ),
)

SCANNER_AGENTS = re.compile(
    r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb|ffuf|wfuzz|wpscan|"
    r"nuclei|acunetix|nessus|openvas|hydra",
    re.IGNORECASE,
)


def _decode(path: str) -> str:
    """URL-decode twice to catch double-encoded payloads like %2527."""
    return unquote_plus(unquote_plus(path))


def detect_web_attacks(events: list[WebEvent], cfg: DetectionConfig) -> list[Alert]:
    hits: dict[tuple[str, str], list[WebEvent]] = defaultdict(list)
    for event in events:
        decoded = _decode(event.path)
        for sig in WEB_SIGNATURES:
            if sig.pattern.search(decoded):
                hits[(sig.rule_id, event.ip)].append(event)

    by_id = {sig.rule_id: sig for sig in WEB_SIGNATURES}
    alerts = []
    for (rule_id, ip), matched in hits.items():
        sig = by_id[rule_id]
        succeeded = sum(1 for e in matched if 200 <= e.status < 300)
        severity = sig.severity
        note = ""
        if succeeded:
            severity = Severity(min(severity + 1, Severity.CRITICAL))
            note = f" {succeeded} of them returned a 2xx response, so check whether the attack worked."
        alerts.append(Alert(
            rule_id=rule_id,
            title=sig.title,
            severity=severity,
            mitre_id=sig.mitre_id,
            mitre_name=sig.mitre_name,
            description=f"{len(matched)} request(s) from {ip} matched {sig.title} patterns.{note}",
            ip=ip,
            first_seen=matched[0].timestamp,
            last_seen=matched[-1].timestamp,
            count=len(matched),
            evidence=[e.raw for e in matched[:MAX_EVIDENCE]],
        ))
    return alerts


def detect_scanners(events: list[WebEvent], cfg: DetectionConfig) -> list[Alert]:
    alerts = []
    flagged = [e for e in events if SCANNER_AGENTS.search(e.user_agent)]
    for ip, ip_events in _group(flagged, lambda e: e.ip).items():
        tools = sorted({SCANNER_AGENTS.search(e.user_agent).group(0).lower() for e in ip_events})
        alerts.append(Alert(
            rule_id="WEB-005",
            title="Known vulnerability scanner",
            severity=Severity.MEDIUM,
            mitre_id="T1595.002",
            mitre_name="Active Scanning: Vulnerability Scanning",
            description=f"{ip} sent {len(ip_events)} request(s) with scanner user agents: {', '.join(tools)}.",
            ip=ip,
            first_seen=ip_events[0].timestamp,
            last_seen=ip_events[-1].timestamp,
            count=len(ip_events),
            evidence=[e.raw for e in ip_events[:MAX_EVIDENCE]],
        ))
    return alerts


def detect_directory_bruteforce(events: list[WebEvent], cfg: DetectionConfig) -> list[Alert]:
    not_found = [e for e in events if e.status == 404]
    alerts = []
    window = timedelta(seconds=cfg.not_found_window)
    for ip, ip_events in _group(not_found, lambda e: e.ip).items():
        start, end = _densest_window([e.timestamp for e in ip_events], window)
        burst = ip_events[start : end + 1]
        if len(burst) < cfg.not_found_threshold:
            continue
        alerts.append(Alert(
            rule_id="WEB-006",
            title="Directory / file brute forcing",
            severity=Severity.MEDIUM,
            mitre_id="T1595.003",
            mitre_name="Active Scanning: Wordlist Scanning",
            description=(
                f"{len(burst)} requests from {ip} returned 404 within {cfg.not_found_window}s, "
                "which looks like a wordlist scan for hidden paths."
            ),
            ip=ip,
            first_seen=burst[0].timestamp,
            last_seen=burst[-1].timestamp,
            count=len(ip_events),
            evidence=[e.raw for e in burst[:MAX_EVIDENCE]],
        ))
    return alerts


AUTH_DETECTORS = (
    detect_ssh_brute_force,
    detect_password_spray,
    detect_success_after_failures,
    detect_root_login,
    detect_sudo_shell,
)
WEB_DETECTORS = (detect_web_attacks, detect_scanners, detect_directory_bruteforce)


def run_all(
    auth_events: list[AuthEvent],
    web_events: list[WebEvent],
    cfg: DetectionConfig | None = None,
) -> list[Alert]:
    cfg = cfg or DetectionConfig()
    alerts: list[Alert] = []
    for detector in AUTH_DETECTORS:
        alerts.extend(detector(auth_events, cfg))
    for detector in WEB_DETECTORS:
        alerts.extend(detector(web_events, cfg))
    alerts.sort(key=lambda a: (-a.severity, a.first_seen or datetime.min))
    return alerts
