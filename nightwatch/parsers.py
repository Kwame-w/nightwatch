"""Parsers that turn raw log lines into typed events.

Lines that are not security relevant (or are malformed) are skipped rather
than raising, because real-world logs are always messy.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path

from .models import AuthEvent, WebEvent

# --- Linux auth.log (syslog format) -------------------------------------------

_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/.]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

_SSH_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)
_SSH_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)
_SSH_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+)")
_SUDO = re.compile(r"^\s*(?P<user>\S+) : .*?USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.+)$")


def _syslog_time(month: str, day: str, clock: str, year: int) -> datetime | None:
    try:
        return datetime.strptime(f"{year} {month} {day} {clock}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def parse_auth_line(line: str, year: int) -> AuthEvent | None:
    """Parse one auth.log line. Syslog omits the year, so the caller supplies it."""
    line = line.rstrip("\n")
    prefix = _SYSLOG_PREFIX.match(line)
    if not prefix:
        return None
    ts = _syslog_time(prefix["month"], prefix["day"], prefix["time"], year)
    if ts is None:
        return None
    host, proc, msg = prefix["host"], prefix["proc"], prefix["msg"]

    if proc == "sshd":
        for kind, pattern in (
            ("ssh_failed", _SSH_FAILED),
            ("ssh_accepted", _SSH_ACCEPTED),
            ("ssh_invalid_user", _SSH_INVALID),
        ):
            m = pattern.match(msg)
            if m:
                groups = m.groupdict()
                return AuthEvent(
                    timestamp=ts,
                    host=host,
                    kind=kind,
                    user=groups.get("user") or None,
                    ip=groups.get("ip"),
                    method=groups.get("method"),
                    raw=line,
                )
    elif proc == "sudo":
        m = _SUDO.match(msg)
        if m and m["target"] == "root":
            return AuthEvent(
                timestamp=ts, host=host, kind="sudo", user=m["user"], ip=None,
                method=m["cmd"].strip(), raw=line,
            )
    return None


# --- Apache / Nginx combined log format ---------------------------------------

_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: [^"]*)?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)")?'
)


def parse_web_line(line: str) -> WebEvent | None:
    line = line.rstrip("\n")
    m = _COMBINED.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except ValueError:
        return None
    return WebEvent(
        timestamp=ts,
        ip=m["ip"],
        method=m["method"],
        path=m["path"],
        status=int(m["status"]),
        size=0 if m["size"] == "-" else int(m["size"]),
        referrer=m["referrer"] or "",
        user_agent=m["ua"] or "",
        raw=line,
    )


# --- File helpers -------------------------------------------------------------

def _read_lines(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        yield from handle


def parse_auth_file(path: Path, year: int) -> list[AuthEvent]:
    return _collect(parse_auth_line(line, year) for line in _read_lines(path))


def parse_web_file(path: Path) -> list[WebEvent]:
    return _collect(parse_web_line(line) for line in _read_lines(path))


def _collect(events: Iterable) -> list:
    return sorted((e for e in events if e is not None), key=lambda e: e.timestamp)
