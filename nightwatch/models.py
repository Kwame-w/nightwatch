"""Core data structures shared by parsers, detectors and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from {choices})") from exc


@dataclass(frozen=True)
class AuthEvent:
    """A single security-relevant line from a Linux auth log (sshd / sudo)."""

    timestamp: datetime
    host: str
    kind: str  # ssh_failed, ssh_accepted, ssh_invalid_user, sudo
    user: str | None
    ip: str | None
    method: str | None = None  # password / publickey for ssh, command for sudo
    raw: str = ""


@dataclass(frozen=True)
class WebEvent:
    """A single request from an Apache/Nginx combined-format access log."""

    timestamp: datetime
    ip: str
    method: str
    path: str
    status: int
    size: int
    referrer: str
    user_agent: str
    raw: str = ""


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: Severity
    mitre_id: str
    mitre_name: str
    description: str
    ip: str | None = None
    user: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    count: int = 1
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.name.lower()
        for key in ("first_seen", "last_seen"):
            if data[key] is not None:
                data[key] = data[key].isoformat()
        return data
