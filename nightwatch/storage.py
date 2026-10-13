"""Persist events and alerts to SQLite so they can be hunted with SQL afterwards."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from importlib import resources
from pathlib import Path

from .models import Alert, AuthEvent, WebEvent


def _iso(ts: datetime | None) -> str | None:
    return ts.isoformat(timespec="seconds") if ts else None


def connect(path: Path | str, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        # Ad-hoc hunting queries run on a read-only connection, so a typo'd
        # DELETE or DROP can't damage the evidence.
        conn = sqlite3.connect(f"file:{Path(path).resolve()}?mode=ro", uri=True)
    else:
        conn = sqlite3.connect(path)
        conn.executescript(resources.files("nightwatch").joinpath("schema.sql").read_text(encoding="utf-8"))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def save_run(
    conn: sqlite3.Connection,
    auth_events: list[AuthEvent],
    web_events: list[WebEvent],
    alerts: list[Alert],
    sources: dict[str, str],
) -> int:
    """Store one analysis run in a single transaction. Returns the run id.

    Every value goes through ``?`` placeholders: log lines are attacker-controlled,
    and a line containing ``'); DROP TABLE alerts; --`` must stay plain data.
    """
    with conn:
        cur = conn.execute(
            "INSERT INTO runs (started_at, sources) VALUES (?, ?)",
            (_iso(datetime.now()), "; ".join(f"{k}={v}" for k, v in sources.items())),
        )
        run_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO auth_events (run_id, ts, host, kind, user, ip, method, raw) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(run_id, _iso(e.timestamp), e.host, e.kind, e.user, e.ip, e.method, e.raw) for e in auth_events],
        )
        conn.executemany(
            "INSERT INTO web_events (run_id, ts, ip, method, path, status, size, user_agent, raw)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(run_id, _iso(e.timestamp), e.ip, e.method, e.path, e.status, e.size, e.user_agent, e.raw)
             for e in web_events],
        )
        conn.executemany(
            "INSERT INTO alerts (run_id, rule_id, title, severity, severity_n, mitre_id, mitre_name, description,"
            " ip, user, first_seen, last_seen, count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(run_id, a.rule_id, a.title, a.severity.name.lower(), int(a.severity), a.mitre_id, a.mitre_name,
              a.description, a.ip, a.user, _iso(a.first_seen), _iso(a.last_seen), a.count) for a in alerts],
        )
    return run_id


def builtin_queries() -> dict[str, str]:
    """Bundled hunting queries, keyed by file name without ``.sql``."""
    folder = resources.files("nightwatch").joinpath("queries")
    return {
        entry.name.removesuffix(".sql"): entry.read_text(encoding="utf-8")
        for entry in sorted(folder.iterdir(), key=lambda e: e.name)
        if entry.name.endswith(".sql")
    }


def describe(sql: str) -> str:
    """The first comment line of a query file, used as its description."""
    for line in sql.splitlines():
        if line.startswith("--"):
            return line.lstrip("- ").strip()
    return ""


def run_query(conn: sqlite3.Connection, sql: str) -> tuple[list[str], list[tuple]]:
    cur = conn.execute(sql)
    columns = [d[0] for d in cur.description or []]
    return columns, [tuple(row) for row in cur.fetchall()]


def format_table(columns: list[str], rows: list[tuple], max_width: int = 60) -> str:
    if not columns:
        return "(no result set)"

    def cell(value) -> str:
        text = "" if value is None else str(value)
        return text if len(text) <= max_width else text[: max_width - 3] + "..."

    body = [[cell(v) for v in row] for row in rows]
    widths = [max(len(c), *(len(r[i]) for r in body)) if body else len(c) for i, c in enumerate(columns)]
    line = "  ".join(c.ljust(w) for c, w in zip(columns, widths, strict=True))
    out = [line, "  ".join("-" * w for w in widths)]
    out += ["  ".join(v.ljust(w) for v, w in zip(r, widths, strict=True)) for r in body]
    out.append(f"({len(rows)} row{'s' if len(rows) != 1 else ''})")
    return "\n".join(out)
