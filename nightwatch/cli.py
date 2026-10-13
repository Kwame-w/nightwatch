"""Command-line interface: ``nightwatch --auth auth.log --web access.log``."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import __version__, report, storage
from .detectors import DetectionConfig, run_all
from .models import Severity
from .parsers import parse_auth_file, parse_web_file


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nightwatch",
        description="Detect brute force, password spraying, web attacks and scanners in log files.",
    )
    p.add_argument("--auth", type=Path, action="append", default=[], metavar="FILE",
                   help="Linux auth.log / secure file (repeatable)")
    p.add_argument("--web", type=Path, action="append", default=[], metavar="FILE",
                   help="Apache/Nginx combined access log (repeatable)")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="year for syslog timestamps, which omit it (default: current year)")
    p.add_argument("--json", type=Path, metavar="FILE", help="write a JSON report")
    p.add_argument("--html", type=Path, metavar="FILE", help="write an HTML report")
    p.add_argument("--db", type=Path, metavar="FILE",
                   help="store events and alerts in a SQLite database for SQL hunting (see nightwatch-hunt)")
    p.add_argument("--min-severity", default="low", help="hide alerts below this level")
    p.add_argument("--fail-on", metavar="SEVERITY",
                   help="exit with code 2 if any alert is at or above this level (useful in CI)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colours")

    tuning = p.add_argument_group("detection tuning")
    defaults = DetectionConfig()
    for name, help_text in (
        ("brute_force_threshold", "failed logins per IP to call it brute force"),
        ("brute_force_window", "brute-force window in seconds"),
        ("spray_user_threshold", "distinct usernames per IP to call it spraying"),
        ("spray_window", "spraying window in seconds"),
        ("compromise_failure_threshold", "failures before a success that indicate compromise"),
        ("not_found_threshold", "404s per IP to call it directory brute forcing"),
        ("not_found_window", "404 window in seconds"),
    ):
        tuning.add_argument(f"--{name.replace('_', '-')}", type=int,
                            default=getattr(defaults, name), help=f"{help_text} (default: %(default)s)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.auth and not args.web:
        parser.error("give at least one --auth or --web log file")

    try:
        min_sev = Severity.parse(args.min_severity)
        fail_on = Severity.parse(args.fail_on) if args.fail_on else None
    except ValueError as exc:
        parser.error(str(exc))

    for path in [*args.auth, *args.web]:
        if not path.is_file():
            parser.error(f"file not found: {path}")

    auth_events = [e for path in args.auth for e in parse_auth_file(path, args.year)]
    web_events = [e for path in args.web for e in parse_web_file(path)]
    auth_events.sort(key=lambda e: e.timestamp)
    web_events.sort(key=lambda e: e.timestamp)

    cfg = DetectionConfig(**{
        name: getattr(args, name)
        for name in DetectionConfig.__dataclass_fields__
        if hasattr(args, name)
    })
    alerts = [a for a in run_all(auth_events, web_events, cfg) if a.severity >= min_sev]

    sources = {}
    if args.auth:
        sources["auth"] = ", ".join(str(p) for p in args.auth)
    if args.web:
        sources["web"] = ", ".join(str(p) for p in args.web)

    print(f"Parsed {len(auth_events)} auth events and {len(web_events)} web requests.\n")
    use_color = not args.no_color and sys.stdout.isatty()
    print(report.to_console(alerts, color=use_color))

    if args.json:
        report.write(args.json, report.to_json(alerts, sources))
        print(f"\nJSON report written to {args.json}")
    if args.db:
        conn = storage.connect(args.db)
        run_id = storage.save_run(conn, auth_events, web_events, alerts, sources)
        conn.close()
        print(f"Events and alerts saved to {args.db} (run {run_id}). Explore with: nightwatch-hunt --db {args.db} --list")
    if args.html:
        report.write(args.html, report.to_html(alerts, sources))
        print(f"HTML report written to {args.html}")

    if fail_on and any(a.severity >= fail_on for a in alerts):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
