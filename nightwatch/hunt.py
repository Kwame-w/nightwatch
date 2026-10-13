"""``nightwatch-hunt``: run SQL threat-hunting queries against a Nightwatch database.

    nightwatch --auth auth.log --web access.log --db hunt.db
    nightwatch-hunt --db hunt.db --list
    nightwatch-hunt --db hunt.db top_attackers
    nightwatch-hunt --db hunt.db --sql "SELECT ip, COUNT(*) FROM web_events GROUP BY ip"
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

from .storage import builtin_queries, connect, describe, format_table, run_query


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nightwatch-hunt", description="Hunt through stored logs and alerts with SQL.")
    p.add_argument("--db", type=Path, required=True, help="SQLite file written by 'nightwatch --db'")
    p.add_argument("query", nargs="*", help="built-in query name(s); use --list to see them")
    p.add_argument("--list", action="store_true", help="list built-in hunting queries")
    p.add_argument("--all", action="store_true", help="run every built-in query")
    p.add_argument("--sql", help="run your own SQL (the database is opened read-only)")
    p.add_argument("--show-sql", action="store_true", help="print each query before its results")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    queries = builtin_queries()

    if args.list:
        width = max(len(n) for n in queries)
        for name, sql in queries.items():
            print(f"{name.ljust(width)}  {describe(sql)}")
        return 0
    if not args.db.is_file():
        parser.error(f"database not found: {args.db} (create it with: nightwatch ... --db {args.db})")

    selected = list(queries) if args.all else args.query
    unknown = [q for q in selected if q not in queries]
    if unknown:
        parser.error(f"unknown query: {', '.join(unknown)} (see --list)")
    jobs = [(name, queries[name]) for name in selected]
    if args.sql:
        jobs.append(("custom", args.sql))
    if not jobs:
        parser.error("give a query name, --all, --sql or --list")

    conn = connect(args.db, read_only=True)
    status = 0
    for i, (name, sql) in enumerate(jobs):
        if i:
            print()
        print(f"== {name}: {describe(sql)}" if describe(sql) else f"== {name}")
        if args.show_sql:
            print(sql.strip() + "\n")
        try:
            print(format_table(*run_query(conn, sql)))
        except sqlite3.Error as exc:
            print(f"SQL error: {exc}")
            status = 1
    conn.close()
    return status


if __name__ == "__main__":
    raise SystemExit(main())
