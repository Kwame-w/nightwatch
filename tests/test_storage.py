import sqlite3
from datetime import datetime
from pathlib import Path

import pytest

from nightwatch import storage
from nightwatch.cli import main as cli_main
from nightwatch.hunt import main as hunt_main
from nightwatch.models import Alert, AuthEvent, Severity

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "hunt.db"
    assert cli_main(["--auth", str(SAMPLES / "auth.log"), "--web", str(SAMPLES / "access.log"),
                     "--year", "2026", "--db", str(path)]) == 0
    return path


def test_run_is_stored(db):
    conn = storage.connect(db, read_only=True)
    counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
              for t in ("runs", "auth_events", "web_events", "alerts")}
    assert counts["runs"] == 1
    assert counts["auth_events"] > 50 and counts["web_events"] > 400
    assert counts["alerts"] == 14


def test_every_builtin_query_runs(db):
    conn = storage.connect(db, read_only=True)
    queries = storage.builtin_queries()
    assert len(queries) >= 7
    for name, sql in queries.items():
        columns, _ = storage.run_query(conn, sql)
        assert columns, name
        assert storage.describe(sql), f"{name} needs a description comment"


def test_hunting_queries_find_the_staged_attacks(db):
    conn = storage.connect(db, read_only=True)
    q = storage.builtin_queries()
    _, rows = storage.run_query(conn, q["success_after_failures"])
    assert rows[0][1:3] == ("deploy", "198.51.100.23") and rows[0][4] >= 5
    _, rows = storage.run_query(conn, q["cross_vector_ips"])
    assert [r[0] for r in rows] == ["203.0.113.45"]
    _, rows = storage.run_query(conn, q["top_attackers"])
    assert rows[0][3] == "critical"


def test_hostile_log_content_is_stored_as_data(tmp_path):
    conn = storage.connect(tmp_path / "x.db")
    evil = "x'); DROP TABLE alerts; --"
    event = AuthEvent(datetime(2026, 1, 1), "h", "ssh_failed", evil, "203.0.113.1", "password", raw=evil)
    alert = Alert("AUTH-001", "t", Severity.HIGH, "T1110", "n", "d", user=evil)
    storage.save_run(conn, [event], [], [alert], {"auth": "test"})
    assert conn.execute("SELECT user FROM alerts").fetchone()[0] == evil
    assert conn.execute("SELECT raw FROM auth_events").fetchone()[0] == evil


def test_custom_sql_is_read_only(db, capsys):
    assert hunt_main(["--db", str(db), "--sql", "DELETE FROM alerts"]) == 1
    assert "readonly" in capsys.readouterr().out
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 14


def test_hunt_cli(db, capsys):
    assert hunt_main(["--db", str(db), "--list"]) == 0
    assert "top_attackers" in capsys.readouterr().out
    assert hunt_main(["--db", str(db), "top_attackers", "--sql", "SELECT 1 AS one"]) == 0
    out = capsys.readouterr().out
    assert "198.51.100.23" in out and "(1 row)" in out
    with pytest.raises(SystemExit):
        hunt_main(["--db", str(db), "no_such_query"])
    with pytest.raises(SystemExit):
        hunt_main(["--db", str(db.parent / "missing.db"), "--all"])


def test_runs_accumulate(db):
    cli_main(["--auth", str(SAMPLES / "auth.log"), "--year", "2026", "--db", str(db)])
    conn = storage.connect(db, read_only=True)
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 2
