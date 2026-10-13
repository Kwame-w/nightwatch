import json
from pathlib import Path

import pytest

from nightwatch.cli import main

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_end_to_end_on_samples(tmp_path, capsys):
    out_json, out_html = tmp_path / "r.json", tmp_path / "r.html"
    code = main([
        "--auth", str(SAMPLES / "auth.log"), "--web", str(SAMPLES / "access.log"),
        "--year", "2026", "--json", str(out_json), "--html", str(out_html),
    ])
    assert code == 0

    data = json.loads(out_json.read_text())
    rules = {a["rule_id"] for a in data["alerts"]}
    assert {"AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005",
            "WEB-001", "WEB-002", "WEB-003", "WEB-004", "WEB-005", "WEB-006"} <= rules
    assert data["summary"]["by_severity"]["critical"] >= 1

    html = out_html.read_text()
    assert "Nightwatch Report" in html
    assert "<script>alert(1)" not in html  # attacker payloads must be escaped


def test_fail_on_returns_2(capsys):
    code = main(["--auth", str(SAMPLES / "auth.log"), "--year", "2026", "--fail-on", "critical"])
    assert code == 2


def test_min_severity_filters(tmp_path):
    out = tmp_path / "r.json"
    main(["--web", str(SAMPLES / "access.log"), "--min-severity", "critical", "--json", str(out)])
    assert all(a["severity"] == "critical" for a in json.loads(out.read_text())["alerts"])


def test_requires_an_input():
    with pytest.raises(SystemExit):
        main([])


def test_missing_file_errors(tmp_path):
    with pytest.raises(SystemExit):
        main(["--auth", str(tmp_path / "nope.log")])
