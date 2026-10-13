"""Output formats: console summary, JSON and a self-contained HTML report."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path

from . import __version__
from .models import Alert, Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;37;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_RESET = "\033[0m"


def summarize(alerts: list[Alert]) -> dict:
    by_sev = Counter(a.severity.name.lower() for a in alerts)
    by_ip = Counter(a.ip for a in alerts if a.ip)
    return {
        "total_alerts": len(alerts),
        "by_severity": {s.name.lower(): by_sev.get(s.name.lower(), 0) for s in reversed(Severity)},
        "top_sources": [{"ip": ip, "alerts": n} for ip, n in by_ip.most_common(10)],
        "mitre_techniques": sorted({f"{a.mitre_id} {a.mitre_name}" for a in alerts}),
    }


def to_console(alerts: list[Alert], color: bool = True) -> str:
    if not alerts:
        return "No alerts. Nothing suspicious found in the supplied logs."
    lines = []
    for alert in alerts:
        sev = alert.severity.name.ljust(8)
        if color:
            sev = f"{_COLORS[alert.severity]}{sev}{_RESET}"
        lines.append(f"[{sev}] {alert.rule_id}  {alert.title}  ({alert.mitre_id})")
        lines.append(f"           {alert.description}")
    summary = summarize(alerts)
    counts = ", ".join(f"{k}: {v}" for k, v in summary["by_severity"].items() if v)
    lines.append("")
    lines.append(f"{summary['total_alerts']} alert(s) - {counts}")
    return "\n".join(lines)


def to_json(alerts: list[Alert], sources: dict[str, str]) -> str:
    payload = {
        "tool": "nightwatch",
        "version": __version__,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "sources": sources,
        "summary": summarize(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }
    return json.dumps(payload, indent=2)


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nightwatch Report</title>
<style>
  :root {{ --bg:#0f1419; --card:#1a2129; --text:#e6e6e6; --muted:#8b98a5; --border:#2b3640;
          --critical:#ff4d6d; --high:#ff8c42; --medium:#f4d35e; --low:#4cc9f0; }}
  body {{ margin:0; font-family:system-ui,-apple-system,Segoe UI,sans-serif; background:var(--bg); color:var(--text); }}
  main {{ max-width:1100px; margin:0 auto; padding:24px 16px; }}
  h1 {{ margin:0 0 4px; }} .muted {{ color:var(--muted); }}
  .tiles {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin:20px 0; }}
  .tile {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:14px; }}
  .tile b {{ display:block; font-size:28px; }}
  .alert {{ background:var(--card); border:1px solid var(--border); border-left:5px solid var(--sev); border-radius:8px; padding:14px 16px; margin:12px 0; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:4px; background:var(--sev); color:#111; font-weight:700; font-size:12px; text-transform:uppercase; }}
  .meta {{ color:var(--muted); font-size:13px; margin:6px 0; }}
  pre {{ background:#0b0f13; padding:10px; border-radius:6px; overflow-x:auto; font-size:12px; white-space:pre-wrap; word-break:break-all; }}
  a {{ color:var(--low); }}
  table {{ border-collapse:collapse; width:100%; }} td,th {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--border); }}
</style>
</head>
<body><main>
<h1>Nightwatch Report</h1>
<div class="muted">Generated {generated} &middot; sources: {sources}</div>
<div class="tiles">{tiles}</div>
<h2>Top sources</h2>
{top_sources}
<h2>Alerts</h2>
{alerts}
</main></body></html>
"""


def to_html(alerts: list[Alert], sources: dict[str, str]) -> str:
    summary = summarize(alerts)
    tiles = [f'<div class="tile"><span class="muted">Total</span><b>{summary["total_alerts"]}</b></div>']
    for sev, n in summary["by_severity"].items():
        tiles.append(
            f'<div class="tile" style="border-top:3px solid var(--{sev})">'
            f'<span class="muted">{sev.title()}</span><b>{n}</b></div>'
        )

    if summary["top_sources"]:
        rows = "".join(
            f"<tr><td>{escape(s['ip'])}</td><td>{s['alerts']}</td></tr>" for s in summary["top_sources"]
        )
        top_sources = f"<table><tr><th>IP</th><th>Alerts</th></tr>{rows}</table>"
    else:
        top_sources = '<p class="muted">None.</p>'

    cards = []
    for a in alerts:
        sev = a.severity.name.lower()
        who = " &middot; ".join(
            part for part in (
                f"IP {escape(a.ip)}" if a.ip else "",
                f"user {escape(a.user)}" if a.user else "",
                f"{a.first_seen:%Y-%m-%d %H:%M:%S} &rarr; {a.last_seen:%H:%M:%S}" if a.first_seen and a.last_seen else "",
            ) if part
        )
        technique_url = "https://attack.mitre.org/techniques/" + a.mitre_id.replace(".", "/") + "/"
        evidence = escape("\n".join(a.evidence))
        cards.append(
            f'<div class="alert" style="--sev:var(--{sev})">'
            f'<span class="badge">{sev}</span> <b>{escape(a.rule_id)} &middot; {escape(a.title)}</b>'
            f'<div class="meta">{who} &middot; <a href="{technique_url}" target="_blank" rel="noopener">'
            f'{escape(a.mitre_id)} {escape(a.mitre_name)}</a></div>'
            f"<div>{escape(a.description)}</div>"
            f"<pre>{evidence}</pre></div>"
        )

    return _HTML_TEMPLATE.format(
        generated=escape(datetime.now().isoformat(timespec="seconds")),
        sources=escape(", ".join(f"{k}={v}" for k, v in sources.items())),
        tiles="".join(tiles),
        top_sources=top_sources,
        alerts="".join(cards) or '<p class="muted">No alerts.</p>',
    )


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
