from __future__ import annotations

import html
from datetime import datetime, timezone

from .. import vrt

_PALETTE = {"P1": "#E26D63", "P2": "#E39A58", "P3": "#D9B65A", "P4": "#6AA9E0", "P5": "#8B93A1"}

_CSS = """
*{box-sizing:border-box}body{margin:0;background:#0A0C10;color:#E8EAEE;font:14px/1.6 ui-sans-serif,system-ui,sans-serif}
a{color:#6E9BF5}.wrap{max-width:960px;margin:0 auto;padding:40px 24px}
h1{font-size:22px;margin:0 0 4px}.sub{color:#8B93A1;font-size:13px}
.bar{display:flex;gap:10px;flex-wrap:wrap;margin:24px 0}
.stat{background:#12151B;border:1px solid #252A34;border-radius:9px;padding:12px 16px;min-width:92px}
.stat .n{font-size:22px;font-weight:700;font-variant-numeric:tabular-nums}.stat .l{color:#8B93A1;font-size:12px}
.f{background:#12151B;border:1px solid #252A34;border-left-width:3px;border-radius:9px;padding:16px 18px;margin:12px 0}
.f h3{margin:0 0 6px;font-size:15px}.tag{display:inline-block;font-size:11px;font-weight:700;padding:1px 8px;border-radius:5px;color:#06080C;margin-right:8px}
.kv{color:#C3C8D1;font-size:13px;margin:3px 0}.kv b{color:#8B93A1;font-weight:500;display:inline-block;min-width:92px}
.mono{font-family:ui-monospace,monospace;font-size:12px;background:#0E1117;border:1px solid #252A34;border-radius:6px;padding:8px 10px;overflow:auto;white-space:pre-wrap;word-break:break-all}
.empty{background:#102820;border:1px solid #1d4733;border-radius:9px;padding:20px;color:#4FB286}
footer{color:#5B6472;font-size:12px;margin-top:40px;border-top:1px solid #252A34;padding-top:16px}
"""


def _finding_block(f) -> str:
    color = _PALETTE.get(f.priority_label or "P5", "#8B93A1")
    rows = [
        ("Asset", html.escape(f.asset.label())),
        ("VRT", html.escape(f.vrt_id)),
        ("Confidence", f.confidence.value),
    ]
    if f.asset.ip:
        rows.append(("IP", html.escape(f.asset.ip)))
    body = "".join(f'<div class="kv"><b>{k}</b>{v}</div>' for k, v in rows)
    extra = ""
    if f.evidence:
        extra += f'<div class="kv"><b>Evidence</b>{html.escape(f.evidence)}</div>'
    if f.request:
        extra += f'<div class="mono">{html.escape(f.request)}</div>'
    if f.remediation:
        extra += f'<div class="kv"><b>Fix</b>{html.escape(f.remediation)}</div>'
    return (
        f'<div class="f" style="border-left-color:{color}">'
        f'<h3><span class="tag" style="background:{color}">{f.priority_label}</span>{html.escape(f.title)}</h3>'
        f'{body}{extra}</div>'
    )


def render_html(report) -> str:
    counts = report.counts
    stats = "".join(
        f'<div class="stat"><div class="n" style="color:{_PALETTE[k]}">{counts.get(k, 0)}</div><div class="l">{k}</div></div>'
        for k in ("P1", "P2", "P3", "P4") if int(k[1]) in report.bands
    )
    stats += f'<div class="stat"><div class="n">{report.pages_crawled}</div><div class="l">pages</div></div>'
    if report.findings:
        blocks = "".join(_finding_block(f) for f in report.findings)
    else:
        blocks = '<div class="empty">No in-scope P1–P4 findings. Clean within the tested surface.</div>'
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    targets = html.escape(", ".join(report.targets))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>prowlscanner report</title><style>{_CSS}</style></head>
<body><div class="wrap">
<h1>prowlscanner report</h1>
<div class="sub">{targets} · {generated} · VRT {vrt.release_date()}</div>
<div class="bar">{stats}</div>
{blocks}
<footer>Priorities from the Bugcrowd Vulnerability Rating Taxonomy. Findings are evidence-backed and confidence-scored; verify before reporting.</footer>
</div></body></html>"""
