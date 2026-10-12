from .json_report import render_json
from .html import render_html
from .sarif import render_sarif
from .submission import render_submission, render_submissions

__all__ = [
    "render_json", "render_html", "render_sarif",
    "render_submission", "render_submissions", "summary_lines",
]


_COLORS = {"P1": "\x1b[1;31m", "P2": "\x1b[31m", "P3": "\x1b[33m", "P4": "\x1b[36m", "P5": "\x1b[90m"}
_RESET = "\x1b[0m"


def summary_lines(report, color: bool = True) -> list[str]:
    lines = []
    counts = report.counts
    band = ", ".join(f"P{b}" for b in report.bands)
    lines.append(f"scan complete in {report.duration:.1f}s — {report.pages_crawled} pages, bands {band}")
    tally = " ".join(f"{k}:{counts.get(k, 0)}" for k in ("P1", "P2", "P3", "P4") if k[1:] and int(k[1]) in report.bands)
    lines.append(f"findings: {len(report.findings)}  ({tally})")
    for finding in report.findings:
        label = finding.priority_label or "--"
        prefix = f"{_COLORS.get(label, '')}{label}{_RESET}" if color else label
        lines.append(f"  {prefix}  {finding.title}")
        lines.append(f"       asset: {finding.asset.label()}")
        lines.append(f"       vrt:   {finding.vrt_id}  ({finding.confidence.value})")
        if finding.evidence:
            lines.append(f"       why:   {finding.evidence}")
    return lines
