from __future__ import annotations

import json
from datetime import datetime, timezone

from .. import vrt


def build(report) -> dict:
    return {
        "tool": "prowlscanner",
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vrt_release": vrt.release_date(),
        "targets": report.targets,
        "bands": list(report.bands),
        "duration_seconds": round(report.duration, 2),
        "stats": {
            "pages_crawled": report.pages_crawled,
            "modules_run": report.modules_run,
            "counts": report.counts,
            "total": len(report.findings),
        },
        "hosts": [
            {"host": h.host, "ips": h.ips, "ptr": h.ptr, "resolved": h.resolved}
            for h in report.hosts
        ],
        "attack_surface": report.surface,
        "attack_graph": report.graph,
        "findings": [f.as_dict() for f in report.findings],
    }


def render_json(report, indent: int = 2) -> str:
    return json.dumps(build(report), indent=indent)
