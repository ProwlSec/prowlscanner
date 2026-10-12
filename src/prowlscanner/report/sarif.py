from __future__ import annotations

import json

from .. import vrt

_LEVEL = {1: "error", 2: "error", 3: "warning", 4: "warning", 5: "note"}


def build(report) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for finding in report.findings:
        rule_id = finding.vrt_id
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": vrt.name(rule_id),
                "shortDescription": {"text": vrt.name(rule_id)},
                "properties": {"priority": finding.priority_label, "vrt": rule_id},
            }
        results.append({
            "ruleId": rule_id,
            "level": _LEVEL.get(finding.priority or 5, "note"),
            "message": {"text": f"{finding.title} — {finding.evidence}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.asset.url or finding.asset.label()}
                }
            }],
            "properties": {
                "confidence": finding.confidence.value,
                "priority": finding.priority_label,
                "asset": finding.asset.label(),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "prowlscanner",
                "informationUri": "https://github.com/ProwlSec/prowlscanner",
                "version": "0.1.0",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def render_sarif(report) -> str:
    return json.dumps(build(report), indent=2)
