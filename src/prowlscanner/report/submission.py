from __future__ import annotations

from .. import vrt


def render_submission(finding) -> str:
    target_location = finding.asset.host or finding.asset.ip or finding.asset.label()
    bug_url = finding.asset.url or finding.asset.label()
    steps = "\n".join(finding.steps_list)
    poc_parts = []
    if finding.request:
        poc_parts.append(finding.request)
    if finding.response_excerpt:
        poc_parts.append(f"Response evidence:\n{finding.response_excerpt}")
    if not poc_parts:
        poc_parts.append(finding.evidence)
    poc = "\n\n".join(poc_parts)
    return (
        f"Target Location\n{target_location}\n"
        f"Target category\n{finding.target_category}\n"
        f"VRT\n{vrt.readable_chain(finding.vrt_id)}\n"
        f"Priority\n{finding.priority_label} ({finding.confidence.value})\n"
        f"Bug URL\n{bug_url}\n"
        f"Description\n{finding.description_text}\n\n"
        f"Business Impact\n\n{finding.impact_text}\n\n"
        f"Steps to Reproduce\n\n{steps}\n\n"
        f"Remediation\n\n{finding.remediation}\n\n"
        f"Proof of Concept (PoC)\n\n{poc}\n"
    )


def render_submissions(report) -> str:
    if not report.findings:
        return "No in-scope P1–P4 findings to report.\n"
    blocks = []
    for index, finding in enumerate(report.findings, start=1):
        blocks.append(f"{'=' * 72}\nFINDING {index} of {len(report.findings)}\n{'=' * 72}\n\n" + render_submission(finding))
    return "\n\n".join(blocks)
