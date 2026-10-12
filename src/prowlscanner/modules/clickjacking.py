from __future__ import annotations

import re
from urllib.parse import urlparse

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "server_security_misconfiguration/clickjacking/sensitive_action"
_FRAME_ANCESTORS = re.compile(r"frame-ancestors", re.IGNORECASE)
_SENSITIVE_INPUT = re.compile(r"type=['\"]?(?:password|email)['\"]?", re.IGNORECASE)


def framing_allowed(headers: dict[str, str]) -> bool:
    xfo = headers.get("x-frame-options", "").strip().lower()
    if xfo in ("deny", "sameorigin") or xfo.startswith("allow-from"):
        return False
    csp = headers.get("content-security-policy", "")
    if _FRAME_ANCESTORS.search(csp):
        return False
    return True


class Clickjacking(Module):
    name = "clickjacking"
    vrt_targets = (_VRT,)
    passive = True

    async def run(self, ctx: Context) -> None:
        reported: set[str] = set()
        for page in ctx.pages:
            if not page.forms:
                continue
            has_sensitive = _SENSITIVE_INPUT.search(page.response.text) or any(
                any(h in i.lower() for h in ("pass", "card", "cvv", "transfer", "amount")) for f in page.forms for i in f.inputs
            )
            if not has_sensitive:
                continue
            if not framing_allowed(page.response.headers):
                continue
            base = urlparse(page.url)._replace(query="").geturl()
            if base in reported:
                continue
            reported.add(base)
            ctx.add(Finding(
                module=self.name,
                vrt_id=_VRT,
                title="Clickjacking possible on a sensitive-action page",
                asset=ctx.asset_for(page.url),
                evidence="Page with a sensitive form is framable: no X-Frame-Options and no CSP frame-ancestors.",
                confidence=Confidence.FIRM,
                remediation="Send X-Frame-Options: DENY or CSP frame-ancestors 'none' on sensitive pages.",
            ))
