from __future__ import annotations

import re

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "sensitive_data_exposure/visible_detailed_error_page/detailed_server_configuration"

_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Python traceback", re.compile(r"Traceback \(most recent call last\):")),
    ("Java stack trace", re.compile(r"\bat [a-z0-9_.]+\([A-Za-z0-9_]+\.java:\d+\)")),
    ("PHP fatal error", re.compile(r"(?:PHP )?(?:Fatal error|Warning):.*on line \d+", re.IGNORECASE)),
    ("ASP.NET stack trace", re.compile(r"\[(?:SqlException|NullReferenceException|Exception)[^\]]*\]|Microsoft \.NET Framework")),
    ("Ruby exception", re.compile(r"\b[A-Za-z0-9_]+Error \(.*\):\s")),
    ("phpinfo output", re.compile(r"phpinfo\(\)|PHP Version \d")),
    ("framework debug page", re.compile(r"Whoops, looks like something went wrong|Werkzeug Debugger|DEBUG = True")),
    ("stack trace header", re.compile(r"Exception in thread \"")),
)


def detect_verbose_error(body: str) -> str:
    for label, pattern in _SIGNATURES:
        if pattern.search(body):
            return label
    return ""


class VerboseError(Module):
    name = "verbose-error"
    vrt_targets = (_VRT,)
    passive = True

    async def run(self, ctx: Context) -> None:
        seen: set[str] = set()
        for page in ctx.pages:
            label = detect_verbose_error(page.response.text)
            if not label:
                continue
            key = page.url.split("?")[0]
            if key in seen:
                continue
            seen.add(key)
            ctx.add(Finding(
                module=self.name,
                vrt_id=_VRT,
                title=f"Verbose error page discloses server internals ({label})",
                asset=ctx.asset_for(page.url),
                evidence=f"The response exposes a {label}, revealing stack traces or server configuration.",
                confidence=Confidence.FIRM,
                response_excerpt=page.response.text[:200],
                remediation="Disable debug mode in production and return generic error pages; log details server-side only.",
                extra={"signature": label},
            ))
