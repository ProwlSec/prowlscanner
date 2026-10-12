from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "server_side_injection/file_inclusion/local"
_HINTS = ("file", "path", "page", "template", "doc", "document", "include",
          "load", "read", "name", "download", "view", "filename", "dir")
_PAYLOADS = (
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..\\..\\..\\..\\..\\windows\\win.ini",
)
_SIGNATURES = (
    re.compile(r"root:.*:0:0:", re.MULTILINE),
    re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.IGNORECASE),
)


def leaked_file(body: str) -> str:
    for signature in _SIGNATURES:
        match = signature.search(body)
        if match:
            return match.group(0)[:80]
    return ""


def _candidates(ctx: Context) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for page in ctx.pages:
        parsed = urlparse(page.url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for name, _ in parse_qsl(parsed.query):
            if name.lower() in _HINTS and (base, name) not in seen:
                seen.add((base, name))
                out.append((page.url, name))
    return out


def _set(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, value if k == param else v) for k, v in parse_qsl(parsed.query)]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(pairs), parsed.fragment))


class PathTraversal(Module):
    name = "path-traversal"
    vrt_targets = (_VRT,)
    passive = False

    async def run(self, ctx: Context) -> None:
        for url, param in _candidates(ctx):
            host = urlparse(url).hostname or ""
            if not ctx.scope.permits(host, ctx._ip_for(host)):
                continue
            for payload in _PAYLOADS:
                target = _set(url, param, payload)
                resp = await ctx.client.get(target)
                if not resp.ok:
                    continue
                leaked = leaked_file(resp.text)
                if not leaked:
                    continue
                ctx.add(Finding(
                    module=self.name,
                    vrt_id=_VRT,
                    title=f"Local file inclusion via parameter '{param}'",
                    asset=ctx.asset_for(target),
                    evidence=f"Parameter '{param}' returned OS file contents matching '{leaked}'.",
                    confidence=Confidence.CONFIRMED,
                    request=f"GET {target}",
                    response_excerpt=resp.text[:200],
                    remediation="Reject path separators; resolve against an allowlist of permitted files.",
                    extra={"parameter": param, "payload": payload},
                ))
                break
