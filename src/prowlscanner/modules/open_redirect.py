from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "unvalidated_redirects_and_forwards/open_redirect/get_based"
_CANARY_HOST = "prowl-canary.example"
_CANARY = f"https://{_CANARY_HOST}/"
_HINTS = ("url", "next", "redirect", "redir", "return", "returnurl", "dest",
          "destination", "continue", "goto", "to", "out", "target", "rurl")


def redirects_offsite(location: str, body: str) -> bool:
    if location:
        host = urlparse(location if "://" in location else "http://x" + location).hostname or ""
        if host == _CANARY_HOST:
            return True
    lowered = body[:4000].lower()
    return _CANARY_HOST in lowered and ("location" in lowered or "http-equiv" in lowered or "window.location" in lowered)


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


class OpenRedirect(Module):
    name = "open-redirect"
    vrt_targets = (_VRT,)
    passive = False

    async def run(self, ctx: Context) -> None:
        for url, param in _candidates(ctx):
            host = urlparse(url).hostname or ""
            if not ctx.scope.permits(host, ctx._ip_for(host)):
                continue
            target = _set(url, param, _CANARY)
            resp = await ctx.client.get(target, follow_redirects=False)
            if not resp.ok:
                continue
            location = resp.headers.get("location", "")
            if not redirects_offsite(location, resp.text):
                continue
            ctx.add(Finding(
                module=self.name,
                vrt_id=_VRT,
                title=f"Open redirect via parameter '{param}'",
                asset=ctx.asset_for(target),
                evidence=f"Parameter '{param}' redirected to an attacker-controlled host ({_CANARY_HOST}).",
                confidence=Confidence.CONFIRMED,
                request=f"GET {target}",
                response_excerpt=f"Location: {location}" if location else resp.text[:160],
                remediation="Allowlist redirect destinations; never redirect to raw user-supplied URLs.",
                extra={"parameter": param},
            ))
