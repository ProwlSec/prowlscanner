from __future__ import annotations

import secrets as _rand
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "cross_site_scripting_xss/reflected/non_self"


def _breakout(token: str) -> str:
    return f'{token}"><svg/onload={token}>'


def reflected_unencoded(body: str, token: str) -> bool:
    marker = f'"><svg/onload={token}>'
    if marker in body:
        return True
    return f"<svg/onload={token}>" in body


def _injection_points(ctx: Context) -> list[tuple[str, str]]:
    points: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for page in ctx.pages:
        parsed = urlparse(page.url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for name, _ in parse_qsl(parsed.query):
            key = (base, name)
            if key not in seen:
                seen.add(key)
                points.append((page.url, name))
        for form in page.forms:
            if form.method != "get":
                continue
            faction = urlparse(form.action)
            fbase = f"{faction.scheme}://{faction.netloc}{faction.path}"
            for field_name in form.inputs:
                key = (fbase, field_name)
                if key not in seen:
                    seen.add(key)
                    seed = urlunparse((faction.scheme, faction.netloc, faction.path, "", urlencode({field_name: "1"}), ""))
                    points.append((seed, field_name))
    return points


def _with_value(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query)]
    found = False
    for i, (k, _) in enumerate(pairs):
        if k == param:
            pairs[i] = (k, value)
            found = True
    if not found:
        pairs.append((param, value))
    query = urlencode(pairs)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))


class ReflectedXSS(Module):
    name = "reflected-xss"
    vrt_targets = (_VRT,)
    passive = False

    async def run(self, ctx: Context) -> None:
        for url, param in _injection_points(ctx):
            host = urlparse(url).hostname or ""
            if not ctx.scope.permits(host, ctx._ip_for(host)):
                continue
            token = "prwl" + _rand.token_hex(4)
            target = _with_value(url, param, _breakout(token))
            resp = await ctx.client.get(target)
            if not resp.ok or "html" not in resp.content_type:
                continue
            if not reflected_unencoded(resp.text, token):
                continue
            ctx.add(Finding(
                module=self.name,
                vrt_id=_VRT,
                title=f"Reflected XSS via parameter '{param}'",
                asset=ctx.asset_for(target),
                evidence=f"Parameter '{param}' reflected an unencoded script breakout into the HTML response.",
                confidence=Confidence.CONFIRMED,
                request=f"GET {target}",
                response_excerpt=self._excerpt(resp.text, token),
                remediation="Context-encode output and apply a strict Content-Security-Policy.",
                extra={"parameter": param},
            ))

    @staticmethod
    def _excerpt(body: str, token: str) -> str:
        idx = body.find(token)
        if idx < 0:
            return ""
        start = max(0, idx - 40)
        return body[start: idx + 60]
