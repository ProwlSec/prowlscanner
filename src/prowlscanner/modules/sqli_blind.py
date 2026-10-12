from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "server_side_injection/sql_injection"
_DELAY = 5.0
_PAYLOADS = (
    "' AND SLEEP(5)-- -",
    "' OR SLEEP(5)-- -",
    "';SELECT pg_sleep(5)-- -",
    "' AND 1=(SELECT 1 FROM pg_sleep(5))-- -",
    "';WAITFOR DELAY '0:0:5'-- -",
    "1 AND SLEEP(5)",
)


def is_time_based(baseline_elapsed: float, injected_elapsed: float, delay: float = _DELAY) -> bool:
    floor = delay * 0.8
    if baseline_elapsed >= floor:
        return False
    return injected_elapsed >= floor and (injected_elapsed - baseline_elapsed) >= delay * 0.7


def _points(ctx: Context) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for page in ctx.pages:
        parsed = urlparse(page.url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for name, _ in parse_qsl(parsed.query):
            if (base, name) not in seen:
                seen.add((base, name))
                out.append((page.url, name))
    return out


def _set(url: str, param: str, suffix: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, (v + suffix) if k == param else v) for k, v in parse_qsl(parsed.query)]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(pairs), parsed.fragment))


class SqlInjectionBlind(Module):
    name = "sqli-blind"
    vrt_targets = (_VRT,)
    passive = False

    async def run(self, ctx: Context) -> None:
        for url, param in _points(ctx):
            host = urlparse(url).hostname or ""
            if not ctx.scope.permits(host, ctx._ip_for(host)):
                continue
            baseline = await ctx.client.get(url)
            if not baseline.ok or baseline.elapsed >= _DELAY * 0.8:
                continue
            for payload in _PAYLOADS:
                first = await ctx.client.get(_set(url, param, payload))
                if not first.ok or not is_time_based(baseline.elapsed, first.elapsed):
                    continue
                confirm = await ctx.client.get(_set(url, param, payload))
                if not confirm.ok or not is_time_based(baseline.elapsed, confirm.elapsed):
                    continue
                ctx.add(Finding(
                    module=self.name,
                    vrt_id=_VRT,
                    title=f"Blind (time-based) SQL injection via parameter '{param}'",
                    asset=ctx.asset_for(_set(url, param, payload)),
                    evidence=(f"Parameter '{param}' delayed the response to {confirm.elapsed:.1f}s with a time-based "
                              f"payload (baseline {baseline.elapsed:.1f}s), confirmed twice."),
                    confidence=Confidence.FIRM,
                    request=f"GET {_set(url, param, payload)}",
                    remediation="Use parameterized queries / prepared statements; never concatenate input into SQL.",
                    extra={"parameter": param, "payload": payload, "elapsed": round(confirm.elapsed, 2)},
                ))
                break
