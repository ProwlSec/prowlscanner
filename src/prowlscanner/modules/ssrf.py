from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "server_security_misconfiguration/server_side_request_forgery_ssrf/internal_data_exposure"
_HINTS = ("url", "uri", "dest", "destination", "callback", "webhook", "image", "img",
          "src", "load", "fetch", "proxy", "open", "domain", "host", "site", "feed", "link", "u")
_PAYLOADS = (
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://localhost/",
    "file:///etc/passwd",
)
_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cloud instance metadata", re.compile(r"\b(ami-id|instance-id|iam/security-credentials|meta-data/)\b")),
    ("/etc/passwd via file://", re.compile(r"root:.*:0:0:", re.MULTILINE)),
    ("internal service banner", re.compile(r"\b(Jenkins|phpMyAdmin|RabbitMQ Management|Kubernetes)\b")),
)


def ssrf_signature(body: str) -> str:
    for label, pattern in _SIGNATURES:
        if pattern.search(body):
            return label
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


class SSRF(Module):
    name = "ssrf"
    vrt_targets = (_VRT,)
    passive = False

    async def run(self, ctx: Context) -> None:
        for url, param in _candidates(ctx):
            host = urlparse(url).hostname or ""
            if not ctx.scope.permits(host, ctx._ip_for(host)):
                continue
            baseline = await ctx.client.get(url)
            base_sig = ssrf_signature(baseline.text) if baseline.ok else ""
            for payload in _PAYLOADS:
                target = _set(url, param, payload)
                resp = await ctx.client.get(target)
                if not resp.ok:
                    continue
                signature = ssrf_signature(resp.text)
                if not signature or signature == base_sig:
                    continue
                ctx.add(Finding(
                    module=self.name,
                    vrt_id=_VRT,
                    title=f"Server-side request forgery via parameter '{param}'",
                    asset=ctx.asset_for(target),
                    evidence=f"Parameter '{param}' fetched an internal resource; response disclosed {signature}.",
                    confidence=Confidence.CONFIRMED,
                    request=f"GET {target}",
                    response_excerpt=resp.text[:200],
                    remediation="Validate and allowlist outbound destinations; block link-local, loopback and internal ranges.",
                    extra={"parameter": param, "payload": payload, "signature": signature},
                ))
                break
