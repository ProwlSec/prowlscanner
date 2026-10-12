from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "sensitive_data_exposure/disclosure_of_secrets/for_publicly_accessible_asset"

_PROBES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("/.git/config", re.compile(r"\[core\]", re.IGNORECASE), "Exposed Git repository config"),
    ("/.git/HEAD", re.compile(r"ref:\s*refs/"), "Exposed Git repository metadata"),
    ("/.env", re.compile(r"(?m)^[A-Z0-9_]{2,}=.+"), "Exposed environment file"),
    ("/.svn/entries", re.compile(r"(?m)^\d+\s*$|svn://"), "Exposed Subversion metadata"),
    ("/.DS_Store", re.compile(r"Bud1|\x00\x00\x00\x01Bud1"), "Exposed .DS_Store listing"),
    ("/config.php.bak", re.compile(r"<\?php|define\(|\$db"), "Exposed PHP config backup"),
    ("/wp-config.php.bak", re.compile(r"DB_PASSWORD|DB_NAME"), "Exposed WordPress config backup"),
    ("/.aws/credentials", re.compile(r"aws_access_key_id", re.IGNORECASE), "Exposed AWS credentials file"),
    ("/docker-compose.yml", re.compile(r"(?m)^\s*services:"), "Exposed docker-compose file"),
)


def _origins(ctx: Context) -> list[str]:
    seen: set[str] = set()
    for page in ctx.pages:
        parsed = urlparse(page.url)
        if parsed.scheme and parsed.netloc:
            seen.add(f"{parsed.scheme}://{parsed.netloc}")
    return sorted(seen)


class SensitiveExposure(Module):
    name = "sensitive-exposure"
    vrt_targets = (_VRT,)
    passive = False

    async def run(self, ctx: Context) -> None:
        for origin in _origins(ctx):
            host = urlparse(origin).hostname or ""
            if not ctx.scope.permits(host, ctx._ip_for(host)):
                continue
            for path, signature, title in _PROBES:
                url = urljoin(origin + "/", path.lstrip("/"))
                resp = await ctx.client.get(url)
                if not resp.ok or resp.status != 200 or not resp.text:
                    continue
                if "html" in resp.content_type and "<html" in resp.text[:500].lower():
                    continue
                if not signature.search(resp.text):
                    continue
                ctx.add(Finding(
                    module=self.name,
                    vrt_id=_VRT,
                    title=title,
                    asset=ctx.asset_for(url),
                    evidence=f"{path} returned {resp.status} matching a known sensitive-file signature",
                    confidence=Confidence.CONFIRMED,
                    request=f"GET {url}",
                    response_excerpt=resp.text[:200],
                    remediation="Block access to this path and remove the artifact from the web root.",
                ))
