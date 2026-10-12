from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "server_security_misconfiguration/exposed_portal/admin_portal"

_PROBES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("WordPress admin", "wp-login.php", re.compile(r"user_login|wp-submit|WordPress", re.IGNORECASE)),
    ("phpMyAdmin", "phpmyadmin/", re.compile(r"phpMyAdmin", re.IGNORECASE)),
    ("Jenkins", "jenkins/", re.compile(r"Jenkins|hudson", re.IGNORECASE)),
    ("Grafana", "grafana/login", re.compile(r"Grafana", re.IGNORECASE)),
    ("Tomcat Manager", "manager/html", re.compile(r"Tomcat|Manager Application", re.IGNORECASE)),
    ("Django admin", "admin/login/", re.compile(r"Django administration", re.IGNORECASE)),
    ("Adminer", "adminer.php", re.compile(r"Adminer", re.IGNORECASE)),
    ("Kibana", "app/kibana", re.compile(r"Kibana", re.IGNORECASE)),
)


def admin_fingerprint(body: str, pattern: re.Pattern[str]) -> bool:
    return bool(pattern.search(body))


def _origins(ctx: Context) -> list[str]:
    seen: set[str] = set()
    for page in ctx.pages:
        parsed = urlparse(page.url)
        if parsed.scheme and parsed.netloc:
            seen.add(f"{parsed.scheme}://{parsed.netloc}")
    return sorted(seen)


class AdminPortal(Module):
    name = "admin-portal"
    vrt_targets = (_VRT,)
    passive = False

    async def run(self, ctx: Context) -> None:
        for origin in _origins(ctx):
            host = urlparse(origin).hostname or ""
            if not ctx.scope.permits(host, ctx._ip_for(host)):
                continue
            for service, path, pattern in _PROBES:
                url = urljoin(origin + "/", path)
                resp = await ctx.client.get(url)
                if not resp.ok or resp.status not in (200, 401, 403):
                    continue
                if not admin_fingerprint(resp.text, pattern):
                    continue
                ctx.add(Finding(
                    module=self.name,
                    vrt_id=_VRT,
                    title=f"Exposed administrative portal ({service})",
                    asset=ctx.asset_for(url),
                    evidence=f"{service} administrative interface is reachable at {path} (HTTP {resp.status}).",
                    confidence=Confidence.FIRM,
                    request=f"GET {url}",
                    response_excerpt=resp.text[:200],
                    remediation="Restrict admin interfaces to trusted networks/VPN and enforce strong authentication.",
                    extra={"service": service, "status": resp.status},
                ))
