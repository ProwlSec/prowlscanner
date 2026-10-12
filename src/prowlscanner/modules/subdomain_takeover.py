from __future__ import annotations

from urllib.parse import urlparse

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "server_security_misconfiguration/misconfigured_dns/subdomain_takeover"

_FINGERPRINTS: tuple[tuple[str, str], ...] = (
    ("GitHub Pages", "There isn't a GitHub Pages site here"),
    ("AWS S3", "NoSuchBucket"),
    ("AWS S3", "The specified bucket does not exist"),
    ("Heroku", "No such app"),
    ("Heroku", "herokucdn.com/error-pages/no-such-app.html"),
    ("Shopify", "Sorry, this shop is currently unavailable"),
    ("Fastly", "Fastly error: unknown domain"),
    ("Pantheon", "The gods are wise, but do not know of the site which you seek"),
    ("Tumblr", "Whatever you were looking for doesn't currently exist at this address"),
    ("Bitbucket", "Repository not found"),
    ("Read the Docs", "unknown to Read the Docs"),
    ("Surge.sh", "project not found"),
    ("Netlify", "Not Found - Request ID"),
    ("Cargo", "404 Blog is not found"),
    ("Agile CRM", "Sorry, this page is no longer available"),
)


def fingerprint_takeover(body: str) -> str:
    for service, signature in _FINGERPRINTS:
        if signature in body:
            return service
    return ""


class SubdomainTakeover(Module):
    name = "subdomain-takeover"
    vrt_targets = (_VRT,)
    passive = True

    async def run(self, ctx: Context) -> None:
        seen: set[str] = set()
        for page in ctx.pages:
            parsed = urlparse(page.url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin in seen:
                continue
            seen.add(origin)
            service = fingerprint_takeover(page.response.text)
            if not service:
                continue
            ctx.add(Finding(
                module=self.name,
                vrt_id=_VRT,
                title=f"Possible subdomain takeover ({service})",
                asset=ctx.asset_for(origin + "/"),
                evidence=f"{parsed.hostname} serves the '{service}' unclaimed-resource fingerprint, indicating a dangling DNS record.",
                confidence=Confidence.FIRM,
                response_excerpt=page.response.text[:200],
                remediation=f"Remove the dangling DNS record or reclaim the {service} resource it points to.",
                extra={"service": service},
            ))
