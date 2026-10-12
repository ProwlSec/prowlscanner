from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

from ..config import ScanConfig
from ..crawl import Page
from ..findings import Asset, Finding
from ..http import Client
from ..resolve import HostInfo
from ..scope import Scope


@dataclass
class Context:
    config: ScanConfig
    scope: Scope
    client: Client
    hosts: list[HostInfo]
    pages: list[Page]
    event: Callable[[str, str], None] = lambda kind, message: None
    findings: list[Finding] = field(default_factory=list)

    def _ip_for(self, host: str) -> str:
        for info in self.hosts:
            if info.host == host and info.ips:
                return info.ips[0]
        return ""

    def asset_for(self, url: str) -> Asset:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return Asset(
            url=url,
            host=host,
            ip=self._ip_for(host),
            port=parsed.port,
            scheme=parsed.scheme,
        )

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        label = finding.priority_label or "--"
        self.event("finding", f"[{label}] {finding.title} — {finding.asset.label()}")


class Module:
    name: str = ""
    vrt_targets: tuple[str, ...] = ()
    passive: bool = True

    async def run(self, ctx: Context) -> None:
        raise NotImplementedError
