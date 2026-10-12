from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

from . import vrt
from .config import ScanConfig
from .crawl import Page, crawl
from .findings import Finding
from .http import Client
from .modules import ALL_MODULES, Context
from .resolve import HostInfo, resolve_all
from .scope import Scope
from .surface import build_graph, build_surface

Event = Callable[[str, str], None]


@dataclass
class Report:
    targets: list[str]
    hosts: list[HostInfo]
    findings: list[Finding]
    pages_crawled: int
    modules_run: list[str]
    started: float
    finished: float
    bands: tuple[int, ...]
    surface: dict = field(default_factory=dict)
    graph: dict = field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        tally = {label: 0 for label in ("P1", "P2", "P3", "P4", "P5")}
        for finding in self.findings:
            label = finding.priority_label
            if label:
                tally[label] = tally.get(label, 0) + 1
        return tally

    @property
    def duration(self) -> float:
        return self.finished - self.started


class Engine:
    def __init__(
        self,
        config: ScanConfig,
        *,
        seed_urls: list[str] | None = None,
        event: Event | None = None,
    ) -> None:
        self.config = config
        self.scope = Scope.build(config.in_scope, config.out_of_scope)
        self.seed_urls = list(seed_urls or [])
        self.event = event or (lambda kind, message: None)

    def _modules(self):
        selected = []
        for module_cls in ALL_MODULES:
            targets = module_cls.vrt_targets or ()
            usable = [
                t for t in targets
                if vrt.priority(t) in self.config.bands and not self.config.skipped(t)
            ]
            if usable:
                selected.append(module_cls())
        return selected

    async def _probe(self, client: Client, host: str) -> list[str]:
        for scheme in ("https", "http"):
            resp = await client.get(f"{scheme}://{host}/")
            if resp.ok:
                parsed = urlparse(resp.url)
                return [f"{parsed.scheme}://{parsed.netloc}/"]
        return []

    async def _recon(self, client: Client) -> tuple[list[HostInfo], list[str]]:
        hosts = [h for h in self.scope.seeds() if "/" not in h]
        infos = await resolve_all(hosts)
        seeds: list[str] = list(self.seed_urls)
        for info in infos:
            if info.resolved:
                detail = f"{info.host} -> {', '.join(info.ips)}" + (f" [{info.ptr}]" if info.ptr else "")
                self.event("recon", f"resolved {detail}")
            else:
                self.event("recon", f"could not resolve {info.host} ({info.error or 'no records'})")
                continue
            found = await self._probe(client, info.host)
            for base in found:
                self.event("recon", f"live web service at {base}")
                seeds.append(base)
        deduped = list(dict.fromkeys(seeds))
        return infos, deduped

    def _keep(self, finding: Finding) -> bool:
        if vrt.priority(finding.vrt_id) not in self.config.bands:
            return False
        if self.config.skipped(finding.vrt_id):
            return False
        return self.scope.permits(finding.asset.host, finding.asset.ip)

    async def run(self) -> Report:
        started = time.time()
        self.event("phase", "recon")
        async with Client(
            concurrency=self.config.concurrency,
            rate=self.config.rate,
            timeout=self.config.timeout,
            verify_tls=self.config.verify_tls,
            user_agent=self.config.user_agent,
            headers=self.config.headers,
        ) as client:
            hosts, seeds = await self._recon(client)
            if not seeds:
                self.event("phase", "report")
                return Report(self.config.in_scope, hosts, [], 0, [], started, time.time(), self.config.bands)

            self.event("phase", "crawl")
            pages: list[Page] = []

            def on_page(page: Page) -> None:
                self.event("crawl", f"{page.response.status} {page.url}")

            pages = await crawl(
                client, seeds, self.scope,
                max_depth=self.config.max_depth,
                max_urls=self.config.max_urls,
                on_page=on_page,
            )
            self.event("info", f"crawled {len(pages)} page(s)")

            self.event("phase", "scan")
            modules = self._modules()
            ctx = Context(self.config, self.scope, client, hosts, pages, self.event)
            for module in modules:
                self.event("module", f"running {module.name}")
                try:
                    await module.run(ctx)
                except Exception as exc:
                    self.event("error", f"{module.name}: {exc}")

        self.event("phase", "report")
        kept = [f for f in ctx.findings if self._keep(f)]
        unique: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for finding in kept:
            if finding.dedupe_key in seen:
                continue
            seen.add(finding.dedupe_key)
            unique.append(finding)
        unique.sort(key=lambda f: (f.priority or 9, 0 if f.confidence.value == "confirmed" else 1))
        return Report(
            targets=self.config.in_scope,
            hosts=hosts,
            findings=unique,
            pages_crawled=len(pages),
            modules_run=[m.name for m in modules],
            started=started,
            finished=time.time(),
            bands=self.config.bands,
            surface=build_surface(hosts, pages),
            graph=build_graph(self.config.in_scope, hosts, pages, unique),
        )
