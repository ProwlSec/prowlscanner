from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    in_scope: list[str]
    out_of_scope: list[str] = field(default_factory=list)
    not_applicable: list[str] = field(default_factory=list)
    bands: tuple[int, ...] = (1, 2, 3, 4)
    authorized: bool = False
    max_depth: int = 2
    max_urls: int = 300
    concurrency: int = 15
    rate: float = 12.0
    timeout: float = 15.0
    verify_tls: bool = True
    user_agent: str = "prowlscanner/0.1 (+https://github.com/ProwlSec/prowlscanner)"
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str) -> "ScanConfig":
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
        bands = tuple(raw.get("bands", [1, 2, 3, 4]))
        return cls(
            in_scope=list(raw.get("in_scope", [])),
            out_of_scope=list(raw.get("out_of_scope", [])),
            not_applicable=list(raw.get("not_applicable", [])),
            bands=bands,
            authorized=bool(raw.get("authorized", False)),
            max_depth=int(raw.get("max_depth", 2)),
            max_urls=int(raw.get("max_urls", 300)),
            concurrency=int(raw.get("concurrency", 15)),
            rate=float(raw.get("rate", 12.0)),
            timeout=float(raw.get("timeout", 15.0)),
            verify_tls=bool(raw.get("verify_tls", True)),
            user_agent=raw.get("user_agent", cls.user_agent),
            headers=dict(raw.get("headers", {})),
        )

    def skipped(self, vrt_id: str) -> bool:
        return any(vrt_id == p or vrt_id.startswith(p.rstrip("/") + "/") for p in self.not_applicable)
