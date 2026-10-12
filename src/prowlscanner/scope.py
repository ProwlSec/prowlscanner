from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def _strip(spec: str) -> str:
    spec = spec.strip().rstrip("/")
    if "://" in spec:
        parsed = urlparse(spec)
        host = parsed.hostname or ""
        if parsed.port:
            return f"{host}:{parsed.port}"
        return host
    return spec


def _is_domain(value: str) -> bool:
    if not value or value.count(".") < 1:
        return False
    return all(_LABEL.match(part) for part in value.split("."))


@dataclass(frozen=True)
class Matcher:
    kind: str
    raw: str
    host: str = ""
    network: str = ""

    @classmethod
    def parse(cls, spec: str) -> "Matcher":
        cleaned = _strip(spec).lower()
        host_only = cleaned.split(":", 1)[0]
        if cleaned.startswith("*."):
            return cls("wildcard", spec, host=cleaned[2:])
        if "/" in host_only:
            try:
                net = ipaddress.ip_network(host_only, strict=False)
                return cls("cidr", spec, network=str(net))
            except ValueError:
                pass
        try:
            ipaddress.ip_address(host_only)
            return cls("ip", spec, host=host_only)
        except ValueError:
            pass
        return cls("domain", spec, host=host_only)

    def match_host(self, host: str) -> bool:
        host = (host or "").lower().rstrip(".")
        if not host:
            return False
        if self.kind == "wildcard":
            return host == self.host or host.endswith("." + self.host)
        if self.kind == "domain":
            return host == self.host
        return False

    def match_ip(self, ip: str) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if self.kind == "ip":
            return str(addr) == self.host
        if self.kind == "cidr":
            return addr in ipaddress.ip_network(self.network)
        return False

    def matches(self, host: str, ip: str = "") -> bool:
        return self.match_host(host) or self.match_ip(ip) or self.match_ip(host)


@dataclass
class Scope:
    include: list[Matcher]
    exclude: list[Matcher]

    @classmethod
    def build(cls, in_scope: list[str], out_of_scope: list[str] | None = None) -> "Scope":
        return cls(
            include=[Matcher.parse(s) for s in in_scope if s.strip()],
            exclude=[Matcher.parse(s) for s in (out_of_scope or []) if s.strip()],
        )

    def permits(self, host: str, ip: str = "") -> bool:
        if any(m.matches(host, ip) for m in self.exclude):
            return False
        return any(m.matches(host, ip) for m in self.include)

    def seeds(self) -> list[str]:
        out = []
        for m in self.include:
            if m.kind in ("domain", "ip"):
                out.append(m.host)
            elif m.kind == "wildcard":
                out.append(m.host)
            elif m.kind == "cidr":
                out.append(m.network)
        return out
