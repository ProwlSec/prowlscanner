from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field


@dataclass
class HostInfo:
    host: str
    ips: list[str] = field(default_factory=list)
    ptr: str = ""
    resolved: bool = False
    error: str = ""


def _resolve_sync(host: str) -> HostInfo:
    info = HostInfo(host=host)
    try:
        results = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        info.error = str(exc)
        return info
    info.ips = sorted({item[4][0] for item in results})
    info.resolved = bool(info.ips)
    if info.ips:
        try:
            info.ptr = socket.gethostbyaddr(info.ips[0])[0]
        except (socket.herror, socket.gaierror, OSError):
            info.ptr = ""
    return info


async def resolve(host: str) -> HostInfo:
    return await asyncio.to_thread(_resolve_sync, host)


async def resolve_all(hosts: list[str]) -> list[HostInfo]:
    return await asyncio.gather(*(resolve(h) for h in hosts))
