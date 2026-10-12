from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    content_type: str
    elapsed: float
    history: tuple[int, ...]
    set_cookies: tuple[str, ...] = ()
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.error == "" and self.status > 0


class RateLimiter:
    def __init__(self, rate: float) -> None:
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            if now < self._next:
                await asyncio.sleep(self._next - now)
                now = time.monotonic()
            self._next = now + self._interval


class Client:
    def __init__(
        self,
        *,
        concurrency: int = 15,
        rate: float = 12.0,
        timeout: float = 15.0,
        verify_tls: bool = True,
        user_agent: str = "prowlscanner/0.1",
        headers: dict[str, str] | None = None,
    ) -> None:
        base_headers = {"User-Agent": user_agent, "Accept": "*/*"}
        if headers:
            base_headers.update(headers)
        self._limiter = RateLimiter(rate)
        self._sem = asyncio.Semaphore(max(1, concurrency))
        self._client = httpx.AsyncClient(
            headers=base_headers,
            timeout=timeout,
            verify=verify_tls,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=concurrency),
        )

    async def __aenter__(self) -> "Client":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        follow_redirects: bool = True,
        **kwargs: object,
    ) -> Response:
        await self._limiter.wait()
        async with self._sem:
            start = time.monotonic()
            try:
                resp = await self._client.request(
                    method, url, follow_redirects=follow_redirects, **kwargs
                )
            except httpx.HTTPError as exc:
                return Response(url, 0, {}, "", "", time.monotonic() - start, (), error=str(exc))
            body = resp.content[: 2 * 1024 * 1024]
            text = body.decode(resp.encoding or "utf-8", errors="replace")
            return Response(
                url=str(resp.url),
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                text=text,
                content_type=resp.headers.get("content-type", ""),
                elapsed=time.monotonic() - start,
                history=tuple(r.status_code for r in resp.history),
                set_cookies=tuple(resp.headers.get_list("set-cookie")),
            )

    async def get(self, url: str, **kwargs: object) -> Response:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: object) -> Response:
        return await self.request("HEAD", url, follow_redirects=False, **kwargs)
