from __future__ import annotations

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "server_security_misconfiguration/missing_secure_or_httponly_cookie_flag/session_token"
_SESSION_HINTS = ("sess", "sid", "token", "auth", "jsessionid", "phpsessid", "asp.net")


def _name(cookie: str) -> str:
    return cookie.split("=", 1)[0].strip().lower()


def _is_session(name: str) -> bool:
    return any(hint in name for hint in _SESSION_HINTS)


def missing_flags(cookie: str, over_https: bool) -> list[str]:
    attrs = cookie.lower()
    missing = []
    if "httponly" not in attrs:
        missing.append("HttpOnly")
    if over_https and "secure" not in attrs:
        missing.append("Secure")
    return missing


class CookieFlags(Module):
    name = "cookie-flags"
    vrt_targets = (_VRT,)
    passive = True

    async def run(self, ctx: Context) -> None:
        reported: set[tuple[str, str]] = set()
        for page in ctx.pages:
            over_https = page.url.lower().startswith("https://")
            for cookie in page.response.set_cookies:
                name = _name(cookie)
                if not _is_session(name):
                    continue
                missing = missing_flags(cookie, over_https)
                if not missing:
                    continue
                key = (page.response.url.split("?")[0], name)
                if key in reported:
                    continue
                reported.add(key)
                ctx.add(Finding(
                    module=self.name,
                    vrt_id=_VRT,
                    title=f"Session cookie '{name}' missing {', '.join(missing)}",
                    asset=ctx.asset_for(page.url),
                    evidence=f"Set-Cookie for '{name}' is missing: {', '.join(missing)}.",
                    confidence=Confidence.FIRM,
                    response_excerpt=cookie[:160],
                    remediation="Set HttpOnly and Secure (and SameSite) on all session cookies.",
                    extra={"cookie": name, "missing": missing},
                ))
