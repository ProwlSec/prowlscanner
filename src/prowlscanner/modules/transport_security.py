from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT_LOGIN = "broken_authentication_and_session_management/weak_login_function/over_http"
_VRT_TOKEN = "sensitive_data_exposure/sensitive_token_in_url/user_facing"
_PASSWORD_INPUT = re.compile(r"<input[^>]+type=['\"]?password['\"]?", re.IGNORECASE)
_TOKEN_PARAM = ("token", "access_token", "auth", "jwt", "apikey", "api_key", "sessionid", "sid", "key")


class TransportSecurity(Module):
    name = "transport-security"
    vrt_targets = (_VRT_LOGIN, _VRT_TOKEN)
    passive = True

    async def run(self, ctx: Context) -> None:
        login_seen: set[str] = set()
        token_seen: set[str] = set()
        for page in ctx.pages:
            parsed = urlparse(page.url)
            if parsed.scheme == "http" and _PASSWORD_INPUT.search(page.response.text):
                base = f"{parsed.netloc}{parsed.path}"
                if base not in login_seen:
                    login_seen.add(base)
                    ctx.add(Finding(
                        module=self.name,
                        vrt_id=_VRT_LOGIN,
                        title="Login form served over cleartext HTTP",
                        asset=ctx.asset_for(page.url),
                        evidence="A password field is delivered over HTTP, exposing credentials in transit.",
                        confidence=Confidence.FIRM,
                        response_excerpt="<input type=password ...>",
                        remediation="Serve all authentication pages exclusively over HTTPS and enforce HSTS.",
                    ))
            for name, _ in parse_qsl(parsed.query):
                if name.lower() in _TOKEN_PARAM:
                    base = f"{parsed.netloc}{parsed.path}:{name.lower()}"
                    if base not in token_seen:
                        token_seen.add(base)
                        ctx.add(Finding(
                            module=self.name,
                            vrt_id=_VRT_TOKEN,
                            title=f"Sensitive token in URL parameter '{name}'",
                            asset=ctx.asset_for(page.url),
                            evidence=f"Parameter '{name}' carries a sensitive token in the query string (logged, cached, leaked via Referer).",
                            confidence=Confidence.FIRM,
                            remediation="Move sensitive tokens out of URLs into headers or POST bodies.",
                            extra={"parameter": name},
                        ))
