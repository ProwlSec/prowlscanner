from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from urllib.parse import urlparse

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "broken_authentication_and_session_management/authentication_bypass"
_TOKEN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
_WEAK_SECRETS = (
    "secret", "secretkey", "secret_key", "password", "passwd", "changeme", "admin",
    "jwt", "jwtsecret", "jwt_secret", "key", "private", "token", "test", "default",
    "supersecret", "s3cr3t", "letmein", "root", "1234567890", "qwerty", "your-256-bit-secret",
    "your_jwt_secret", "mysecret", "secretkey123", "0000", "null", "none", "app_secret",
)


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def parse_jwt(token: str) -> tuple[dict, dict] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def crack_hs(token: str, wordlist: tuple[str, ...] = _WEAK_SECRETS) -> str | None:
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return None
    parsed = parse_jwt(token)
    if not parsed:
        return None
    alg = str(parsed[0].get("alg", "")).upper()
    digest = _HASHES.get(alg)
    if not digest:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        expected = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    except binascii.Error:
        return None
    for secret in wordlist:
        candidate = hmac.new(secret.encode(), signing_input, digest).digest()
        if hmac.compare_digest(candidate, expected):
            return secret
    return None


def _collect(ctx: Context):
    for page in ctx.pages:
        sources = []
        sources.extend(page.response.set_cookies)
        sources.append(page.response.text)
        sources.append(urlparse(page.url).query)
        for source in sources:
            for match in _TOKEN.finditer(source or ""):
                yield page.url, match.group(0)


class JsonWebToken(Module):
    name = "jwt"
    vrt_targets = (_VRT,)
    passive = True

    async def run(self, ctx: Context) -> None:
        seen: set[str] = set()
        for url, token in _collect(ctx):
            if token in seen:
                continue
            seen.add(token)
            parsed = parse_jwt(token)
            if not parsed:
                continue
            header, _ = parsed
            alg = str(header.get("alg", "")).lower()
            if alg == "none":
                ctx.add(Finding(
                    module=self.name,
                    vrt_id=_VRT,
                    title="JWT accepts 'none' algorithm (signature not enforced)",
                    asset=ctx.asset_for(url),
                    evidence="A JWT with header alg=none is in use, indicating the server does not enforce token signatures.",
                    confidence=Confidence.FIRM,
                    response_excerpt=token[:80],
                    remediation="Reject 'none' and unexpected algorithms; pin the expected alg server-side.",
                    extra={"alg": "none"},
                ))
                continue
            secret = crack_hs(token)
            if secret:
                ctx.add(Finding(
                    module=self.name,
                    vrt_id=_VRT,
                    title="JWT signed with a weak, guessable secret",
                    asset=ctx.asset_for(url),
                    evidence=f"The HMAC signing key was recovered offline ('{secret}'); tokens can be forged to impersonate any user.",
                    confidence=Confidence.CONFIRMED,
                    response_excerpt=token[:80],
                    remediation="Rotate to a long, random signing key (>=256 bits) stored as a secret.",
                    extra={"alg": header.get("alg"), "secret": secret},
                ))
