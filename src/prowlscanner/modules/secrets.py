from __future__ import annotations

import math
import re
from collections import Counter

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "sensitive_data_exposure/disclosure_of_secrets/for_publicly_accessible_asset"

_PLACEHOLDERS = (
    "example", "your_", "changeme", "placeholder", "xxxx", "dummy", "sample",
    "redacted", "<", "{{", "}}", "insert", "replace", "test_key", "0000000000",
)

_RULES: tuple[tuple[str, re.Pattern[str], str, float], ...] = (
    ("AWS access key id", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "confirmed", 0.0),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "confirmed", 0.0),
    ("GitHub token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,255})\b"), "confirmed", 0.0),
    ("GitHub fine-grained PAT", re.compile(r"\b(github_pat_[0-9A-Za-z_]{80,255})\b"), "confirmed", 0.0),
    ("GitLab PAT", re.compile(r"\b(glpat-[0-9A-Za-z\-_]{20})\b"), "confirmed", 0.0),
    ("Slack token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,64})\b"), "confirmed", 0.0),
    ("Stripe live secret", re.compile(r"\b(sk_live_[0-9A-Za-z]{24,99})\b"), "confirmed", 0.0),
    ("Square access token", re.compile(r"\b(sq0atp-[0-9A-Za-z\-_]{22})\b"), "confirmed", 0.0),
    ("SendGrid key", re.compile(r"\b(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})\b"), "confirmed", 0.0),
    ("npm token", re.compile(r"\b(npm_[0-9A-Za-z]{36})\b"), "confirmed", 0.0),
    ("Private key block", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)"), "confirmed", 0.0),
    ("Google OAuth token", re.compile(r"\b(ya29\.[0-9A-Za-z\-_]{30,})\b"), "firm", 0.0),
    ("Assigned secret", re.compile(
        r"(?i)(?:api[_\-]?key|secret|access[_\-]?token|client[_\-]?secret|password)"
        r"['\"]?\s*[:=]\s*['\"]([0-9A-Za-z\-_.=+/]{16,120})['\"]"), "firm", 3.6),
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _placeholder(value: str) -> bool:
    low = value.lower()
    return any(token in low for token in _PLACEHOLDERS) or len(set(value)) <= 2


def scan(text: str) -> list[tuple[str, str, str]]:
    hits: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for title, pattern, confidence, min_entropy in _RULES:
        for match in pattern.finditer(text):
            value = match.group(1)
            if not value or _placeholder(value) or value in seen:
                continue
            if min_entropy and _entropy(value) < min_entropy:
                continue
            seen.add(value)
            hits.append((title, value, confidence))
    return hits


def _redact(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * (len(value) - keep * 2)}{value[-keep:]}"


class Secrets(Module):
    name = "secrets"
    vrt_targets = (_VRT,)
    passive = True

    async def run(self, ctx: Context) -> None:
        for page in ctx.pages:
            ctype = page.response.content_type
            if not ("javascript" in ctype or "json" in ctype or "html" in ctype or page.url.endswith(".js")):
                continue
            for title, value, confidence in scan(page.response.text):
                ctx.add(Finding(
                    module=self.name,
                    vrt_id=_VRT,
                    title=f"Exposed secret: {title}",
                    asset=ctx.asset_for(page.url),
                    evidence=f"{title} = {_redact(value)}",
                    confidence=Confidence(confidence),
                    response_excerpt=_redact(value),
                    remediation="Rotate the exposed credential and remove it from client-delivered assets.",
                    extra={"secret_type": title},
                ))
