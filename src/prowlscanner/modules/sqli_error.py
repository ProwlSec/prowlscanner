from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..findings import Confidence, Finding
from .base import Context, Module

_VRT = "server_side_injection/sql_injection"
_ERRORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("MySQL", re.compile(r"SQL syntax.*MySQL|valid MySQL result|MySqlClient\.|com\.mysql\.jdbc", re.IGNORECASE)),
    ("PostgreSQL", re.compile(r"PostgreSQL.*ERROR|pg_query\(\)|PSQLException|unterminated quoted string", re.IGNORECASE)),
    ("MSSQL", re.compile(r"Microsoft SQL Server|ODBC SQL Server Driver|Unclosed quotation mark after", re.IGNORECASE)),
    ("Oracle", re.compile(r"ORA-\d{5}|Oracle error|quoted string not properly terminated", re.IGNORECASE)),
    ("SQLite", re.compile(r"SQLite/JDBCDriver|SQLite3::|sqlite3.OperationalError|unrecognized token", re.IGNORECASE)),
)
_MARKERS = ("'", "')", "\"")


def db_error(body: str) -> str:
    for engine, pattern in _ERRORS:
        if pattern.search(body):
            return engine
    return ""


def _points(ctx: Context) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for page in ctx.pages:
        parsed = urlparse(page.url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for name, _ in parse_qsl(parsed.query):
            if (base, name) not in seen:
                seen.add((base, name))
                out.append((page.url, name))
    return out


def _set(url: str, param: str, suffix: str) -> str:
    parsed = urlparse(url)
    pairs = []
    for k, v in parse_qsl(parsed.query):
        pairs.append((k, v + suffix if k == param else v))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(pairs), parsed.fragment))


class SqlInjectionError(Module):
    name = "sqli-error"
    vrt_targets = (_VRT,)
    passive = False

    async def run(self, ctx: Context) -> None:
        for url, param in _points(ctx):
            host = urlparse(url).hostname or ""
            if not ctx.scope.permits(host, ctx._ip_for(host)):
                continue
            baseline = await ctx.client.get(url)
            if baseline.ok and db_error(baseline.text):
                continue
            for marker in _MARKERS:
                target = _set(url, param, marker)
                resp = await ctx.client.get(target)
                if not resp.ok:
                    continue
                engine = db_error(resp.text)
                if not engine:
                    continue
                ctx.add(Finding(
                    module=self.name,
                    vrt_id=_VRT,
                    title=f"SQL injection ({engine}) via parameter '{param}'",
                    asset=ctx.asset_for(target),
                    evidence=f"Injecting {marker!r} into '{param}' triggered a {engine} database error not present in the baseline.",
                    confidence=Confidence.FIRM,
                    request=f"GET {target}",
                    response_excerpt=resp.text[:200],
                    remediation="Use parameterized queries / prepared statements; never concatenate input into SQL.",
                    extra={"parameter": param, "engine": engine},
                ))
                break
