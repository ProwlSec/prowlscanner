from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse, urlsplit

from .http import Client, Response
from .scope import Scope


@dataclass
class Form:
    action: str
    method: str
    inputs: list[str] = field(default_factory=list)


@dataclass
class Page:
    url: str
    response: Response
    query: dict[str, str] = field(default_factory=dict)
    forms: list[Form] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)


class _Extractor(HTMLParser):
    def __init__(self, base: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[Form] = []
        self._form: Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and data.get("href"):
            self.links.append(urljoin(self.base, data["href"]))
        elif tag == "script" and data.get("src"):
            self.scripts.append(urljoin(self.base, data["src"]))
        elif tag == "form":
            self._form = Form(
                action=urljoin(self.base, data.get("action", self.base)),
                method=(data.get("method") or "get").lower(),
            )
        elif tag in ("input", "textarea", "select") and self._form is not None:
            if data.get("name"):
                self._form.inputs.append(data["name"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _same_doc(url: str) -> str:
    split = urlsplit(url)
    return split._replace(fragment="").geturl()


def parse_page(url: str, response: Response) -> Page:
    query = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
    page = Page(url=url, response=response, query=query)
    if "html" in response.content_type or "<html" in response.text[:2000].lower():
        extractor = _Extractor(url)
        try:
            extractor.feed(response.text)
        except Exception:
            pass
        page.links = extractor.links
        page.scripts = extractor.scripts
        page.forms = extractor.forms
    return page


async def crawl(
    client: Client,
    seeds: list[str],
    scope: Scope,
    *,
    max_depth: int = 2,
    max_urls: int = 300,
    on_page: object = None,
) -> list[Page]:
    seen: set[str] = set()
    pages: list[Page] = []
    queue: deque[tuple[str, int]] = deque((s, 0) for s in seeds)
    while queue and len(pages) < max_urls:
        url, depth = queue.popleft()
        norm = _same_doc(url)
        if norm in seen:
            continue
        seen.add(norm)
        host = urlparse(url).hostname or ""
        if not scope.permits(host):
            continue
        response = await client.get(url)
        if not response.ok:
            continue
        page = parse_page(response.url or url, response)
        pages.append(page)
        if callable(on_page):
            on_page(page)
        if depth < max_depth:
            for link in page.links + page.scripts:
                link_host = urlparse(link).hostname or ""
                if link_host and scope.permits(link_host) and _same_doc(link) not in seen:
                    queue.append((link, depth + 1))
    return pages
