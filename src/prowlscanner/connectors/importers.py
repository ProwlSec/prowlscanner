from __future__ import annotations

import json
import re
from xml.etree import ElementTree

_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def parse_postman(text: str) -> list[str]:
    data = json.loads(text)
    urls: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if "request" in node:
                url = node["request"].get("url") if isinstance(node["request"], dict) else None
                urls.extend(_url_from_postman(url))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return _dedupe(urls)


def _url_from_postman(url: object) -> list[str]:
    if isinstance(url, str):
        return [url] if url.startswith("http") else []
    if isinstance(url, dict):
        raw = url.get("raw")
        if isinstance(raw, str) and raw.startswith("http"):
            return [raw]
        host = url.get("host")
        if host:
            host_str = ".".join(host) if isinstance(host, list) else str(host)
            path = url.get("path")
            path_str = "/".join(path) if isinstance(path, list) else str(path or "")
            protocol = url.get("protocol", "https")
            return [f"{protocol}://{host_str}/{path_str}".rstrip("/")]
    return []


def parse_burp(text: str) -> list[str]:
    urls: list[str] = []
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return []
    for element in root.iter("url"):
        if element.text:
            urls.append(element.text.strip())
    return _dedupe(urls)


def parse_urls(text: str) -> list[str]:
    urls: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _URL.search(line)
        urls.append(match.group(0) if match else line.split()[0])
    return _dedupe(urls)


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def detect_and_parse(text: str) -> tuple[str, list[str]]:
    head = text.lstrip()[:400].lower()
    if head.startswith("{") and ('"item"' in text[:4000] or '"info"' in text[:4000]):
        return "postman", parse_postman(text)
    if head.startswith("<?xml") or "<items" in head or "<url>" in head:
        return "burp", parse_burp(text)
    return "urls", parse_urls(text)


def load(path: str) -> tuple[str, list[str]]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return detect_and_parse(handle.read())
