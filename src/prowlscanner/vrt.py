from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

_LABELS = {1: "P1", 2: "P2", 3: "P3", 4: "P4", 5: "P5"}


@lru_cache(maxsize=1)
def _data() -> dict:
    raw = resources.files("prowlscanner").joinpath("data/vrt.json").read_text(encoding="utf-8")
    parsed = json.loads(raw)
    index: dict[str, dict] = {}
    names: dict[str, str] = {}

    def walk(node: dict, trail: list[str]) -> None:
        path = trail + [node["id"]]
        children = node.get("children")
        key = "/".join(path)
        names[key] = node.get("name", node["id"])
        if children:
            for child in children:
                walk(child, path)
        else:
            index[key] = {
                "priority": node.get("priority"),
                "name": node.get("name", node["id"]),
                "path": key,
            }

    for node in parsed["content"]:
        walk(node, [])
    return {
        "release": parsed.get("metadata", {}).get("release_date"),
        "index": index,
        "names": names,
    }


def release_date() -> str | None:
    return _data()["release"]


def lookup(vrt_id: str) -> dict | None:
    return _data()["index"].get(vrt_id)


def priority(vrt_id: str) -> int | None:
    entry = lookup(vrt_id)
    return entry["priority"] if entry else None


def label(vrt_id: str) -> str | None:
    value = priority(vrt_id)
    return _LABELS.get(value) if value is not None else None


def name(vrt_id: str) -> str:
    entry = lookup(vrt_id)
    if entry:
        return entry["name"]
    return _data()["names"].get(vrt_id, vrt_id)


def readable_chain(vrt_id: str, sep: str = " > ") -> str:
    names = _data()["names"]
    parts = vrt_id.split("/")
    chain = []
    for i in range(len(parts)):
        chain.append(names.get("/".join(parts[: i + 1]), parts[i]))
    return sep.join(chain)


def reportable(vrt_id: str, bands: tuple[int, ...] = (1, 2, 3, 4)) -> bool:
    return priority(vrt_id) in bands


def known(vrt_id: str) -> bool:
    return lookup(vrt_id) is not None
