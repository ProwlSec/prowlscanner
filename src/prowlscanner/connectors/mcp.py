from __future__ import annotations

import asyncio
import json
import sys

from .. import __version__, vrt

PROTOCOL = "2024-11-05"

_TOOLS = [
    {
        "name": "prowl_scan",
        "description": "Run an authorized web vulnerability scan against a target (domain, *.wildcard, URL, IP, or CIDR). Returns the findings report as JSON. You must set authorize=true to confirm the target is in scope for testing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "domain, *.wildcard, URL, IP, or CIDR"},
                "authorize": {"type": "boolean", "description": "confirm you are authorized to test this target"},
                "max_urls": {"type": "integer", "description": "max pages to crawl (default 200)"},
                "bands": {"type": "array", "items": {"type": "integer"}, "description": "priority bands, default [1,2,3,4]"},
            },
            "required": ["target", "authorize"],
        },
    },
    {
        "name": "prowl_vrt",
        "description": "Look up a Vulnerability Rating Taxonomy id and return its priority (P1-P5), label and readable category chain.",
        "inputSchema": {
            "type": "object",
            "properties": {"vrt_id": {"type": "string"}},
            "required": ["vrt_id"],
        },
    },
    {
        "name": "prowl_modules",
        "description": "List the available detection modules and the VRT categories each one covers.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _text(payload: object) -> dict:
    body = payload if isinstance(payload, str) else json.dumps(payload, indent=2)
    return {"content": [{"type": "text", "text": body}], "isError": False}


def _error(message: str) -> dict:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _run_scan(args: dict) -> dict:
    if not args.get("authorize"):
        return _error("Refused: set authorize=true to confirm you are permitted to test this target.")
    target = (args.get("target") or "").strip()
    if not target:
        return _error("No target provided.")
    from ..config import ScanConfig
    from ..engine import Engine
    from ..report.json_report import build

    config = ScanConfig(in_scope=[target], authorized=True)
    if args.get("max_urls"):
        config.max_urls = int(args["max_urls"])
    if args.get("bands"):
        config.bands = tuple(int(b) for b in args["bands"])
    seeds = [target] if "://" in target else []
    report = asyncio.run(Engine(config, seed_urls=seeds).run())
    return _text(build(report))


def _tool_call(name: str, args: dict) -> dict:
    if name == "prowl_scan":
        return _run_scan(args)
    if name == "prowl_vrt":
        vid = args.get("vrt_id", "")
        if not vrt.known(vid):
            return _error(f"Unknown VRT id: {vid}")
        return _text({"vrt_id": vid, "priority": vrt.priority(vid), "label": vrt.label(vid),
                      "chain": vrt.readable_chain(vid)})
    if name == "prowl_modules":
        from ..modules import ALL_MODULES
        return _text([{"module": m.name, "vrt": list(m.vrt_targets)} for m in ALL_MODULES])
    return _error(f"Unknown tool: {name}")


def handle(message: dict) -> dict | None:
    method = message.get("method")
    mid = message.get("id")
    if method == "initialize":
        result = {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "prowlscanner", "version": __version__},
        }
    elif method == "tools/list":
        result = {"tools": _TOOLS}
    elif method == "tools/call":
        params = message.get("params", {})
        result = _tool_call(params.get("name", ""), params.get("arguments", {}) or {})
    elif method == "ping":
        result = {}
    elif method in ("notifications/initialized", "notifications/cancelled"):
        return None
    else:
        if mid is None:
            return None
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "method": method, "message": "Method not found"}}
    if mid is None:
        return None
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def serve_stdio() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle(message)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    return 0
