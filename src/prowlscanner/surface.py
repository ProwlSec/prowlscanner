from __future__ import annotations

from urllib.parse import urlparse


def build_surface(hosts, pages) -> dict:
    endpoints = []
    parameters: set[str] = set()
    servers: set[str] = set()
    for page in pages:
        params = list(page.query.keys())
        for form in page.forms:
            params.extend(form.inputs)
        parameters.update(params)
        server = page.response.headers.get("server", "")
        if server:
            servers.add(server)
        endpoints.append({
            "url": page.url,
            "status": page.response.status,
            "params": sorted(set(params)),
            "content_type": page.response.content_type.split(";")[0],
        })
    return {
        "endpoints": endpoints,
        "parameters": sorted(parameters),
        "servers": sorted(servers),
        "hosts": [
            {"host": h.host, "ips": h.ips, "ptr": h.ptr, "resolved": h.resolved}
            for h in hosts
        ],
    }


def build_graph(targets, hosts, pages, findings) -> dict:
    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()

    def node(node_id: str, kind: str, label: str) -> None:
        if node_id not in seen:
            seen.add(node_id)
            nodes.append({"id": node_id, "type": kind, "label": label})

    def edge(src: str, dst: str) -> None:
        if src in seen and dst in seen:
            edges.append({"from": src, "to": dst})

    root = "scope"
    node(root, "scope", ", ".join(targets) or "scope")
    for info in hosts:
        if not info.resolved:
            continue
        hid = "host:" + info.host
        node(hid, "host", info.host + (f" [{info.ptr}]" if info.ptr else ""))
        edge(root, hid)
        for ip in info.ips:
            iid = "ip:" + ip
            node(iid, "ip", ip)
            edge(hid, iid)

    for page in pages:
        parsed = urlparse(page.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        oid = "svc:" + origin
        node(oid, "service", origin)
        edge("host:" + (parsed.hostname or ""), oid)
        eid = "ep:" + page.url
        node(eid, "endpoint", parsed.path or "/")
        edge(oid, eid)

    for index, finding in enumerate(findings):
        fid = f"find:{index}"
        node(fid, "finding", f"{finding.priority_label} {finding.title}")
        url = finding.asset.url or ""
        if ("ep:" + url) in seen:
            edge("ep:" + url, fid)
        else:
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if ("svc:" + origin) in seen:
                edge("svc:" + origin, fid)
            else:
                edge(root, fid)
    return {"nodes": nodes, "edges": edges}
