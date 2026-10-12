import json

from prowlscanner.connectors import importers, mcp


def test_parse_postman_raw_and_object():
    collection = {
        "info": {"name": "demo"},
        "item": [
            {"name": "a", "request": {"url": "https://api.example.com/v1/users"}},
            {"name": "b", "request": {"url": {"protocol": "https", "host": ["app", "example", "com"], "path": ["login"]}}},
        ],
    }
    urls = importers.parse_postman(json.dumps(collection))
    assert "https://api.example.com/v1/users" in urls
    assert "https://app.example.com/login" in urls


def test_parse_burp_xml():
    xml = "<items><item><url>https://t.example.com/a</url></item><item><url>https://t.example.com/b</url></item></items>"
    assert importers.parse_burp(xml) == ["https://t.example.com/a", "https://t.example.com/b"]


def test_parse_urls_and_detect():
    kind, urls = importers.detect_and_parse("https://a.example.com/\nb.example.com\n# comment\n")
    assert kind == "urls"
    assert "https://a.example.com/" in urls and "b.example.com" in urls
    assert importers.detect_and_parse('{"info":{},"item":[]}')[0] == "postman"
    assert importers.detect_and_parse("<items><item><url>https://x/y</url></item></items>")[0] == "burp"


def test_mcp_initialize_and_tools():
    init = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init["result"]["protocolVersion"] == mcp.PROTOCOL
    assert init["result"]["serverInfo"]["name"] == "prowlscanner"
    tools = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in tools["result"]["tools"]}
    assert {"prowl_scan", "prowl_vrt", "prowl_modules"} <= names


def test_mcp_vrt_and_modules_tools():
    vid = "server_side_injection/sql_injection"
    res = mcp.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                      "params": {"name": "prowl_vrt", "arguments": {"vrt_id": vid}}})
    payload = json.loads(res["result"]["content"][0]["text"])
    assert payload["priority"] == 1 and payload["label"] == "P1"
    mods = mcp.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                       "params": {"name": "prowl_modules", "arguments": {}}})
    assert not mods["result"]["isError"]


def test_mcp_scan_requires_authorization():
    res = mcp.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                      "params": {"name": "prowl_scan", "arguments": {"target": "example.com", "authorize": False}}})
    assert res["result"]["isError"]


def test_mcp_notifications_have_no_response():
    assert mcp.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
