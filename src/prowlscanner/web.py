from __future__ import annotations

import asyncio
import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse


def _page() -> str:
    try:
        return resources.files("prowlscanner").joinpath("web/console.html").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return _PAGE

from .config import ScanConfig
from .connectors import importers
from .engine import Engine
from .report.json_report import build as _build_report

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>prowlscanner console</title><style>
*{box-sizing:border-box}body{margin:0;background:#0A0C10;color:#E8EAEE;font:14px/1.5 ui-sans-serif,system-ui,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:28px 22px}
h1{font-size:18px;margin:0 0 2px;display:flex;gap:9px;align-items:center}
.lg{width:20px;height:20px;border-radius:6px;background:linear-gradient(135deg,#6E9BF5,#8E6BE0)}
.sub{color:#8B93A1;font-size:12px;margin-bottom:18px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
input[type=text]{flex:1;min-width:240px;background:#12151B;border:1px solid #252A34;color:#E8EAEE;border-radius:8px;padding:10px 12px;font:inherit}
button{background:#6E9BF5;border:0;color:#06080C;font-weight:600;border-radius:8px;padding:10px 18px;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
label.ck{color:#C3C8D1;font-size:12px;display:flex;gap:6px;align-items:center}
.phases{display:flex;gap:8px;margin:18px 0}
.ph{flex:1;text-align:center;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#5B6472;background:#12151B;border:1px solid #252A34;border-radius:7px;padding:7px}
.ph.on{color:#06080C;background:#6E9BF5;border-color:#6E9BF5}.ph.done{color:#4FB286;border-color:#1d4733}
.bar{display:flex;gap:8px;margin:14px 0}
.stat{background:#12151B;border:1px solid #252A34;border-radius:8px;padding:8px 14px;min-width:70px}
.stat .n{font-size:18px;font-weight:700}.stat .l{font-size:11px;color:#8B93A1}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:8px}
@media(max-width:760px){.cols{grid-template-columns:1fr}}
.panel{background:#0E1117;border:1px solid #252A34;border-radius:9px;padding:12px;height:360px;overflow:auto}
.panel h2{font-size:12px;color:#8B93A1;margin:0 0 8px;text-transform:uppercase;letter-spacing:.06em}
.log{font-family:ui-monospace,monospace;font-size:12px;white-space:pre-wrap;word-break:break-word}
.ev{color:#8B93A1}.ev.recon{color:#6AA9E0}.ev.finding{color:#E26D63}.ev.phase{color:#9FBEFA;font-weight:600}
.f{border-left:3px solid #8B93A1;background:#12151B;border-radius:7px;padding:10px 12px;margin:0 0 9px}
.f h3{margin:0 0 4px;font-size:13px}.tag{font-size:10px;font-weight:700;padding:1px 7px;border-radius:4px;color:#06080C;margin-right:7px}
.f .m{color:#8B93A1;font-size:12px}.P1{color:#E26D63}.P2{color:#E39A58}.P3{color:#D9B65A}.P4{color:#6AA9E0}
</style></head><body><div class="wrap">
<h1><span class="lg"></span>prowlscanner</h1>
<div class="sub">authorized web vulnerability hunter · P1–P4 findings with evidence</div>
<div class="row">
<input id="t" type="text" placeholder="example.com · *.example.com · https://site · 10.0.0.1 · 10.0.0.0/24">
<button id="go">Hunt</button>
</div>
<div class="row" style="margin-top:8px"><label class="ck"><input id="auth" type="checkbox"> I am authorized to test this target</label></div>
<div class="phases" id="phases"></div>
<div class="bar" id="bar"></div>
<div class="cols">
<div class="panel"><h2>Live feed</h2><div class="log" id="log"></div></div>
<div class="panel"><h2>Findings</h2><div id="find"></div></div>
</div></div>
<script>
const PHASES=["recon","crawl","scan","report"];
const log=document.getElementById('log'),find=document.getElementById('find'),bar=document.getElementById('bar'),phasesEl=document.getElementById('phases');
function drawPhases(active,done){phasesEl.innerHTML=PHASES.map(p=>{let c='ph';if(done.has(p))c+=' done';if(p===active)c+=' on';return `<div class="${c}">${p}</div>`}).join('')}
function line(kind,msg){const d=document.createElement('div');d.className='ev '+kind;d.textContent=(kind==='phase'?'▸ ':'  ')+msg;log.appendChild(d);log.scrollTop=log.scrollHeight}
let done=new Set();
document.getElementById('go').onclick=()=>{
  const t=document.getElementById('t').value.trim();if(!t)return;
  if(!document.getElementById('auth').checked){alert('Confirm authorization first.');return}
  log.innerHTML='';find.innerHTML='';bar.innerHTML='';done=new Set();drawPhases('recon',done);
  const go=document.getElementById('go');go.disabled=true;
  const es=new EventSource('/api/scan?target='+encodeURIComponent(t)+'&authorized=1');
  es.addEventListener('phase',e=>{const p=e.data;PHASES.forEach(x=>{if(x===p)return;if(PHASES.indexOf(x)<PHASES.indexOf(p))done.add(x)});drawPhases(p,done);line('phase',p)});
  ['recon','crawl','module','info','error'].forEach(k=>es.addEventListener(k,e=>line(k,e.data)));
  es.addEventListener('finding',e=>line('finding',e.data));
  es.addEventListener('report',e=>{const r=JSON.parse(e.data);render(r)});
  es.addEventListener('done',()=>{es.close();go.disabled=false;done=new Set(PHASES);drawPhases(null,done)});
  es.onerror=()=>{es.close();go.disabled=false};
};
function render(r){
  const c=r.stats.counts;bar.innerHTML=['P1','P2','P3','P4'].map(k=>`<div class="stat"><div class="n ${k}">${c[k]||0}</div><div class="l">${k}</div></div>`).join('')+`<div class="stat"><div class="n">${r.stats.pages_crawled}</div><div class="l">pages</div></div>`;
  if(!r.findings.length){find.innerHTML='<div class="m">No in-scope P1–P4 findings.</div>';return}
  find.innerHTML=r.findings.map(f=>`<div class="f" style="border-left-color:var(--x)"><h3><span class="tag ${f.priority_label}" style="background:currentColor">${f.priority_label}</span>${esc(f.title)}</h3><div class="m">${esc(f.asset.url||f.asset.host)} · ${f.confidence} · ${esc(f.vrt_id)}</div></div>`).join('');
}
function esc(s){const d=document.createElement('div');d.textContent=s==null?'':s;return d.innerHTML}
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    server_authorize = False

    def log_message(self, *args: object) -> None:
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, _page().encode("utf-8"), "text/html; charset=utf-8")
            return
        if parsed.path == "/api/scan":
            self._scan(parse_qs(parsed.query))
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/import":
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            try:
                kind, urls = importers.detect_and_parse(raw)
            except Exception as exc:
                self._send(400, json.dumps({"error": str(exc)}).encode(), "application/json")
                return
            primary = ""
            if urls:
                first = urls[0]
                primary = urlparse(first).hostname or first.split("/")[0] if "://" in first else first
            body = json.dumps({"kind": kind, "count": len(urls), "urls": urls[:200], "primary": primary})
            self._send(200, body.encode(), "application/json")
            return
        self._send(404, b"not found", "text/plain")

    def _sse(self, kind: str, data: str) -> None:
        payload = f"event: {kind}\ndata: {data}\n\n".encode("utf-8")
        self.wfile.write(payload)
        self.wfile.flush()

    def _scan(self, params: dict[str, list[str]]) -> None:
        target = (params.get("target", [""])[0]).strip()
        authorized = self.server_authorize or params.get("authorized", ["0"])[0] in ("1", "true", "yes")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        if not target:
            self._sse("error", "no target provided")
            self._sse("done", "{}")
            return
        if not authorized:
            self._sse("error", "authorization not confirmed")
            self._sse("done", "{}")
            return

        events: "queue.Queue[tuple[str, str] | None]" = queue.Queue()

        def emit(kind: str, message: str) -> None:
            events.put((kind, message))

        def worker() -> None:
            try:
                config = ScanConfig(in_scope=[target], authorized=True)
                seeds = [target] if "://" in target else []
                engine = Engine(config, seed_urls=seeds, event=emit)
                report = asyncio.run(engine.run())
                events.put(("__report__", json.dumps(_build_report(report))))
            except Exception as exc:
                events.put(("error", f"scan failed: {exc}"))
            finally:
                events.put(None)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        while True:
            item = events.get()
            if item is None:
                break
            kind, message = item
            try:
                if kind == "__report__":
                    self._sse("report", message)
                else:
                    self._sse(kind, message)
            except (BrokenPipeError, ConnectionResetError):
                break
        try:
            self._sse("done", "{}")
        except (BrokenPipeError, ConnectionResetError):
            pass


def serve(host: str = "127.0.0.1", port: int = 8787, authorize: bool = False) -> int:
    _Handler.server_authorize = authorize
    httpd = ThreadingHTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}/"
    print(f"prowlscanner console on {url}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0
