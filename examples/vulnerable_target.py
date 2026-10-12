"""Intentionally vulnerable local target for exercising prowlscanner.

For local testing only. Binds to 127.0.0.1. Do not expose this to a network.
    python examples/vulnerable_target.py --port 8099
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt(payload: dict, secret: str) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    sig = _b64url(hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def _none_jwt(payload: dict) -> str:
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    return f"{header}.{body}."


_WEAK_JWT = _make_jwt({"user": "admin", "role": "admin"}, "secret")
_NONE_JWT = _none_jwt({"user": "guest"})

_HOME = f"""<!doctype html><html><head><title>Demo Shop</title>
<script src="/app.js"></script></head><body>
<h1>Demo Shop</h1>
<a href="/search?q=widgets">search</a>
<a href="/product?cat=1">products</a>
<a href="/download?file=readme.txt">download</a>
<a href="/go?next=/home">continue</a>
<a href="/account?token=sk_demo_123">account</a>
<a href="/fetch?url=http://example.com/">preview</a>
<a href="/report?id=1">report</a>
<a href="/feed.xml">feed</a>
<a href="/crash">status</a>
<a href="/login">login</a>
<!-- legacy token: {_NONE_JWT} -->
</body></html>"""

_APP_JS = 'const cfg={apiKey:"AIzaSyA1234567890abcdefghijklmnopqrstuvw",env:"prod"};'
_ENV = "APP_ENV=production\nAWS_SECRET=AKIA1234567890ABCDEF\nDB_PASSWORD=sup3rs3cr3tvalue123\n"
_LOGIN = """<!doctype html><html><body><h1>Sign in</h1>
<form method="post" action="/login">
<input name="user" type="text"><input name="pass" type="password">
<button>Login</button></form></body></html>"""
_WP_LOGIN = """<!doctype html><html><head><title>Log In</title></head><body>
<form name="loginform" action="wp-login.php"><input name="user_login"><input name="pwd" type="password">
<input type="submit" name="wp-submit" value="Log In"></form>Powered by WordPress</body></html>"""
_MYSQL_ERROR = ("<b>Warning</b>: You have an error in your SQL syntax; check the manual that "
                "corresponds to your MySQL server version near \"'\" at line 1")
_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
_METADATA = "ami-id\nami-launch-index\ninstance-id\ninstance-type\niam/security-credentials/\n"
_TRACEBACK = ("<pre>Traceback (most recent call last):\n  File \"/app/views.py\", line 42, in get\n"
              "    user = User.objects.get(id=request.GET['id'])\nKeyError: 'id'</pre>")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass

    def _html(self, body: str, status: int = 200, cookie: bool = False) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if cookie:
            self.send_header("Set-Cookie", "SID=abc123def456; Path=/")
            self.send_header("Set-Cookie", f"session={_WEAK_JWT}; Path=/")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _text(self, body: str, ctype: str = "text/plain", status: int = 200) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query)
        if path == "/":
            self._html(_HOME, cookie=True)
        elif path == "/app.js":
            self._text(_APP_JS, "application/javascript")
        elif path == "/.env":
            self._text(_ENV)
        elif path == "/.git/config":
            self._text("[core]\n\trepositoryformatversion = 0\n")
        elif path == "/search":
            self._html(f"<html><body>Results for: {q.get('q', [''])[0]}</body></html>")
        elif path == "/product":
            cat = q.get("cat", [""])[0]
            if "'" in cat or '"' in cat:
                self._html(f"<html><body>{_MYSQL_ERROR}</body></html>", status=500)
            else:
                self._html(f"<html><body>Category {cat} products</body></html>")
        elif path == "/download":
            name = q.get("file", [""])[0]
            self._text(_PASSWD if "etc/passwd" in name.replace("\\", "/") else f"contents of {name}")
        elif path == "/fetch":
            dest = q.get("url", [""])[0]
            if "169.254.169.254" in dest:
                self._text(_METADATA)
            elif "127.0.0.1" in dest or "localhost" in dest:
                self._text("<html><body>Demo Shop</body></html>", "text/html")
            else:
                self._text(f"fetched {dest}")
        elif path == "/report":
            rid = q.get("id", [""])[0].lower()
            if any(s in rid for s in ("sleep", "pg_sleep", "waitfor")):
                time.sleep(5)
            self._html(f"<html><body>Report {q.get('id', [''])[0]}</body></html>")
        elif path == "/feed.xml":
            self._text("<?xml version=\"1.0\"?><feed><item>demo</item></feed>", "application/xml")
        elif path == "/crash":
            self._html(f"<html><body>{_TRACEBACK}</body></html>", status=500)
        elif path == "/go":
            self.send_response(302)
            self.send_header("Location", q.get("next", ["/"])[0])
            self.end_headers()
        elif path == "/account":
            self._html("<html><body>Account overview</body></html>")
        elif path == "/login":
            self._html(_LOGIN)
        elif path == "/wp-login.php":
            self._html(_WP_LOGIN)
        else:
            self._html("<html><body>not found</body></html>", status=404)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        if urlparse(self.path).path == "/feed.xml" and "file:///etc/passwd" in body and "SYSTEM" in body:
            self._text(f"<data>{_PASSWD}</data>", "application/xml")
        else:
            self._html("<html><body>ok</body></html>")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8099)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"vulnerable target on http://127.0.0.1:{args.port}/ (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
