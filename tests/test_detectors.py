from prowlscanner.modules.admin_portal import admin_fingerprint
from prowlscanner.modules.clickjacking import framing_allowed
import re
from prowlscanner.modules.jwt import crack_hs, parse_jwt
from prowlscanner.modules.sqli_blind import is_time_based
from prowlscanner.modules.ssrf import ssrf_signature
from prowlscanner.modules.xxe import xxe_leak
from prowlscanner.modules.subdomain_takeover import fingerprint_takeover
from prowlscanner.modules.verbose_error import detect_verbose_error
from prowlscanner.modules.cookie_flags import missing_flags
from prowlscanner.modules.open_redirect import redirects_offsite
from prowlscanner.modules.path_traversal import leaked_file
from prowlscanner.modules.reflected_xss import reflected_unencoded
from prowlscanner.modules.secrets import scan
from prowlscanner.modules.sqli_error import db_error


def test_secrets_detects_real_and_skips_placeholder():
    hits = scan('const k="AKIAIOSFODNN7EXAMPLE"; token="AKIA1234567890ABCDEF";')
    values = [v for _, v, _ in hits]
    assert "AKIA1234567890ABCDEF" in values
    assert "AKIAIOSFODNN7EXAMPLE" not in values


def test_sql_error_signatures():
    assert db_error("You have an error in your SQL syntax; MySQL server version") == "MySQL"
    assert db_error("ORA-01756: quoted string not properly terminated") == "Oracle"
    assert db_error("totally normal page") == ""


def test_path_traversal_signature():
    assert leaked_file("root:x:0:0:root:/root:/bin/bash\n")
    assert leaked_file("[fonts]\nxyz")
    assert not leaked_file("nothing here")


def test_reflected_xss_requires_unencoded():
    token = "prwlabcd"
    assert reflected_unencoded(f'<div>"><svg/onload={token}></div>', token)
    assert not reflected_unencoded(f"<div>&quot;&gt;&lt;svg/onload={token}&gt;</div>", token)


def test_open_redirect_offsite():
    assert redirects_offsite("https://prowl-canary.example/", "")
    assert not redirects_offsite("https://www.example.com/home", "")


def test_cookie_flags():
    assert "HttpOnly" in missing_flags("SID=abc; Path=/", over_https=False)
    assert "Secure" in missing_flags("SID=abc; HttpOnly", over_https=True)
    assert missing_flags("SID=abc; HttpOnly; Secure", over_https=True) == []


def test_clickjacking_framing():
    assert framing_allowed({})
    assert not framing_allowed({"x-frame-options": "DENY"})
    assert not framing_allowed({"content-security-policy": "frame-ancestors 'none'"})


def test_ssrf_signatures():
    assert ssrf_signature("ami-id\ninstance-id\n")
    assert ssrf_signature("root:x:0:0:root:/root:/bin/bash")
    assert not ssrf_signature("just a normal page")


def test_subdomain_takeover_fingerprint():
    assert fingerprint_takeover("There isn't a GitHub Pages site here.") == "GitHub Pages"
    assert fingerprint_takeover("<Error><Code>NoSuchBucket</Code></Error>") == "AWS S3"
    assert not fingerprint_takeover("welcome home")


def test_verbose_error_detection():
    assert detect_verbose_error("Traceback (most recent call last):")
    assert detect_verbose_error("PHP Fatal error: undefined on line 10")
    assert not detect_verbose_error("ok")


def test_admin_fingerprint():
    assert admin_fingerprint("Powered by WordPress wp-submit", re.compile(r"wp-submit|WordPress", re.I))
    assert not admin_fingerprint("nothing", re.compile(r"phpMyAdmin"))


def test_time_based_decision():
    assert is_time_based(0.2, 5.1)
    assert not is_time_based(0.2, 0.3)
    assert not is_time_based(5.0, 5.2)


def test_xxe_leak():
    assert xxe_leak("root:x:0:0:root:/root:/bin/bash")
    assert not xxe_leak("<data>ok</data>")


def test_jwt_parse_and_crack():
    import base64, hmac, hashlib, json

    def b64(d):
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"user": "admin"}).encode())
    sig = b64(hmac.new(b"secret", f"{head}.{body}".encode(), hashlib.sha256).digest())
    token = f"{head}.{body}.{sig}"
    assert parse_jwt(token)[1]["user"] == "admin"
    assert crack_hs(token) == "secret"
    strong = f"{head}.{body}.{b64(hmac.new(b'f8s9d-unguessable-xkcd-correct-horse', (head+'.'+body).encode(), hashlib.sha256).digest())}"
    assert crack_hs(strong) is None
