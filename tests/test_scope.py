from prowlscanner.scope import Matcher, Scope


def test_wildcard_matches_subdomains_and_apex():
    m = Matcher.parse("*.example.com")
    assert m.kind == "wildcard"
    assert m.match_host("api.example.com")
    assert m.match_host("example.com")
    assert not m.match_host("example.org")
    assert not m.match_host("notexample.com")


def test_domain_is_exact():
    m = Matcher.parse("example.com")
    assert m.match_host("example.com")
    assert not m.match_host("api.example.com")


def test_ip_and_cidr():
    assert Matcher.parse("10.0.0.5").match_ip("10.0.0.5")
    cidr = Matcher.parse("10.0.0.0/24")
    assert cidr.match_ip("10.0.0.200")
    assert not cidr.match_ip("10.0.1.1")


def test_url_spec_reduces_to_host():
    m = Matcher.parse("https://app.example.com/login?x=1")
    assert m.match_host("app.example.com") or m.match_host("app.example.com".lower())


def test_scope_include_and_exclude():
    scope = Scope.build(["*.example.com"], ["admin.example.com"])
    assert scope.permits("api.example.com")
    assert not scope.permits("admin.example.com")
    assert not scope.permits("example.org")
