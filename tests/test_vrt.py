from prowlscanner import vrt


def test_known_priorities():
    assert vrt.priority("server_side_injection/sql_injection") == 1
    assert vrt.priority("cross_site_scripting_xss/reflected/non_self") == 3
    assert vrt.priority("unvalidated_redirects_and_forwards/open_redirect/get_based") == 4
    assert vrt.priority("cross_site_scripting_xss/reflected/self") == 5


def test_band_filter_excludes_p5():
    assert vrt.reportable("server_side_injection/sql_injection")
    assert not vrt.reportable("cross_site_scripting_xss/reflected/self")


def test_labels_and_chain():
    assert vrt.label("server_side_injection/sql_injection") == "P1"
    chain = vrt.readable_chain("cross_site_scripting_xss/reflected/non_self")
    assert ">" in chain and "XSS" in chain.upper()


def test_release_date_present():
    assert vrt.release_date()
