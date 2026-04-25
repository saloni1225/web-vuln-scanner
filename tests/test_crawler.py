from backend.core.crawler import LinkParser, canonicalize_url, classify_endpoint_type, extract_candidates_from_text


def test_link_parser_collects_links_and_forms():
    parser = LinkParser()
    parser.feed('<a href="/login">Login</a><form method="post" action="/submit"><input name="email"><textarea name="note"></textarea></form>')
    assert "/login" in parser.links
    assert parser.forms[0]["method"] == "post"
    assert parser.forms[0]["inputs"] == ["email", "note"]


def test_canonicalize_url_preserves_spa_hash_routes():
    assert canonicalize_url("http://127.0.0.1:3000/#/search?q=juice") == "http://127.0.0.1:3000/#/search?q=juice"


def test_extract_candidates_from_script_like_text():
    text = 'window.__routes=["/#/search","/rest/products/search","/api/Products"];'
    candidates = extract_candidates_from_text(text)
    assert "/#/search" in candidates
    assert "/rest/products/search" in candidates
    assert "/api/Products" in candidates


def test_classify_endpoint_type_marks_graphql():
    assert classify_endpoint_type("http://127.0.0.1:3000/graphql") == "graphql"
    assert classify_endpoint_type("http://127.0.0.1:3000/rest/products") == "api"
