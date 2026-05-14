from backend.core.crawler import LinkParser, canonicalize_url, classify_endpoint_type, extract_candidates_from_text, extract_hidden_api_candidates, guess_query_params


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


def test_extract_candidates_limits_numeric_spa_noise():
    text = 'window.__routes=["/10","/20","/30","/40","/50","/rest/products/search"];'
    candidates = extract_candidates_from_text(text)
    numeric_routes = [candidate for candidate in candidates if candidate.strip("/").isdigit()]
    assert len(numeric_routes) == 3
    assert "/rest/products/search" in candidates


def test_guess_query_params_does_not_turn_login_into_get_fuzz_target():
    assert guess_query_params("http://127.0.0.1:3000/rest/user/login") == []


def test_classify_endpoint_type_marks_graphql():
    assert classify_endpoint_type("http://127.0.0.1:3000/graphql") == "graphql"
    assert classify_endpoint_type("http://127.0.0.1:3000/rest/products") == "api"


def test_extract_hidden_api_candidates_from_fetch_and_strings():
    text = 'fetch("/api/users"); const gql="/graphql"; axios.get("/rest/items");'
    candidates = extract_hidden_api_candidates(text)
    assert "/api/users" in candidates
    assert "/graphql" in candidates
    assert "/rest/items" in candidates
