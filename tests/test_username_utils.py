from unittest.mock import patch

import catexe.app as app
from catexe.modules.username_utils import normalize_username, username_search_variants


def test_normalize_styled_latin_username():
    assert normalize_username("𝘊𝘢𝘵.𝘦𝘹𝘦") == "Cat.exe"
    assert normalize_username(" @Cat.exe ") == "Cat.exe"
    assert normalize_username("cat\u200b.exe") == "cat.exe"


def test_username_search_variants_cover_case_accents_italic_and_punctuation():
    variants = username_search_variants("𝘛ést.User")
    assert variants[0] == "Tést.User"
    assert "Test.User" in variants
    assert "tést.user" in variants
    assert "test.user" in variants
    assert "test_user" in variants
    assert "test-user" in variants
    assert "testuser" in variants
    assert len(variants) <= 8


def test_username_search_variants_are_bounded_and_stable():
    assert username_search_variants("FOO") == ["FOO", "foo"]
    assert username_search_variants("a.b", max_variants=3) == ["a.b", "ab", "a_b"]


def test_wmn_check_queries_normalized_username_and_preserves_pretty_url():
    class Response:
        status_code = 404
        text = "not found"

    site = {
        "uri_check": "https://example.test/u/{account}",
        "uri_pretty": "https://example.test/profile/{account}",
        "e_code": 200,
        "e_string": "account",
    }
    with patch.object(app.HTTP, "get", return_value=Response()) as mocked:
        assert app.wmn_check(site, "𝘊𝘢𝘵.𝘦𝘹𝘦") is None
    assert mocked.call_args.args[0] == "https://example.test/u/Cat.exe"


def test_wmn_check_does_not_accept_generic_status_without_marker():
    class Response:
        status_code = 200
        text = "generic page"

    site = {
        "uri_check": "https://example.test/@{account}",
        "e_code": 200,
        "e_string": "profile marker",
    }
    with patch.object(app.HTTP, "get", return_value=Response()):
        assert app.wmn_check(site, "𝘊𝘢𝘵.𝘦𝘹𝘦") is None


def test_stackoverflow_requires_exact_display_name():
    class Response:
        status_code = 200
        text = '{"items":[{"display_name":"tomcat.exe"}]}'

        @staticmethod
        def json():
            return {"items": [{"display_name": "tomcat.exe"}]}

    site = {
        "name": "StackOverflow",
        "uri_check": "https://api.stackexchange.com/2.3/users?inname={account}&site=stackoverflow",
        "uri_pretty": "https://stackoverflow.com/users/filter?search={account}",
        "e_code": 200,
        "e_string": '"items":[{',
    }
    with patch.object(app.HTTP, "get", return_value=Response()):
        assert app.wmn_check(site, "Cat.exe") is None
