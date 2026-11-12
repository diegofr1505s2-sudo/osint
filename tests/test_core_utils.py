import re

from catexe.core_utils import clean_path, haversine, parse_json, stamp


def test_clean_path_handles_shell_prefix_and_quotes():
    assert clean_path("& 'photo test.jpg'") == "photo test.jpg"


def test_haversine_returns_zero_for_same_point():
    assert haversine(48.8566, 2.3522, 48.8566, 2.3522) == 0


def test_parse_json_accepts_trailing_comma():
    assert parse_json("réponse: {\"ok\": true,}") == {"ok": True}


def test_stamp_is_filename_safe():
    value = stamp()
    assert len(value) == 15
    assert re.fullmatch(r"\d{8}_\d{6}", value)
