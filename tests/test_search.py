from catexe.modules.search import APPROX, EXACT, edit_distance_at_most_one, normalize_search_text, search_match


def test_exact_is_literal_and_approx_ignores_case_and_accents():
    assert search_match("Sherlock", "Sherlock Holmes", EXACT)
    assert not search_match("sherlock", "Sherlock Holmes", EXACT)
    assert search_match("cafe", "Café des outils", APPROX)


def test_approx_accepts_one_character_edit_and_adjacent_transposition():
    assert edit_distance_at_most_one("sherlok", "sherlock")
    assert edit_distance_at_most_one("ab", "ba")
    assert edit_distance_at_most_one("cat", "cart")
    assert search_match("sherlok", "Sherlock OSINT tool", APPROX)
    assert not search_match("sherlokxx", "Sherlock OSINT tool", APPROX)


def test_approx_requires_all_query_tokens_and_avoids_short_fuzzy_tokens():
    assert search_match("cafe outil", "Café des outils locaux", APPROX)
    assert not search_match("cafe absent", "Café des outils locaux", APPROX)
    assert not search_match("cat", "cart", APPROX)
    assert normalize_search_text("Éléphant  À PARIS") == "elephant a paris"
