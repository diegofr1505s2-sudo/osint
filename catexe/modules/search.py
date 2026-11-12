"""Correspondance de recherche locale, exacte ou tolérante à une modification."""
from __future__ import annotations

import unicodedata


EXACT = "exact"
APPROX = "approx"


def normalize_search_text(value: object) -> str:
    """Normalise la casse, les accents et les espaces pour le mode approximatif."""
    text = unicodedata.normalize("NFKD", str(value)).casefold()
    text = "".join(char for char in text if unicodedata.category(char) != "Mn")
    return " ".join(text.split())


def edit_distance_at_most_one(left: str, right: str, *, allow_transposition: bool = True) -> bool:
    """Dit si deux chaînes sont identiques ou diffèrent d'une seule édition."""
    if left == right:
        return True
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        diffs = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]
        if len(diffs) == 1:
            return True
        return (allow_transposition and len(diffs) == 2 and diffs[1] == diffs[0] + 1
                and left[diffs[0]] == right[diffs[1]] and left[diffs[1]] == right[diffs[0]])

    short, long = (left, right) if len(left) < len(right) else (right, left)
    i = j = edits = 0
    while i < len(short) and j < len(long):
        if short[i] == long[j]:
            i += 1
            j += 1
        else:
            edits += 1
            j += 1
            if edits > 1:
                return False
    return True


def search_match(query: object, candidate: object, mode: str = EXACT, *, min_fuzzy_length: int = 4) -> bool:
    """Matche littéralement en exact; en approx tolère casse/accents et une édition.

    Approximate matching works token-by-token, requires all query words to match,
    and only applies edit distance to tokens at least ``min_fuzzy_length`` chars.
    This conservative floor prevents very short queries from exploding into false hits.
    """
    raw_query = str(query)
    raw_candidate = str(candidate)
    if not raw_query:
        return True
    if mode != APPROX:
        return raw_query in raw_candidate

    needle = normalize_search_text(raw_query)
    haystack = normalize_search_text(raw_candidate)
    if not needle:
        return True
    if needle in haystack:
        return True
    qwords = needle.split()
    cwords = haystack.split()
    for word in qwords:
        if word in cwords:
            continue
        if len(word) < min_fuzzy_length or not any(
            len(candidate_word) >= min_fuzzy_length and edit_distance_at_most_one(word, candidate_word)
            for candidate_word in cwords
        ):
            return False
    return True


def one_edit_variants(value: str, alphabet: str = "abcdefghijklmnopqrstuvwxyz0123456789._-", *, include_transpositions: bool = True) -> list[str]:
    """Génère des variantes distinctes à une édition; n'effectue aucun appel réseau."""
    value = str(value)
    variants: dict[str, None] = {}
    for i in range(len(value)):
        variants.setdefault(value[:i] + value[i + 1:], None)  # suppression
        for char in alphabet:
            if char != value[i]:
                variants.setdefault(value[:i] + char + value[i + 1:], None)  # remplacement
    for i in range(len(value) + 1):
        for char in alphabet:
            variants.setdefault(value[:i] + char + value[i:], None)  # insertion
    if include_transpositions:
        for i in range(len(value) - 1):
            if value[i] != value[i + 1]:
                variants.setdefault(value[:i] + value[i + 1] + value[i] + value[i + 2:], None)
    variants.pop(value, None)
    return list(variants)
