"""Normalisation prudente des pseudos avant interrogation de services externes."""
from __future__ import annotations

import unicodedata
import re


def normalize_username(value: str) -> str:
    """Convertit les variantes Unicode compatibles en forme comparable.

    NFKC transforme notamment les caractères mathématiques stylisés comme
    ``𝘊𝘢𝘵.𝘦𝘹𝘦`` en ``Cat.exe``. Les caractères Unicode non compatibles sont
    conservés : ils peuvent être des pseudos légitimes sur certaines plateformes.
    Les caractères de contrôle et de format invisibles sont retirés.
    """
    text = str(value or "").strip().lstrip("@")
    text = unicodedata.normalize("NFKC", text)
    return "".join(char for char in text if unicodedata.category(char) not in {"Cc", "Cf"})


def username_search_variants(value: str, *, max_variants: int = 8) -> list[str]:
    """Construit un petit ensemble stable d'écritures équivalentes d'un pseudo.

    Les caractères Unicode de compatibilité (dont les lettres mathématiques
    stylisées/italiques), la casse et les accents sont normalisés. Les
    séparateurs présents dans le pseudo peuvent être convertis entre point,
    tiret et souligné, ou retirés. Aucune faute arbitraire d'une lettre n'est
    générée et cette fonction ne fait aucun accès réseau.
    """
    normalized = normalize_username(value)
    if not normalized or max_variants < 1:
        return []
    accentless = "".join(
        char for char in unicodedata.normalize("NFKD", normalized)
        if unicodedata.category(char) != "Mn"
    )
    candidates = [normalized, accentless, normalized.casefold(), accentless.casefold()]
    canonical = accentless.casefold()
    if re.search(r"[._-]", canonical):
        candidates.append(re.sub(r"[._-]+", "", canonical))
        for separator in (".", "_", "-"):
            candidates.append(re.sub(r"[._-]+", separator, canonical))
    results: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in results and all(char.isalnum() or char in "._-" for char in candidate):
            results.append(candidate)
            if len(results) >= max_variants:
                break
    return results
