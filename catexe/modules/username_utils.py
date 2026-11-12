"""Normalisation prudente des pseudos avant interrogation de services externes."""
from __future__ import annotations

import unicodedata


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
