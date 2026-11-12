"""Utilitaires purs et réutilisables de CAT.EXE.

Ce module ne dépend ni de Rich, ni de l'état global de l'application, ni du
réseau. Il peut donc être testé et réutilisé par les futurs modules.
"""
from __future__ import annotations

import datetime
import json
import math
import re


def stamp() -> str:
    """Retourne un horodatage compact pour les noms de fichiers."""
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def clean_path(value: str) -> str:
    """Nettoie un chemin collé depuis PowerShell ou un terminal."""
    value = value.strip()
    if value.startswith("& "):
        value = value[2:]
    return value.strip().strip("'\"")


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calcule la distance en kilomètres entre deux coordonnées GPS."""
    radians = math.radians
    h = math.sin(radians(lat2 - lat1) / 2) ** 2
    h += math.cos(radians(lat1)) * math.cos(radians(lat2)) * math.sin(radians(lon2 - lon1) / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))


def parse_json(text: str | None) -> object | None:
    """Parse un objet JSON présent dans une réponse textuelle, avec tolérance aux virgules finales."""
    match = re.search(r"\{[\s\S]*\}", text or "")
    if not match:
        return None
    for candidate in (match.group(0), re.sub(r",\s*([}\]])", r"\1", match.group(0))):
        try:
            return json.loads(candidate)
        except (TypeError, ValueError):
            pass
    return None
