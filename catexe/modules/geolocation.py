"""Modèles prudents pour les hypothèses de géolocalisation."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GeoHypothesis:
    lat: float
    lon: float
    label: str
    probability: float | None = None
    source: str = "unknown"
    evidence: tuple[str, ...] = ()
    radius_km: float | None = None

    @property
    def confidence(self) -> str:
        if self.source == "exif":
            return "high"
        if self.probability is None:
            return "low"
        if self.probability >= 0.65:
            return "medium"
        return "low"


def rank_hypotheses(hypotheses: list[GeoHypothesis]) -> list[GeoHypothesis]:
    """Trie les hypothèses sans transformer une estimation en certitude."""
    return sorted(hypotheses, key=lambda item: item.probability or 0.0, reverse=True)


def confidence_text(hypothesis: GeoHypothesis) -> str:
    labels = {"high": "élevée", "medium": "moyenne", "low": "faible"}
    return labels[hypothesis.confidence]


def limitation_text(hypothesis: GeoHypothesis) -> str:
    if hypothesis.source == "exif":
        return "GPS EXIF présent ; position de l’appareil, à vérifier selon la chaîne de conservation du fichier."
    radius = f"Zone d’incertitude : environ {hypothesis.radius_km:g} km." if hypothesis.radius_km else "Zone d’incertitude non calculée."
    return f"Estimation non confirmée. {radius}"
