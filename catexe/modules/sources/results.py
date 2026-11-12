"""Contrat commun pour les résultats des adaptateurs de sources."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterator


STATUSES = frozenset({"found", "not_found", "probable", "blocked", "rate_limited", "error", "unknown"})
CONFIDENCES = frozenset({"high", "medium", "low", "none"})


@dataclass(frozen=True)
class SourceResult:
    """Résultat explicite d’une vérification de source.

    ``status`` décrit ce qui a réellement été observé ; il ne transforme pas
    un blocage réseau en absence de compte. ``confidence`` décrit la fiabilité
    de l’inférence, pas la popularité de la source.
    """

    source: str
    status: str
    confidence: str
    url: str | None = None
    reason: str | None = None
    checked_at: str = ""
    http_status: int | None = None
    method: str = "http_adapter"

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"Statut de source inconnu : {self.status}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"Niveau de confiance inconnu : {self.confidence}")
        if not self.checked_at:
            object.__setattr__(self, "checked_at", datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @property
    def legacy_status(self) -> str:
        """Libellé français historique conservé pour l’interface actuelle."""
        return {
            "found": "trouvé",
            "not_found": "absent",
            "probable": "à vérifier",
            "unknown": "manuel",
            "blocked": "injoignable",
            "rate_limited": "injoignable",
            "error": "injoignable",
        }[self.status]

    def __iter__(self) -> Iterator[object]:
        """Permet la compatibilité temporaire avec ``status, code = result``."""
        yield self.legacy_status
        yield self.http_status


def result_from_probe(*, source: str, url: str | None, http_status: int | None, value: int | None, reason: str | None = None, method: str = "http_adapter") -> SourceResult:
    """Convertit la sortie historique 0/1/None d’un parseur en résultat fiable."""
    if value == 1:
        status, confidence = "found", "medium"
    elif value == 0:
        status, confidence = "not_found", "low"
    else:
        status, confidence = "probable", "low"
    if http_status in (401, 403):
        status, confidence = "blocked", "none"
        reason = reason or f"Service bloqué ou authentification requise (HTTP {http_status})"
    elif http_status in (429, 503):
        status, confidence = "rate_limited", "none"
        reason = reason or f"Service temporairement indisponible ou limité (HTTP {http_status})"
    return SourceResult(source, status, confidence, url, reason, http_status=http_status, method=method)


def source_error(*, source: str, url: str | None, reason: str, http_status: int | None = None, method: str = "http_adapter") -> SourceResult:
    return SourceResult(source, "error", "none", url, reason, http_status=http_status, method=method)
