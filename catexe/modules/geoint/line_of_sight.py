"""Calcul de visibilité géographique sur un profil d'altitudes fourni."""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Sequence

EARTH_RADIUS_M = 6_371_008.8


@dataclass(frozen=True)
class SightlineResult:
    visible: bool | None
    distance_m: float
    minimum_clearance_m: float | None
    obstruction_fraction: float | None
    sample_count: int
    sample_spacing_m: float
    curvature_coefficient: float
    source_note: str = (
        "Profil numérique d'altitude 90 m (Copernicus GLO-90 via Open-Meteo). "
        "Les bâtiments, arbres et obstacles plus petits que la résolution ne sont pas modélisés."
    )


def _distance_m(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1 = map(math.radians, a)
    lat2, lon2 = map(math.radians, b)
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(h)))


def analyze_sightline(
    start: tuple[float, float],
    end: tuple[float, float],
    elevations_m: Sequence[float | None],
    observer_height_m: float = 1.7,
    target_height_m: float = 10.0,
    curvature_coefficient: float = 0.13,
) -> SightlineResult:
    """Compare le rayon visuel aux altitudes échantillonnées et au relief terrestre.

    Le coefficient 0.13 représente une réfraction atmosphérique conventionnelle.
    Les extrémités de la ligne de visée sont surélevées des hauteurs spécifiées.
    Une altitude manquante produit un résultat indéterminé, jamais « visible ».
    """
    if len(elevations_m) < 3:
        raise ValueError("Le profil doit contenir au moins trois altitudes.")
    if not all(math.isfinite(v) and 0 <= v <= 9000 for v in (observer_height_m, target_height_m)):
        raise ValueError("Les hauteurs doivent être finies et comprises entre 0 et 9000 m.")
    if not math.isfinite(curvature_coefficient) or not 0 <= curvature_coefficient < 1:
        raise ValueError("Le coefficient de réfraction doit être compris entre 0 et 1.")
    distance = _distance_m(start, end)
    if distance <= 0:
        raise ValueError("Les coordonnées de départ et d'arrivée doivent être distinctes.")
    n = len(elevations_m)
    spacing = distance / (n - 1)
    if any(value is None or not math.isfinite(value) for value in elevations_m):
        return SightlineResult(None, distance, None, None, n, spacing, curvature_coefficient)
    elevations = [float(value) for value in elevations_m]
    effective_radius = EARTH_RADIUS_M / (1.0 - curvature_coefficient)
    clearances: list[tuple[float, float]] = []
    for index in range(1, n - 1):
        fraction = index / (n - 1)
        sight_altitude = (
            (1.0 - fraction) * (elevations[0] + observer_height_m)
            + fraction * (elevations[-1] + target_height_m)
        )
        curvature_bulge = distance**2 * fraction * (1.0 - fraction) / (2.0 * effective_radius)
        terrain_altitude = elevations[index] + curvature_bulge
        clearances.append((sight_altitude - terrain_altitude, fraction))
    minimum, fraction = min(clearances, key=lambda item: item[0])
    return SightlineResult(
        visible=minimum > 0.0,
        distance_m=distance,
        minimum_clearance_m=minimum,
        obstruction_fraction=fraction,
        sample_count=n,
        sample_spacing_m=spacing,
        curvature_coefficient=curvature_coefficient,
    )
