"""Échantillonnage de profils et accès aux altitudes Copernicus via Open-Meteo."""
from __future__ import annotations

import math
from typing import Callable, Sequence

ELEVATION_API = "https://api.open-meteo.com/v1/elevation"
DATASET_RESOLUTION_M = 90.0
MAX_POINTS_PER_REQUEST = 100
MAX_PROFILE_POINTS = 1200
EARTH_RADIUS_M = 6_371_008.8


def _validate_coordinate(point: tuple[float, float]) -> None:
    if len(point) != 2:
        raise ValueError("Une coordonnée doit contenir latitude et longitude.")
    lat, lon = point
    if not math.isfinite(lat) or not math.isfinite(lon) or not -90 <= lat <= 90 or not -180 <= lon <= 180:
        raise ValueError("Coordonnées invalides : latitude [-90, 90], longitude [-180, 180].")


def _distance_m(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1 = map(math.radians, a)
    lat2, lon2 = map(math.radians, b)
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(h)))


def great_circle_profile(
    start: tuple[float, float],
    end: tuple[float, float],
    spacing_m: float = DATASET_RESOLUTION_M,
    max_points: int = MAX_PROFILE_POINTS,
) -> list[tuple[float, float]]:
    """Renvoie des points régulièrement espacés sur le grand cercle, extrémités incluses."""
    _validate_coordinate(start)
    _validate_coordinate(end)
    if not math.isfinite(spacing_m) or spacing_m <= 0:
        raise ValueError("L'espacement doit être supérieur à zéro.")
    distance = _distance_m(start, end)
    if distance <= 0.01:
        raise ValueError("Les coordonnées doivent être distinctes.")
    segments = max(2, math.ceil(distance / spacing_m))
    count = segments + 1
    if count > max_points:
        raise ValueError(
            f"Le trajet nécessite {count} points, au-delà de la limite de {max_points}. "
            "Raccourcis le trajet pour conserver une résolution utile."
        )
    lat1, lon1 = map(math.radians, start)
    lat2, lon2 = map(math.radians, end)
    va = (math.cos(lat1) * math.cos(lon1), math.cos(lat1) * math.sin(lon1), math.sin(lat1))
    vb = (math.cos(lat2) * math.cos(lon2), math.cos(lat2) * math.sin(lon2), math.sin(lat2))
    dot = max(-1.0, min(1.0, sum(x * y for x, y in zip(va, vb))))
    omega = math.acos(dot)
    if math.pi - omega < 1e-8:
        raise ValueError("Le trajet antipodal est ambigu; choisis un trajet plus court.")
    points: list[tuple[float, float]] = []
    for index in range(count):
        t = index / segments
        if omega < 1e-8:
            v = tuple((1 - t) * x + t * y for x, y in zip(va, vb))
        else:
            scale_a = math.sin((1 - t) * omega) / math.sin(omega)
            scale_b = math.sin(t * omega) / math.sin(omega)
            v = tuple(scale_a * x + scale_b * y for x, y in zip(va, vb))
        norm = math.sqrt(sum(component * component for component in v))
        x, y, z = (component / norm for component in v)
        points.append((math.degrees(math.atan2(z, math.hypot(x, y))), math.degrees(math.atan2(y, x))))
    points[0], points[-1] = start, end
    return points


def fetch_open_meteo_elevations(
    points: Sequence[tuple[float, float]],
    get_json: Callable[..., dict],
) -> list[float | None]:
    """Récupère les altitudes par lots de 100 coordonnées maximum.

    `get_json` est injecté par l'application pour réutiliser son client HTTP
    centralisé et permettre des tests sans réseau.
    """
    if not points:
        raise ValueError("Aucun point à échantillonner.")
    for point in points:
        _validate_coordinate(point)
    results: list[float | None] = []
    for offset in range(0, len(points), MAX_POINTS_PER_REQUEST):
        batch = points[offset : offset + MAX_POINTS_PER_REQUEST]
        payload = get_json(
            ELEVATION_API,
            timeout=25,
            params={
                "latitude": ",".join(f"{lat:.7f}" for lat, _ in batch),
                "longitude": ",".join(f"{lon:.7f}" for _, lon in batch),
            },
        )
        elevations = payload.get("elevation") if isinstance(payload, dict) else None
        if not isinstance(elevations, list) or len(elevations) != len(batch):
            raise ValueError("Réponse d'altitude invalide ou incomplète d'Open-Meteo.")
        for value in elevations:
            if value is None:
                results.append(None)
            elif isinstance(value, (int, float)) and math.isfinite(value):
                results.append(float(value))
            else:
                raise ValueError("Open-Meteo a retourné une altitude mal formée.")
    return results
