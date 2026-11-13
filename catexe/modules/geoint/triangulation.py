"""Intersection prudente de relèvements sur un plan local tangent."""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Sequence

EARTH_RADIUS_M = 6_371_008.8


@dataclass(frozen=True)
class BearingObservation:
    latitude: float
    longitude: float
    azimuth_deg: float


@dataclass(frozen=True)
class TriangulationResult:
    latitude: float
    longitude: float
    residual_rms_m: float
    uncertainty_radius_m: float
    minimum_crossing_angle_deg: float
    all_rays_forward: bool
    distances_m: tuple[float, ...]
    note: str = (
        "Position estimée par ajustement des relèvements dans un plan local. "
        "L'incertitude dépend de la précision des azimuts saisie par l'utilisateur."
    )


def intersect_bearings(
    observations: Sequence[BearingObservation],
    bearing_uncertainty_deg: float = 1.0,
) -> TriangulationResult:
    """Ajuste le point le plus proche de plusieurs lignes de relèvement.

    Les azimuts sont exprimés en degrés dans le sens horaire depuis le nord vrai.
    L'incertitude renvoyée est un rayon indicatif, pas un intervalle statistique.
    """
    if len(observations) < 2:
        raise ValueError("Il faut au moins deux relèvements.")
    if not math.isfinite(bearing_uncertainty_deg) or not 0 < bearing_uncertainty_deg <= 45:
        raise ValueError("L'incertitude d'azimut doit être comprise entre 0 et 45 degrés.")
    for obs in observations:
        if (
            not math.isfinite(obs.latitude)
            or not math.isfinite(obs.longitude)
            or not math.isfinite(obs.azimuth_deg)
            or not -90 <= obs.latitude <= 90
            or not -180 <= obs.longitude <= 180
        ):
            raise ValueError("Coordonnée ou azimut invalide.")
    lat0 = sum(item.latitude for item in observations) / len(observations)
    lon_sin = sum(math.sin(math.radians(item.longitude)) for item in observations)
    lon_cos = sum(math.cos(math.radians(item.longitude)) for item in observations)
    lon0 = math.degrees(math.atan2(lon_sin, lon_cos))
    cos_lat = math.cos(math.radians(lat0))
    if abs(cos_lat) < 0.01:
        raise ValueError("La projection locale près des pôles est trop imprécise.")
    points: list[tuple[float, float, float]] = []
    for obs in observations:
        dlon = (obs.longitude - lon0 + 180) % 360 - 180
        east = EARTH_RADIUS_M * cos_lat * math.radians(dlon)
        north = EARTH_RADIUS_M * math.radians(obs.latitude - lat0)
        az = math.radians(obs.azimuth_deg % 360)
        points.append((east, north, az))
    if max(math.hypot(east, north) for east, north, _ in points) > 200_000:
        raise ValueError("Les points dépassent 200 km du centre local; utilise une projection géodésique adaptée.")
    for index, (east, north, _) in enumerate(points):
        if any(math.hypot(east - other_east, north - other_north) < 1.0
               for other_east, other_north, _ in points[index + 1 :]):
            raise ValueError("Chaque relèvement doit partir d'une position distincte.")

    # Pour chaque relèvement, le vecteur normal à la ligne est (cos(az), -sin(az)).
    nxx = nxy = nyy = bx = by = 0.0
    for east, north, az in points:
        a, b = math.cos(az), -math.sin(az)
        c = a * east + b * north
        nxx += a * a
        nxy += a * b
        nyy += b * b
        bx += a * c
        by += b * c
    determinant = nxx * nyy - nxy * nxy
    if determinant <= 1e-8:
        raise ValueError("Les relèvements sont presque parallèles : la position serait indéterminée.")
    x = (bx * nyy - by * nxy) / determinant
    y = (nxx * by - nxy * bx) / determinant

    signed_residuals: list[float] = []
    distances: list[float] = []
    forward: list[bool] = []
    for east, north, az in points:
        a, b = math.cos(az), -math.sin(az)
        signed_residuals.append(a * (x - east) + b * (y - north))
        along = (x - east) * math.sin(az) + (y - north) * math.cos(az)
        distances.append(math.hypot(x - east, y - north))
        forward.append(along > 0)
    rms = math.sqrt(sum(value * value for value in signed_residuals) / len(signed_residuals))
    crossing_angles = []
    for i, left in enumerate(observations):
        for right in observations[i + 1 :]:
            difference = abs((left.azimuth_deg - right.azimuth_deg) % 180)
            crossing_angles.append(min(difference, 180 - difference))
    min_angle = min(crossing_angles)
    if min_angle < 0.5:
        raise ValueError("L'angle de croisement est trop faible pour une estimation stable.")
    angle_uncertainty = math.radians(bearing_uncertainty_deg)
    uncertainty = rms + max(distances) * math.tan(angle_uncertainty) / math.sin(math.radians(min_angle))
    latitude = lat0 + math.degrees(y / EARTH_RADIUS_M)
    longitude = lon0 + math.degrees(x / (EARTH_RADIUS_M * cos_lat))
    longitude = (longitude + 180) % 360 - 180
    return TriangulationResult(
        latitude=latitude,
        longitude=longitude,
        residual_rms_m=rms,
        uncertainty_radius_m=uncertainty,
        minimum_crossing_angle_deg=min_angle,
        all_rays_forward=all(forward),
        distances_m=tuple(distances),
    )
