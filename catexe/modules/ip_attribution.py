"""Interprétation prudente des réponses de géolocalisation IP."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IPAttribution:
    country: str | None
    city: str | None
    provider: str | None
    agreement: int
    compared_sources: int
    precision: str
    warning: str = ""


def summarize_ip_sources(who: dict, api: dict) -> IPAttribution:
    """Compare deux sources publiques sans prétendre localiser un utilisateur."""
    country_who = who.get("country")
    country_api = api.get("country")
    city_who = who.get("city")
    city_api = api.get("city")
    country_values = [v for v in (country_who, country_api) if v]
    city_values = [v for v in (city_who, city_api) if v]
    agreement = 0
    compared = 0
    if country_values:
        compared += 1
        agreement += int(len(set(country_values)) == 1)
    if city_values:
        compared += 1
        agreement += int(len(set(city_values)) == 1)
    precision = "ville estimée" if city_values else "pays estimé" if country_values else "inconnue"
    return IPAttribution(
        country=country_who or country_api,
        city=city_who or city_api,
        provider=(who.get("connection") or {}).get("isp") or api.get("isp"),
        agreement=agreement,
        compared_sources=compared,
        precision=precision,
        warning="Localisation estimée du réseau ; impossible de déduire l’adresse ou la position exacte d’une personne.",
    )
