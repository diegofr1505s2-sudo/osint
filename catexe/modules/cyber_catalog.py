"""Catalogue local de ressources cyber, sans exécution automatique."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


def load_catalog(path: Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("tools"), list):
        raise ValueError("Format de catalogue cyber invalide")
    return data


def search_tools(tools: list[dict[str, Any]], query: str = "", category: str | None = None, risk: str | None = None, platform: str | None = None) -> list[dict[str, Any]]:
    needle = query.casefold().strip()
    result = []
    for tool in tools:
        haystack = " ".join(str(tool.get(key, "")) for key in ("name", "description", "category", "language", "source_ref")).casefold()
        if needle and needle not in haystack:
            continue
        if category and tool.get("category") != category:
            continue
        if risk and tool.get("risk_level") != risk:
            continue
        if platform and platform not in (tool.get("platforms") or []):
            continue
        result.append(tool)
    return sorted(result, key=lambda item: (RISK_ORDER.get(item.get("risk_level", "medium"), 1), str(item.get("name", "")).casefold()))


def categories(tools: list[dict[str, Any]]) -> list[str]:
    return sorted({str(tool.get("category")) for tool in tools if tool.get("category")})


def platforms(tools: list[dict[str, Any]]) -> list[str]:
    return sorted({platform for tool in tools for platform in (tool.get("platforms") or [])})


def risk_label(value: str) -> str:
    return {"low": "faible", "medium": "moyen", "high": "élevé"}.get(value, "inconnu")
