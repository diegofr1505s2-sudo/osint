"""Gestion centralisée de la configuration locale de CAT.EXE."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

DEFAULT_CONFIG: dict[str, Any] = {
    "anim": True,
    "ollama_model": "qwen2.5vl:7b",
    "ollama_text": "qwen2.5:3b",
    "ollama_light": "qwen2.5:1.5b",
    "ollama_ocr": "qwen2.5vl:3b",
    "ollama_cyber": "qwen2.5:7b",
    "ollama_code": "qwen2.5:7b",
    "page": 0,
    "lang": "fr",
    "theme": "graphite",
    "sobre": True,
}


def config_path(base: Path) -> Path:
    return base / "config.json"


def load_config(path: Path) -> dict[str, Any]:
    """Charge la configuration locale, sans jamais échouer au démarrage."""
    config = dict(DEFAULT_CONFIG)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            config.update(data)
    except (OSError, ValueError, TypeError):
        pass
    return config


def save_config(path: Path, config: dict[str, Any]) -> None:
    """Écrit la configuration locale de manière lisible."""
    path.write_text(json.dumps(config, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
