"""Routage déterministe des tâches vers des profils d’IA locale Ollama."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AIProfile:
    key: str
    label: str
    config_key: str
    default_model: str
    purpose: str


AI_PROFILES = {
    "light": AIProfile("light", "IA légère", "ollama_light", "qwen2.5:1.5b", "extraction et réponses rapides"),
    "text": AIProfile("text", "IA texte", "ollama_text", "qwen2.5:3b", "synthèse et raisonnement général"),
    "vision": AIProfile("vision", "IA vision", "ollama_model", "qwen2.5vl:7b", "images, GEOINT et description visuelle"),
    "ocr": AIProfile("ocr", "IA OCR", "ollama_ocr", "qwen2.5vl:3b", "texte présent dans une image"),
    "cyber": AIProfile("cyber", "IA cyber", "ollama_cyber", "qwen2.5:7b", "logs, configuration et analyse défensive"),
    "code": AIProfile("code", "IA code", "ollama_code", "qwen2.5:7b", "Python, Bash, PowerShell et JavaScript"),
}

AI_TASKS = {
    "summary": "text",
    "analysis": "text",
    "metadata_explanation": "light",
    "vision": "vision",
    "geoint": "vision",
    "ocr": "ocr",
    "cyber": "cyber",
    "code": "code",
}


def profile_for(task: str, image: bool = False) -> AIProfile:
    task_profile = AI_TASKS.get(task, task if task in AI_PROFILES else "text")
    if image and task_profile != "ocr":
        return AI_PROFILES["vision"]
    return AI_PROFILES[task_profile]


def configured_model(task: str, config: dict, image: bool = False) -> str:
    profile = profile_for(task, image=image)
    return config.get(profile.config_key) or profile.default_model


def available_model(model: str, installed: list[str] | None) -> str:
    """Retourne le modèle demandé s’il est installé, sinon une indication stable."""
    if installed is None:
        return model
    for candidate in installed:
        if candidate == model or candidate == model + ":latest" or candidate.startswith(model + ":"):
            return candidate
    return model
