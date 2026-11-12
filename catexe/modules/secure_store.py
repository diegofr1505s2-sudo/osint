"""Stockage local prudent des secrets CAT.EXE.

Le fichier reste local, n’est jamais ajouté aux rapports et reçoit des
permissions restrictives quand le système les supporte. Les variables
d’environnement gardent la priorité pour les déploiements automatisés.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Mapping


_SECRET_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,80}$")


class SecretStore:
    def __init__(self, path: Path, environ: Mapping[str, str] | None = None):
        self.path = Path(path)
        self.environ = environ if environ is not None else os.environ
        self.values: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self.values = {str(k): str(v) for k, v in data.items() if v}
        except (OSError, ValueError, TypeError):
            self.values = {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(self.values, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(temp, 0o600)
        except OSError:
            pass
        temp.replace(self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def get(self, name: str, default: str = "") -> str:
        env_name = "CATEXE_SECRET_" + name.upper().replace("-", "_").replace(".", "_")
        return self.environ.get(env_name) or self.values.get(name, default)

    def has(self, name: str) -> bool:
        env_name = "CATEXE_SECRET_" + name.upper().replace("-", "_").replace(".", "_")
        return bool(self.environ.get(env_name)) or name in self.values

    def set(self, name: str, value: str) -> None:
        if not _SECRET_NAME.fullmatch(name):
            raise ValueError(f"Nom de secret invalide : {name}")
        self.values[name] = value
        self._save()

    def delete(self, name: str) -> None:
        self.values.pop(name, None)
        self._save()

    def migrate(self, config: dict, names: tuple[str, ...]) -> bool:
        changed = False
        for name in names:
            value = config.pop(name, "")
            if value and not self.get(name):
                self.set(name, str(value))
            if value:
                changed = True
        return changed

    def redact(self, text: str) -> str:
        result = str(text)
        candidates = set(self.values.values())
        candidates.update(v for k, v in self.environ.items() if k.startswith("CATEXE_SECRET_") and v)
        for value in sorted({v for v in candidates if len(v) >= 4}, key=len, reverse=True):
            result = result.replace(value, "[SECRET REDACTED]")
        return result

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self.values))
