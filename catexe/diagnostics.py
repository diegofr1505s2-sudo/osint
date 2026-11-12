"""Diagnostic local et sans réseau de l'environnement CAT.EXE.

Le diagnostic ne charge pas l'application complète afin de fonctionner même
lorsqu'une dépendance optionnelle est absente. Il ne transmet aucune donnée.
"""
from __future__ import annotations

import importlib.util
import json
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str
    category: str

    @property
    def ok(self) -> bool:
        return self.status == "OK"


def _module(name: str, label: str, category: str = "optional") -> Check:
    present = importlib.util.find_spec(name) is not None
    return Check(label, "OK" if present else "absent", "module installé" if present else "module non installé", category)


def _command(name: str, label: str, category: str = "optional") -> Check:
    path = shutil.which(name)
    return Check(label, "OK" if path else "absent", path or "commande introuvable", category)


def _version() -> Check:
    current = sys.version_info
    good = current >= (3, 11)
    return Check("Python", "OK" if good else "KO", platform.python_version(), "required")


def _python_compile(root: Path) -> Check:
    files = sorted(root.rglob("*.py"))
    failures: list[str] = []
    for path in files:
        try:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
        except (OSError, SyntaxError) as exc:
            failures.append(f"{path.relative_to(root)}: {exc}")
    return Check("Compilation Python", "OK" if not failures else "KO", f"{len(files)} fichier(s) vérifié(s)" if not failures else "; ".join(failures), "required")


def collect_checks(root: Path | None = None) -> list[Check]:
    root = (root or Path(__file__).resolve().parent.parent).resolve()
    checks = [_version(), _python_compile(root)]
    checks.extend([
        _module("requests", "Requests", "required"),
        _module("rich", "Rich", "required"),
        _module("PIL", "Pillow", "optional"),
        _module("pillow_heif", "HEIC / HEIF", "optional"),
        _module("phonenumbers", "Numéros", "optional"),
        _module("numpy", "NumPy", "optional"),
        _module("pypdf", "PDF (pypdf)", "optional"),
        _module("fpdf", "PDF (fpdf2)", "optional"),
        _module("playwright", "Playwright", "browser"),
        _command("ollama", "Ollama", "ai"),
        _command("ffmpeg", "FFmpeg", "ffmpeg"),
        _command("ffprobe", "FFprobe", "ffmpeg"),
    ])
    return checks


def as_dict(checks: Iterable[Check]) -> list[dict[str, str]]:
    return [asdict(check) for check in checks]


def render(checks: Iterable[Check]) -> str:
    rows = list(checks)
    lines = ["CAT.EXE — Diagnostic système", "=" * 32]
    for check in rows:
        lines.append(f"{check.name} : {check.status} — {check.detail}")
    lines.append("")
    for category, label in (("required", "Obligatoire"), ("optional", "Optionnel"), ("ai", "IA locale"), ("ffmpeg", "FFmpeg"), ("browser", "Navigateur")):
        names = [c.name for c in rows if c.category == category and c.status == "OK"]
        missing = [c.name for c in rows if c.category == category and c.status != "OK"]
        lines.append(f"{label} : OK={', '.join(names) or 'aucun'}" + (f" | absents={', '.join(missing)}" if missing else ""))
    return "\n".join(lines)


def run(root: Path | None = None, *, as_json: bool = False) -> int:
    checks = collect_checks(root)
    if as_json:
        print(json.dumps(as_dict(checks), ensure_ascii=False, indent=2))
    else:
        print(render(checks))
    return 0 if all(c.ok for c in checks if c.category == "required") else 1


if __name__ == "__main__":
    raise SystemExit(run(as_json="--json" in sys.argv))
