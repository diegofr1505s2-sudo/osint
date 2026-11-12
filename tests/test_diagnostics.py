from pathlib import Path

from catexe.diagnostics import collect_checks, render


ROOT = Path(__file__).resolve().parents[1]


def test_diagnostic_contains_required_checks():
    checks = collect_checks(ROOT)
    names = {check.name for check in checks}
    assert {"Python", "Requests", "Rich", "FFmpeg", "Playwright", "Ollama"} <= names


def test_render_is_localized_and_classified():
    text = render(collect_checks(ROOT))
    assert "Diagnostic système" in text
    assert "Obligatoire" in text
    assert "IA locale" in text
    assert "Navigateur" in text
