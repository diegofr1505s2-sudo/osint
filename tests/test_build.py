import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_windows_scripts_use_consistent_python_version_and_build_spec():
    for name in ("LANCER.bat", "CREER_EXE.bat"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "-3.14" not in text
        assert "-3.11" in text
        assert "Python 3.11" in text
    build = (ROOT / "CREER_EXE.bat").read_text(encoding="utf-8")
    assert "CatExe.spec" in build
    assert "data CatExe-OSINT\\data" in build
    assert "resultats" in build and "cache" in build


def test_pyinstaller_spec_and_example_exclude_personal_runtime_data():
    spec = (ROOT / "CatExe.spec").read_text(encoding="utf-8")
    assert '"lang"' in spec and '"data"' in spec
    assert "secrets.json" not in spec
    example = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))
    assert not any(key.endswith(("_token", "_key")) for key in example)
    assert "keys" not in example


def test_startup_has_no_simulated_boot_logs_or_chcp_command():
    app = (ROOT / "catexe" / "app.py").read_text(encoding="utf-8")
    assert "anim_bootlog" not in app
    assert "système de fichiers chiffré" not in app
    assert "empreinte sha256" not in app
    for name in ("LANCER.bat", "CREER_EXE.bat"):
        text = (ROOT / name).read_text(encoding="utf-8").lower()
        assert "chcp " not in text
