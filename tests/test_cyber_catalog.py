import json
from pathlib import Path

from catexe.modules.cyber_catalog import categories, load_catalog, platforms, risk_label, search_tools


ROOT = Path(__file__).resolve().parents[1]


def test_catalog_file_is_valid_and_sourced():
    catalog = load_catalog(ROOT / "data" / "cyber_tools.json")
    assert catalog["source"]["repository"].endswith("hacking-ethique")
    assert len(catalog["tools"]) >= 20
    assert all(tool.get("source_ref") for tool in catalog["tools"])
    json.dumps(catalog, ensure_ascii=False)


def test_catalog_search_and_filters_are_deterministic():
    tools = load_catalog(ROOT / "data" / "cyber_tools.json")["tools"]
    assert "ExifTool" in [x["name"] for x in search_tools(tools, query="métadonnées")]
    assert any(x["name"] == "Sherlock" for x in search_tools(tools, category="OSINT"))
    assert all(x["risk_level"] == "high" for x in search_tools(tools, risk="high"))
    assert "Sherlock" in [x["name"] for x in search_tools(tools, query="sherlok", mode="approx")]
    assert "Sherlock" not in [x["name"] for x in search_tools(tools, query="sherlok", mode="exact")]
    assert any(x["name"] == "Ollama" for x in search_tools(tools, platform="Windows"))
    assert "forensics" in categories(tools)
    assert "Linux" in platforms(tools)
    assert risk_label("high") == "élevé"
