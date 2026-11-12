from catexe.modules.menu_registry import KEYW, build_sections
from catexe.modules.ui import UIContext, _plain


def test_menu_registry_is_data_driven():
    sections = build_sections(23)
    values = {value for _, items in sections for value, *_ in items}
    assert len(sections) == 8
    assert len(values) == 60
    assert "mod_settings" in values
    assert "mod_diagnostics" in values
    assert KEYW["mod_social"]


def test_ui_context_normalizes_search_text():
    ctx = UIContext(con=None, tr=lambda text: text, escape=lambda text: text, colors={"G": "G", "P": "P", "Y": "Y", "M": "M"})
    assert _plain(ctx, "Été GEOINT") == "ete geoint"
