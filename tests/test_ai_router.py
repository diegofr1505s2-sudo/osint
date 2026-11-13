from catexe.modules.ai_router import AI_PROFILES, AI_TASKS, configured_model, profile_for


def test_task_routing_is_specialized():
    assert profile_for("summary").key == "text"
    assert profile_for("metadata_explanation").key == "light"
    assert profile_for("geoint").key == "vision"
    assert profile_for("ocr").key == "ocr"
    assert profile_for("cyber").key == "cyber"
    assert profile_for("code").key == "code"
    assert profile_for("unknown-task").key == "text"


def test_image_overrides_text_task():
    assert profile_for("summary", image=True).key == "vision"
    assert profile_for("ocr", image=True).key == "ocr"


def test_configured_models_are_used_without_network_calls():
    config = {"ollama_cyber": "local-cyber:latest"}
    assert configured_model("cyber", config) == "local-cyber:latest"
    assert configured_model("ocr", {"ollama_ocr": "local-ocr:latest"}, image=True) == "local-ocr:latest"
    assert configured_model("summary", {}) == AI_PROFILES["text"].default_model
    assert set(("summary", "vision", "ocr", "cyber", "code")) <= set(AI_TASKS)


def test_settings_mark_installed_and_missing_models():
    from catexe.app import model_install_mark

    assert model_install_mark("qwen2.5:3b", ["qwen2.5:3b"]) == "☑ installé"
    assert model_install_mark("qwen2.5:3b", ["qwen2.5:7b"]) == "☐ non installé"
    assert model_install_mark("qwen2.5:3b", None) == "○ Ollama non détecté"
