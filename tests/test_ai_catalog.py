from catexe.modules.ai_catalog import AI_CATALOG, CATEGORY_INFO, catalog_model_sizes, models_for_profile


def test_catalog_contains_the_requested_categories_and_explanations():
    assert set(AI_CATALOG) == {"Texte", "Vision", "Extraction", "Audio"}
    assert all(CATEGORY_INFO[category] for category in AI_CATALOG)
    assert [len(AI_CATALOG[key]) for key in ("Texte", "Vision", "Extraction", "Audio")] == [10, 12, 10, 10]


def test_text_profile_contains_verified_ollama_tags_and_not_encoder_models():
    tags = {model.ollama_tag for model in models_for_profile("text")}
    assert {"qwen3.5:0.8b", "qwen3.5:4b", "gemma3:1b", "glm-4.7-flash"} <= tags
    assert None not in tags


def test_vision_profile_contains_multimodal_tags_and_omits_text_only_models():
    tags = {model.ollama_tag for model in models_for_profile("vision")}
    assert {"qwen3.5:0.8b", "qwen3.5:2b", "qwen3.5:4b", "gemma4:e2b", "gemma4:e4b"} <= tags
    assert "gemma3:1b" not in tags
    assert "llama3.2:1b" not in tags


def test_model_sizes_include_actual_large_glm_download_estimate():
    sizes = catalog_model_sizes()
    assert sizes["qwen3.5:0.8b"] == "1.2–1.3 Go"
    assert sizes["glm-4.7-flash"] == "19 Go Q4_K_M"


def test_extraction_and_audio_models_are_informational_not_ollama_pulls():
    for category in ("Extraction", "Audio"):
        assert all(model.ollama_tag is None for model in AI_CATALOG[category])
