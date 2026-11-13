"""Catalogue explicatif des modèles locaux et de leurs runtimes."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CatalogModel:
    name: str
    parameters: str
    purpose: str
    ollama_tag: str | None = None
    download_size: str = ""
    note: str = ""


CATEGORY_INFO = {
    "Texte": (
        "Modèles de dialogue : résumer, expliquer, rédiger et raisonner. Les très petits modèles "
        "répondent vite, mais peuvent manquer de précision. Les tailles indiquent les paramètres; "
        "la RAM et la taille téléchargée dépendent aussi de la quantification."
    ),
    "Vision": (
        "Modèles vision-langage : prennent une image en entrée et produisent une réponse textuelle. "
        "Ils servent notamment à décrire une photo ou lire des détails visuels. Une analyse d’image "
        "reste une hypothèse et ne remplace pas les métadonnées EXIF ni une vérification terrain."
    ),
    "Extraction": (
        "Modèles spécialisés qui extraient des entités, classent, vectorisent ou reclassent des textes. "
        "Ils ne remplacent pas un modèle de dialogue. CAT.EXE les documente ici, mais leur runtime "
        "d’extraction/embeddings n’est pas encore raccordé à l’application."
    ),
    "Audio": (
        "Modèles spécialisés pour transcrire la parole, générer une voix, détecter l’activité vocale "
        "ou distinguer les locuteurs. Ils nécessitent des pipelines audio dédiés qui ne sont pas encore "
        "intégrés à CAT.EXE."
    ),
}

AI_CATALOG: dict[str, tuple[CatalogModel, ...]] = {
    "Texte": (
        CatalogModel("Qwen 3.5 0.8B", "0.8B", "Dialogue léger et tâches rapides.", "qwen3.5:0.8b", "1.2–1.3 Go"),
        CatalogModel("Gemma 3 1B", "1B", "Petit modèle généraliste texte.", "gemma3:1b", "806 Mo"),
        CatalogModel("Llama 3.2 1B", "1B", "Dialogue et résumés légers.", "llama3.2:1b", "1.3 Go"),
        CatalogModel("SmolLM2 1.7B", "1.7B", "Modèle compact pour réponses simples.", "smollm2:1.7b", "1.8 Go"),
        CatalogModel("Gemma 3 270M", "270M", "Très petit modèle texte; capacité limitée.", "gemma3:270m", "292 Mo"),
        CatalogModel("Qwen 3.5 4B", "4B", "Modèle généraliste plus capable; texte et image.", "qwen3.5:4b", "3.3–4.0 Go"),
        CatalogModel("Phi-3.5 Mini", "3.8B", "Petit modèle de dialogue avec long contexte.", "phi3.5:3.8b", "2.2 Go"),
        CatalogModel("Gemma 4 E2B", "2.3B effectifs", "Modèle compact multimodal texte/image.", "gemma4:e2b", "4.6–7.5 Go", "Taille disque réelle supérieure au nombre de paramètres effectifs."),
        CatalogModel("Llama 3.2 3B", "3B", "Dialogue, consignes et résumés.", "llama3.2:3b", "2.0 Go"),
        CatalogModel("GLM-4.7-Flash", "30B-A3B", "Modèle MoE de dialogue; demande beaucoup d’espace disque.", "glm-4.7-flash", "19 Go Q4_K_M", "Ollama indique 19 Go pour Q4_K_M, pas ~5.5 Go; Ollama récent requis."),
    ),
    "Vision": (
        CatalogModel("Gemma 4 E4B", "4.5B effectifs", "Analyse d’images et réponses texte.", "gemma4:e4b", "6.6–9.5 Go", "Le E4B désigne les paramètres actifs/effectifs, pas l’espace disque."),
        CatalogModel("WebBrain VL 2 450M", "453M", "Vision et langage.", note="Runtime et poids hors Ollama; non détecté par CAT.EXE."),
        CatalogModel("MiniCPM-V 4.7 1B", "1B", "Vision-langage compact.", note="Cette variante précise n’est pas un tag Ollama vérifié."),
        CatalogModel("LFM2.5-VL-450M", "450M", "Compréhension visuelle compacte.", note="Runtime spécialisé; non détecté par Ollama."),
        CatalogModel("LFM2.5-VL-1.6B", "1.6B", "Compréhension visuelle légère.", note="Runtime spécialisé; non détecté par Ollama."),
        CatalogModel("Qwen 3.5 2B", "2B", "Vision-langage de taille intermédiaire.", "qwen3.5:2b", "2.7–3.1 Go"),
        CatalogModel("Qwen 3.5 0.8B", "0.8B", "Vision-langage très léger.", "qwen3.5:0.8b", "1.2–1.3 Go"),
        CatalogModel("LFM3-VLD-2B", "2B", "Vision et compréhension multimodale.", note="Runtime spécialisé; non détecté par Ollama."),
        CatalogModel("LFM2.5-VL-3B", "3B", "Vision-langage.", note="Runtime spécialisé; non détecté par Ollama."),
        CatalogModel("Qwen 3.5 4B", "4B", "Vision-langage plus capable.", "qwen3.5:4b", "3.3–4.0 Go"),
        CatalogModel("Gemma 3 4B", "4B", "Modèle texte/image disponible dans Ollama.", "gemma3:4b", "3.4 Go", "Ajout compatible proposé en plus de la liste."),
        CatalogModel("MiniCPM-V 2.6 8B", "8B", "Variante vision actuellement référencée par Ollama.", "minicpm-v:8b", "5.5 Go", "Ce n’est pas le MiniCPM-V 4.7 1B indiqué dans la liste."),
    ),
    "Extraction": (
        CatalogModel("GLiNER2.5-Decide", "340M", "Classification et extraction guidées par les étiquettes fournies."),
        CatalogModel("Vela 3.0 · vela3-fast", "380M", "Modèle de décision/extraction compact."),
        CatalogModel("relweave-1.7b-base", "1.7B", "Modèle de base spécialisé pour extraction/relations."),
        CatalogModel("UltraBERT-380M", "380M", "Encodeur compact pour tâches NLP."),
        CatalogModel("DeBERTa-v3-large", "~435M", "Encodeur pour classification et extraction de texte."),
        CatalogModel("Ettin-400M", "400M", "Encodeur de texte compact."),
        CatalogModel("BGE-M3", "~568M", "Embeddings multilingues pour retrouver des textes proches."),
        CatalogModel("BGE Small EN v1.5", "~33M", "Embeddings compacts pour recherche en anglais."),
        CatalogModel("Qwen3 Embedding 0.6B", "0.6B", "Transforme les textes en vecteurs de recherche sémantique."),
        CatalogModel("Qwen3 Reranker 0.6B", "0.6B", "Réordonne les résultats selon leur pertinence pour une requête."),
    ),
    "Audio": (
        CatalogModel("Kokoro-82M", "82M", "Synthèse vocale à partir de texte."),
        CatalogModel("Parakeet-TDT 0.6B", "0.6B", "Transcription automatique de la parole."),
        CatalogModel("PocketTTS", "100M", "Synthèse vocale légère."),
        CatalogModel("Phonon", "31M", "Modèle audio léger; tâche et moteur propres au paquet choisi."),
        CatalogModel("Silero VAD", "309K", "Détection des segments contenant de la parole."),
        CatalogModel("Whisper Tiny", "39M", "Reconnaissance et transcription de parole."),
        CatalogModel("Whisper Small", "~244M", "Transcription multilingue, plus lourd que Tiny."),
        CatalogModel("Magpie-TTS Multilingual", "357M", "Synthèse vocale multilingue."),
        CatalogModel("Nemotron 3 · diarization", "100M", "Diarisation : estimation des changements de locuteur."),
        CatalogModel("pyannote Community-1", "8.35M", "Diarisation et segmentation des locuteurs."),
    ),
}


def models_for_profile(profile: str) -> tuple[CatalogModel, ...]:
    """Renvoie les modèles Ollama actuellement compatibles avec le profil."""
    if profile in ("vision", "ocr"):
        category = "Vision"
    else:
        category = "Texte"
    models = [model for model in AI_CATALOG[category] if model.ollama_tag]
    if profile in ("vision", "ocr"):
        models.extend(
            model for model in AI_CATALOG["Texte"]
            if model.ollama_tag == "gemma4:e2b"
        )
    if profile == "light":
        light_tags = {"qwen3.5:0.8b", "gemma3:270m", "gemma3:1b", "llama3.2:1b", "smollm2:1.7b"}
        models = [model for model in models if model.ollama_tag in light_tags]
    return tuple(models)


def catalog_model_sizes() -> dict[str, str]:
    """Tailles estimées des téléchargements Ollama connus."""
    return {
        model.ollama_tag: model.download_size
        for models in AI_CATALOG.values()
        for model in models
        if model.ollama_tag and model.download_size
    }
