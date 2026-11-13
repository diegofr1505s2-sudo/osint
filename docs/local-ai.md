# IA locale et catalogue des modèles

CAT.EXE utilise Ollama pour les profils de dialogue et d’analyse d’image actuellement intégrés. Le menu **Réglages → Catalogue IA par catégorie** présente les familles **Texte**, **Vision**, **Extraction** et **Audio**, une courte explication de leur rôle, les paramètres annoncés, le tag Ollama éventuel et une coche d’installation. Une coche indique qu’un modèle est présent sur cet ordinateur, pas qu’il a été sélectionné pour un profil.

Dans **Réglages → Profils IA à configurer**, tu choisis séparément le modèle pour Texte, Vision, IA légère, OCR, Cyber et Code. Seuls les tags marqués Ollama peuvent être choisis et téléchargés par ces profils. CAT.EXE demande confirmation avant de télécharger un modèle manquant. Les paramètres indiquent l’échelle du modèle; ils ne correspondent pas à la quantité de RAM ou d’espace disque requise.

## À quoi servent les catégories

- **Texte** : conversation, rédaction, résumés, explications et analyses. Les modèles plus petits répondent généralement plus vite, mais peuvent manquer de précision.
- **Vision** : comprend des images et répond en texte. CAT.EXE l’utilise pour certaines analyses visuelles et OCR. Une interprétation d’image reste une hypothèse; elle ne remplace pas les données EXIF ou une source vérifiable.
- **Extraction** : extrait/classifie des entités, transforme des textes en vecteurs de recherche (embeddings) ou reclasse des résultats. Ces modèles ne sont pas des chatbots.
- **Audio** : transcription de parole, synthèse vocale, détection d’activité vocale et diarisation (repérage des changements de locuteur).

Dans **Extracteur d’indices**, tu peux choisir un fichier image puis confirmer l’OCR local : le texte lu est aussi passé dans l’extracteur d’indices (emails, IP, IBAN, etc.). Ce parcours utilise le profil **OCR**, séparé du profil Vision employé pour interpréter une image ou estimer une géolocalisation.

Le reste du catalogue Extraction/Audio est informatif pour le moment : ces modèles nécessitent des bibliothèques et pipelines spécialisés que CAT.EXE ne lance pas encore. Ils sont donc marqués **Moteur séparé requis**, et ne sont pas présentés comme installés par Ollama.

## Compatibilité Ollama et tailles

La bibliothèque Ollama confirme des tags utilisables pour les familles Qwen 3.5, Gemma 3/4, Llama 3.2, SmolLM2, Phi-3.5 et GLM-4.7-Flash. Les petits tags de la liste, tels que `qwen3.5:0.8b`, `qwen3.5:2b`, `qwen3.5:4b`, `gemma3:270m`, `gemma3:1b`, `llama3.2:1b` et `smollm2:1.7b`, sont affichés dans la bonne catégorie avec une estimation de téléchargement. Qwen 3.5 accepte texte et image dans Ollama; Gemma 3 270M/1B est texte seulement, tandis que Gemma 3 4B prend aussi les images. [Qwen 3.5 dans Ollama](https://ollama.com/library/qwen3.5) [Gemma 3 dans Ollama](https://ollama.com/library/gemma3) [Llama 3.2 dans Ollama](https://ollama.com/library/llama3.2) [SmolLM2 dans Ollama](https://ollama.com/library/smollm2) [Phi-3.5 dans Ollama](https://ollama.com/library/phi3.5)

Gemma 4 E2B/E4B est présenté avec ses paramètres **effectifs** et une estimation de la taille téléchargée, qui est plus grande que le nombre de paramètres ne le laisse penser. La variante MiniCPM-V 4.7 1B de la liste n’a pas de tag Ollama vérifié; la bibliothèque Ollama référence plutôt MiniCPM-V 2.6 8B (`minicpm-v:8b`), qui est inclus comme option distincte. [Gemma 4 dans Ollama](https://ollama.com/library/gemma4) [MiniCPM-V dans Ollama](https://ollama.com/library/minicpm-v)

**Correction importante :** le tag Ollama `glm-4.7-flash` correspond à un modèle MoE 30B-A3B. La variante Q4_K_M affichée par Ollama fait environ **19 Go**, et non ~5,5 Go. Le catalogue signale cette différence pour éviter un téléchargement trop lourd inattendu. [GLM-4.7-Flash dans Ollama](https://ollama.com/library/glm-4.7-flash)

## Confidentialité et limites

Les profils Ollama fonctionnent sur le PC lorsque le serveur Ollama local est actif; CAT.EXE n’envoie pas leurs prompts à un service cloud. Ollama peut conserver des journaux selon sa propre configuration. Le téléchargement d’un modèle nécessite Internet et de l’espace disque. Vérifie les licences, les besoins matériels et l’origine des modèles avant leur utilisation.

Les résultats produits par un modèle sont indicatifs. Les valeurs déterministes ont priorité : EXIF réel, réponse d’API vérifiée, DNS et calculs géographiques ne sont pas remplacés par une hypothèse de modèle.
