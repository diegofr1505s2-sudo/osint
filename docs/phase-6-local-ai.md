# CAT.EXE — Phase 6 : IA locales spécialisées

## Profils

`catexe/modules/ai_router.py` définit six profils Ollama locaux :

- `light` : extraction et réponses rapides ;
- `text` : synthèses et raisonnement général ;
- `vision` : images et GEOINT ;
- `ocr` : texte présent dans une image ;
- `cyber` : logs, configurations et analyse défensive ;
- `code` : Python, Bash, PowerShell et JavaScript.

Les tâches sont routées par `AI_TASKS` : `summary`, `vision`, `geoint`, `ocr`,
`cyber`, `code` et `metadata_explanation` choisissent automatiquement le
profil adapté. Un appel image force le profil vision.

## Installation contrôlée

Aucun modèle n’est téléchargé automatiquement. `ollama_setup()` conserve le
comportement existant : le modèle n’est installé qu’après demande explicite,
avec son nom et sa taille affichés.

Le menu Réglages permet de choisir séparément les modèles léger, OCR, cyber et
code, en plus des profils texte et vision existants.

## Règle de priorité

Les données déterministes restent prioritaires :

```text
EXIF réel > hypothèse IA
DNS réel > interprétation IA
validation IBAN > avis IA
réponse API officielle > résumé IA
```

L’IA locale est utilisée comme aide d’analyse et fonctionne sans clé ni envoi
vers un service distant.
