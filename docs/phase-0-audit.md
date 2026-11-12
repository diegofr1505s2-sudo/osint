# CAT.EXE — Phase 0 : audit et préparation

## État de référence

- Dépôt : `osint_tool_code_cat.exe`
- Branche de travail : `phase-0-audit-preparation`
- Version applicative observée : `6.3`
- Point d’entrée : `main.py` ou `python -m catexe`
- Compatibilité annoncée : Python 3.11+
- Aucun appel réseau n’est effectué par le diagnostic.

## Commandes de vérification

Depuis la racine du dépôt :

```bash
python -m catexe.diagnostics
python -m catexe.diagnostics --json  # à utiliser avec l’option CLI si nécessaire
python -m py_compile main.py catexe/*.py catexe/modules/*.py catexe/modules/sources/*.py
```

Le diagnostic peut aussi être ouvert depuis le menu principal avec **CAT.EXE → Diagnostic système**.

## Catégorisation

### Obligatoire au démarrage

`Python >= 3.11`, `requests` et `rich`. Sans ces éléments, l’application ne peut pas démarrer correctement.

### Optionnel

`Pillow`, `pillow-heif`, `phonenumbers`, `numpy`, `pypdf` et `fpdf2`. Les fonctionnalités associées doivent rester désactivées ou signalées si un module manque.

### IA locale

`Ollama` et ses modèles locaux. Aucune installation ou téléchargement automatique n’est déclenché par la Phase 0.

### FFmpeg

`ffmpeg` et `ffprobe`, nécessaires aux analyses audio/vidéo avancées. Leur absence ne doit pas empêcher le démarrage général.

### Navigateur

`Playwright`, réservé aux fonctionnalités nécessitant un navigateur contrôlé. La Phase 0 ne lance aucun navigateur.

## Scripts de lancement

Les scripts `LANCER.bat`, `CREER_EXE.bat` et `lancer.sh` ont été conservés comme état de référence. Leur validation Windows complète devra être réalisée sur Windows en Phase 9 ; le sandbox Linux ne peut pas certifier l’exécution de `.bat`.

## Règles de sécurité de préparation

Les données runtime (`resultats/`, `cache/`, `config.json`) restent ignorées par Git. Aucun cookie, secret, token ou résultat personnel ne doit être ajouté au dépôt. Les phases ultérieures devront conserver cette séparation.
