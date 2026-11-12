# CAT.EXE OSINT · GEOINT   (https://github.com/diegofr1505s2-sudo/osint)

CAT.EXE est un outil local d’audit OSINT/GEOINT en ligne de commande, écrit en Python 3.11+. Il regroupe des modules d’analyse de données publiques, à utiliser sur soi-même ou sur des cibles autorisées.

## Usage légal et confidentialité

Utilisez CAT.EXE uniquement sur vos propres données ou avec une autorisation explicite. Ne l’utilisez pas pour surveiller, harceler ou identifier une personne sans son accord.

Les résultats sont enregistrés localement dans `resultats/`. Les tokens et clés API sont conservés séparément dans `secrets.json`, ignoré par Git. Les secrets sont caviardés des rapports et ne sont pas envoyés à l’auteur. Les cookies doivent être traités comme des mots de passe et ne doivent jamais être partagés.

## Installation depuis les sources

### Windows

```powershell
py -3.11 -m pip install -r requirements.txt
py -3.11 main.py
```

Vous pouvez aussi lancer `LANCER.bat`. Le script recherche Python 3.11+, installe les dépendances et lance CAT.EXE.

### Linux et macOS

```bash
python3 -m pip install -r requirements.txt
python3 main.py
```

## Diagnostic système

Le diagnostic local vérifie Python, les dépendances, Ollama, FFmpeg et Playwright sans envoyer de données :

```bash
python -m catexe --diagnostic
python -m catexe --diagnostic --json
```

Le même contrôle est accessible depuis **CAT.EXE → Diagnostic système**.

## Build Windows autonome

Depuis un poste Windows connecté à Internet :

```text
CREER_EXE.bat
```

Le script utilise `CatExe.spec`, installe PyInstaller si nécessaire et produit :

```text
CatExe-OSINT/
├── CatExe-OSINT.exe
├── data/
├── lang/
├── resultats/
└── cache/
```

Le binaire est console, autonome vis-à-vis de Python et ne contient pas de configuration personnelle. Vérifiez l’empreinte SHA256 d’une release avec :

```powershell
certutil -hashfile CatExe-OSINT.exe SHA256
```

Les programmes Python compilés peuvent être signalés à tort par certains antivirus. Vérifiez le dépôt, la release et l’empreinte avant toute autorisation.

## Fonctionnalités principales

- audit de pseudos, e-mails, domaines et IP ;
- analyse de métadonnées et GPS EXIF ;
- hypothèses de géolocalisation avec limites explicites ;
- validation locale IBAN/VIN ;
- rapports HTML/PDF et graphe d’enquête ;
- profils IA locaux texte, légère, vision, OCR, cyber et code ;
- catalogue cyber local avec filtres, risques et sources ;
- stockage local des secrets avec caviardage des exports.

## Tests et qualité

Les outils de développement sont déclarés dans `requirements-dev.txt` :

```bash
python -m pip install -r requirements-dev.txt
python -m py_compile main.py catexe/*.py catexe/modules/*.py tests/*.py
pytest
ruff check .
```

`app.py` et l’ancien composant UI restent temporairement exclus du lint ruff pendant leur extraction progressive, mais restent compilés et couverts par les tests d’intégration.

## Structure

```text
main.py                         # point d’entrée
catexe/app.py                   # orchestration historique
catexe/modules/                 # composants extraits et testables
data/cyber_tools.json           # catalogue cyber local
lang/                           # traductions intégrées
cookies/incoming/               # espace local réservé aux imports autorisés
resultats/                      # rapports locaux ignorés par Git
cache/                          # cache local ignoré par Git
docs/                           # documentation des limites et phases
tests/                          # tests unitaires locaux
```

Voir également :

- [`docs/metadata.md`](docs/metadata.md)
- [`docs/local-ai.md`](docs/local-ai.md)
- [`docs/cyber-catalog.md`](docs/cyber-catalog.md)
- [`docs/pseudo-search.md`](docs/pseudo-search.md)
- [`docs/troubleshooting.md`](docs/troubleshooting.md)
- [`cookies/README.md`](cookies/README.md)

## Licence

MIT, voir [`LICENSE`](LICENSE).
