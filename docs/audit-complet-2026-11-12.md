# Rapport technique — audit complet CAT.EXE

**Date de l’audit :** 12 novembre 2026
**Branche auditée :** `main`
**Commit audité :** `8656c4b` — `docs: finalize v7 features and Windows build`
**Résultat global :** **SUCCÈS — 0 échec automatisé**

## Synthèse

L’audit a vérifié la compilation Python, la suite pytest, le lint ruff, les deux points d’entrée CLI, le diagnostic texte et JSON, les imports d’intégration, le catalogue cyber, le routeur IA, le module de métadonnées, la protection des fichiers runtime et la spécification PyInstaller.

Toutes les vérifications automatisées sont passées. La suite comporte **29 tests réussis**. Le smoke build PyInstaller a produit un binaire Linux à partir de `CatExe.spec`, puis les artefacts temporaires ont été supprimés. La génération d’un véritable `.exe` Windows n’a pas été exécutée dans ce sandbox Linux ; elle reste couverte par `CREER_EXE.bat` et devra être validée sur un poste Windows.

## Matrice des contrôles

| Contrôle | Commande ou périmètre | Résultat |
|---|---|---|
| État Git | `git status`, branche `main` | OK, arbre propre avant audit |
| Format du diff | `git diff --check` | OK |
| Version Python | Python 3.12.3 | OK, compatible avec la cible Python 3.11+ |
| Compilation | `python3 -m py_compile` sur l’application, modules et tests | OK, 31 fichiers vérifiés par le diagnostic |
| Tests | `pytest` | OK, 29 passed |
| Qualité | `ruff check .` | OK |
| Diagnostic texte | `python3 -m catexe.diagnostics` | OK |
| Diagnostic JSON | `python3 -m catexe.diagnostics --json` | OK, 14 contrôles |
| Point d’entrée racine | `python3 main.py --diagnostic` | OK |
| Point d’entrée package | `python3 -m catexe --diagnostic --json` | OK |
| Imports intégrés | application, menu, catalogue, IA, métadonnées | OK |
| JSON | `data/cyber_tools.json`, `config.example.json` | OK |
| Protection runtime | `config.json`, `secrets.json`, règles Git | OK |
| Scripts Windows | contrôles statiques de `LANCER.bat` et `CREER_EXE.bat` | OK |
| Spec PyInstaller | `CatExe.spec` | OK |
| Smoke build | PyInstaller sous Linux | OK |

## Résultats détaillés

### Compilation et tests

La compilation de tous les fichiers Python suivis du projet passe sans erreur. Pytest rapporte :

```text
29 passed in 0.33s
```

Les tests couvrent notamment :

- utilitaires purs et configuration d’interface ;
- diagnostic système ;
- résultats normalisés des sources ;
- géolocalisation et attribution IP ;
- validation IBAN/VIN ;
- coffre local de secrets et caviardage ;
- routeur IA local ;
- catalogue cyber et filtres ;
- extraction de métadonnées EXIF ;
- scripts Windows, spec PyInstaller et absence de secrets dans l’exemple de configuration.

Ruff termine avec :

```text
All checks passed!
```

Le monolithe historique `catexe/app.py` et le composant UI hérité restent temporairement exclus du lint global, conformément à `docs/phase-8-refactorisation-tests.md`. Ils sont cependant compilés et couverts par les tests et les imports d’intégration.

### Diagnostic système

Le diagnostic a détecté 14 éléments :

- Python : OK — 3.12.3 ;
- compilation Python : OK — 31 fichiers ;
- Requests, Rich, Pillow, HEIC/HEIF, Numéros, NumPy : OK ;
- pypdf et fpdf2 : OK ;
- Playwright : OK ;
- FFmpeg et FFprobe : OK ;
- Ollama : absent.

L’absence d’Ollama est un état optionnel attendu, pas un échec de CAT.EXE. L’application reste utilisable sans IA locale ; les fonctions IA affichent une indisponibilité explicite et ne requièrent pas de service distant.

Les sorties texte et JSON sont cohérentes depuis les deux points d’entrée : `main.py` et `python -m catexe`.

### Intégration des modules

L’import réel de `catexe.app` a été vérifié avec :

- le menu principal et `mod_cyber_catalog` ;
- les 21 entrées du catalogue cyber ;
- les six profils du routeur IA ;
- le module de métadonnées et ses points cardinaux.

Aucun appel réseau, modèle IA ou outil cyber n’a été nécessaire pour cette vérification d’import.

### Build et distribution Windows

Les contrôles statiques confirment que :

- `LANCER.bat` et `CREER_EXE.bat` utilisent bien `py -3.11` ;
- l’ancien appel erroné `-3.14` a disparu ;
- les erreurs d’installation et de build sont contrôlées ;
- `CREER_EXE.bat` utilise `CatExe.spec` ;
- `lang/` et `data/` sont copiés dans la distribution ;
- `resultats/` et `cache/` sont créés à côté du binaire ;
- `config.json` et `secrets.json` ne sont pas embarqués.

Le smoke build PyInstaller local a créé `dist/CatExe-OSINT`, puis `build/` et `dist/` ont été supprimés. Comme l’environnement d’audit est Linux, ce résultat valide la spec et le graphe de dépendances, mais ne remplace pas un build et un lancement sur Windows.

### Confidentialité et fichiers runtime

Les contrôles confirment que :

- `config.json` est ignoré par Git ;
- `secrets.json` est ignoré par Git ;
- aucun de ces fichiers n’existe dans l’arbre audité ;
- `config.example.json` ne contient ni secret ni dictionnaire de clés ;
- la spec PyInstaller ne référence pas `secrets.json`.

## Limites de l’audit

L’audit n’a pas testé les services externes en conditions réelles : APIs publiques, DNS, services sociaux, urlscan, registres et Tor. Ces dépendances peuvent être indisponibles, limitées ou modifier leur interface indépendamment du code local.

L’audit n’a pas lancé Ollama ni téléchargé de modèle IA. Les tests vérifient le routage, la configuration et les messages d’indisponibilité, pas la qualité sémantique des réponses produites par chaque modèle.

L’audit n’a pas produit de `.exe` Windows depuis le sandbox Linux. Une validation finale sur Windows doit lancer `CREER_EXE.bat`, démarrer `CatExe-OSINT.exe`, exécuter `CatExe-OSINT.exe --diagnostic` si le build le permet, vérifier l’accès à `data/` et `lang/`, puis calculer l’empreinte SHA256.

## Conclusion

Le code généré est cohérent, compilable et validé par 29 tests automatisés. Les deux points d’entrée CLI, le diagnostic JSON, le catalogue, le routeur IA, les métadonnées et la chaîne PyInstaller répondent aux contrôles prévus. Le seul état dégradé détecté est l’absence volontaire d’Ollama, qui correspond à une dépendance optionnelle. La prochaine vérification utile est un build réel et un lancement de l’exécutable sur Windows.

## Reproduction de l’audit

Depuis la racine du projet :

```bash
python3 -m py_compile main.py catexe/*.py catexe/modules/*.py catexe/modules/sources/*.py tests/*.py
pytest
ruff check .
python3 -m catexe --diagnostic
python3 -m catexe --diagnostic --json
python3 -m PyInstaller --noconfirm --clean CatExe.spec
```

Le build PyInstaller doit être lancé dans un environnement où PyInstaller est installé. Sous Windows, utiliser de préférence `CREER_EXE.bat`.
