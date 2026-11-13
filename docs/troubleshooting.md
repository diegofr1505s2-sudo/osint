# Dépannage

## Python introuvable sous Windows

Installez Python 3.11 ou une version plus récente depuis python.org, en
activant le lanceur Python, puis relancez `LANCER.bat`. Le script vérifie
également les installations utilisateur et `python` présent dans le PATH.

## Dépendance manquante

Depuis la racine du dépôt :

```powershell
py -3.11 -m pip install -r requirements.txt
py -3.11 -m catexe --diagnostic
```

Le diagnostic indique les modules et outils optionnels manquants sans envoyer
de données.

## Ollama indisponible

L’application reste utilisable sans IA locale. Installez Ollama séparément,
lancez-le, puis consultez `Réglages → Catalogue IA par catégorie` et choisissez
un modèle dans `Réglages → Profils IA à configurer`. Aucun modèle lourd n’est
téléchargé sans confirmation.

## Build EXE

Lancez `CREER_EXE.bat` depuis Windows. Le script installe PyInstaller,
construit `CatExe-OSINT.exe` selon `CatExe.spec`, puis copie `lang/`, `data/`,
`resultats/` et `cache/` dans `CatExe-OSINT/`.

Si un antivirus signale le binaire PyInstaller, vérifiez la source, la release
et l’empreinte SHA256 avant de l’autoriser. Ne téléchargez pas un exécutable
provenant d’une source inconnue.
