# CAT.EXE — Phase 8 : refactorisation et tests

## Découpage réalisé

Les primitives de métadonnées image ont été extraites de `catexe/app.py` vers
[`catexe/modules/metadata.py`](../catexe/modules/metadata.py) : conversion
GPS DMS, points cardinaux et lecture EXIF. Le contrat historique est conservé
par `read_exif()` : image redressée, dictionnaire lisible, GPS optionnel et
informations caméra.

Ce premier découpage prépare l’extraction progressive des domaines social,
e-mail, réseau, métadonnées, cookies, business, crypto et apprentissage sans
réécrire les fonctionnalités dans un seul changement massif.

## Contrôles

Les outils de développement sont déclarés dans `requirements-dev.txt`.
`pyproject.toml` configure :

```text
python -m py_compile ...
pytest
ruff check .
```

Le monolithe historique `catexe/app.py` et le composant UI hérité
`catexe/modules/ui.py` sont temporairement exclus du lint global. Ils restent
compilés et couverts par les tests d’intégration ; les nouveaux modules
extraits et les tests sont, eux, contrôlés par ruff dès leur création. Cette
exclusion sera réduite à mesure que les domaines seront déplacés vers
`catexe/modules/`.

Les tests restent locaux et déterministes. Les appels réseau, IA et outils
externes ne sont pas nécessaires pour vérifier les primitives extraites.
