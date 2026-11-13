# GEOINT : ligne de vue et triangulation

CAT.EXE propose deux outils dans **Distance · horizon**.

## Ligne de vue avec relief

L’outil échantillonne le grand cercle entre deux coordonnées, récupère les altitudes de Copernicus DEM GLO-90 via l’API Elevation d’Open-Meteo, puis compare le profil du terrain à la ligne de visée. Le modèle utilise un coefficient de réfraction atmosphérique conventionnel de 0,13 et les hauteurs de l’observateur et de la cible saisies par l’utilisateur.

Avant l’appel réseau, CAT.EXE indique le nombre d’échantillons et demande une confirmation. Les coordonnées sont transmises à Open-Meteo uniquement après accord. Le service annonce une résolution nominale de 90 m; ce calcul ne représente pas les bâtiments, la végétation, les murs ni les obstacles plus petits que cette résolution. Les erreurs du DEM ou des coordonnées peuvent modifier le verdict. Une altitude manquante donne **Indéterminé**, jamais « dégagé ».

Les résultats et les exports attribuent la source à Open-Meteo et au Copernicus DEM. Pour les détails d’API et d’attribution, voir [la documentation officielle Open-Meteo Elevation API](https://open-meteo.com/en/docs/elevation-api).

## Triangulation par relèvements

La triangulation utilise au moins deux coordonnées connues et leurs azimuts vers la cible, en degrés dans le sens horaire depuis le nord vrai. Le calcul est local et n’envoie pas ces données à un service tiers. Il ajuste l’intersection dans un plan local, puis affiche le résidu moyen, l’angle de croisement minimal et une incertitude indicative calculée à partir de l’erreur angulaire que l’utilisateur fournit.

Ce résultat n’est pas une précision statistique ni une identité confirmée. Des lignes presque parallèles sont refusées; les relèvements qui pointent à l’opposé de l’estimation et les résidus élevés sont signalés. L’azimut magnétique doit être corrigé de la déclinaison locale avant saisie. Le modèle plan est destiné à une zone locale, pas à des points séparés par des distances continentales.
