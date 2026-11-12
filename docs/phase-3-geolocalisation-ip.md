# CAT.EXE — Phase 3 : géolocalisation et IP

## Géolocalisation d’image

Les résultats peuvent maintenant être représentés par des `GeoHypothesis` :

- source (`exif`, `geoclip`, `vision`, etc.) ;
- coordonnées ;
- probabilité éventuelle ;
- indices ;
- rayon d’incertitude ;
- confiance (`high`, `medium`, `low`).

Le GPS EXIF est présenté comme une position de l’appareil, tandis que les
sorties GeoCLIP et vision sont explicitement des estimations non confirmées.
Les hypothèses restent multiples et sont classées sans être transformées en
adresse exacte.

## Attribution IP

Les réponses ipwho.is et ip-api sont comparées pour afficher :

- pays et ville estimés ;
- accord entre les sources ;
- précision (`pays estimé` ou `ville estimée`) ;
- opérateur réseau ;
- avertissement indiquant qu’une IP ne permet pas de déduire la position d’une personne.

Les coordonnées IP restent approximatives et correspondent au réseau ou à
l’opérateur, pas à un domicile ou à un utilisateur précis.
