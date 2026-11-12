# CAT.EXE — Phase 2 : fiabilité des sources

## Contrat normalisé

Les adaptateurs peuvent maintenant renvoyer `SourceResult` depuis
`catexe/modules/sources/results.py`. Chaque résultat contient :

- `source` et `url` ;
- `status` : `found`, `not_found`, `probable`, `blocked`, `rate_limited`, `error` ou `unknown` ;
- `confidence` : `high`, `medium`, `low` ou `none` ;
- `reason`, `checked_at`, `http_status` et `method`.

Un service bloqué (`403`) ou limité (`429`) n’est donc plus confondu avec un
compte absent. Les erreurs réseau sont également conservées comme erreurs.

## Compatibilité

Le vérificateur de pseudos utilise ce contrat, mais `SourceResult` reste
décomposable en `(statut français historique, code HTTP)` afin de préserver
le rendu et les rapports existants pendant la migration des modules.

## Règle d’interprétation

Une réponse positive issue d’un parseur HTTP non officiel est marquée avec une
confiance `medium`, une absence avec `low`, et un blocage ou une erreur avec
`none`. La confiance pourra être affinée par adaptateur dans les prochaines
étapes.
