# CAT.EXE — Phase 5 : confidentialité et secrets

## Stockage

Les jetons et clés API ne sont plus conservés dans `config.json`.
`SecretStore` les place dans `secrets.json`, avec permissions `0600` lorsque le
système le permet. Les variables `CATEXE_SECRET_*` ont priorité pour les
installations automatisées.

Les anciennes valeurs présentes dans `config.json` sont migrées au premier
chargement, puis retirées de la configuration générale. Le fichier de
configuration ne conserve que les préférences d’interface et d’exécution.

## Rapports

`add_report()` redige les valeurs connues du coffre avant de les transmettre au
rapport et au graphe. Les secrets ne doivent donc pas apparaître dans les
exports générés par CAT.EXE.

## Limites

`secrets.json` reste un fichier local protégé par les permissions du système ;
ce n’est pas un coffre matériel ni une garantie contre un compte administrateur
ou un malware local. Pour un environnement de production, utiliser de
préférence les variables d’environnement ou le gestionnaire de secrets du
système d’exploitation.
