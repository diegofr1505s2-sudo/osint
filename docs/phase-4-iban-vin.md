# CAT.EXE — Phase 4 : validation IBAN et VIN

## IBAN

`financial_identifiers.validate_iban()` sépare désormais :

- normalisation des espaces et de la casse ;
- pays et longueur attendue ;
- clé de contrôle modulo 97 ;
- cohérence structurelle complète ;
- code banque français et nom connu quand disponible.

L’API bancaire externe reste un enrichissement facultatif. Une réponse de
l’API ne prouve jamais que le compte appartient à une personne ou à une
entreprise.

## VIN

`decode_vin()` distingue :

- format de 17 caractères et exclusion de I, O et Q ;
- constructeur WMI connu ou inconnu ;
- région de fabrication ;
- année-modèle potentiellement cyclique ;
- contrôle de chiffre VIN pour les formats où il est applicable ;
- numéro de série.

La base NHTSA demeure une source externe partielle, particulièrement pour les
véhicules non destinés au marché américain. Pour un véhicule français,
HistoVec et les documents du propriétaire restent nécessaires pour l’historique.
