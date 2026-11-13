# Recherche exacte et approximative

CAT.EXE utilise **Exact** par défaut. Dans les listes filtrables, le raccourci **F2** bascule entre `Exact` et `Approx`. Le graphe d’enquête et le catalogue cyber local disposent aussi de leur propre basculeur.

En mode Exact, la recherche de filtre est littérale : la casse et les accents sont significatifs. En mode Approx, elle ignore la casse et les accents et tolère une seule insertion, suppression, substitution ou transposition adjacente par mot. Pour limiter les faux positifs, la tolérance d’une modification s’applique aux mots d’au moins quatre caractères; tous les mots de la requête doivent correspondre.

Les identifiants structurés (IP, domaines, emails, IBAN, VIN, adresses et identifiants de plateforme) restent traités littéralement. Exception : quand l’utilisateur lance le module **Pseudos (95 sites)**, CAT.EXE recherche automatiquement un ensemble limité d’écritures équivalentes : casse, accents, caractères Unicode stylisés normalisés par NFKC, et séparateurs point/tiret/souligné. Cette expansion fait partie de la recherche de pseudo lancée explicitement et n’engendre pas de fautes arbitraires d’une lettre. Les autres variantes envoyées à des services externes nécessitent une confirmation pour la recherche concernée.

Après l’exécution d’un module qui a ajouté des résultats au rapport, CAT.EXE propose facultativement une analyse approfondie avec le modèle de texte Ollama configuré. Cette analyse est locale; elle distingue faits et hypothèses, signale les limites et suggère des pistes à vérifier sans lancer ces pistes automatiquement. Le menu Réglages affiche une coche si le modèle sélectionné est détecté dans l’inventaire Ollama local; le bouton d’actualisation relit cet inventaire.
