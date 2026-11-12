# Recherche de pseudos

CAT.EXE normalise les caractères Unicode stylisés avant les interrogations
externes. Par exemple, `𝘊𝘢𝘵.𝘦𝘹𝘦` est recherché comme `Cat.exe`, ce qui évite que
certains sites réduisent les caractères stylisés à des points ou renvoient une
page générique considérée à tort comme un compte.

La recherche utilise l’identifiant exact quand l’API le permet. Une recherche
sur un nom partiel peut encore produire plusieurs comptes légitimes : vérifiez
la photo, la bio, les liens et l’identifiant interne avant de relier deux
comptes.

Un nom affiché comme `Cat.exe` peut être différent de l’identifiant
réel `cat.3xe`. Pour retrouver ce compte, recherchez l’identifiant exact quand
il est visible ; le catalogue de sites ne peut pas déduire de façon fiable une
transformation leetspeak entre les deux.
