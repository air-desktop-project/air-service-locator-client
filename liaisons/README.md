# Les liaisons

Python, Ruby, C++, Kotlin, Swift. **Toutes passent par l'ABI C** exposée par
`crates/asl-client-ffi`, et aucune ne parle à Rust directement.

## Pourquoi une seule porte

Aucun de ces cinq langages ne sait appeler du Rust ; tous savent appeler du C.
Écrire cinq passages natifs reviendrait à maintenir cinq fois la même logique de
conversion — et c'est la copie qu'on oublie qui finit par diverger.

Le prix est réel : l'ABI C est un plus petit dénominateur commun, et chaque
liaison doit rehabiller ce qu'elle reçoit pour ressembler à son langage. Un
utilisateur Python attend une exception, pas un code de retour négatif.

## Ce que chaque liaison doit rendre, et qui n'est pas négociable

| | |
|---|---|
| **Les erreurs** | Traduites dans la forme du langage — une exception en Python et en Ruby, un `Result` en Swift et en Kotlin, un code en C++. Jamais un entier négatif rendu tel quel. |
| **La mémoire** | Rien de ce que la bibliothèque alloue n'est libéré par l'hôte. Chaque liaison enveloppe les pointeurs opaques dans le mécanisme de son langage. |
| **Le nommage** | Celui du langage d'accueil, pas celui de l'ABI. |
| **Le fil d'exécution** | La connexion est tenue et le keepalive tourne : une liaison doit dire clairement ce qui tourne en arrière-plan, et ce qu'il faut fermer. |

## État

**Rien n'est écrit.** `asl-client` n'expose encore aucune fonction, et une
liaison vers une surface vide ne se vérifierait pas.

## Ce qui n'est pas décidé

- **Un dépôt par liaison, ou tout ici ?** Les écosystèmes de paquets ont chacun
  leurs attentes — un `pyproject.toml` à la racine, un `.gemspec`, un
  `Package.swift`. Les empiler dans un seul dépôt les fait se marcher dessus ;
  les séparer multiplie les CI à tenir.
- **Comment le binaire natif est distribué.** Une roue Python par plate-forme et
  par architecture, c'est vite huit artefacts à construire à chaque version.
- **Qui construit pour macOS et Windows**, que la CI Linux ne couvre pas.
