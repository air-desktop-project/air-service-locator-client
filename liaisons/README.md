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

**L'ABI est là. Python l'est. Les quatre autres, non.**

| | |
|---|---|
| [`python/`](python/) | Écrite, éprouvée, sans aucune dépendance. `scripts/check-python.sh`. |
| [`ruby/`](ruby/) | Écrite, éprouvée, sans aucune dépendance. `scripts/check-ruby.sh`. |
| [`cpp/`](cpp/) | Écrite, éprouvée. En-tête seul : elle INCLUT le contrat au lieu de le recopier. `scripts/check-cpp.sh`. |
| `kotlin/` | Rien. |
| `swift/` | Rien. |


`crates/asl-client-ffi` exporte onze fonctions, et `crates/asl-client-ffi/include/asl.h`
les déclare avec la RAISON de chacune — pourquoi `asl_client_neuf` n'ouvre aucune
connexion, pourquoi un verdict a quatre valeurs et non deux, pourquoi libérer le
client retire l'annonce.

Ce qui reste à faire, pour chacun des deux langages restants, est ce que le
tableau ci-dessus exige : traduire les erreurs, envelopper le pointeur opaque,
renommer, et DIRE ce qui tourne en arrière-plan.

**Commencez par l'en-tête, et non par ce fichier-ci** : il est le contrat, et il
est écrit à la main pour cette raison. Puis regardez `python/` et `ruby/`, qui ont
déjà tranché les mêmes questions — notamment les deux qu'aucun en-tête ne pose :

**Une liaison doit faire respecter ce que l'ABI se contente de dire.** Un client
ne se partage pas entre fils ; en C c'est un commentaire, en Python et en Ruby
c'est un verrou, parce que personne ne lit le commentaire.

**Une liaison doit rendre le contrôle à son hôte pendant qu'elle attend.** Vingt
secondes d'attente réseau, ce sont vingt secondes pendant lesquelles
l'application qui nous embarque doit continuer de servir. En Python c'est `CDLL`
plutôt que `PyDLL` ; en Ruby, `need_gvl: false` ; en C++ la question ne se pose
pas, et `cpp/README.md` le dit quand même — parce qu'un lecteur venu de Python la
cherchera.

**Et les réponses diffèrent d'un langage à l'autre.** C++ ne pose PAS de verrou
là où Python et Ruby en posent un : la convention « objets distincts, sûr ; même
objet, non sûr » y est universelle, et un verrou rendrait `Client` non déplaçable.
Recopier la réponse de Python aurait été plus simple que de reposer la question.

## Ce qui n'est pas décidé

- **Un dépôt par liaison, ou tout ici ?** Les écosystèmes de paquets ont chacun
  leurs attentes — un `pyproject.toml` à la racine, un `.gemspec`, un
  `Package.swift`. Les empiler dans un seul dépôt les fait se marcher dessus ;
  les séparer multiplie les CI à tenir.
- **Comment le binaire natif est distribué.** Une roue Python par plate-forme et
  par architecture, c'est vite huit artefacts à construire à chaque version.
- **Qui construit pour macOS et Windows**, que la CI Linux ne couvre pas.
