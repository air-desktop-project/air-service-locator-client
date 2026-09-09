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
| **Les erreurs** | Traduites dans la forme du langage — une exception en Python et en Ruby, un `Result` en Kotlin, un code `[[nodiscard]]` en C++, un `throw` en Swift. Jamais un entier négatif rendu tel quel. |
| **La mémoire** | Rien de ce que la bibliothèque alloue n'est libéré par l'hôte. Chaque liaison enveloppe les pointeurs opaques dans le mécanisme de son langage. |
| **Le nommage** | Celui du langage d'accueil, pas celui de l'ABI. |
| **Le fil d'exécution** | La connexion est tenue et le keepalive tourne : une liaison doit dire clairement ce qui tourne en arrière-plan, et ce qu'il faut fermer. |

## État

**Les cinq sont écrites et éprouvées**, chacune avec sa barrière.

| | |
|---|---|
| [`python/`](python/) | Écrite, éprouvée, sans aucune dépendance. `scripts/check-python.sh`. |
| [`ruby/`](ruby/) | Écrite, éprouvée, sans aucune dépendance. `scripts/check-ruby.sh`. |
| [`cpp/`](cpp/) | Écrite, éprouvée. En-tête seul : elle INCLUT le contrat au lieu de le recopier. `scripts/check-cpp.sh`. |
| [`kotlin/`](kotlin/) | Écrite, éprouvée, sans aucune dépendance. **JVM seulement — pas Android.** `scripts/check-kotlin.sh`. |
| [`swift/`](swift/) | Écrite, éprouvée. Elle INCLUT le contrat, et le compilateur refuse de partager un client. `scripts/check-swift.sh`. |


`crates/asl-client-ffi` exporte onze fonctions, et `crates/asl-client-ffi/include/asl.h`
les déclare avec la RAISON de chacune — pourquoi `asl_client_neuf` n'ouvre aucune
connexion, pourquoi un verdict a quatre valeurs et non deux, pourquoi libérer le
client retire l'annonce.

Ce qui reste à faire, pour le langage restant, est ce que le tableau ci-dessus
exige : traduire les erreurs, envelopper le pointeur opaque,
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
Kotlin en pose un, mais pour une raison encore différente — sur la JVM, un objet
rangé dans un conteneur d'injection et appelé depuis un pool de fils est le cas
ORDINAIRE. Recopier la réponse de Python aurait été plus simple que de reposer la
question trois fois.

**Une troisième question s'est ajoutée : peut-on INCLURE le contrat ?** C++ le
peut, et n'a donc aucune conformité à vérifier — le compilateur est la barrière.
Les trois autres recopient `asl.h` et doivent comparer, chacune à sa façon :
`ctypes.Structure` en Python, `pack` en Ruby, `MemoryLayout` en Kotlin.

## La distribution du binaire natif

**UNE ARCHIVE POUR LES CINQ, ET NON CINQ FORMATS.** Une roue Python, une gemme,
un JAR, une archive C++ et un paquet SwiftPM porteraient le même objet et les
mêmes en-têtes ; les construire séparément multiplierait par cinq les occasions
de publier des versions qui ne correspondent pas.

```sh
./scripts/construire-natif.sh              # une archive pour cette plate-forme
./scripts/empaqueter-liaisons.sh distribution/asl-natif-*.tar.gz
```

L'archive porte l'objet partagé, la bibliothèque statique, `asl.h`, `asl.hpp` et
une carte de module **engendrée** — celle du dépôt pointe l'en-tête à son
emplacement de source, ce qui ne mène nulle part dans une archive. Ce qui est
dérivé ne peut pas diverger de ce dont il dérive.

Le `MANIFESTE` porte la version, la cible, le compilateur et une empreinte par
fichier. **Aucune date** : elle rendrait deux constructions du même code
différentes, donc invérifiables l'une par l'autre. Deux constructions successives
donnent bien le même octet quand `tar` est celui de GNU, et la ligne
`reproductible` le dit quand il ne l'est pas.

### Trois liaisons embarquent, deux lient

Python, Ruby et Kotlin **chargent** l'objet à l'exécution : il doit voyager avec
leur paquet. C++ et Swift **lient** à la construction : ils consomment l'archive,
en-têtes compris.

Kotlin est le seul cas particulier : **un JAR n'est pas un système de fichiers**,
donc l'objet y est une ressource qu'il faut extraire dans un fichier temporaire
avant que `SymbolLookup` puisse l'ouvrir. Le coût — un écrit et une ouverture au
premier appel, une fois par processus — est le prix d'un JAR autonome.

### `scripts/check-distribution.sh` est la seule barrière qui juge l'installation

Toutes les autres posent `ASL_BIBLIOTHEQUE` ou passent `-L target/debug` : elles
éprouvent les liaisons, jamais leur installation. Or c'est là que tout se joue
pour un porteur, qui n'aura ni variable d'environnement ni arbre de sources.

Celle-ci les **retire** de l'environnement et vérifie que les cinq marchent sur la
seule archive.

### macOS et Windows

`.github/workflows/natif.yml` construit et vérifie l'archive sur les trois
systèmes. Il **ne publie rien** : publier demande des secrets et une décision de
version, qui n'appartiennent pas à un déclencheur automatique.

## Ce qui n'est pas décidé

- **Un dépôt par liaison, ou tout ici ?** Les écosystèmes de paquets ont chacun
  leurs attentes — un `pyproject.toml` à la racine, un `.gemspec`, un
  `Package.swift`. Les empiler dans un seul dépôt les fait se marcher dessus ;
  les séparer multiplie les CI à tenir. Ce qui déclenchera la séparation est
  nommé dans chaque manifeste : le jour où il faudra publier par plate-forme.
- **Vers quels registres publier, et sous quelle identité.** PyPI, RubyGems,
  Maven Central et un registre SwiftPM n'ont ni les mêmes exigences de nommage,
  ni les mêmes secrets. L'archive existe ; ce qui la reçoit, non.
