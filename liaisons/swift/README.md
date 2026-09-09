# `asl` pour Swift

Annoncer un service et retrouver un port, sans qu'aucun daemon ait de numéro de
port fixe.

```swift
import Asl

let client = try Client(
    annuaires: [("203.0.113.7:6630", "nitrogen.example")],
    racines: pem,
    identite: identite)

try client.annoncer(service: "depot", points: [try Point(.tcp, 8080)])
servirPourToujours()          // l'annonce se tient toute seule
```

Et du côté qui consomme :

```swift
for candidat in try client.ou(machine: machine, service: "depot") {
    print("\(candidat) \(candidat.verdict)")   // [2001:db8::1]:8080 enCours
}
```

## Elle n'a rien à transcrire

Python, Ruby et Kotlin doivent **recopier** `asl.h` — constantes, dispositions,
tailles — et une barrière existe de chaque côté pour comparer la copie à
l'original.

Swift, comme C++, sait **inclure** le contrat : `Sources/CAsl/module.modulemap`
pointe l'en-tête lui-même, pas une copie. Il n'y a donc pas de seconde source à
faire diverger, et pas de conformité à vérifier — une signature qui aurait bougé
ne compile pas.

## Le compilateur refuse le partage. Il n'y a pas de verrou

`Client` **ne conforme pas à `Sendable`**, délibérément. Sous le mode Swift 6, le
compilateur interdit alors de le partager entre domaines d'isolement — dans un
acteur, dans une variable globale, dans une fermeture que plusieurs tiennent.

C'est la quatrième réponse à la même question, et la seule qui ne coûte rien :

| | |
|---|---|
| Python, Ruby | un verrou, parce que personne n'y lit la phrase |
| Kotlin | un verrou, parce qu'un objet partagé entre fils y est le cas ordinaire |
| C++ | la phrase seule, parce que « objets distincts, sûr » y est universel |
| **Swift** | **le compilateur, parce qu'il sait le vérifier** |

**Le déplacement, lui, reste permis** — et c'est juste. L'isolement par régions
sait prouver qu'un client dont plus rien ne se sert peut partir ailleurs : ce
n'est pas un partage, et l'ABI ne l'interdit pas.

`essais/ne_compile_pas/PartageEntreTaches.swift` épingle ce refus, et la barrière
exige qu'il échoue.

## `deinit` est déterministe, et c'est la seule liaison où il l'est

Détruire le client retire l'annonce : la connexion **est** le bail, il n'y a pas
de « retrait » séparé à appeler.

Ruby et Kotlin ont besoin d'un finaliseur — un filet, qui s'exécute quand le
ramasse-miettes passe, c'est-à-dire à un moment qu'on ne choisit pas. **Ici le
comptage de références rend `deinit` déterministe** : la dernière référence qui
disparaît ferme, tout de suite. « Le laisser sortir de portée » est une réponse
juste, et un essai le vérifie avec une référence faible.

`fermer()` existe pour rendre l'instant explicite, et il est idempotent.

## Les fautes sont levées, pas rendues

`liaisons/README.md` prescrivait un `Result` pour Swift comme pour Kotlin. **Ce
n'est plus la forme du langage** : depuis Swift 5.5 et l'arrivée d'`async`/`await`,
`Result` est un adaptateur pour les API à rappel, et `throws` est l'idiome.

L'intention de la table est tenue — jamais un entier négatif rendu tel quel, et
une faute qu'on ne peut pas ignorer : le compilateur exige un `try` sur chaque
appel. C'est le pendant de `[[nodiscard]]` en C++.

Qui veut un `Result` l'obtient en une ligne : `Result { try client.etat() }`.

| | |
|---|---|
| `.argument` | Une adresse illisible, un port nul, une graine de mauvaise taille. |
| `.configuration` | Il manque un annuaire ou une racine. **Réessayer ne réparerait rien.** |
| `.injoignable` | Personne n'a répondu. Un câble débranché. |
| `.refuse` | L'annuaire a compris, et il a dit non. Un droit manquant. |
| `.pasDIdentite` | Cette machine n'est pas enrôlée. |
| `.deja` | Ce client annonce déjà. |
| `.interne` | L'impossible, rattrapé — **le processus n'a pas été tué**. |
| `.ferme` | Ce client a été fermé. **Seule faute qui ne vient pas de l'ABI.** |

## Ce qui tourne en arrière-plan

`annoncer` **rend la main tout de suite** : un annuaire injoignable ne doit pas
empêcher un daemon de démarrer. Ce qui tient l'annonce ensuite est un fil natif —
ni une `Task`, ni un fil du pool coopératif, et il n'entre jamais dans le moteur
Swift. Il se reconnecte seul, bascule sur l'autre annuaire racine quand le premier
tombe, et n'abandonne jamais.

**`enroler` et `ou` BLOQUENT** — jusqu'à vingt secondes. Ne les appelez pas depuis
le pool coopératif : un fil bloqué là-bas ne se remplace pas. Un fil à vous, ou
`DispatchQueue.global()`.

## Construire

```sh
cargo build --release
swift build -Xlinker -L$PWD/../../target/release
```

`Package.swift` **ne cherche pas l'objet natif** : son emplacement dépend du
déploiement, et le deviner ferait échouer de façon obscure chez tous ceux qui ont
une autre arborescence. La carte de module contient `link "asl_client_ffi"`, donc
il n'y a que le répertoire à indiquer.

Sans SwiftPM, directement :

```sh
swiftc -swift-version 6 -I liaisons/swift/Sources/CAsl \
       -L target/release mon_daemon.swift -o mon_daemon
```

## Le verdict a quatre valeurs, et il n'y a pas de `joignable`

`enCours` n'affirme rien : l'annuaire répond avant d'avoir sondé, pour ne pas
faire attendre le démarrage d'un daemon. `nonSonde` dit qu'il ne mesurera pas —
UDP n'a pas de poignée de main, donc une sonde n'y distinguerait pas « écoute et
ignore » de « rien n'écoute ».

Une propriété `candidat.joignable` serait juste une fois sur deux, et ferait
écarter un candidat parfaitement bon.

## `Identite` cache sa graine

La description par défaut d'une `struct` aurait imprimé le secret au premier
`print(identite)`. Elle dit `graine: <32 octets>`, et un essai le vérifie.

## Les essais

```sh
./scripts/check-swift.sh
```

Ils compilent la bibliothèque **seule** d'abord — si elle ne compilait
qu'accompagnée de ses essais, un porteur le découvrirait et pas nous —, avec
`-warnings-as-errors`, exécutent cinquante-huit vérifications, exigent que le
fichier `ne_compile_pas/` refuse, et passent `swift format lint`.

Le contrôle de forme est ici et nulle part ailleurs : `swift format` est dans la
chaîne d'outils, comme `cargo fmt`. `ruff`, `rubocop` et `ktlint` sont des
installations séparées, et les imposer ferait de leur présence une condition pour
construire ce dépôt.
