# `asl` pour Kotlin

Annoncer un service et retrouver un port, sans qu'aucun daemon ait de numéro de
port fixe.

```kotlin
import io.github.airdesktopproject.asl.*

Client.ouvrir(
    annuaires = listOf("203.0.113.7:6630" to "nitrogen.example"),
    racines = Files.readAllBytes(Path.of("/etc/asl/ca.pem")),
    identite = Identite(machine, graine),
).getOrThrow().use { client ->
    client.annoncer("depot", listOf(Point(Protocole.TCP, 8080))).getOrThrow()
    servirPourToujours()          // l'annonce se tient toute seule
}
```

Et du côté qui consomme :

```kotlin
client.ou(machine, "depot").getOrThrow().forEach { candidat ->
    println("$candidat ${candidat.verdict}")   // [2001:db8::1]:8080 EN_COURS
}
```

## Ce qu'il faut, et ce qui n'est pas couvert

**Un JDK 22 ou plus**, et `--enable-native-access` au lancement :

```sh
java --enable-native-access=ALL-UNNAMED -cp … MonDaemon
```

Sans ce drapeau, la JVM avertit aujourd'hui — « Restricted methods will be
blocked in a future release » — et refusera demain.

**ANDROID N'EST PAS COUVERT, ET NE PEUT PAS L'ÊTRE PAR CETTE LIAISON.** Android
n'a pas `java.lang.foreign`. L'y porter demanderait JNI, c'est-à-dire d'écrire et
de distribuer de la glu en C — exactement ce que la contrainte C4 de ce dépôt
refuse partout ailleurs. Un client Android passe par l'application du dépôt
`air-service-locator-android`, qui est un consommateur de l'annuaire et non un
daemon qui s'annonce.

## Pourquoi `java.lang.foreign` et non JNI, JNA ou JNR

**JNI demande d'écrire du C** : une glu native à compiler, à distribuer par
plate-forme, et à maintenir.

**JNA et JNR sont des dépendances**, et JNA embarque ses propres objets natifs.
Ce que cette bibliothèque tire, ses porteurs l'installent — c'est la même règle
que `ctypes` en Python et `fiddle` en Ruby, prise pour la même raison.

Le prix est réel et il est écrit ci-dessus : un JDK récent, un drapeau au
lancement, et pas d'Android.

## Ce qui tourne en arrière-plan

`annoncer` **rend la main tout de suite** : un annuaire injoignable ne doit pas
empêcher un daemon de démarrer. Le service écoute déjà pendant que l'annonce
cherche encore.

Ce qui la tient ensuite est **un fil natif**, à l'intérieur de la bibliothèque —
ni un `Thread`, ni un dispatcher de coroutine, et il n'entre jamais dans la JVM.
Il se reconnecte seul, bascule sur l'autre annuaire racine quand le premier
tombe, et n'abandonne jamais.

`client.etat()` dit où il en est. Le seul champ dont un humain doit être averti
est `abandonnee` : la tâche **ne renonce que sur une faute de configuration**,
jamais sur une panne de réseau.

**`enroler` et `ou` BLOQUENT** — jusqu'à vingt secondes. Ne les appelez pas depuis
un dispatcher destiné au calcul ; `Dispatchers.IO`, ou un fil à vous.

## Fermer le client retire l'annonce

La connexion **est** le bail : il n'y a pas de « retrait » séparé à appeler.
Laisser le client se faire ramasser retire donc l'annonce quand le
ramasse-miettes passe, c'est-à-dire à un moment que vous ne choisissez pas.

**Employez `use`.** Un `Cleaner` existe, mais c'est un filet, pas un moyen — et
`close()` et lui sont exclusifs l'un de l'autre, donc une double libération est
impossible.

## Les erreurs sont dans le type

Jamais un entier négatif rendu tel quel : les verbes rendent un `Result<T>`, donc
on ne peut pas en tirer une valeur sans avoir dit quoi faire de l'autre cas.
Toutes les fautes descendent de `AslErreur`.

| | |
|---|---|
| `MauvaisArgument` | Une adresse illisible, un port nul, une graine de mauvaise taille. |
| `Configuration` | Il manque un annuaire ou une racine. **Réessayer ne réparerait rien.** |
| `Injoignable` | Personne n'a répondu. Un câble débranché. |
| `Refuse` | L'annuaire a compris, et il a dit non. Un droit manquant. |
| `PasDIdentite` | Cette machine n'est pas enrôlée. |
| `Deja` | Ce client annonce déjà. |
| `Interne` | L'impossible, rattrapé — **la JVM n'a pas été tuée**. |
| `Ferme` | Ce client a été fermé. |

`Injoignable` et `Refuse` restent distincts parce qu'ils se corrigent à des
endroits opposés.

## Plusieurs fils

`Client` sérialise ses appels, **et c'est la seule des trois liaisons à verrou
dont la raison n'est pas « personne ne lit la documentation »**.

En C++, la phrase suffit : « objets distincts, sûr ; même objet, non sûr » y est
la convention de la bibliothèque standard. Sur la JVM, non — un objet rangé dans
un conteneur d'injection et appelé depuis un pool de fils est le cas **ordinaire**,
pas l'exception. Le verrou transforme donc un comportement indéfini en file
d'attente.

Le coût est réel : `etat()` attend pendant un `ou()` en cours, qui peut durer
vingt secondes.

## `Identite` n'est pas une `data class`

Une `data class` aurait imprimé la graine — le secret — au premier `log.debug`.
Son `toString` dit `graine=<32 octets>`, et un essai le vérifie.

## Le verdict a quatre valeurs, et il n'y a pas de `joignable`

`EN_COURS` n'affirme rien : l'annuaire répond avant d'avoir sondé, pour ne pas
faire attendre le démarrage d'un daemon. `NON_SONDE` dit qu'il ne mesurera pas —
UDP n'a pas de poignée de main, donc une sonde n'y distinguerait pas « écoute et
ignore » de « rien n'écoute ».

Une propriété `candidat.joignable` serait juste une fois sur deux, et ferait
écarter un candidat parfaitement bon.

## L'objet natif

Ce paquet est du Kotlin pur : il **cherche** `libasl_client_ffi.so`, il ne
l'embarque pas.

```sh
cargo build --release
export ASL_BIBLIOTHEQUE=$PWD/target/release/libasl_client_ffi.so
```

Cherché dans l'ordre : `ASL_BIBLIOTHEQUE`, puis chaque répertoire de
`java.library.path`, puis le chargeur du système. À défaut,
`BibliothequeIntrouvable` liste ce qui a été essayé — **une installation
incomplète n'est pas une panne d'exécution**.

## Les essais

```sh
./scripts/check-kotlin.sh
```

Ils lisent `crates/asl-client-ffi/include/asl.h` et comparent : constantes,
tailles, et **les décalages de chaque champ**. La JVM ne peut pas inclure un
en-tête C — C++ obtient cette conformité gratuitement, Kotlin doit la vérifier.

`build.gradle.kts` existe pour les porteurs et n'est **jamais exécuté par la CI de
ce dépôt** : une barrière qui téléchargerait une enveloppe Gradle ne serait pas
une barrière.
