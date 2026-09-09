# `asl` pour C++

Annoncer un service et retrouver un port, sans qu'aucun daemon ait de numéro de
port fixe.

```cpp
#include <asl.hpp>

asl::Client client;
if (asl::Client::ouvrir(client) != asl::Faute::Ok) { /* … */ }

if (auto f = client.ajouter_annuaire("203.0.113.7:6630", "nitrogen.example");
    f != asl::Faute::Ok) {
    std::fprintf(stderr, "%s\n", asl::message(f));
    return 1;
}
(void)client.poser_racines(pem);
(void)client.poser_identite(identite);

if (auto f = client.annoncer("depot", {{asl::Protocole::Tcp, 8080}});
    f != asl::Faute::Ok) { /* … */ }

servir_pour_toujours();   // l'annonce se tient toute seule
```

Et du côté qui consomme :

```cpp
std::vector<asl::Candidat> candidats;
if (client.ou(machine, "depot", candidats) == asl::Faute::Ok) {
    for (const auto& c : candidats) {
        std::printf("%s\n", c.texte().c_str());   // [2001:0db8:…:0001]:8080
    }
}
```

## Elle ne transcrit rien, et c'est sa particularité

Python et Ruby doivent **recopier** `asl.h` — constantes, dispositions, tailles —
et une barrière entière existe de chaque côté pour comparer la copie à
l'original.

C++ est le seul des cinq qui puisse **inclure** le contrat. Il n'y a donc pas de
seconde source à faire diverger, pas de conformité à vérifier à l'exécution : le
compilateur est la barrière, et `static_assert` remplace les essais que les deux
autres doivent écrire.

C'est aussi la première fois que `asl.h` est **compilé** : il se dit un en-tête C
depuis qu'il existe, et Python comme Ruby ne font que le lire avec des
expressions régulières. `scripts/check-cpp.sh` le compile en C99, C11 et C17.

## Elle ne lève jamais

Beaucoup de bases C++ se construisent avec `-fno-exceptions` — jeux, audio,
embarqué, moteurs de rendu. Une bibliothèque qui imposerait les exceptions à son
hôte commettrait exactement la faute que ce produit refuse partout ailleurs :
décider à la place de qui l'embarque.

Les fautes sortent donc en `enum class Faute`, et **chaque fonction qui en rend
une est `[[nodiscard]]`**. C'est ce qui remplace l'exception : en Python un code
de retour oublié est invisible, ici le compilateur le dit.

Un essai garde cette annotation — `essais/ne_compile_pas/faute_ignoree.cpp`
**doit échouer à compiler**, et la barrière l'exige.

## Sur les fils : objets distincts, sûr ; même objet, non sûr

C'est la convention de la bibliothèque standard, et tout le monde en C++ la
connaît.

Les liaisons Python et Ruby posent un verrou parce que, là-bas, personne ne lit
cette phrase — et parce que deux appels concurrents aliaseraient un `&mut` du côté
Rust, ce qui est un comportement indéfini et non un ralentissement. Ici la phrase
suffit : un verrou rendrait `Client` non déplaçable, ou coûterait une allocation
pour un `std::mutex` dont l'immense majorité des porteurs n'ont aucun besoin.

**Et la question du GVL ne se pose pas** — il n'y en a pas. Elle est nommée ici
parce qu'un lecteur venu de la liaison Python la cherchera.

## Ce qui tourne en arrière-plan

`annoncer` **rend la main tout de suite** : un annuaire injoignable ne doit pas
empêcher un daemon de démarrer. Ce qui tient l'annonce ensuite est un fil natif,
à l'intérieur de la bibliothèque — il se reconnecte seul, bascule sur l'autre
annuaire racine quand le premier tombe, et n'abandonne jamais.

`client.etat(etat)` dit où il en est. Le seul champ dont un humain doit être
averti est `abandonnee` : la tâche **ne renonce que sur une faute de
configuration**, jamais sur une panne de réseau.

## Détruire le client retire l'annonce

La connexion **est** le bail : il n'y a pas de « retrait » séparé. Le destructeur
ferme proprement, ce qui épargne à l'annuaire la minute d'inactivité pendant
laquelle il donnerait une adresse morte — cet appel peut donc prendre jusqu'à deux
secondes.

`Client` est **déplaçable et non copiable** : deux clients qui partageraient un
pointeur le libéreraient deux fois. Un client déplacé laisse l'original vide, et
un client vide refuse tout au lieu de déréférencer le néant.

## Construire

En-tête seul. Il faut deux répertoires d'inclusion — le nôtre et celui de
`asl.h` — et l'objet natif :

```sh
cargo build --release
g++ -std=c++17 -I liaisons/cpp/include -I crates/asl-client-ffi/include \
    mon_daemon.cpp -L target/release -lasl_client_ffi -o mon_daemon
```

Ou par CMake :

```cmake
add_subdirectory(liaisons/cpp)
target_link_libraries(mon_daemon PRIVATE asl::asl /chemin/libasl_client_ffi.so)
```

`CMakeLists.txt` **ne cherche pas l'objet natif** : son emplacement dépend du
déploiement, et le deviner ferait échouer de façon obscure chez tous ceux qui ont
une autre arborescence.

## Le verdict a quatre valeurs, et il n'y a pas de `joignable()`

`EnCours` n'affirme rien : l'annuaire répond avant d'avoir sondé, pour ne pas
faire attendre le démarrage d'un daemon. `NonSonde` dit qu'il ne mesurera pas —
UDP n'a pas de poignée de main, donc une sonde n'y distinguerait pas « écoute et
ignore » de « rien n'écoute ».

Un `candidat.joignable()` serait juste une fois sur deux, et ferait écarter un
candidat parfaitement bon.

## L'adresse IPv6 n'est pas abrégée

`Candidat::texte()` écrit les huit groupes en entier. **La compression de la
RFC 5952 a des règles** — une seule série de zéros, la plus longue, la première en
cas d'égalité — qu'une implémentation hâtive rate, et une adresse mal abrégée est
pire qu'une adresse verbeuse : elle se recopie et ne résout pas.

Les crochets, eux, sont là : sans eux, `2001:db8::1:8080` est ambigu.

## Les essais

```sh
./scripts/check-cpp.sh
```

`g++` et `clang++`, en C++17, C++20 et C++23, avec `-Wall -Wextra -Wpedantic
-Werror`. Un en-tête qui avertit chez son porteur est un en-tête qu'il finira par
mettre en liste noire.
