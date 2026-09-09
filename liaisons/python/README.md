# `asl` pour Python

Annoncer un service et retrouver un port, sans qu'aucun daemon ait de numéro de
port fixe.

```python
import asl

racines = open("/etc/asl/ca.pem", "rb").read()

with asl.Client(
    annuaires=[("203.0.113.7:6630", "nitrogen.example")],
    racines=racines,
    identite=(machine, graine),
) as client:
    client.annoncer("depot", [asl.Point(asl.Protocole.TCP, 8080)])
    servir_pour_toujours()          # l'annonce se tient toute seule
```

Et du côté qui consomme :

```python
for candidat in client.ou(machine, "depot"):
    print(candidat, candidat.verdict.name)   # [2001:db8::1]:8080 EN_COURS
```

## Ce qui tourne en arrière-plan

`annoncer` **rend la main tout de suite** : un annuaire injoignable ne doit pas
empêcher un daemon de démarrer. Votre service écoute déjà pendant que l'annonce
cherche encore.

Ce qui la tient ensuite est **un fil natif**, à l'intérieur de la bibliothèque —
ni un `threading.Thread`, ni une tâche `asyncio`, et il ne touche jamais à
l'interpréteur. Il se reconnecte seul, bascule sur l'autre annuaire racine quand
le premier tombe, et n'abandonne jamais.

`client.etat()` dit où il en est. Le seul champ dont un humain doit être averti
est `abandonnee` : la tâche **ne renonce que sur une faute de configuration**,
jamais sur une panne de réseau, quelle qu'en soit la durée.

## Fermer le client retire l'annonce

La connexion **est** le bail : il n'y a pas de « retrait » séparé à appeler.
Laisser le `Client` se faire ramasser retire donc l'annonce au moment où le
ramasse-miettes passe, c'est-à-dire à un moment que vous ne choisissez pas.

**Employez `with`.** `__del__` existe, mais c'est un filet, pas un moyen : pendant
l'arrêt de l'interpréteur, il peut ne jamais être appelé.

## Ce que cette liaison n'installe pas

Rien. `ctypes`, `dataclasses`, `enum`, `ipaddress` et `threading` sont dans la
bibliothèque standard, et `pyproject.toml` ne déclare aucune dépendance. Un
daemon qui vous embarque n'hérite d'aucun paquet — c'est la même règle que du
côté Rust, où `check-sans-c.sh` refuse toute crate qui compilerait du C.

`cffi` serait plus rapide et attraperait davantage de fautes à la construction.
Il serait aussi une dépendance. Le prix de `ctypes` est payé dans `asl/_abi.py` :
**chaque signature est déclarée à la main**, parce que sans `argtypes` `ctypes`
devine `int` et tronque un pointeur de soixante-quatre bits — une corruption à
l'appel, pas une erreur au chargement.

## L'objet natif

Ce paquet est du Python pur : il **cherche** `libasl_client_ffi.so`, il ne
l'embarque pas encore.

```sh
cargo build --release
export ASL_BIBLIOTHEQUE=$PWD/target/release/libasl_client_ffi.so
```

Cherché dans l'ordre : `ASL_BIBLIOTHEQUE`, puis à côté du paquet, puis le
chargeur du système. À défaut, `asl.BibliothequeIntrouvable` est levée avec la
liste de ce qui a été essayé — **une installation incomplète n'est pas une panne
d'exécution**, et un `OSError` nu enverrait chercher au mauvais endroit.

Une vraie distribution embarquerait l'objet dans une roue, une par plate-forme et
par architecture. Ce n'est pas fait, et `liaisons/README.md` dit pourquoi la
question n'est pas tranchée.

## Les erreurs

Jamais un entier négatif rendu tel quel. `asl.Erreur` suffit à tout attraper ;
les classes filles distinguent ce qui se corrige différemment :

| | |
|---|---|
| `MauvaisArgument` | Une adresse illisible, un port nul, une graine de mauvaise taille. |
| `Configuration` | Il manque un annuaire ou une racine. **Réessayer ne réparerait rien.** |
| `Injoignable` | Personne n'a répondu. Un câble débranché. |
| `Refuse` | L'annuaire a compris, et il a dit non. Un droit manquant. |
| `PasDIdentite` | Cette machine n'est pas enrôlée. |
| `Deja` | Ce client annonce déjà. |
| `Interne` | L'impossible, rattrapé — **votre processus n'a pas été tué**. |

`Injoignable` et `Refuse` restent distincts parce qu'ils se corrigent à des
endroits opposés.

## Le verdict a quatre valeurs, et il n'y a pas de `joignable`

`EN_COURS` n'affirme rien : l'annuaire répond avant d'avoir sondé, pour ne pas
faire attendre le démarrage d'un daemon. `NON_SONDE` dit qu'il ne mesurera pas —
UDP n'a pas de poignée de main, donc une sonde n'y distinguerait pas « écoute et
ignore » de « rien n'écoute ».

Une propriété `candidat.joignable` serait juste une fois sur deux, et ferait
écarter un candidat parfaitement bon. Il n'y en a pas.

## Plusieurs fils

`Client` sérialise ses appels. L'ABI dit qu'un client ne se partage pas entre
fils ; en Rust deux appels concurrents aliaseraient un `&mut`, ce qui est un
comportement indéfini et non un ralentissement. En Python personne ne lit cette
phrase : la liaison la fait respecter, et **transforme l'indéfini en file
d'attente**.

Le coût est réel : `etat()` attend pendant un `ou()` en cours, qui peut durer
vingt secondes. Un daemon qui annonce n'appelle pas `ou()`, donc les deux se
croisent rarement.

## Les essais

```sh
./scripts/check-python.sh
```

Ils lisent `crates/asl-client-ffi/include/asl.h` et comparent : constantes,
tailles, **ordre des champs**. Rien dans les deux langages ne relie ces fichiers,
et une divergence ne plante pas — elle ment.
