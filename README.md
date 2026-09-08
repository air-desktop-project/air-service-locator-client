# air-service-locator-client

**Ce que des tiers installent.** La bibliothèque qu'un daemon lie pour s'annoncer
auprès d'un annuaire `air-service-locator`, celle qu'un de ses clients lie pour
retrouver un port, ses liaisons vers cinq langages, et l'utilitaire `asl`.

> ## État : une arborescence, et rien qui fonctionne
>
> Les trois crates compilent, sont lintées et formatées, et la CI les vérifie —
> mais **aucune n'expose la moindre fonction**. Les spécifications sont écrites
> (dépôt serveur, `docs/`) ; le code ne l'est pas.
>
> `asl` le dit quand on le lance, plutôt que d'afficher une aide qui
> promettrait des commandes qui n'existent pas.

## Le problème

Un daemon qui écoute sur un port choisi au démarrage est un daemon que ses
clients ne savent plus joindre. Le réflexe est de figer un numéro de port ; il se
paie en collisions, en pare-feu à rouvrir, et en un service qui ne peut pas
tourner deux fois sur la même machine.

`air-service-locator` déplace la question : le daemon obtient le port qu'il veut,
puis **l'annonce** ; ses clients **le demandent** avant de se connecter. Cette
bibliothèque est ce qui fait les deux.

## Ce que le dépôt contient

| Crate | Ce que c'est |
|---|---|
| `asl-client` | La bibliothèque Rust. Les deux bouts : annoncer, et résoudre. |
| `asl-client-ffi` | La même, derrière une **ABI C** — `cdylib` et `staticlib`. |
| `asl-cli` | L'utilitaire `asl`. |
| [`liaisons/`](liaisons/) | Python, Ruby, C++, Kotlin, Swift. Toutes par l'ABI C. |

## Les décisions qui gouvernent ce dépôt

### Une seule porte native

Aucun des cinq langages ne sait appeler du Rust ; tous savent appeler du C.
Cinq passages natifs, ce serait cinq copies de la même logique de conversion —
et c'est la copie qu'on oublie qui finit par diverger.

**Aucun type Rust ne traverse la frontière.** Ni `String`, ni `Result`, ni
générique. Un `String` rendu à Python serait un bloc alloué par l'allocateur de
Rust que l'appelant tenterait de libérer avec le sien.

**Le retrait d'une signature est une rupture majeure**, pour cinq écosystèmes
qui ne se mettent pas à jour au même rythme. Un ajout est libre ; c'est le
retrait qui casse.

### Pas une ligne de C

Structurellement, et pas par goût : une bibliothèque chargée dans un interpréteur
Python ou Ruby qui lierait sa propre libcrypto entrerait en conflit avec celle du
processus hôte, et ce genre de panne se diagnostique en jours.

C'est ce qui rend le transport tenable : **HTTP/3 sur QUIC**, avec la pile écrite
pour `air-mail-server`, pure Rust.

### La connexion est tenue

Le daemon ouvre une connexion QUIC et la maintient par un keepalive : **la
connexion *est* le bail**. Pas de réannonce périodique à écrire, un arrêt propre
instantané, et le mapping NAT tenu ouvert sans mécanisme séparé.

**IPv6 d'abord, IPv4 en repli.** Une machine avec une IPv6 publique n'est
derrière aucun NAT ; c'est la voie normale, et IPv4 est le chemin où les
problèmes commencent.

### La reprise est le mécanisme de haute disponibilité

Un annuaire injoignable ne doit pas empêcher un daemon de démarrer. La
bibliothèque rend la main immédiatement, se connecte en arrière-plan, essaie les
annuaires dans l'ordre, et réessaie avec un recul exponentiel et un bruit de
±20 % — sans jamais abandonner.

**Ce code de reprise EST la bascule entre les deux annuaires racines**, et il n'y
en a pas d'autre : l'état vivant n'est délibérément pas répliqué entre annuaires,
parce qu'il se reconstruit ici, tout seul, en un keepalive.

## Ce que le porteur doit poser sur une machine

**Une paire de clés Ed25519 que la bibliothèque génère ELLE-MÊME**, et dont la
partie privée ne quitte jamais la machine. Il n'y a **aucun secret partagé** à
poser : c'est la règle du produit, pas une préférence.

L'enrôlement se fait en une commande — `asl enrole <code>` — avec un code court
que l'application affiche, à usage unique et valable quelques minutes. La
bibliothèque génère alors sa paire et présente sa clé publique. **Le code n'est
pas un justificatif durable** : il n'ouvre qu'une opération, lier une clé.

Le même objet des deux côtés : la machine qui héberge le daemon porte la
capacité `annonce`, celle qui consomme porte `lecture`.

**Il n'existe aucun mode anonyme.** Une résolution hors d'une connexion
authentifiée par une clé n'est pas prévue par le serveur, et un client qui
coderait un chemin de repli « sans authentification » ouvrirait une porte qui
n'existe pas.

## La dépendance vers le dépôt serveur

`asl-id` et `asl-proto` vivent dans `air-service-locator-server`, qui porte les
spécifications : le dépôt qui décrit la grammaire porte la grammaire.

Elles sont tirées par une **dépendance `git` épinglée sur un SHA**. C'est une
solution d'attente, et elle est datée : elle échappe à `cargo audit`, et une
réécriture d'historique là-bas casserait la construction ici sans que rien ne
l'annonce. **Ce qui la remplacera : publier les deux crates sur crates.io** le
jour où le protocole se stabilise — un tiers qui embarque cette bibliothèque doit
pouvoir la tirer d'un registre, pas d'un dépôt git dont il ne sait rien.

## Les barrières

```sh
scripts/check-tout.sh     # compile, clippy, essais, format — dans cet ordre
scripts/check-dco.sh      # après avoir committé
```

Celle qui manque et qui comptera le plus ici est `check-abi.sh`. Elle
s'ajoutera avec la première fonction exportée, jamais avant : comparer un
en-tête vide à un en-tête vide est une barrière qui n'a rien examiné.

## Les quatre dépôts

| Dépôt | Ce qu'il porte |
|---|---|
| `air-service-locator-server` | Le service. **Et les spécifications.** |
| `air-service-locator-client` | Ce dépôt. |
| `air-service-locator-ios` | L'application iOS. |
| `air-service-locator-android` | L'application Android. |

## Licence

MPL-2.0 — voir [LICENSE](LICENSE).
