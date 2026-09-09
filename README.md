# air-service-locator-client

**Ce que des tiers installent.** La bibliothèque qu'un daemon lie pour s'annoncer
auprès d'un annuaire `air-service-locator`, celle qu'un de ses clients lie pour
retrouver un port, ses liaisons vers cinq langages, et l'utilitaire `asl`.

> ## État : la logique, pas encore le transport
>
> **`asl-client` porte la politique de reprise et l'identité d'une machine**,
> couvertes à 100 % et éprouvées par le fuzz.
>
> **`asl-client` ne fait toujours aucune entrée-sortie, et reste `no_std`.** Ce
> n'est pas un état subi : c'est ce qui permet d'éprouver la reprise sans
> attendre une seconde de délai — dix mille tours coûtent une boucle, là où un
> vrai recul exponentiel y mettrait des jours. Le transport vit à côté, dans
> `asl-client-tokio`, la seule crate de ce dépôt qui attend.
>
> L'utilitaire `asl` fait les quatre verbes ; `asl-client-ffi` exporte onze
> symboles, inscrits au registre et déclarés dans `include/asl.h` ; **les liaisons
> Python, Ruby, C++ et Kotlin sont écrites et éprouvées.** Swift ne l'est pas.

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

Trois propriétés le tiennent, et la cible de fuzz les vérifie sur n'importe
quelle suite d'événements :

- **Le délai n'est jamais nul.** Ce serait la boucle serrée qu'on évite.
- **Il ne dépasse jamais le plafond bruité.** Sinon un daemon attendrait plus
  longtemps que son propre keepalive, et son bail tomberait pendant qu'il
  patiente.
- **Le compteur d'essais sature au lieu de déborder.** Après soixante-quatre
  échecs, un décalage non saturé rendrait un délai nul — et la reprise
  deviendrait exactement l'attaque qu'elle protège contre.

**Le bruit n'est pas du raffinement.** Sans lui, mille daemons dont l'annuaire
vient de tomber réessaient à la même seconde et le remettent à terre à l'instant
où il se relève.

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
scripts/check-tout.sh     # sept barrières, le fuzz, la couverture et les essais
scripts/check-dco.sh      # après avoir committé
```

`check-sans-c.sh` **compte davantage ici que dans le dépôt serveur** : là-bas,
une crate qui lierait du C s'exécuterait sur nos machines ; ici, elle serait
chargée dans le processus de quelqu'un d'autre.

`check-abi.sh` compare **trois sources qui doivent dire la même chose** : les
symboles que `libasl_client_ffi.so` exporte vraiment, le registre `abi.txt`, et
les fonctions déclarées dans `include/asl.h`. Deux suffiraient à se contredire
sans que personne s'en aperçoive — un symbole qu'aucun en-tête ne déclare n'est
atteignable par personne, et une déclaration sans symbole derrière est une erreur
d'édition de liens chez le consommateur, jamais chez nous.

Un ajout est libre mais doit être inscrit dans le même commit ; **un retrait est
une rupture majeure**, pour cinq écosystèmes à la fois qui ne se mettent pas à
jour au même rythme.

## Les quatre dépôts

| Dépôt | Ce qu'il porte |
|---|---|
| `air-service-locator-server` | Le service. **Et les spécifications.** |
| `air-service-locator-client` | Ce dépôt. |
| `air-service-locator-ios` | L'application iOS. |
| `air-service-locator-android` | L'application Android. |

## Licence

MPL-2.0 — voir [LICENSE](LICENSE).
