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
> **les cinq liaisons — Python, Ruby, C++, Kotlin, Swift — sont écrites et
> éprouvées**, chacune avec sa barrière ; et `scripts/construire-natif.sh` en
> fait UNE archive que les cinq savent consommer, sur les trois systèmes.
>
> Ce qui manque est la publication vers les registres — PyPI, RubyGems, Maven
> Central —, qui demande des secrets et une décision de version.

## La voie mobile

Depuis le 2026-09-12, ce dépôt porte aussi ce que les deux applications
(`air-service-locator-ios`, `air-service-locator-android`) embarquent :
`asl-client::appareil` (ce qu'un téléphone compose, sans signer — sa clé vit
dans son matériel), la connexion tenue d'`asl-client-tokio::Tenue`, l'ABI
`asl_appareil_*` d'`asl-client-ffi` avec sa **signature par rappel**, et
`asl-client-android`, les symboles JNI exportés depuis Rust. Depuis 0.9.0,
**un appareil qui rejoint un compte entre attesté comme le premier** : il tire
son défi sur sa connexion nue AVANT de générer sa clé, la montre à l'ancien
appareil, puis prouve et présente sa chaîne d'un même verbe, sur la même
connexion (`asl_appareil_rejoindre_atteste`, `POST /v1/attestation`) — un Mac,
sans chaîne, prouve sur cette connexion-là par `asl_appareil_connecter`.
`scripts/construire-mobile.sh` produit l'xcframework et l'objet JNI. Le détail,
et ce que le serveur doit encore servir, est dans [`CLAUDE.md`](CLAUDE.md).

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

**Sans rien dire, `asl` joint les annuaires racines** — `asl-root.air-desktop.org:6630`,
un alias DNS qui rend les deux serveurs racines et que le DNS sert en tournant —
avec **la racine d'`air-desktop-project` épinglée dans le binaire**
(`crates/asl-cli/racines/air-desktop-project.pem`). `--directory`/`ASL_DIRECTORY`
et `--roots`/`ASL_ROOTS` servent à viser autre chose : un banc, une autre
autorité. Il n'y a toujours aucun repli sur le magasin du système.

**La grammaire d'`asl` est en anglais** — commandes, options, variables
d'environnement, `--help` — parce que c'est la langue d'un terminal, quel que
soit celui qui s'y assoit ; ses messages, eux, sont en français, comme tout
ce dépôt.

L'enrôlement se fait en une commande — `asl enroll <code>` — avec un code court
que l'application affiche, à usage unique et valable quelques minutes. La
bibliothèque génère alors sa paire et présente sa clé publique. **Le code n'est
pas un justificatif durable** : il n'ouvre qu'une opération, lier une clé.

Le même objet des deux côtés : la machine qui héberge le daemon porte la
capacité `annonce`, celle qui consomme porte `lecture`.

**La machine sait pour qui elle agit.** L'enrôlement rend son identifiant et
celui de son propriétaire, tous deux publics ; `asl` les range dans son fichier
d'identité, `asl identity` les rend hors ligne, et `asl diagnose` les demande
à l'annuaire (`GET /v1/moi`) — et complète le fichier d'une machine enrôlée
avant que l'annuaire ne rende le propriétaire. De là, un programme de B part
d'un `u-…` que A lui a donné : `asl machines <u-…>` liste ce que A lui a ouvert,
`asl where <service>` trouve toutes les instances d'un nom qu'il a le droit de
voir — sans qu'un humain ait à recopier des `m-…`. Sans argument, `asl machines`
rend les siennes ; et `asl enrolled` rend **les appareils enrôlés sur le compte
de cette machine** (`GET /v1/moi/appareils`, révoqués marqués, modèle et
plate-forme quand l'appareil s'est décrit, « en attente d'attestation » pour
une clé apportée par un autre appareil et pas encore prouvée sous une posture
exigée) — pour soi seulement : nommer un autre compte est refusé avant toute
requête, un appareil ne sort pas de son compte.

**L'exploitant vérifie la voie entre les deux racines depuis une machine
enrôlée** : `asl replication` demande `GET /v1/replication` à la racine que
l'alias lui a donnée — et dit laquelle, puisque l'alias en rend deux — puis
rend, sur une ligne, le pair, la voie (`ouverte`, `coupée`, ou `seule` sans
pair réglé), son horloge (`compteur`) et le curseur qu'elle tient pour l'autre
(`appliqué`, l'estampille de la dernière opération de l'autre qu'elle a
appliquée — `replication.md` §8 du serveur). **L'écart entre les deux n'est
pas un retard** : l'horloge compte aussi les écritures de la racine jointe, le
curseur ne compte que celles de l'autre. Ce qui se conclut se conclut depuis
les deux — lancé deux fois, il joint en général les deux racines — : si
l'`appliqué` d'une racine égale le `compteur` de l'autre, elle a tout
appliqué ; en dessous, **on ne sait pas** — l'autre a peut-être haussé son
horloge sur ce qu'elle recevait sans rien écrire (les racines du 21/09 :
`23` contre `35`, et rien en retard). Ce qui prouve l'état, c'est la voie :
`ouverte` ne laisse rien en attente plus d'une seconde, `coupée` si.

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
scripts/check-version.sh  # après avoir committé : la version a changé, et tout la suit
```

**Chaque PR change la version** (`CLAUDE.md`), et `check-version` la tient : une
PR dont `[workspace.package] version` est celle de `main` ne se merge pas.
`asl --version` dit la version et le commit du binaire.

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
