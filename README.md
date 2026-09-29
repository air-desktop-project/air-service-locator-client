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

**Le retrait d'une signature est une rupture**, pour cinq écosystèmes qui ne
se mettent pas à jour au même rythme. Un ajout est libre ; c'est le retrait qui
casse — un cran majeur à partir de 1.0, un cran **mineur** tant qu'on est en
0.x (semver §4), et il se dit ici, dans `abi.txt` et dans la PR.

**Deux retraits à ce jour.** D'abord **0.19.0, la fin de la bascule** (décision 58,
étape 5). `asl_client_racines` et `asl_appareil_racines` — l'autorité PEM de
la forme d'hier — ne sont plus exportés, ni `Natif.racines` côté JNI, ni
`poser_racines`/`poserRacines`/`racines:` dans les cinq liaisons, dont
`ajouter_annuaire` prend désormais l'identité `n-…` au lieu d'un nom de
certificat. Puis **0.20.0** : `asl_client_annuaire` et `asl_appareil_annuaire`
— un annuaire posé par son NOM, qui ne se croyait plus depuis 0.19.0 et
rendait toujours `ASL_CONFIGURATION` — ne sont plus exportés, ni
`Natif.annuaire` côté JNI ; `asl_client_annuaire_identifie` et
`asl_appareil_annuaire_identifie` les remplacent.

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

## Installer asl sur Linux

**Par un paquet Debian, pas par une copie de binaire** : `dpkg` sait alors ce
qui est posé, le retire proprement, et refuse un paquet d'une autre
architecture que la machine. La cible est Ubuntu, comme pour l'annuaire.

Le paquet `asl` existe en **`amd64` et en `arm64`** — un PC ou un Raspberry Pi.
La CI construit les deux, chacun sur sa propre architecture, les éprouve avec
`scripts/check-paquet.sh`, et les publie en artefacts `asl-amd64-deb` et
`asl-arm64-deb`. Une machine sans Rust reçoit donc `asl` sans rien construire :

```sh
# le dernier run vert de main (ou celui d'une PR : --branch <branche>)
run=$(gh run list -R air-desktop-project/air-service-locator-client \
      --workflow ci --branch main --status success --limit 1 \
      --json databaseId --jq '.[0].databaseId')
gh run download "$run" -R air-desktop-project/air-service-locator-client \
    -n asl-arm64-deb -D deb-arm64
sudo apt install ./deb-arm64/asl_<version>_arm64.deb
```

`apt install ./…` et non `dpkg -i` : il installe aussi les dépendances que
`dpkg-shlibdeps` a lues dans le binaire (la libc, `libgcc-s1`), au lieu de
laisser le paquet à moitié configuré. Un artefact de GitHub **expire au bout
de 90 jours** : passé ce délai, relancez le run, ou construisez sur une machine
de la même architecture :

```sh
scripts/paquet.sh                    # asl_<version>_<architecture>.deb
```

**Le paquet ne pose que `/usr/bin/asl` et sa licence**, et n'a aucun script
de mainteneur : ni service, ni compte système, rien qui s'exécute en root à
l'installation. L'identité de la machine est générée par `asl enroll` et vit
chez l'utilisateur (`$XDG_CONFIG_HOME/asl`, sinon `~/.config/asl`, ou
`--state`) : ni l'installation ni le retrait du paquet n'y touchent — `apt
purge asl` ne révoque rien et n'efface aucune clé.

## Ce que le porteur doit poser sur une machine

**Une paire de clés Ed25519 que la bibliothèque génère ELLE-MÊME**, et dont la
partie privée ne quitte jamais la machine. Il n'y a **aucun secret partagé** à
poser : c'est la règle du produit, pas une préférence.

**Sans rien dire, `asl` joint les annuaires racines par leur identité** (C20,
décisions 53 à 58) : les deux racines sont **embarquées dans le binaire** —
leur identifiant `n-…`, leur clé d'identité, leurs adresses IPv6 puis IPv4
(`asl-client::racines`) —, et **aucun nom n'est résolu** : ASL fonctionne sans
DNS. Chaque racine présente un certificat auto-signé par sa clé ; on la croit
si cette clé se déduit en l'identifiant attendu, sans autorité ni nom.
`asl roots` demande la liste à une racine et la vérifie : une seule clé qui ne
donne pas son `n-…` la refuse entière.

**Les locateurs des racines se renouvellent, pas les racines** (0.21.0,
décisions 56, 76 et 85). Après une connexion à une racine embarquée, `asl`
relit `GET /v1/racines` — **si son cache a plus de vingt-quatre heures**, ou
s'il manque, ou s'il ne se lit pas —, la vérifie comme `asl roots`, et garde
dans le fichier `racines`, **à côté de l'identité** (`--state`, `ASL_STATE`,
sinon `~/.config/asl/racines`), les seules adresses littérales des racines
**déjà embarquées**, sous leur `n-…` :

```text
appris_a = 1790000000
racine = n-0PWT8HZD80QMSPPDZ5CQXXYHQC [2001:41d0:20a:900::1dd4]:6630 178.32.16.250:6630
racine = n-3K3P6H252W8K9370QG1YYTWBWB [2001:41d0:20a:900::1d32]:6630 178.32.16.249:6630
```

Une racine inconnue de ce binaire est ignorée — une racine nouvelle exige une
nouvelle version du client —, un nom n'est pas gardé (C20), et **aucune racine
embarquée n'est jamais retirée** : la tournée essaie d'abord les locateurs
appris, puis ceux de la liste embarquée en secours, IPv6 d'abord dans chaque
famille. Le cache ne porte aucune confiance — c'est toujours la clé embarquée
qu'on juge au bout —, et **un cache illisible est ignoré**, jamais une panne :
les racines embarquées répondent, et il se réécrit à la connexion suivante.
Un jour, parce qu'une racine ne déménage que par un geste d'exploitant, rare
et annoncé, et qu'un cache en retard ne casse rien : au moins une racine
écoute sur 6630. `asl diagnose` et `asl roots` disent d'où vient chaque
locateur — `appris`, `embarqué`, ou les deux — et l'âge du cache ; `asl roots`
le remet à jour quel que soit son âge.

**La bascule est finie** (décision 58, étape 5 ; 0.19.0) : depuis le
2026-09-28, les racines ne servent plus que leur certificat d'identité, et le
client ne croit plus que lui. La chaîne d'autorité et sa racine épinglée sont
retirées ; `--directory <hôte:port>=<n-…>` vise un annuaire par son identité,
et c'est la seule forme — un `hôte:port` seul est refusé, et le refus dit
quoi écrire. `--roots` n'existe plus et le dit ; `ASL_ROOTS` est ignorée, avec
un avertissement. Aucun repli sur le magasin du système, ni sur rien d'autre.

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
rend les siennes ; `asl where <n-…> asl-directory` dit **où joindre un
annuaire local** (0.21.0, serveur 0.38.0, `annuaires.md` §2 quinquies) — le
`n-…` de son titulaire, et, avec le droit `localiser`, chaque adresse de
membre vivant avec **l'identité à attendre au bout** (une paire, ce sont deux
clés) ; avec `voir` seul, qu'il existe et qu'il est vivant, sans adresses ;
sinon `404` — introuvable, parti ou hors de vos droits, que la racine ne
distingue pas (C9). Sous un `n-…`, aucun autre nom ne se résout, et la
commande le dit. Ce verbe est de la voie machine (décision 86) : il n'a pas
d'équivalent dans l'ABI ni en JNI — un daemon suit déjà seul le `421` vers
son annuaire local, et les applications lisent l'état de l'annuaire dans
`GET /v1/annuaires`. Et `asl enrolled` rend **les appareils enrôlés sur le compte
de cette machine** (`GET /v1/moi/appareils`, révoqués marqués, modèle et
plate-forme quand l'appareil s'est décrit, « en attente d'attestation » pour
une clé apportée par un autre appareil et pas encore prouvée sous une posture
exigée) — pour soi seulement : nommer un autre compte est refusé avant toute
requête, un appareil ne sort pas de son compte.

**L'exploitant vérifie la voie entre les deux racines depuis une machine
enrôlée** : `asl replication` **joint les DEUX** et rend, pour chacune, le
pair, la voie (`ouverte`, `coupée`, ou `seule` sans pair réglé), son horloge
(`compteur`), le curseur qu'elle tient pour l'autre (`appliqué`) et la
dernière estampille qu'elle a écrite (`écrit`, servi depuis l'annuaire
0.17.0 — `replication.md` §8 du serveur). Puis il conclut.

**Il en joint deux parce qu'une seule ne conclut rien**, et l'écart ne se lit
pas où l'on croit : l'`appliqué` d'une racine se compare à l'`écrit` de
l'AUTRE, jamais à son `compteur` — l'horloge compte aussi les écritures de la
racine elle-même. Les vraies racines le 21/09 : `compteur 35, appliqué 23`
des deux côtés, et rien en retard, parce que l'une avait écrit douze fois et
l'autre rien. Avec `écrit`, ces mêmes nombres se concluent sans ambiguïté.

Une seconde tentative, et pas une de plus, sur l'autre adresse de l'alias.
Si la seconde racine ne répond pas, ou si les deux réponses nomment le même
pair — l'alias rend quatre adresses, deux par banc —, la commande rend ce
qu'elle a et **dit qu'elle ne conclut pas**, plutôt que de conclure sur une
moitié. Une racine d'avant 0.17.0, qui ne rend pas `écrit`, se lit aussi :
sa ligne ne montre pas d'`écrit`, et la conclusion dit ce qui manque. Ce qui
prouve l'état reste la voie : `ouverte` ne laisse rien en attente plus d'une
seconde, `coupée` si.

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
