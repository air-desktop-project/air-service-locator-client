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

**Le paquet ne pose que `/usr/bin/asl`, sa licence, et l'unité utilisateur
`asl-echo.service` désactivée** (plus bas, « L'écho comme service »), et n'a
aucun script de mainteneur : ni service activé, ni compte système, rien qui
s'exécute en root à l'installation. L'identité de la machine est générée par `asl enroll` et vit
chez l'utilisateur (`$XDG_CONFIG_HOME/asl`, sinon `~/.config/asl`, ou
`--state`) : ni l'installation ni le retrait du paquet n'y touchent — `apt
purge asl` ne révoque rien et n'efface aucune clé.

**Sur macOS, l'identité de l'application passe d'abord** (0.22.1, décision 93,
E11 révisé). Un Mac est enrôlé par l'application Service Locator, et son agent
`asl-echo` lit la même identité : toutes deux sont en bac à sable, et
partagent le conteneur de groupe `SB7H9B6TY8.org.airdesktop.servicelocator`.
`asl` cherche donc, dans l'ordre :

1. `--state`, puis `ASL_STATE` — **tels quels, sans aucun repli** ;
2. le conteneur de groupe,
   `~/Library/Group Containers/SB7H9B6TY8.org.airdesktop.servicelocator/Library/Application Support/asl/`,
   s'il porte une `identite` ;
3. l'ancien conteneur de l'application,
   `~/Library/Containers/org.airdesktop.servicelocator.mac/Data/Library/Application Support/asl/`,
   s'il en porte une — avec un avertissement : l'application la migre au
   premier lancement, il suffit de la lancer ;
4. `$XDG_CONFIG_HOME/asl`, sinon `~/.config/asl`.

Quand aucun ne porte d'identité, `asl enroll` écrit **dans le conteneur de
groupe si le dossier du groupe existe** (l'application est installée), sinon
dans `$XDG_CONFIG_HOME/asl`, sinon `~/.config/asl` (0.22.2) : l'`asl` de
l'application est en bac à sable et ne voit pas `~/.config/asl`. Sinon il
écrit là où l'identité est lue, pour que la commande suivante lise celle qu'il
vient de lier.

Le cache `racines` suit l'identité, dans le même dossier. Les chemins partent
du répertoire du compte, jamais du conteneur qu'un bac à sable met dans
`HOME`. **Deux emplacements qui portent des machines différentes sont dits à
chaque commande**, sur la sortie d'erreur, en une ligne ; la plus haute
priorité est prise. `asl identity` et `asl diagnose` disent d'où l'identité
est lue. Linux ne change pas.

## asl sur macOS

**Sur macOS, `asl` est livré dans l'application**, pas par un paquet :
`Air Service Locator.app/Contents/Helpers/asl`, binaire **universel** (arm64 +
x86_64), **en bac à sable** (Mac App Store). Ce dépôt le produit, le projet
Mac le reprend — épinglé par le SHA de ce dépôt, comme le xcframework — et le
signe.

- **Ce dépôt** : `scripts/asl-macos.sh` construit les deux tranches, les réunit
  par `lipo`, vérifie sur chacune l'`Info.plist` intégré, et produit
  `distribution/asl-macos-universel-<version>.tar.gz` (le binaire **non
  signé**, `asl.entitlements`, la licence, un `MANIFESTE` avec les empreintes).
  La CI le lance sur un runner macOS (`asl-macos.yml`, sur `main` et sur les PR
  qui touchent au code) et publie l'artefact **`asl-macos-universel`**.
- **L'`Info.plist` intégré** (`crates/asl-cli/build.rs`, macOS seulement) :
  `__TEXT,__info_plist`, identifiant `org.airdesktop.servicelocator.asl`,
  versions = celle du crate. **Sans lui, un `asl` signé en bac à sable meurt au
  démarrage** (SIGILL dans `sandbox.cold`, macOS 15.7.9) : le bac à sable n'a
  pas de paquet autour de l'exécutable pour savoir qui il est.
- **Le projet Mac** signe avec son Developer ID, le runtime renforcé,
  l'identifiant `org.airdesktop.servicelocator.asl`, et ces droits
  (`asl.entitlements`, dans l'archive) :

  ```xml
  <key>com.apple.security.app-sandbox</key>              <true/>
  <key>com.apple.security.network.client</key>           <true/>
  <key>com.apple.security.network.server</key>           <true/>
  <key>com.apple.security.application-groups</key>
  <array><string>SB7H9B6TY8.org.airdesktop.servicelocator</string></array>
  ```

  `network.server` n'est pas un luxe : la pile QUIC lie un socket UDP local
  pour recevoir, et le bac à sable tient ce `bind` pour « serveur » — sans ce
  droit, tout est « injoignable ».

**Ce que le bac à sable change pour qui tape `asl`** :

- son `HOME` est son propre conteneur,
  `~/Library/Containers/org.airdesktop.servicelocator.asl/Data` ; `asl`
  remonte au répertoire du compte et y trouve le conteneur de groupe, là où
  l'application et son agent tiennent l'identité de la machine ;
- **`--state` et `ASL_STATE` ne peuvent viser que ce qu'il atteint** : son
  conteneur, ou le conteneur de groupe. Un autre dossier est refusé par le
  système (`Operation not permitted`), pas par `asl` ;
- `~/.config/asl` lui est invisible : `asl enroll` écrit dans le groupe.

**La commande dans le terminal : un lien `~/.local/bin/asl`** vers
`/Applications/Air Service Locator.app/Contents/Helpers/asl`. L'application
étant en bac à sable, elle ne peut pas écrire d'elle-même dans `~/.local/bin`
(une exception temporaire serait refusée sur le Mac App Store). Le bouton
« Installer la commande asl » ouvre donc un sélecteur de dossier
(`NSOpenPanel`) qui propose `~/.local/bin` ; l'utilisateur confirme, et
l'application obtient le droit d'y créer le lien par
`com.apple.security.files.user-selected.read-write` — un droit de
l'APPLICATION, pas d'`asl`. La fiche affiche aussi la commande à copier :

```sh
ln -s "/Applications/Air Service Locator.app/Contents/Helpers/asl" ~/.local/bin/asl
```

**Pour le développement**, un `asl` autonome, non signé et hors bac à sable,
reste possible : `cargo build --release -p asl-cli` sur un Mac. Il cherche
l'identité dans le même ordre (macOS peut demander, une fois, l'autorisation
d'accéder aux données d'une autre application), et `--state` y vise n'importe
quel dossier.

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
sinon `~/.config/asl/racines` — sur macOS, le dossier où l'identité est lue), les seules adresses littérales des racines
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

**Les domaines se lisent depuis une machine** (0.22.0, serveur 0.39.0,
`protocole.md` §3) — pourvu qu'elle porte la capacité `lecture`. `asl
domains` liste ceux que son compte voit : les siens, et ceux où l'un de ses
groupes tient un droit, chacun avec son alias, son hébergeur (`racines` ou
l'annuaire local), vos droits, et « domaine racine » pour lui seul. `asl
domain <d-…|alias> [--where]` en montre un : alias, propriétaire,
hébergeur, droits, puis **chaque machine qui y est rangée** — identifiant,
nom d'hôte, alias, propriétaire — et **leurs services** (`GET
/v1/machines/{m}/services`), annoncés ou partis : ceux de vos machines, et,
depuis le serveur 0.40.0 (0.22.3), **ceux de toutes les machines du domaine
pour qui y a `voir`** — sans leurs adresses : un service vivant d'autrui se
dit « annoncé », sans candidat. Avec `--where`, chaque service annoncé se
résout comme `asl where <m-…> <nom>` : sur vos machines, et sur toutes celles
du domaine s'il vous donne `localiser` ; sinon, la ligne « adresse : hors de
vos droits » le dit. L'alias est sensible à la casse ; un alias que plusieurs
domaines portent est refusé, candidats listés. Deux silences y sont dits
pour ce qu'ils sont : une liste de domaines vide veut dire « pas de
`lecture` » (un compte a toujours le sien) ; et des machines absentes sans
`voir` ne veulent pas dire un domaine vide. La bibliothèque porte ces lectures typées dans
`asl_client_tokio::domaines` (`Connexion::{domaines, domaines_par_alias,
domaine, services_de_machine}`) ; l'ABI C et JNI n'en ont pas — ce sont des
lectures de la voie machine, et les applications lisent les mêmes routes
sur la voie appareil par `asl_appareil_requete`.

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

**L'écho : prouver qu'une machine est joignable, et que c'est bien elle**
(0.23.0, serveur 0.42.0, `protocole.md` §3 quater, décisions 89 à 93).
`asl echo` fait répondre cette machine : il lie **une** socket UDP à un port
tiré **au hasard dans la plage 6631–6639** (le suivant de son ordre tiré si
celui-là est pris ; toute la plage prise est une faute de configuration,
« aucun port libre dans 6631–6639 », code 2), annonce `asl-echo` avec un seul point `udp:<port>`, et
**tient le bail sur cette même socket** — derrière un NAT, le mapping que le
bail ouvre et que son keepalive garde est celui de la socket où l'écho
écoute. Il ne répond qu'aux sondes signées, vérifiées hors ligne : celle de
l'annuaire qui tient son bail (sous la clé que la poignée de main a jugée) ou
d'une racine embarquée, datée à deux minutes près ; celle d'`asl ping`, munie
d'un jeton qu'une racine a signé pour la clé de CETTE machine et celle du
sondeur, et signée par ce dernier. **À tout le reste, le silence** — pas
d'erreur, pas de refus. Le débit est borné par source **avant** toute
vérification (cinq par seconde, dix d'avance, une `/64` en IPv6 ; cinquante
par seconde en tout), un défi ne sert qu'une fois, et la réponse fait 132
octets pour une requête de 384 : aucune amplification. Il refuse de tourner
en root, ne rend pas la main, et Ctrl-C ou `SIGTERM` ferment le bail
proprement. Son journal est sobre : une ligne par preuve rendue, un bilan par
minute au plus de ce qu'il a tu, et l'horloge qui dérive quand une sonde
d'annuaire authentique arrive hors de sa fenêtre.

**La plage s'ouvre une fois dans le pare-feu de chaque machine qui fait
tourner l'écho** (décision du 2026-09-29 : un port éphémère tombait sous la
politique `drop` du pare-feu, et personne ne peut ouvrir d'avance un port
qu'il ne connaît pas) :

```sh
# nft, dans la chaîne input de la table inet filter
nft add rule inet filter input udp dport 6631-6639 accept
# ou ufw
sudo ufw allow proto udp from any to any port 6631:6639
```

Neuf ports, et non un : plusieurs échos peuvent tourner sur une machine, et
l'écho reste sans port fixe (décision 89) — il ne répond de toute façon
qu'aux sondes signées.

```text
$ asl echo
écho           m-3GE1R70W3GE1R70W3GE1R70W3G — udp 6634, tiré dans 6631–6639
               il ne répond qu'aux sondes signées ; aux autres, le silence.
bail           tenu par n-0PWT8HZD80QMSPPDZ5CQXXYHQC ([2001:41d0:20a:900::1dd4]:6630) — s-1Y7R… annoncé, vu depuis [2a01:e0a:…]:6634
verdict        udp:6634     joignable      constaté à 1790000000000
sonde          jeton    m-40G2081040G2081040G2081040 depuis [2a01:cb00:…]:47031 — preuve rendue
```

**L'écho comme service : une unité systemd UTILISATEUR, posée désactivée**
(0.23.1, décision 93). Le paquet Debian pose
`/usr/lib/systemd/user/asl-echo.service`, qui lance `/usr/bin/asl echo`, et
**n'active rien** — aucun script de mainteneur : l'écho répond au nom de la
clé de cette machine, et c'est à celui qui la porte de le vouloir. `asl
enroll` le rappelle en une ligne. Sous le compte qui a enrôlé la machine :

```sh
systemctl --user enable --now asl-echo
journalctl --user -u asl-echo -f          # ce qu'il dit
```

**Sur un serveur où personne n'ouvre de session**, le gestionnaire de
l'utilisateur ne tourne pas, et l'unité ne démarrerait qu'à la première
connexion — c'est ce qu'on oublie. Une fois, en root, pour ce compte :

```sh
sudo loginctl enable-linger <compte>
```

L'unité redémarre sur panne (`Restart=on-failure`, dix secondes, cinq
départs en dix minutes au plus), **mais pas sur un refus** : une faute de
configuration (code 2 — pas d'identité, plage prise, lancé en root) ou une
clé refusée par l'annuaire (code 3) la laissent arrêtée, en échec visible
dans `systemctl --user status asl-echo`, plutôt qu'en boucle au journal. Une
unité SYSTÈME (`asl-echo@<compte>`) est écartée en v1 : root déciderait pour
la clé d'un utilisateur.

`asl ping <m-…|nom|alias>` pose la question « est-ce que je la joins, d'ici,
maintenant ? » : il résout la cible (un nom ou un alias est cherché parmi les
machines que ce compte voit ; plusieurs sont listées, aucune n'est choisie),
résout son `asl-echo` (`GET /v1/ou/{m}/asl-echo`), demande un jeton
(`POST /v1/echo/jetons`), sonde chaque candidat — IPv6 d'abord, trois envois
d'une seconde, chacun avec son défi — et **vérifie la réponse contre la clé
que le jeton porte**, signée par la racine. Il dit toujours d'où la sonde est
partie et sous quelle adresse l'écho l'a vue :

```text
$ asl ping grenier
sonde partie de m-40G2081040G2081040G2081040 (carbon) depuis [2a01:cb00:…]:47031, vue par l'écho comme [2a01:cb00:…]:47031
  [2a01:e0a:…]:6634  udp  réflexif  joignable d'ici — 18 ms, preuve vérifiée (depuis [2a01:cb00:…]:47031)
grenier (m-3GE1R70W3GE1R70W3GE1R70W3G) : joignable d'ici, 18 ms, preuve vérifiée
  — clé de m-3GE1R70W3GE1R70W3GE1R70W3G selon la racine n-0PWT8HZD80QMSPPDZ5CQXXYHQC ; constaté à 12:02:31 UTC
```

Ses codes de sortie sont ceux de la spécification : `0` joignable d'ici,
preuve vérifiée ; `1` pas de réponse d'ici (filtré, écho arrêté, ou sonde
refusée — l'écho se tait dans les trois cas) ; `2` **quelqu'un d'autre répond
à cette adresse** (une autre clé), ou une réponse illisible ; `3`
introuvable — pas d'écho annoncé ou pas le droit de le localiser, que la
racine ne distingue pas (C9) ; `4` annuaire injoignable. `asl ping` ne
remonte rien : son verdict est celui d'ici.

Dans la bibliothèque, la socket partagée est `Connexion::ouvrir_sur` et
`asl_client_tokio::joindre_sur` : non connectée, elle est **triée au premier
octet** — le QUIC de l'annuaire à la connexion, l'écho (`0x04` à `0x0F`)
mis de côté pour le porteur (`Connexion::echos`, `envoyer_a`), le reste
jeté. La politique — qui croire, le débit, l'anti-rejeu, le jugement d'une
réponse — est `asl_client::echo`, sans une entrée-sortie, couverte et
fuzzée. **Ce qui manque encore, et viendra** : PCP et NAT-PMP (décision 96),
le LaunchAgent du Mac, et l'identité sur macOS dans le conteneur de
groupe. Et, faute de `getifaddrs` (C4), l'écho n'annonce
qu'une adresse locale par famille : celle par laquelle la machine sort vers
l'annuaire.

**La passerelle : UPnP, pour mettre toutes les chances de son côté** (0.24.0,
décisions 94 à 97). Derrière une box, le bail ne laisse entrer que ce que le
NAT veut bien laisser entrer ; une redirection demandée à la box laisse
entrer tout le monde sur **ce port-là** — c'est ce qui rend l'écho joignable
d'un `asl ping` lancé d'ailleurs. **Active par défaut** ; `asl echo
--no-upnp`, ou `ASL_ECHO_UPNP=0` dans l'environnement d'une unité, la coupe.
Une tâche à côté de l'écho, qui ne retarde jamais une réponse :

- **elle cherche la box sur le lien local seulement** — `M-SEARCH` vers
  `239.255.255.250:1900` et `[ff02::c]:1900`, `InternetGatewayDevice:2` puis
  `:1` — et ne suit une `LOCATION` que si c'est **l'adresse littérale qui a
  répondu**, sur le réseau local : aucun nom (C20), aucun tiers (C19) ;
- **elle ne demande que le port de l'écho, en UDP** : `AddAnyPortMapping`
  (IGD v2), sinon `AddPortMapping` (le même port externe d'abord, trois ports
  tirés au hasard sur conflit `718`), **bail d'une heure renouvelé toutes les
  trente minutes**, permanent seulement si la box l'exige (`725`) ; et le trou
  IPv6 (`WANIPv6FirewallControl:1`, `AddPinhole`) si la box le propose et le
  permet — sinon elle se tait, sauf `--verbose` ;
- **elle compare `GetExternalIPAddress` à `vu_depuis`** : égales, la box est
  le dernier NAT et la redirection est annoncée ; une adresse privée ou
  partagée (`100.64.0.0/10`), ou une autre, c'est **un double NAT** — dit, et
  pas annoncé ;
- **elle l'annonce** par le champ `passerelle` (`{"port":…,"via":"upnp"}`, le
  port seul : l'annuaire emploie l'adresse qu'il a observée), réannoncé sur la
  même connexion — **et seulement à un annuaire 0.44.0 ou plus**, lu dans
  `GET /v1/version` : un annuaire plus ancien refuserait l'annonce entière ;
- **elle recommence** toutes les trente minutes et quand l'adresse change, et
  **retire tout à l'arrêt, avant de fermer le bail** ; ce qu'elle a ouvert est
  retenu dans le répertoire d'état (`upnp-<port>`), et **retiré au démarrage
  suivant** si l'écho a été tué.

```text
passerelle     redirection UPnP : udp 6634 → box 203.0.113.7:6634, bail 1 h
annonce        réannoncée avec la passerelle : port externe 6634 (upnp)
passerelle     redirection retirée : udp 6634
```

Le codec — SSDP, HTTP/1.1 (`Content-Length`, `chunked`, ou jusqu'à la
fermeture), un XML réduit sans DTD, SOAP, la mémoire — est la crate
**`asl-upnp`** : sans une entrée-sortie ni une dépendance, couverte à 100 %,
quatre cibles de fuzz. `igd-next` n'a servi que de référence (décision 96).
**UPnP reste hors d'`asl-client`** : c'est l'utilitaire qui le parle, pas la
bibliothèque que chargent les daemons des autres. `ASL_ECHO_SSDP=<ip:port>`
interroge une passerelle en unicast plutôt que les groupes — c'est ainsi que
les essais parlent à une fausse box, et qu'aucun ne touche la vraie.

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
