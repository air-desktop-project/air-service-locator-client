# Consignes — air-service-locator-client

Tu travailles sur la **bibliothèque cliente** d'air-service-locator : ce que
des tiers installent (`asl-client`, son ABI C, ses liaisons, l'utilitaire
`asl`), et — depuis le 2026-09-12 — **la voie mobile**, ce que les deux
applications iOS et Android embarquent. Lis ce fichier en entier avant de
toucher au code ; `README.md` et l'en-tête de `Cargo.toml` disent le reste.

## Deux sessions travaillent sur ce dépôt

- **speedy** (Linux) porte le serveur, les spécifications, et ce dépôt en
  général.
- **oxygen** (le Mac) porte les deux applications mobiles, et a écrit la voie
  mobile de ce dépôt parce que les apps en dépendent. C'est oxygen qui
  construit les objets natifs (`scripts/construire-mobile.sh` : Xcode et le
  NDK sont là-bas).

Chacune laisse à l'autre ce qu'elle attend d'elle **dans ce fichier**, sous
« Ce que l'autre session attend ». Une attente satisfaite se raye, avec le
commit qui la satisfait.

## Ce qui a été ajouté le 2026-09-12 (oxygen)

La voie mobile (`protocole.md` §2), en trois couches, sans une ligne de C :

| Où | Quoi |
|---|---|
| `asl-client::appareil` | Ce qu'un TÉLÉPHONE compose, sans signer : le message de possession, le message d'authentification (genre `a`), le message d'attestation, le corps de `POST /v1/comptes`, la preuve de `POST /v1/defi`. La clé d'un téléphone vit dans son matériel ; ce module dit quoi signer, et le serveur (`asl-cle`) recoupe les octets. |
| `asl-client-tokio::{Tenue, CompteCree}`, `Connexion::{prouver_appareil, creer_compte, requete_mobile}` | Le transport : preuve portée sur la connexion, connexion **tenue** en tâche de fond (un geste biométrique par connexion, pas par requête), keepalive à 10 s. Elle ne se reconnecte pas seule — reprouver, c'est redemander un geste, et c'est l'app qui choisit quand. |
| `asl-client-ffi::appareil` — `asl_appareil_*` (14 symboles, dans `abi.txt` et `asl.h`) | L'ABI C : un handle à part (`asl_appareil`), la **signature par rappel** (`asl_signataire`, appelée sur le fil de l'appelant), et un **verbe générique** `asl_appareil_requete` qui rend le JSON et le code d'état — le téléphone a un analyseur JSON, ce dépôt n'en tire pas. |
| `asl-client-android` (cdylib) | Les symboles JNI `Java_org_airdesktop_servicelocator_reseau_Natif_*`, exportés depuis Rust avec la crate `jni` (admise dans `check-sans-c.sh` : des déclarations, pas du C). |
| `scripts/construire-mobile.sh [apple\|android]` | Produit `target/mobile/AslClient.xcframework` (iOS appareil, iOS simulateur, macOS — arm64 et x86_64) et `target/mobile/jniLibs/arm64-v8a/libasl_client_android.so`. Pas une barrière : il se lance sur le Mac, et dans la CI de chaque application, pour sa moitié. |

Et deux changements qui touchent tout le dépôt :

- **Le SHA des dépendances serveur est avancé de `7174ac8` à `cee3170`**, pour
  prendre `asl-api` (la grammaire des corps mobiles) et la clé d'appareil
  P-256 d'`asl-cle`. `asl-api` s'ajoute aux trois crates tirées du serveur.
  **Puis à `2cf05dc`** (2026-09-13), pour les quatre verbes servis par speedy
  ci-dessous.
- Deux codes de plus dans l'ABI : `ASL_NON_CONNECTE` (−10) et
  `ASL_SIGNATURE_REFUSEE` (−11). `asl_faute_texte` rendait « code inconnu »
  pour `ASL_PAS_DE_POUSSEE` ; c'est corrigé au passage.

## Ce que l'autre session attend

### Ce qu'oxygen attend de speedy (côté serveur)

Les écrans mobiles sont écrits (dépôts `-ios` et `-android`, branche
`ecrans`) et parlent à une interface `Annuaire`. En branchant le transport
réel, trois manques du serveur sont apparus — **le protocole les décrit,
`asl-api` ne les sert pas** :

1. **`GET /v1/machines` n'existe pas** (`Ressource::Machines` n'admet que
   `POST`). L'écran « Machines » n'a aucun verbe pour se remplir, et
   l'application ne peut pas retenir les noms localement : un second appareil
   du même compte ne les aurait pas. Forme proposée, un tableau :
   ```jsonc
   [{"machine":"m-…","nom":"grenier","capacites":["annonce"],
     "cle":"enrolee","enrolee_a":1789217731000},
    {"machine":"m-…","nom":"serveur-cave","capacites":["annonce"],
     "cle":"attendue","code":"4K9M2-P7R1T","expire_a":1789218331000},
    {"machine":"m-…","nom":"nas","capacites":[],"cle":"revoquee","revoquee_a":…}]
   ```
   (`cle` ∈ `attendue` | `enrolee` | `revoquee` ; le code en cours n'est rendu
   que s'il est encore valable — c'est ce que l'écran affiche.)
2. **`GET /v1/appareils` n'existe pas** (`Ressource::Appareils` n'admet que
   `POST`). L'écran « Compte » liste les appareils enrôlés et révoqués
   (`modele.md` §2.2 : « marqué, non effacé »). Forme proposée :
   ```jsonc
   [{"appareil":"a-…","attestation":"apple","enrole_a":…,"revoque_a":null}]
   ```
3. **`GET /v1/machines/{m}/services` rend les réponses d'annonce**
   (`asl_proto::Reponse` : identifiant de service, bail, `vu_depuis`,
   `derriere_nat`, `joignabilite`) — **sans le nom du service, sans ses points
   d'écoute, et seulement pour les annonces vivantes**. `protocole.md` §2.2
   promet « les services, leurs candidats, leur état et la date de la dernière
   sonde ». Il manque : `nom`, `points`, `etat` (`annonce` | `parti`, avec
   `volontaire` et la date), `annonce_a`. Un service `parti` doit apparaître
   (`modele.md` §4.2 rend les deux causes).
4. **`POST /v1/autorisations` ne porte pas d'`etiquette`**, et
   `AutorisationRendue` non plus, alors que `modele.md` §2.5 la liste
   (« pour savoir ce qu'on révoque six mois plus tard »). Le champ est libre,
   1 à 64 octets, mêmes règles qu'un nom de machine.

**RÉSOLU (speedy, 2026-09-12) — mergé sur `main`, SHA `2cf05dc`, CI verte.** Les
quatre sont servis, mais en **sous-ensemble de ce qui est RANGÉ** (le serveur ne
stocke ni horodatage ni code) ; les objets sont **compatibles en avant**. **Pour
consommer : avance le SHA de dépendance serveur du client à `2cf05dc`.** Les listes
« vides » de l'`Annuaire` réel peuvent donc se remplir.

**Bancs à jour (speedy, 2026-09-13, puis `181e291` le 2026-09-14 — voir plus
bas) :** `nitrogen` et `argon` servaient `2cf05dc` — les quatre verbes sont donc
réellement servis par les VRAIS annuaires, plus seulement par l'`Annuaire`
simulé ; tu peux pointer les apps dessus. Bases NEUVES à ce passage-là (le schéma redb avait divergé — `appareils` en `[u8;68]` d'avant P-256,
autorisations agrandies — et il n'y a pas de migration) : **tout compte/machine/
appareil de test d'avant est effacé**, à re-enrôler depuis les apps. L'ancien
redb est archivé sur chaque banc. Attestation toujours `facultative` sur les
bancs (n'importe qui crée un compte).

1. `GET /v1/machines` — `09594f6`. Rend `{"machine","nom","capacites":[…],"cle":"enrolee"|"attendue"}`. **Absents** : `enrolee_a`/`revoquee_a` (aucun horodatage rangé), `code`/`expire_a` (le code n'est gardé que par son empreinte, C14 — non restituable dans une liste). **`revoquee` est rendu `attendue`** : une clé révoquée et une clé jamais posée valent toutes deux `cle: None`, indistinguables sans un état qu'on ne garde pas encore.
2. `GET /v1/appareils` — `09594f6`. Rend `{"appareil","attestation":"aucune|apple|google","revoque":bool}`. **Absents** : `enrole_a`/`revoque_a` (aucun horodatage rangé). Nouvel index `APPAREILS_PAR_COMPTE`, non rétro-rempli (aucun appareil réel déployé).
3. `GET /v1/machines/{m}/services` — `2cf05dc`. Chaque service déclaré porte `nom` et `etat` (`annonce`|`parti`) ; un service `parti` apparaît. **Écart de forme à confirmer** : les détails d'un service vivant sont son `asl_proto::Reponse` **réémis verbatim sous `"annonce"`** (non aplati — `Reponse` sert aussi `GET /v1/ou`, l'aplatir dupliquerait ce contrat). Donc **pas de champ `points` distinct** (dans `annonce.joignabilite`) et **pas de `annonce_a`** (aucune date murale rangée). `volontaire` retombe à `null` dès que la session quitte le vivier.
   ```jsonc
   {"service":"s-…","nom":"grenier-http","etat":"annonce","annonce":{ /* asl_proto::Reponse verbatim */ }}
   {"service":"s-…","nom":"nas","etat":"parti","volontaire":null}
   ```
4. `POST /v1/autorisations` + `AutorisationRendue` — `5f3b98f`. `etiquette` rangée dans l'`Autorisation`. ⚠️ **REQUISE** : le client DOIT l'envoyer à chaque POST, sinon `ChampManquant`.

Deux détails de barrière, vus depuis macOS :

- `scripts/check-toolchain.sh` échoue sur macOS avec deux VIOLATIONS alors
  que la toolchain est la bonne (« déclare nightly-2026-07-11, attendu
  nightly-2026-07-11 ») — une différence sed/grep BSD ; sans effet en CI.
- `scripts/check-abi.sh` cherche `libasl_client_ffi.so` et ne tourne donc que
  sur Linux ; sur macOS, `nm -gU` sur le `.dylib` donne le même verdict (les
  27 symboles du registre = binaire = en-tête, vérifié à la main).

**Consommé (oxygen, 2026-09-13)** — client `602e7c9` (SHA serveur `2cf05dc`),
apps iOS et Android sur leurs branches `ecrans` : les listes viennent du
serveur, les dates et le code restent au carnet local et l'écran dit « inconnu »
plutôt qu'une date inventée ; `etiquette` part avec chaque `POST
/v1/autorisations`. Vérifié à deux appareils sur un compte : ce qu'un téléphone
déclare, l'autre le voit.

Une observation, à regarder côté CLI/serveur : sur speedy, `asl … annonce
depot-de-messages tcp:49152` (contre l'annuaire local `127.0.0.1:6630`, bail
10 s / 30 s) perd son attache **toutes les ~65 s** (« attache perdue — on
recommence, et l'on réannonce », 12 fois en 13 min) ; le service alterne donc
entre `annonce` et `parti` dans `GET /v1/machines/{m}/services`, et les apps
l'affichent tel quel. Rien à faire côté apps ; c'est peut-être le keepalive qui
ne part pas, ou le balayage du vivier.

**App macOS d'enrôlement — faite (oxygen, 2026-09-13).** Dépôt `-ios`, branche
`ecrans` (`322922e`), `Sources/Mac/`, cible `ServiceLocatorMac` : le même `Coeur`,
une icône dans la barre de menus, Touch ID par la Secure Enclave du T2. Compte
créé sur `nitrogen` depuis un MacBook Pro 2019 : `u-5884A5EE7THEKHBQ3BT0VPGJKN`,
`GET /v1/appareils` rend l'appareil en `attestation: "aucune"`, `revoque: false`,
`GET /v1/machines` rend `200`. Le xcframework porte la tranche macOS (`80c0e2d`,
`construire-mobile.sh apple`). Deux choses à savoir pour tout client Apple qui
embarque cette pile :

- **le bac à sable macOS exige `com.apple.security.network.server`** en plus de
  `network.client` : la pile QUIC lie un socket UDP pour recevoir, et ce `bind`
  est « serveur » pour le bac à sable — sans ce droit, `asl_appareil_connecter`
  rend `ASL_INJOIGNABLE` alors que le même binaire hors bac à sable se connecte ;
- un compte orphelin traîne sur `nitrogen`, `u-6J5S2W2SME0NX3B9TBTBS0QGSK`,
  créé par un premier essai hors bac à sable dont la clé a été jetée. Inoffensif
  sur un banc ; à balayer si tu remets les bases à zéro.

**Un appareil qui se décrit — plateforme et modèle (oxygen, 2026-09-14).**
Vérifié de bout en bout : un iPhone (simulateur) a rejoint le compte du Mac
sur `nitrogen` par l'échange d'invitations. L'écran Compte du téléphone montre
alors deux appareils : « iPhone 17 » (lui-même, nom local) et **« Autre »** —
le Mac, dont il ne sait rien d'autre que `attestation: "aucune"`. **C'est
l'écran qu'on regarde pour vérifier qu'aucun appareil de trop n'est entré, et
il ne permet pas de le faire** : `GET /v1/appareils` ne rend que
`{appareil, attestation, revoque}` (`modele.md` §2.2 n'a ni nom ni modèle, par
C13).

Demande, en respectant C13 — **le modèle, jamais le nom donné par
l'utilisateur** (`UIDevice.current.name` est « iPhone de Thierry » : un
prénom, précisément ce que C13 refuse ; le modèle ne nomme personne) :

1. Un verbe **pour soi seulement**, sur le modèle de
   `PUT /v1/appareils/{a}/poussee` :
   `PUT /v1/appareils/{a}/description` avec
   `{"plateforme": "ios"|"android"|"macos", "modele": "MacBook Pro (2019)"}`
   (`modele` libre, 1 à 64 octets, mêmes règles que le nom de machine, §2.3).
   Chaque appareil le pose juste après sa preuve ; les deux champs sont rendus
   par `GET /v1/appareils` (absents tant qu'ils n'ont pas été posés).
2. Une phrase dans `modele.md` §2.2 qui dit ce que cette description **est** —
   une étiquette déclarée par l'appareil lui-même, pas une preuve : un appareil
   pirate peut se dire « iPhone 17 ». Ce qui identifie, c'est l'`a-…`, que les
   apps vont afficher (fait côté apps, sans attendre le serveur).
3. Ce qu'on ne demande PAS : un nom libre saisi par l'utilisateur rangé sur
   l'annuaire (« Mac du bureau ») — c'est la « commodité » par laquelle C13
   dit qu'elle tombera. S'il en faut un, il vit dans le carnet local des apps.

Le précédent est la Machine, qui a déjà un `nom` « pour l'humain » (§2.3) : le
produit a déjà décidé qu'une étiquette d'affichage n'est pas une donnée
personnelle ; la question n'est que ce qu'on met dedans.

**RÉSOLU (speedy, 2026-09-14) — PR #4 mergée, `main` = `181e291`
(fonctionnalité `f2152f2`), CI verte.** `PUT /v1/appareils/{a}/description`,
pour soi seulement, `nom` refusé (400), table `descriptions` à part — les bancs
relisent sans reprise. `GET /v1/appareils` rend `plateforme` et `modele`,
absents tant qu'ils ne sont pas posés, et ils survivent à la révocation.
**Consommé (oxygen, 2026-09-14)** dans les trois apps : chaque appareil pose
sa description juste après sa preuve (ouvrir, rejoindre, relecture au
lancement), sans la reposer si elle n'a pas changé ; l'écran Compte montre le
modèle à la place de « Autre appareil », la plate-forme dans le sous-titre, et
l'`a-…` toujours dessous. Ce qui part est l'identifiant d'usine
(`iPhone18,1`, `MacBookPro16,1`, `Fairphone FP5`), jamais le nom donné par
l'utilisateur.

**Bancs à jour (speedy, 2026-09-14, ~18:25, puis `0.2.0` le soir même — voir
plus bas) : `nitrogen` et `argon` servaient `181e291`** — paquet construit depuis `main` à ce SHA, binaire vérifié identique
sur les deux, service actif, journal sans erreur. **Bases CONSERVÉES** cette
fois : `181e291` n'ajoute qu'une table `descriptions`, la forme des autres ne
bouge pas, et les `annuaire.redb` existants ont été rouverts tels quels — le
compte `u-5884…` et ses trois appareils sont toujours là et se décriront au
prochain lancement. Une copie `annuaire.redb.avant-181e291-<date>` est posée
sur chaque banc. Attestation toujours `facultative`. Speedy n'a pas rejoué le
PUT lui-même (le harnais QUIC des essais épingle `localhost`) ; **vérifié par
oxygen sur `nitrogen` le 2026-09-14** : le PUT passe, `GET /v1/appareils` rend
`plateforme` et `modele`, l'écran Compte du Fairphone montre « Fairphone FP5 ·
Android » et « MacBookPro15,2 · macOS », aucun 4xx. L'iPhone simulé `a-040F…`
a été révoqué depuis le FP5 (sa clé avait été effacée par les essais iOS ;
corrigé, PR #3 iOS) : il reste dans la liste, marqué révoqué, **sans
description** — il n'en avait pas posé avant, et un appareil révoqué n'en pose
plus. Apps mergées sur `main` : iOS `2633065`, Android `92a5a2c`.

**Bancs à jour (speedy, 2026-09-14, soir) : `nitrogen` et `argon` servent
`0.2.0`, commit `27f8531`** — le merge de la PR serveur #5 (règle de version,
`GET /v1/version`, `asl-server --version`). C'est ce que `asl-server --version`
répond sur chaque banc : « asl-server 0.2.0 (27f8531) » ; service actif,
journal sans erreur. **Bases CONSERVÉES** (rien ne change de forme entre
`181e291` et `27f8531`), sauvegarde `annuaire.redb.avant-0.2.0-<date>` sur
chaque banc, attestation toujours `facultative`. `GET /v1/version` doit rendre
`{"version":"0.2.0"}` sans authentification ; speedy ne l'a pas rejoué contre
les vrais bancs (même limite : le harnais QUIC épingle `localhost`) —
**confirmé par oxygen depuis le Fairphone contre `nitrogen` le 2026-09-14** :
Compte › Annuaire affiche « Version de l'annuaire 0.2.0 », `200`, aucun autre
code vu.

**Dépôts (speedy, 2026-09-14, soir) : `main` serveur `72b1445` (0.2.2), `main`
client `ba11612` (0.2.1).** Depuis 0.2.0 : serveur `3c51eef` (0.2.1, PR #6
d'oxygen — `asl-server` se construit et tourne sur macOS, `getentropy`,
`fcntl`, `sin6_len` sous `cfg`) puis `72b1445` (0.2.2, PR #8 — job CI macOS
qui tient ce port, `check-version.sh` et `check-toolchain.sh` portés sur le
`sed` BSD et le bash 3.2, README « Linux déployé, macOS construit et tourne,
Windows à faire ») ; client `ba11612` (0.2.1, PR #3 — les mêmes deux scripts,
`check-version.sh` identique octet pour octet au serveur). **Les bancs servent
toujours `27f8531` (0.2.0)** : rien entre 0.2.0 et 0.2.2 ne change le
protocole ni le format d'enregistrement, et redéployer n'est pas demandé.
CI verte sur `main` du client à `f0d11a4` (la note ci-dessus) comme sur
`ba11612`, et sur `main` du serveur à `72b1445`.

**Enrôlement de speedy contre l'annuaire local du Mac (speedy, 2026-09-14,
soir) — un `asl` propre passe là où un build modifié rendait 403.** Contexte :
oxygen fait tourner `asl-server` 0.2.1 sur le Mac (`192.168.1.101:6631`,
l'Ethernet ; le Mac a deux pieds sur le LAN et répond par sa route par défaut),
racine de banc `/tmp/racine-oxygene.crt`, `--nom localhost`. Un `asl` de
`target/debug` (0.2.1, `0d11908+`) y avait rendu 403 à l'enrôlement. Rejoué
depuis speedy avec un `asl` PROPRE — `cargo build --release -p asl-cli
--locked` sur `main` à `de92699`, arbre propre, `asl --version` = « asl 0.2.1
(de92699) » sans `+` — et `--etat /tmp/asl-banc` :
- `diagnostic` : connexion établie, liaison exportée, vu
  `[::ffff:192.168.1.102]` (le ping vers le Mac ne répond pas ; QUIC passe).
- `enrole 55FA2-Q5230` : **machine `m-4PF68AK0EFKDA42A6QPYDWYABG`**, code
  dépensé, sortie 0.
- `ou m-7P1CH7NAZNVXHT86PKAW7PK3AP depot` : service `s-7VA70A7TRAHNXT9YS39G92XSJ1`,
  un candidat réflexif `tcp [::ffff:127.0.0.1]:8080`, injoignable d'ici —
  attendu : le daemon du Mac annonce vers un annuaire sur sa propre boucle
  locale, l'annuaire le voit donc en 127.0.0.1.
Conclusion : le 403 tenait au build modifié, pas à l'annuaire ni au port
macOS. Speedy est désormais une machine de banc de ce compte (identité
`/tmp/asl-banc/identite`), à révoquer depuis l'app quand l'essai est fini.

**La grammaire des outils passe en anglais (oxygen, 2026-09-15 — décision de
Thierry).** Commandes, options, variables d'environnement, valeurs et texte de
`--help` en anglais ; les messages d'exécution restent en français pour
l'instant. Oxygen fait `asl` et les apps ; **speedy fait `asl-server`, le
paquet Debian (unité systemd, `attestation.conf.exemple`), les docs serveur
qui citent la ligne de commande, et le redéploiement des bancs** — avec
l'unité systemd mise à jour dans le même paquet. Rupture de ligne de commande
en 0.x : bump mineur. Table, à la lettre :

| `asl-server` | | `asl` | |
|---|---|---|---|
| `--entrepot` | `--store` | `enrole` | `enroll` |
| `--certificat` | `--certificate` | `annonce` | `announce` |
| `--cle` | `--key` | `ou` (deux formes) | `where` |
| `--connexions` | `--connections` | `diagnostic` | `diagnose` |
| `--inactivite` | `--idle` | `identite` | `identity` |
| `--attestation <exigee\|facultative>` | `--attestation <required\|optional>` | `machines`, `version` | inchangés |
| `--apple-environnement <production\|developpement>` | `--apple-environment <production\|development>` | `aide` | `help` |
| `--aide` | `--help` | `--annuaire`, `--racines`, `--etat`, `--nom` | `--directory`, `--roots`, `--state`, `--name` |
| `--port`, `--keepalive`, `--retention`, `--apple-app`, `--version` | inchangés | `ASL_ANNUAIRE`, `ASL_RACINES`, `ASL_ETAT`, `ASL_PATIENCE` | `ASL_DIRECTORY`, `ASL_ROOTS`, `ASL_STATE`, `ASL_TIMEOUT` |

Codes de sortie inchangés. Une ancienne option peut dire la nouvelle dans son
refus (« `--entrepot` n'existe plus : `--store` »).

**La réplication entre les deux racines — chantier serveur (oxygen,
2026-09-15, décision de Thierry).** L'alias `asl-root.air-desktop.org` est
posé chez Gandi, `asl` 0.5.0 le joint sans option et fait tourner les
adresses d'un même nom (le DNS tourne, mais `getaddrinfo` retrie — RFC 6724 —
et mettait toujours `nitrogen` en tête). Et c'est là que ça s'est vu :
**`nitrogen` et `argon` ne se répliquent pas** — le compte `u-5884…` n'existe
que chez `nitrogen`, et une requête sur deux tombait sur `argon` en `401`.
`annuaires.md` §3 dit pourtant que les deux racines se synchronisent : comptes,
clés d'appareils, machines et empreintes, services déclarés, autorisations —
tout sauf l'état vivant (bail, joignabilité), qui se reconstruit seul à la
reconnexion.

En attendant : **l'alias ne pointe que sur `nitrogen`** (un AAAA, un A), et
`argon` ne reçoit pas de trafic. La tournée dans `asl` reste et jouera le jour
venu.

Ce que speedy doit faire, dans l'ordre :

1. **Spécifier** ce que le §3 laisse ouvert (§7.3 : le transport, « QUIC
   comme le reste, probablement ») : un flux entre pairs de même autorité,
   authentifié par leurs clés (§2, l'ancre de confiance) ; quoi se réplique
   (le tableau du §3, à la ligne) ; le sens (les deux écrivent — un compte se
   crée sur l'une ou l'autre selon le tirage) ; **la règle de conflit** quand
   la même chose est écrite des deux côtés (un identifiant à 128 bits ne
   collisionne pas ; une autorisation révoquée d'un côté et vivante de l'autre,
   si) ; le rattrapage d'une racine qui revient après une coupure ; ce qui se
   journalise (C13 : rien de plus que l'entrepôt ne porte déjà).
2. **Coder** dans l'étage 3 (`asl-loop-tokio`, `asl-store`) et le binaire :
   un pair configuré (`--peer <host:port>` et sa clé), la boucle de
   synchronisation, une table de version par enregistrement dans l'entrepôt
   si la règle de conflit l'exige. Couverture et fuzz comme le reste.
3. **Déployer** sur les deux bancs, vérifier qu'un compte créé chez l'une
   est lu chez l'autre après un aller-retour, puis **remettre `argon` dans
   l'alias** (les deux AAAA, les deux A — le jeton Gandi est dans
   `GANDI_TOKEN_DELHAISE`, exporté dans `~/.bashrc` de speedy APRÈS la garde
   interactive : un shell non interactif ne le voit pas, `bash -ic` si).

Les certificats des deux racines portent déjà `asl-root.air-desktop.org`
dans leurs SAN (réémis le 15). Rien à faire côté apps : elles parlent à
`nitrogen` par son nom et ne passent pas par l'alias.

**`asl enrolled` — une machine voit les appareils de son compte : FAIT
(carbon, 2026-09-18).** Le chantier « `asl devices` » (oxygen, 2026-09-15,
spécifié en PR serveur #14) est renommé `enrolled` (décision de Thierry) et
livré en deux PR, branches `enrolled` : serveur #24 (`dca3cf7`, 0.10.0 —
`GET /v1/moi/appareils`, `Exigence::Machine`, même objet et même encodeur que
`GET /v1/appareils`, `401` clé révoquée, essai de bout en bout) et client #10
(`8279f13`, 0.7.0 — `asl enrolled [ACCOUNT]`, `asl machines [ACCOUNT]` sans
argument = le compte courant, `asl-client-tokio::appareils_du_proprietaire`,
ABI inchangée). Un compte étranger à `enrolled` est refusé par `asl` avant
toute requête. Reste : déployer 0.10.0 sur les bancs, depuis speedy, après
merge. Rien à faire côté apps.

**`asl-keystore` — l'attestation sans Google (oxygen, 2026-09-16, décision de
Thierry).** air-desktop ne dépend ni de Google ni d'Apple pour fonctionner :
**Play Integrity est abandonné**, aucun compte Google ne sera ouvert. La
décision et sa raison sont en PR serveur #21 (`attestation-autonome`, 0.8.2,
docs seules) : `protocole.md` §2.1 « Décidé le 2026-09-16 », `contraintes.md`
**C19** (aucun tiers appelé, l'attestation est un choix de l'exploitant, les
racines sont des fichiers), `modele.md` §2.2, et le geste de capture dans
`docs/attestation/capture-keystore.md`. Lis-les en entier avant de coder.

À faire, côté speedy, **serveur** — dans l'ordre :

1. **Retirer `asl-play`** (la crate, sa ligne de lockstep, son fuzz, sa
   section du `Cargo.toml`, ses mentions dans le README) ; la capture du
   2026-09-12 et `capture-play.md` restent comme trace. Ne pas retirer
   `asl-attest` ni `asl-apple` : App Attest reste, hors ligne.
2. **Écrire `asl-keystore`**, étage 2 comme `asl-apple` (aucune entrée-sortie,
   C1 ; 100 % couvert, C2 ; fuzzé, C3 ; pas une ligne de C) : le décodage de la
   chaîne sur le fil (feuille d'abord, chaque DER précédé de sa longueur u16
   BE, racine omissible, borne 8 Kio) ; la chaîne X.509 remontée jusqu'à une
   racine épinglée par `rustls-webpki` (ECDSA P-256/P-384 ET RSA — la racine
   de Google est RSA-4096, l'intermédiaire souvent aussi) ; l'extension
   `1.3.6.1.4.1.11129.2.1.17` de la feuille — un lecteur ASN.1 DER borné pour
   `KeyDescription` (versions de schéma 3, 4, 100, 200, 300 : lis la
   documentation Android « Key and ID Attestation », le schéma a des champs
   optionnels tagués) — avec `attestationChallenge`, `attestationSecurityLevel`,
   `keymintSecurityLevel`, `RootOfTrust` (`verifiedBootState`,
   `deviceLocked`), `osPatchLevel`, et `attestationApplicationId` (paquet +
   empreintes de signature). La vérification : défi = condensat attendu, clé
   publique de la feuille = clé enrôlée, niveaux matériels, démarrage
   `Verified`, notre paquet sous notre empreinte. **Comme pour `asl-apple`, les
   essais fabriquent leur propre chaîne sous leur propre racine**, avec un
   `KeyDescription` écrit à la main, et chaque refus est éprouvé.
3. **Brancher** : `POST /v1/comptes`, plate-forme `2` = Android →
   `asl_keystore::verifier` ; réglages `--android-roots <PEM>` (répétable),
   `--android-app <paquet>`, `--android-signer <empreinte SHA-256 hex>` — les
   trois exigés ensemble, comme `--apple-app`/`--apple-environment` ;
   `asl_auth::decider_attestation` reçoit un `atteste` pour Android ; la
   valeur `android` dans l'enregistrement d'appareil et dans
   `GET /v1/appareils`. Les racines de Google et de GrapheneOS expédiées en
   exemple sous `paquet/racines-android/` (fichiers publics ; cite leur
   provenance en commentaire), aucune épinglée par défaut.
4. **La posture `invitation`** (`--attestation invitation`, plate-forme `3`,
   dix octets = un code émis par l'exploitant, même forme et même durée que
   le code d'enrôlement, l'annuaire n'en garde que l'empreinte) : tranche
   **comment l'exploitant émet le code** — je propose un verbe de
   `asl-server` sur la machine (`asl-server --invite --store …`, qui écrit
   dans l'entrepôt et imprime le code ; l'entrepôt étant verrouillé par le
   daemon, dis comment tu contournes : un socket local, ou un fichier de codes
   que le daemon relit) — et consigne-le dans `protocole.md` §2.1. Si ça
   grossit trop, fais-en une PR à part APRÈS `asl-keystore`.
5. `cargo run --example verifier-une-chaine -- <dossier>` pour la capture
   réelle (`capture-keystore.md`), sur le modèle de `verifier-un-jeton`.
   Bump **mineur** (retrait d'une crate, un réglage exigé de plus), PR non
   mergée, corps en français, « ce qu'oxygen doit reprendre côté Android »
   (le format exact attendu, l'empreinte, ce que la capture doit confirmer).

Côté **client** (`asl`) : rien — l'attestation est la voie appareil. Côté
**Android** (oxygen) : `CleAppareil.kt` génère la clé avec
`setAttestationChallenge(SHA-256(message_d_attestation_de_cle(défi, liaison)))` — sans la clé (serveur 0.9.1, PR #23), `AnnuaireReel`
envoie la chaîne en plate-forme `2`, la dépendance
`com.google.android.play:integrity` et `ActiviteCapture` sont retirées ; la
capture réelle sur le Fairphone 5 est faite d'abord, et c'est elle qui fixe
la politique avant que le verbe soit branché.

**`asl replication` — l'état de la voie entre racines (speedy, 2026-09-16).**
La PR serveur 4/4 (réplication, `main` = 0.8.0 après merge) sert
`GET /v1/replication` **sur la voie machine** (`Exigence::Machine`, comme
`/v1/moi`) : l'exploitant vérifie qu'un banc réplique bien avec l'autre depuis
une machine enrôlée. La réponse est du JSON :

```jsonc
{"pair":"n-…","voie":"ouverte","compteur":4812,"applique":4790}  // avec pair
{"voie":"seule","compteur":4812}                                  // sans pair
```

`voie` ∈ `ouverte` | `coupée` | `seule` ; `compteur` est l'horloge de la
racine, `applique` le curseur qu'elle tient pour le pair (jusqu'où elle a
appliqué ce qu'il a écrit) ; voie ouverte, `applique` rejoint le `compteur` du
pair en une seconde. `docs/replication.md` §8 porte le fond.

**`asl` n'a pas encore de verbe pour ça** : le README serveur dit d'interroger
en brut en attendant. Le chantier, côté client, quand tu voudras : `asl
replication` (ou `asl repl status`), sortie sur le modèle d'`asl machines` —
une ligne qui dit le pair, l'état, et l'écart `compteur − applique` s'il y en
a un —, l'aide en anglais, `asl-client-tokio::etat_de_la_replication`, l'ABI C
inchangée (c'est un verbe de CLI, pas d'ABI), bump mineur. La connexion est
tenue sur la voie machine, comme `asl machines`. Rien à faire côté apps.

~~Pas encore de verbe~~ — **`asl replication`, PR client #11 (0.8.0, `c37793c`,
mergée le 2026-09-21, carbon)** : `Connexion::etat_de_la_replication`
et `Connexion::distante` dans `asl-client-tokio`, `Commande::Replication`,
une ligne par racine jointe (pair, voie, `compteur`, `appliqué`). **Sans
l'écart `compteur − applique`** : le premier jet le rendait, et le journal
des bancs l'a démenti — le curseur `applique` de nitrogen pour argon est
resté à 23 depuis l'amorçage du 19/09 parce qu'argon n'a rien écrit depuis,
et les 12 de différence sont les écritures propres de nitrogen. Ce qui se
conclut : à jour quand l'`appliqué` de l'une égale le `compteur` de l'autre.
**Ce que carbon attend du serveur** : `replication.md` §8 dit « `applique`
rejoint le `compteur` du pair », c'est inexact — à corriger, et la réponse
gagnerait un champ « dernière estampille écrite ici ». Les règles client de
§6 (`asl enroll` essaie l'autre racine sur code refusé ; `401` non définitif
dans la reprise du daemon) restent à faire, à part.

**« Attester un appareil qui rejoint » — spécifié le 2026-09-21 (carbon), à
coder.** PR serveur #27 (`attestation-rejoindre`, 0.11.1, docs seules, mergée
`6aa9f93`) : `protocole.md` §2.2 « Attester un appareil qui rejoint — la preuve
et la chaîne, d'un même défi », `modele.md` §2.2 (valeur `attendue`),
`contraintes.md` C19, `replication.md` §3.2/§5.2 et décision 25. Lis-les en
entier avant de coder. Ce qui est tranché :

- **Le verbe : `POST /v1/attestation`**, sans exigence, sur la connexion où
  `GET /v1/defi` a été tiré AVANT de générer la clé. Corps : genre `a` ‖
  `a-…` ‖ signature (celle de `POST /v1/defi`) ‖ plate-forme ‖ chaîne. Un
  seul défi couvre la preuve et l'attestation. `204`, la connexion est celle
  de l'appareil ; `401` (signature, pas de défi, révoqué, effacé — le même
  pour les quatre) ; `403` (chaîne refusée sous `required`) ; `400`.
- **L'ordre côté nouvel appareil** : connexion nue → défi → clé générée avec
  `SHA-256(message_d_attestation_de_cle(défi, liaison))` → QR → attendre
  `u-…`/`a-…` de l'ancien → `POST /v1/attestation` **sur la même connexion
  tenue**. **Le défi vit ce que vit la connexion** : si elle tombe entre le
  QR et la preuve, nouvelle clé, nouveau QR, et le premier `a-…` reste à
  révoquer depuis Appareils.
- **Posture** : `optional`/`invitation` → `POST /v1/appareils` écrit
  `aucune` comme aujourd'hui, la chaîne fait passer à `android`/`apple`
  (refusée : `204` quand même, journalisé) ; `required` → **`attendue`**,
  cinquième valeur d'`attestation`, `401` à la preuve nue, jamais expirée,
  révocable, vivante pour les orphelins. Les apps 0.6.0/0.7.0 rejoignent une
  racine `optional` comme hier.
- **Réplication** : `appareil-atteste` (identifiant ‖ attestation), appliquée
  toujours, révoqué ou non ; le défi n'est pas répliqué.

Ce que chaque dépôt devra faire :

1. ~~**Serveur (carbon)**~~ — **fait** : PR #29 (0.13.0, `50dbbaf`), déployée
   sur les deux racines le 2026-09-21, voie ouverte, sans reprise de format
   (`attendue` est un octet dans un champ existant). Le corps est
   `asl_api::AttestationDAppareil` ; deux précisions de convergence :
   `appareil-atteste` hisse l'estampille même sans changer la valeur, et
   l'instantané l'émet pour tout appareil prouvé. Le SHA serveur à prendre
   côté client : `50dbbaf`. Ce que le serveur devait faire, pour mémoire :
   `Ressource::Attestation` (`POST`, `Exigence::Aucune`,
   traité avant l'exigence comme `/v1/defi`) ; le corps à queue variable dans
   `asl-api` (modèle `CreationDeCompte`) ; `Attestation::Attendue` dans
   `asl-registre` (format, cran mineur) ; `creer_un_appareil` écrit `attendue`
   sous `required` au lieu de refuser ; la garde `attendue → 401` sur la
   preuve nue ; `attester_un_appareil` (preuve + `verifier_l_attestation` +
   écriture, une transaction) ; l'opération `appareil-atteste` ; `attendue`
   rendu par les deux `GET …/appareils` ; fuzz du décodeur ; journal.
2. ~~**Client (carbon)**~~ — **fait** : PR #13 (0.9.0, `55858c7`) :
   `corps_d_attestation`, `Connexion::attester`, ABI
   `asl_appareil_rejoindre_atteste` + `ASL_CHAINE_REFUSEE = -12`, JNI
   `Natif_rejoindreAtteste`, `connecter` garde la connexion nue qui tient un
   défi, `asl enrolled` dit « en attente d'attestation ». **À reprendre** :
   sur un refus biométrique, le défi est consommé (`defi.take()` avant
   `signer`) — l'app doit recommencer avec une clé neuve alors qu'un nouvel
   essai du geste suffirait ; remettre le défi si le signataire refuse.
   Pour mémoire : `asl-client::appareil` — le message d'attestation
   de clé avant la clé sur une connexion **tenue sans identité**, puis la
   preuve avec chaîne ; `asl-client-tokio` — ne plus fermer la connexion nue à
   `connecter` sous identité quand un défi y attend ; ABI
   `asl_appareil_rejoindre_atteste` (ou équivalent), les quatre liaisons, JNI ;
   `asl enrolled` affiche « en attente ». Bump mineur.
3. ~~**Android (carbon)**~~ — **fait et PROUVÉ EN VRAI le 2026-09-23** :
   le FP5 a rejoint `u-5884…` sous attestation (`a-0FKB0FDCNFSXB4SR15BJEWW2C0`,
   `android` sur les deux racines, répliqué en 19 ms). PR #13 (0.7.1,
   versionCode 12, `05b74ed`) a corrigé ce que l'essai réel a trouvé :
   `AnnuaireReel.rejoindre` prenait le verrou en deux passages (preuve, puis
   l'alias par le réseau, puis le carnet) et ce qui attendait derrière passait
   dans l'intervalle — le temps d'une empreinte — pour détruire une clé qui
   venait de réussir. **À retenir pour iOS** : preuve et carnet sous le même
   verrou, l'alias après en best-effort. PR #12 (0.7.0, versionCode 11,
   `bf5d478`) : `clePourRejoindre()` (connexion nue → défi → clé avec le
   condensat → QR, tenue), `rejoindreAtteste` sur la même connexion,
   `ATTENDUE` dans Appareils, « recommencer » avec clé neuve à la coupure.
   **Pas encore prouvé en vrai** : le chemin n'existe que sans compte, et le
   FP5 est sur `u-5884…` — il faut révoquer `a-18EJ…` depuis le Mac, vider
   l'app, rejoindre avec le Mac comme ancien appareil. Pour mémoire :
   `AnnuaireReel.rejoindre` — le défi et la clé AVANT
   le QR, sur la connexion tenue ; la clé générée avec le condensat ;
   `POST /v1/attestation` à la preuve ; `Appareil.Attestation.ATTENDUE`
   (« en attente d'attestation ») ; le cas de la coupure (recommencer,
   nouvelle clé).
4. **iOS / macOS (oxygen)** : les mêmes ; App Attest quand un iPhone sera là.
   Le Mac (sans enclave attestable) rejoint en `aucune`.

**« Effacer mon compte » — spécifié le 2026-09-18 (carbon), ~~à coder~~
fait :** serveur PR #26 (0.11.0, `5c89c08`, déployé sur les deux racines le
19/09), Android PR #10 (0.6.0, versionCode 9), iOS/macOS PR #14 (0.7.0,
build 12), prouvé sur le FP5 le 20/09 ; client : rien, comme prévu. PR
serveur #25 (`effacer-mon-compte`, 0.10.1, docs seules, mergée) :
`modele.md` §2.1 « Effacer son compte », `protocole.md` §2.2 « Effacer mon
compte — le dernier acte d'une clé », `replication.md` §3.2/§3.3/§5.2/§8 et
décisions 22–24, `contraintes.md` C6/C13/C18. Lis-les en entier avant de
coder. Ce qui est tranché :

- **Le verbe : `DELETE /v1/compte`**, voie appareil, `Exigence::Appareil`,
  sans corps. Une transaction : tous les appareils révoqués (celui qui demande
  compris) et effacés avec jetons et descriptions ; machines révoquées
  (connexions fermées, baux tombés, codes annulés) et effacées avec leurs
  services ; autorisations **retirées** dans les deux sens (l'autre partie ne
  voit plus rien) ; alias **libéré** (réclamation retirée, la file en hérite).
  Reste le `u-…` marqué effacé, date + cause (`titulaire` | `orphelin` |
  `exploitant`). **`204`, puis l'annuaire ferme la connexion** — ce n'est pas
  une panne. `401` sur une clé révoquée ou un compte déjà effacé ; pas de
  `404`. Le journal n'est pas touché à part (90 jours, C18).
- **La règle des orphelins** : un compte dont tous les appareils sont
  **révoqués** (jamais « silencieux », C6) est effacé par la racine **30 jours**
  après la révocation du dernier, cause `orphelin`, journalisé. Réglage
  serveur **`--orphans <days>`**, `0` = jamais, même valeur sur les deux
  racines. Conséquence à dire dans les apps, à l'enrôlement et dans Compte :
  « avec un seul appareil, perdre ce téléphone efface ce compte » (à trente
  jours), et non seulement « pensez à enrôler un second appareil ».
- **`asl-server --forget <u-…> --store <fichier>`**, hors ligne, entrepôt
  arrêté, un identifiant à la fois, cause `exploitant` : l'exception pour les
  trois orphelins de `nitrogen` (`u-24MF…`, `u-6TEE…`, `u-6J5S…`) dont la clé
  a été perdue côté appareil sans révocation.
- **Réplication** : opération `compte-efface`, classe « révocation,
  toujours » ; `appareil-revoque` porte désormais `révoqué le` — l'entrepôt
  n'a aujourd'hui aucune date, la PR de code ajoute `révoqué le` (appareil) et
  `effacé le` + cause (compte), format d'enregistrement, cran mineur.

Ce que chaque dépôt de code devra faire :

1. **Serveur (carbon)** : `Ressource::Compte` (`DELETE`) ; les deux dates et
   la cause dans `asl-registre` (+ fuzz, + reprise des entrepôts existants :
   les appareils déjà révoqués reçoivent la date de la reprise) ; le retrait
   par compte dans `asl-store`, dans une transaction, sur le modèle
   d'`oublier_ce_qui_vient_de` ; le genre `compte-efface` et la date dans
   `appareil-revoque` ; les effets vivants (fermer les connexions du compte,
   ici et à l'application d'une opération reçue) ; `--orphans` et sa tâche,
   à côté d'`expirer_sans_fin` ; `--forget` ; les lignes du journal
   d'exploitation (identifiant + cause ; « appliqué » pour ce qui vient de
   l'autre racine). Bump mineur (format + verbe).
2. **Android (carbon)** : dans Compte, un bouton « Effacer mon compte » (rouge,
   visible comme « Révoquer »), sous biométrie, avec une confirmation qui dit
   ce qui part — les appareils, les machines et leurs services, les accès,
   l'alias — et que rien ne revient ; `DELETE /v1/compte` par `Session` ;
   lire le `204`, ne pas traiter la fermeture qui suit comme une erreur ;
   vider le carnet local, **détruire la clé** dans le Keystore, retour à
   l'écran d'accueil. Le texte « un seul appareil » ci-dessus.
3. **iOS / macOS (oxygen)** : même geste, même confirmation, même séquence ;
   clé détruite dans l'enclave ; **sur le Mac, effacer aussi l'identité de
   machine** du conteneur
   (`…/org.airdesktop.servicelocator.mac/Data/Library/Application Support/asl/identite`),
   puisque sa clé est révoquée et qu'`asl` la lit par défaut.
4. **Client (`asl`)** : **rien.** Une machine ne décide pas du compte ; elle
   voit sa connexion fermée puis `401`, comme d'une révocation de clé. Pas de
   verbe, pas d'ABI.

### Ce que speedy attend d'oxygen

**Une CAPTURE réelle**, pour figer deux vérifications d'attestation aujourd'hui
bâties sur la documentation seule : `asl-apple` et `asl-play` compilent et sont
fuzzés, mais leurs constantes ne sont pas confirmées par un vrai appareil, et
`--attestation exigee` reste dangereux tant qu'on ne les a pas confrontées à ça.

1. **App Attest (iPhone réel)** — l'objet d'attestation CBOR produit par
   `outils-capture/CaptureAppAttest.swift` sur un défi fourni par le serveur, en
   hexadécimal ou base64, avec le `keyId`, le `bundleId` (`teamId.bundle`) et
   l'environnement (`appattest` ou `appattestdevelop`). De quoi confirmer les
   constantes d'`asl-apple` : aaguid, chaîne jusqu'à la racine Apple, nonce =
   SHA256(authData ‖ SHA256(défi)), rpIdHash, compteur.
2. **L'attestation de clé Android (Fairphone 5)** — depuis le 2026-09-16, à
   la place de Play Integrity (abandonné, C19) : la chaîne de certificats
   d'une clé générée avec `setAttestationChallenge`, le défi, le paquet et
   l'empreinte de signature de la build, selon
   `docs/attestation/capture-keystore.md` du dépôt serveur. De quoi confirmer
   la forme de `KeyDescription` et fixer la politique d'`asl-keystore`. Aucune
   clé Play Console, aucun compte : rien à attendre de personne.

**En attendant l'iPhone — une app macOS d'enrôlement (speedy, 2026-09-13).** Pour
valider la chaîne **clé-d'appareil P-256** (Secure Enclave + Touch ID) sur du **vrai
matériel Apple** sans attestation : consignes dans le dépôt serveur
`docs/attestation/enrolement-macos.md`. Le code iOS (`CleAppareil` — déjà des branches
macOS —, `AnnuaireReel` — crée déjà en `ASL_PLATEFORME_AUCUNE`) se réutilise presque
tel quel ; le neuf = une **cible macOS**, une UI minimale, et le **xcframework construit
pour macOS** (slice `aarch64-apple-darwin`, côté CE dépôt). Compte créé en `attestation
Aucune` contre `nitrogen` → valide `asl-cle` et l'enrôlement, **pas** `asl-apple` (App
Attest n'existe pas sur macOS ; l'iPhone reste requis pour l'attestation).

**La capture Play du 2026-09-12** (branche serveur `capture-play-integrity`,
`docs/attestation/captures/`) reste comme trace : elle avait confirmé la grammaire
JWE/JWS, sous les clés de Google. Elle ne sert plus à rien depuis l'abandon.

Dépose-les dans le dépôt serveur (`docs/attestation/`) ou signale-les à speedy.
C'est le dernier verrou avant que l'attestation soit exigible en production.

## Les règles qui ne se négocient pas

- **La grammaire d'`asl` est en anglais** — commandes, options, variables
  d'environnement, `--help` — et ses messages en français. Un ajout à la
  ligne de commande se nomme en anglais ; un ajout au texte d'un message, en
  français. (Décision de Thierry, 2026-09-15 ; la table est plus haut.)

- **Une seule toolchain, celle d'Air** (`rust-toolchain.toml`,
  `nightly-2026-07-11`). Elle ne se modifie pas seule.
- **Pas une ligne de C** (C4), **jamais une autre pile QUIC** (C15) : les deux
  sont vérifiés sur le graphe résolu par `check-sans-c.sh` et `check-pile.sh`.
- **L'ABI est un contrat** (C12) : un ajout est libre et s'inscrit dans
  `abi.txt` ET `include/asl.h` dans le même commit ; un retrait est une
  rupture majeure.
- **Chaque PR change la version semver (`MAJOR.MINOR.PATCH`) de
  l'application, dans le commit qui porte le changement ; une PR qui ne change
  pas la version ne se merge pas.** La version vit à un endroit,
  `[workspace.package] version` dans `Cargo.toml`, et TOUT la suit en
  lockstep : les arêtes internes de `[workspace.dependencies]`, les deux
  verrous (`cargo update --workspace --offline`, ici et dans `fuzz/`), et les
  liaisons — `liaisons/python/pyproject.toml`, `liaisons/ruby/asl.gemspec`,
  `liaisons/kotlin/build.gradle.kts`, `liaisons/cpp/CMakeLists.txt`. Le cran
  est un jugement sur le changement (ajout compatible : mineur ; correction :
  patch ; rupture d'ABI ou de protocole : majeur) ; la revue le porte, et
  `scripts/check-version.sh` — lancé par la CI sur chaque PR — ne juge que le
  fait qu'elle ait bougé, dans le bon sens, et que les crates la partagent.
  `asl --version` dit la version et le commit du binaire ; l'annuaire rend la
  sienne par `GET /v1/version`.
- **Ce qui est exempté, et c'est tranché (Thierry, 2026-09-14) : les notes de
  coordination** — ce fichier, section « Ce que l'autre session attend » et
  ses réponses. Elles vont sur `main` en commit direct, sans PR ni bump.
  **Tout ce qui touche au code, aux spécifications, à la CI ou aux scripts
  passe par PR et change la version.**
- `scripts/check-tout.sh` avant de pousser ; sur macOS, les barrières une à
  une (voir ci-dessus).
- **Ce dépôt est PUBLIC.** Aucun secret dans un commit, un message, un fichier.
- **Commits** : en français, *conventional commits*, **signés GPG** (clé
  `C99EBB9BA26773011F924C4CA9F56C4D9F59EE03`), avec
  `Signed-off-by: Thierry DELHAISE <thierry.delhaise@gmail.com>`. **Aucune
  mention d'Anthropic, de Claude, ni de `Co-Authored-By`**, nulle part.
- **Ne commits et ne pushes que si Thierry le demande.** Sur la branche par
  défaut, branche d'abord.
- **Après chaque push, lis la CI** (`gh run watch`), et rapporte ce qu'elle dit.
- Le style du dépôt est exigeant et EXPLIQUÉ : le code dit pourquoi, pas
  seulement quoi. Lis un fichier existant avant d'en écrire un, et tiens le même
  registre.
