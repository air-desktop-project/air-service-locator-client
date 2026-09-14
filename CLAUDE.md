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
code vu. Côté dépôts :
`main` serveur `27f8531`, `main` client `9a34511`, tous deux en `0.2.0`.

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
2. **Play Integrity (Android réel)** — un jeton renvoyé par
   `outils-capture/CaptureIntegrity.kt`, **plus les deux clés Play Console** de la
   « réponse chiffrée gérée par le développeur » : la clé de déchiffrement
   AES-256 et la clé publique de vérification EC (SPKI). De quoi écrire la
   politique de verdict d'`asl-play` (aujourd'hui seul le cœur crypto existe :
   JWE→JWS→JSON, sans décision sur le contenu du verdict).

**En attendant l'iPhone — une app macOS d'enrôlement (speedy, 2026-09-13).** Pour
valider la chaîne **clé-d'appareil P-256** (Secure Enclave + Touch ID) sur du **vrai
matériel Apple** sans attestation : consignes dans le dépôt serveur
`docs/attestation/enrolement-macos.md`. Le code iOS (`CleAppareil` — déjà des branches
macOS —, `AnnuaireReel` — crée déjà en `ASL_PLATEFORME_AUCUNE`) se réutilise presque
tel quel ; le neuf = une **cible macOS**, une UI minimale, et le **xcframework construit
pour macOS** (slice `aarch64-apple-darwin`, côté CE dépôt). Compte créé en `attestation
Aucune` contre `nitrogen` → valide `asl-cle` et l'enrôlement, **pas** `asl-apple` (App
Attest n'existe pas sur macOS ; l'iPhone reste requis pour l'attestation).

**Capture Play déjà là, partielle.** Une première capture réelle est sur la branche
serveur `capture-play-integrity` (`docs/attestation/captures/`) : elle **confirme la
grammaire** (JWE `A256KW`/`A256GCM` → JWS, vérifié octet pour octet — 5 segments, CEK 40,
IV 12, tag 16), mais le jeton est sous les **clés gérées par Google** ; le verdict attend
encore les deux clés « gérées par moi » du point 2.

Dépose-les dans le dépôt serveur (`docs/attestation/`) ou signale-les à speedy.
C'est le dernier verrou avant que l'attestation soit exigible en production.

## Les règles qui ne se négocient pas

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
