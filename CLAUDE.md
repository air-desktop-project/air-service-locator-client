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
| `scripts/construire-mobile.sh [ios\|android]` | Produit `target/mobile/AslClient.xcframework` et `target/mobile/jniLibs/arm64-v8a/libasl_client_android.so`. Pas une barrière : il se lance sur le Mac, et dans la CI de chaque application, pour sa moitié. |

Et deux changements qui touchent tout le dépôt :

- **Le SHA des dépendances serveur est avancé de `7174ac8` à `cee3170`**, pour
  prendre `asl-api` (la grammaire des corps mobiles) et la clé d'appareil
  P-256 d'`asl-cle`. `asl-api` s'ajoute aux trois crates tirées du serveur.
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
