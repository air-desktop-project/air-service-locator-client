/* asl.h — l'ABI C d'air-service-locator.
 *
 * CE FICHIER EST LE CONTRAT, AU MÊME TITRE QUE `abi.txt`.
 *
 * Cinq liaisons passent par ici — Python, Ruby, C++, Kotlin, Swift. Elles vivent
 * dans du code que nous ne voyons pas et ne se mettent pas à jour au même
 * rythme. Un AJOUT est libre ; un RETRAIT casse chez des gens qu'on ne peut ni
 * prévenir ni corriger, et appartient à une version majeure.
 *
 * IL EST ÉCRIT À LA MAIN, ET NON ENGENDRÉ. `cbindgen` produirait des
 * déclarations justes et des commentaires absents — or ce qui se perd entre Rust
 * et cinq langages n'est pas la signature, c'est la RAISON. Pourquoi une
 * fonction rend la main sans avoir rien ouvert, pourquoi un verdict a quatre
 * valeurs et non deux, pourquoi libérer le client retire l'annonce : rien de
 * cela ne s'engendre.
 *
 * `scripts/check-abi.sh` vérifie que ce fichier, `abi.txt` et les symboles
 * réellement exportés par la bibliothèque disent tous la même chose.
 *
 * Licence : MPL-2.0.
 */

#ifndef ASL_H
#define ASL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── LES CODES ──────────────────────────────────────────────────────────────
 *
 * ZÉRO OU NÉGATIF, JAMAIS UNE VALEUR UTILE. Une fonction qui rendrait tantôt un
 * compte, tantôt un code obligerait chaque liaison à connaître la frontière
 * entre les deux — et l'une des cinq la placerait ailleurs. Ce qui est utile
 * sort par un pointeur fourni par l'appelant.
 */
#define ASL_OK                 0
#define ASL_ARGUMENT          -1
#define ASL_CONFIGURATION     -2
#define ASL_INJOIGNABLE       -3
#define ASL_REFUSE            -4
#define ASL_TAMPON_TROP_PETIT -5
#define ASL_INTERNE           -6
#define ASL_PAS_D_IDENTITE    -7
#define ASL_DEJA              -8
/* Pas une panne : l'annuaire ne pousse que ce qui a CHANGÉ, et un service dont
 * les sondes confirment ce qu'il disait déjà n'en produit aucune. Le distinguer
 * d'une liste vide évite de faire croire que les points sont devenus
 * injoignables. */
#define ASL_PAS_DE_POUSSEE    -9
/* Voie mobile : cet appareil n'est pas connecté — asl_appareil_connecter. */
#define ASL_NON_CONNECTE      -10
/* Voie mobile : le signataire de l'application n'a pas rendu de signature.
 * Pas une panne : le PORTEUR n'a pas confirmé, ou a annulé. Rien n'est parti. */
#define ASL_SIGNATURE_REFUSEE -11

/* Tailles de tampons que l'appelant doit fournir. */
#define ASL_IDENTIFIANT_OCTETS 29
#define ASL_GRAINE_OCTETS      32

/* Protocoles. */
#define ASL_TCP 1
#define ASL_UDP 2

/* D'où vient une adresse : observée par l'annuaire, ou annoncée par le daemon. */
#define ASL_REFLEXIF 1
#define ASL_ANNONCE  2

/* Ce que l'annuaire sait d'un point d'écoute.
 *
 * LES TROIS DERNIERS NE VEULENT PAS DIRE « ÇA NE MARCHE PAS ».
 * `ASL_EN_COURS` n'affirme rien — l'annuaire n'a pas fini de mesurer.
 * `ASL_NON_SONDE` dit qu'il ne mesurera pas : UDP n'a pas de poignée de main,
 * donc une sonde n'y distinguerait pas « écoute et ignore » de « rien
 * n'écoute ». Les aplatir en un booléen ferait écarter un candidat bon.
 */
#define ASL_JOIGNABLE         1
#define ASL_INJOIGNABLE_POINT 2
#define ASL_NON_SONDE         3
#define ASL_EN_COURS          4

/* Le daemon est-il derrière un NAT ?
 *
 * TROIS VALEURS, ET NON UN BOOLÉEN. L'annuaire tranche en comparant ce qu'il
 * OBSERVE à ce que le daemon ANNONCE ; si le daemon n'a annoncé aucune adresse
 * locale, il n'y a rien à comparer. Un booléen forcerait à répondre « non »,
 * c'est-à-dire à affirmer une chose qu'on n'a pas mesurée — et un daemon
 * derrière un NAT qui lirait « non » chercherait la panne partout sauf là où
 * elle est.
 */
#define ASL_NAT_NON          1
#define ASL_NAT_OUI          2
#define ASL_NAT_INDETERMINE  3

/* ── LES STRUCTURES ─────────────────────────────────────────────────────────
 *
 * AUCUN TROU IMPLICITE. Cinq langages calculent la disposition chacun de son
 * côté ; un octet de bourrage que le compilateur choisit est l'endroit exact où
 * deux d'entre eux choisiront différemment. Les champs vont du plus large au
 * plus étroit, et le reste est un `reserve` NOMMÉ, à zéro.
 */

/* Un point d'écoute à annoncer. 4 octets. */
typedef struct {
    uint16_t port;      /* jamais zéro */
    uint8_t  protocole; /* ASL_TCP ou ASL_UDP */
    uint8_t  reserve;   /* à zéro */
} asl_point;

/* Où joindre un service, et ce qu'on en sait. 24 octets. */
typedef struct {
    uint8_t  adresse[16]; /* ordre réseau ; les 4 premiers octets en IPv4 */
    uint16_t port;
    uint8_t  protocole;   /* ASL_TCP ou ASL_UDP */
    uint8_t  famille;     /* 4 ou 6 */
    uint8_t  origine;     /* ASL_REFLEXIF ou ASL_ANNONCE */
    uint8_t  verdict;     /* ASL_JOIGNABLE, ASL_INJOIGNABLE_POINT, … */
    uint8_t  reserve[2];  /* à zéro */
} asl_candidat;

/* Ce que l'attache a fait jusqu'ici. 24 octets. */
typedef struct {
    uint64_t attaches;   /* combien de fois on s'est attaché */
    uint64_t ruptures;   /* combien de fois une attache établie s'est rompue */
    uint8_t  attachee;   /* 1 si l'annuaire nous connaît EN CE MOMENT */
    uint8_t  abandonnee; /* 1 si la tâche a renoncé — configuration seulement */
    uint8_t  reserve[6]; /* à zéro */
} asl_etat_t;

/* Le client. Opaque : sa taille et sa disposition ne font pas partie du
 * contrat, et changeront.
 *
 * IL NE SE PARTAGE PAS ENTRE FILS. L'authentification est portée par la
 * connexion : ce qu'une requête a le droit de faire dépend de la clé prouvée sur
 * celle-là. Deux fils qui partageraient un client partageraient leurs droits.
 */
typedef struct asl_client asl_client;

/* ── CE QUI NE TOUCHE À RIEN ────────────────────────────────────────────── */

/* La version de cette bibliothèque. Un pointeur nul est simplement ignoré. */
void asl_version(uint32_t *majeur, uint32_t *mineur, uint32_t *correctif);

/* Ce que veut dire un code.
 *
 * RIEN À LIBÉRER : la chaîne est statique et vit aussi longtemps que la
 * bibliothèque est chargée. Une chaîne allouée obligerait cinq liaisons à penser
 * à la libérer — sur le chemin d'erreur, celui qu'on éprouve le moins.
 */
const char *asl_faute_texte(int32_t code);

/* ── LA CONSTRUCTION ────────────────────────────────────────────────────── */

/* Crée un client. IL N'OUVRE AUCUNE CONNEXION : un annuaire injoignable ne doit
 * pas empêcher un daemon de démarrer. Se libère par asl_client_libere. */
int32_t asl_client_neuf(asl_client **sortie);

/* Ajoute un annuaire. Répétable.
 *
 * `adresse` est LITTÉRALE — « 203.0.113.7:6630 » ou « [2001:db8::1]:6630 » —,
 * jamais un nom : la résolution appartient à l'appelant, qui a déjà son
 * résolveur, sa politique de cache et ses fils. L'utilitaire `asl` fait le sien
 * avec getaddrinfo.
 *
 * `nom` est celui qu'on EXIGE du certificat. Il n'est pas déduit de l'adresse,
 * et il ne peut pas l'être : le déduire reviendrait à faire confiance à qui
 * répond à cette adresse, ce que le certificat existe pour éviter.
 *
 * L'IPv6 est essayé d'abord quel que soit l'ordre des appels ; à l'intérieur
 * d'une famille, c'est cet ordre qui décide.
 */
int32_t asl_client_annuaire(asl_client *client, const char *adresse, const char *nom);

/* Pose les certificats d'autorité, en PEM.
 *
 * IL N'Y A PAS DE REPLI SUR LE MAGASIN DU SYSTÈME : les annuaires racines sont
 * signés par LEUR autorité, et se rabattre en silence sur les centaines de
 * racines d'un système ferait accepter un certificat qu'aucune n'aurait émis.
 */
int32_t asl_client_racines(asl_client *client, const uint8_t *pem, size_t taille);

/* Installe l'identité de cette machine : son identifiant en texte, et les
 * trente-deux octets dont la clé se dérive — ceux qu'asl_enroler a rendus.
 *
 * LA CLÉ EST DÉRIVÉE, ET NON TRANSPORTÉE. La qualité de la graine et sa
 * conservation appartiennent à l'appelant : une graine tirée d'un compteur
 * serait devinable, et toute l'authentification repose là-dessus.
 */
int32_t asl_client_identite(asl_client *client, const char *machine,
                            const uint8_t graine[ASL_GRAINE_OCTETS]);

/* Libère le client — ET RETIRE L'ANNONCE EN LE FAISANT.
 *
 * La connexion EST le bail : rendre le client rend l'annonce. Elle est fermée
 * proprement, ce qui épargne à l'annuaire la minute d'inactivité pendant
 * laquelle il donnerait une adresse morte. Un pointeur nul ne fait rien.
 */
void asl_client_libere(asl_client *client);

/* ── LES VERBES ─────────────────────────────────────────────────────────── */

/* Présente un code d'enrôlement, et rend l'identité obtenue.
 *
 * L'identité est INSTALLÉE dans le client au passage : le code est dépensé, et
 * obliger l'appelant à la réinstaller lui ferait perdre, s'il oubliait, la clé
 * que l'annuaire vient d'accepter. Elle est aussi rendue, pour qu'il la
 * conserve : c'est le seul justificatif durable de cette machine.
 */
int32_t asl_enroler(asl_client *client, const char *code,
                    char machine_sortie[ASL_IDENTIFIANT_OCTETS],
                    uint8_t graine_sortie[ASL_GRAINE_OCTETS]);

/* Annonce ce service, ET REND LA MAIN TOUT DE SUITE.
 *
 * L'annonce est tenue en tâche de fond aussi longtemps que le client vit : elle
 * se réauthentifie et se réannonce seule à chaque reconnexion, et bascule sur
 * l'autre annuaire racine quand le premier tombe. asl_etat dit où elle en est.
 *
 * UN CLIENT N'ANNONCE QU'UNE FOIS : un second appel rend ASL_DEJA plutôt que de
 * remplacer la première en silence, ce qui la retirerait.
 */
int32_t asl_annoncer(asl_client *client, const char *service,
                     const asl_point *points, size_t combien);

/* Où l'attache en est. Un client qui n'a jamais annoncé rend un état à zéro. */
int32_t asl_etat(const asl_client *client, asl_etat_t *sortie);

/* Demande où joindre un service, et rend les candidats DANS L'ORDRE.
 *
 * LE TAMPON SE DIMENSIONNE EN DEUX TEMPS : avec `candidats` nul, ou `combien`
 * trop petit, la fonction écrit dans `ecrit` le nombre qu'il faudrait et rend
 * ASL_TAMPON_TROP_PETIT. C'est l'usage du C, et il évite d'allouer pour le
 * compte de l'appelant — donc de lui faire libérer avec un allocateur qui n'est
 * pas le nôtre.
 */
int32_t asl_ou(asl_client *client, const char *machine, const char *service,
               asl_candidat *candidats, size_t combien, size_t *ecrit);

/* Combien de poussées de verdict sont arrivées depuis le départ.
 *
 * ZÉRO N'EST PAS UNE ANOMALIE : l'annuaire ne pousse que ce qui a CHANGÉ.
 */
int32_t asl_poussees_recues(const asl_client *client, uint64_t *sortie);

/* Ce que l'annuaire a MESURÉ depuis, et poussé sur la connexion tenue.
 *
 * L'annuaire répond `en_cours` à une annonce pour ne pas faire attendre un
 * démarrage le temps d'une sonde vers une machine qui peut ne jamais répondre.
 * SANS CETTE PORTE, un daemon reste à croire que sa joignabilité est en cours de
 * mesure, pour toujours.
 *
 * Elle porte la LISTE ENTIÈRE, et non un delta : la dernière poussée remplace
 * tout ce qui précède, et l'appeler deux fois rend deux fois la même chose tant
 * qu'aucune autre n'est arrivée.
 *
 * `derriere_nat` peut être nul si l'appelant ne s'y intéresse pas. Le tampon se
 * dimensionne en deux temps, comme pour asl_ou.
 *
 * Rend ASL_PAS_DE_POUSSEE tant que rien n'a été poussé.
 */
int32_t asl_derniere_poussee(const asl_client *client,
                             asl_candidat *candidats, size_t combien,
                             size_t *ecrit, uint8_t *derriere_nat);

/* ── LA VOIE MOBILE ─────────────────────────────────────────────────────────
 *
 * CE QU'UN TÉLÉPHONE APPELLE, ET RIEN D'AUTRE. Un handle à part du client des
 * daemons, parce qu'un téléphone n'est pas un daemon : il ADMINISTRE un compte
 * (`protocole.md` §2), sa clé P-256 vit dans la Secure Enclave ou le Keystore
 * sous contrôle biométrique, et ses requêtes sont celles d'un écran.
 *
 * LA SIGNATURE SE FAIT PAR RAPPEL. Cette bibliothèque ne détient jamais la clé
 * d'un appareil — le matériel ne la rend pas. L'application pose une fonction et
 * un contexte (asl_appareil_cle), que la bibliothèque appelle avec les octets à
 * signer au moment exact où le protocole les exige : c'est LÀ que le porteur
 * pose son doigt. Le rappel est fait SUR LE FIL DE L'APPELANT, à l'intérieur de
 * l'appel qui l'a provoqué — donc jamais depuis le fil d'interface.
 *
 * UNE CONNEXION TENUE. L'authentification est portée par la connexion : la clé
 * est prouvée une fois (asl_appareil_connecter), et toutes les requêtes en
 * héritent. Un geste par requête serait intenable ; la connexion est donc gardée
 * vivante en tâche de fond jusqu'à asl_appareil_deconnecter. Elle NE SE
 * RECONNECTE PAS SEULE : reprouver la clé, c'est redemander un geste, et c'est
 * l'application qui choisit quand.
 *
 * UN SEUL FIL À LA FOIS : les appels sur un même handle ne se chevauchent pas.
 */

/* Une clé publique d'appareil : P-256, SEC1 compressé. */
#define ASL_CLE_APPAREIL_OCTETS 33
/* Une signature d'appareil : r ‖ s. */
#define ASL_SIGNATURE_OCTETS 64
/* Un défi, et une liaison de canal. */
#define ASL_DEFI_OCTETS 32
/* Le plus long message qu'un signataire recevra. */
#define ASL_MESSAGE_MAX 138
/* L'attestation la plus longue que l'annuaire admette. */
#define ASL_ATTESTATION_MAX 8192

#define ASL_PLATEFORME_AUCUNE 0
#define ASL_PLATEFORME_APPLE  1
#define ASL_PLATEFORME_GOOGLE 2

/* L'appareil. Opaque, comme asl_client. */
typedef struct asl_appareil asl_appareil;

/* Ce que l'application pose pour signer : reçoit `taille` octets, écrit
 * ASL_SIGNATURE_OCTETS octets `r ‖ s` dans `signature`, rend 0. Toute autre
 * valeur : le porteur n'a pas signé, et l'appel rend ASL_SIGNATURE_REFUSEE. */
typedef int32_t (*asl_signataire)(void *contexte, const uint8_t *message,
                                  size_t taille, uint8_t *signature);

/* Crée un appareil. N'ouvre aucune connexion. Se libère par asl_appareil_libere. */
int32_t asl_appareil_neuf(asl_appareil **sortie);

/* Un annuaire, comme asl_client_annuaire : adresse littérale, nom du certificat. */
int32_t asl_appareil_annuaire(asl_appareil *appareil, const char *adresse, const char *nom);

/* Les racines, comme asl_client_racines : PEM, et aucun repli sur le système. */
int32_t asl_appareil_racines(asl_appareil *appareil, const uint8_t *pem, size_t taille);

/* La clé publique de cet appareil (33 octets, VÉRIFIÉE sur la courbe) et la
 * fonction qui signe avec. `contexte` est rendu tel quel au rappel. */
int32_t asl_appareil_cle(asl_appareil *appareil, const uint8_t cle[ASL_CLE_APPAREIL_OCTETS],
                         asl_signataire signataire, void *contexte);

/* L'identifiant `a-…` de cet appareil, s'il est déjà enrôlé — ce que
 * asl_appareil_creer_compte a rendu la première fois. */
int32_t asl_appareil_identite(asl_appareil *appareil, const char *identifiant);

/* Libère l'appareil, et ferme sa connexion proprement. Un pointeur nul ne fait rien. */
void asl_appareil_libere(asl_appareil *appareil);

/* Ouvre la connexion — IPv6 d'abord, la tournée des annuaires — et PROUVE LA CLÉ
 * si une identité est posée : c'est ici que le signataire est appelé, une fois.
 * Sans identité, la connexion s'ouvre nue, d'où l'on crée un compte. Une
 * connexion déjà ouverte est fermée d'abord. ASL_INJOIGNABLE si personne ne
 * répond, ASL_REFUSE si la preuve ne vérifie pas. */
int32_t asl_appareil_connecter(asl_appareil *appareil);

/* Ferme la connexion, proprement. */
int32_t asl_appareil_deconnecter(asl_appareil *appareil);

/* La liaison de canal de la connexion en cours (32 octets). Elle n'a qu'un
 * emploi côté application : entrer dans ce qu'une attestation couvre. */
int32_t asl_appareil_liaison(asl_appareil *appareil, uint8_t liaison[ASL_DEFI_OCTETS]);

/* Tire un défi (32 octets) sur la connexion en cours. Il ne sert qu'une fois,
 * et c'est le prochain asl_appareil_creer_compte qui le dépense — utile
 * seulement pour composer une attestation par-dessus. */
int32_t asl_appareil_defi(asl_appareil *appareil, uint8_t defi[ASL_DEFI_OCTETS]);

/* Ce dont une attestation couvre le condensat : domaine ‖ clé ‖ défi ‖ liaison,
 * avec le défi d'asl_appareil_defi et la liaison en cours. Tampon en deux temps. */
int32_t asl_appareil_message_pour_attestation(asl_appareil *appareil, uint8_t *sortie,
                                              size_t combien, size_t *ecrit);

/* Crée le compte et enrôle cet appareil. LE PORTEUR EST SOLLICITÉ ICI : le
 * signataire est appelé sur la preuve de possession. Le défi est celui
 * d'asl_appareil_defi s'il en reste un, un neuf sinon. `attestation` est vide
 * pour ASL_PLATEFORME_AUCUNE, exigée pour les autres. Rend `u-…` et `a-…` en
 * texte, NUL compris ; l'identité est INSTALLÉE au passage, et la connexion est
 * désormais celle de cet appareil. */
int32_t asl_appareil_creer_compte(asl_appareil *appareil, uint8_t plateforme,
                                  const uint8_t *attestation, size_t taille,
                                  char compte_sortie[ASL_IDENTIFIANT_OCTETS],
                                  char appareil_sortie[ASL_IDENTIFIANT_OCTETS]);

/* Une requête de protocole.md §2 sur la connexion tenue : méthode (GET, POST,
 * PUT, PATCH, DELETE), chemin (`/v1/…`), corps JSON ou vide.
 *
 * LE CODE D'ÉTAT EST RENDU, JAMAIS JUGÉ : ASL_OK veut dire que l'annuaire a
 * répondu — 404, 409, 204 compris —, et l'application sait quoi en dire.
 * ASL_INJOIGNABLE veut dire que la connexion est tombée : asl_appareil_connecter.
 *
 * Tampon en deux temps, comme asl_ou — ET LA REQUÊTE A ÉTÉ FAITE quand
 * ASL_TAMPON_TROP_PETIT est rendu. Passez d'emblée un tampon de la taille du
 * plus long corps attendu (64 Kio suffisent à tout ce que l'annuaire rend). */
int32_t asl_appareil_requete(asl_appareil *appareil, const char *methode, const char *chemin,
                             const uint8_t *corps, size_t taille,
                             uint8_t *sortie, size_t combien, size_t *ecrit, uint16_t *statut);

/* L'identifiant `a-…` de cet appareil, s'il est enrôlé. ASL_PAS_D_IDENTITE sinon. */
int32_t asl_appareil_identifiant(const asl_appareil *appareil, char sortie[ASL_IDENTIFIANT_OCTETS]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ASL_H */
