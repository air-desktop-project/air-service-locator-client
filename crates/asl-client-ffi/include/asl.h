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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ASL_H */
