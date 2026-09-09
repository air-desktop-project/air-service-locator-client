// asl.hpp — la liaison C++ d'air-service-locator. **En-tête seul.**
//
// ── ELLE NE TRANSCRIT RIEN, ET C'EST SA PARTICULARITÉ ──────────────────────
//
// Python et Ruby doivent RECOPIER `asl.h` : constantes, dispositions, tailles.
// Rien dans ces langages ne relie la copie à l'original, et une barrière entière
// existe de chaque côté pour les comparer.
//
// C++ est le seul des cinq qui puisse INCLURE le contrat. Il n'y a donc pas de
// seconde source à faire diverger, et pas de barrière de conformité à écrire :
// le compilateur est la barrière. Ce fichier ne fait qu'habiller.
//
// ── ELLE NE LÈVE JAMAIS, ET C'EST UNE DÉCISION ─────────────────────────────
//
// Beaucoup de bases C++ se construisent avec `-fno-exceptions` — jeux, audio,
// embarqué, moteurs de rendu. Une bibliothèque qui imposerait les exceptions à
// son hôte commettrait exactement la faute que ce produit refuse partout
// ailleurs : décider à la place de qui nous embarque.
//
// Les fautes sortent donc en `enum class Faute`, et **chaque fonction qui en rend
// une est `[[nodiscard]]`**. C'est ce qui remplace l'exception : en Python un code
// de retour oublié est invisible, ici le compilateur le dit.
//
// ── ELLE N'ALLOUE RIEN QUE VOUS DEVIEZ LIBÉRER ─────────────────────────────
//
// Le pointeur opaque vit dans un `Client` déplaçable et non copiable ; son
// destructeur le rend. Rien de ce que la bibliothèque native alloue ne traverse.
//
// ── SUR LES FILS ───────────────────────────────────────────────────────────
//
// **Objets distincts : sûr. Même objet : non sûr.** C'est la convention de la
// bibliothèque standard, et tout le monde en C++ la connaît.
//
// Les liaisons Python et Ruby posent un verrou parce que, là-bas, personne ne lit
// cette phrase — et parce que deux appels concurrents aliaseraient un `&mut` du
// côté Rust, ce qui est un comportement indéfini et non un ralentissement. Ici
// la phrase suffit : un verrou rendrait `Client` non déplaçable, ou coûterait une
// allocation pour un `std::mutex` dont l'immense majorité des porteurs n'ont
// aucun besoin.
//
// **Et la question du GVL ne se pose pas** — il n'y en a pas. Elle est nommée ici
// parce qu'un lecteur venu de la liaison Python la cherchera.
//
// ── CE QU'IL FAUT POUR COMPILER ────────────────────────────────────────────
//
// C++17, et rien de plus. Pas de `std::expected` (C++23), pas de `std::span`
// (C++20) : cette bibliothèque est embarquée par du code dont nous ne choisissons
// pas la chaîne de compilation.

#ifndef ASL_HPP
#define ASL_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "asl.h"

namespace asl {

// ── LES TAILLES, PROUVÉES À LA COMPILATION ─────────────────────────────────
//
// Python et Ruby vérifient les mêmes nombres à l'exécution, parce qu'ils ne
// peuvent pas faire mieux. Ici, le compilateur qui construira le programme du
// porteur — celui-là même, avec ses options — est celui qui répond.
static_assert(sizeof(asl_point) == 4, "asl_point n'a pas la taille annoncée");
static_assert(sizeof(asl_candidat) == 24, "asl_candidat n'a pas la taille annoncée");
static_assert(sizeof(asl_etat_t) == 24, "asl_etat_t n'a pas la taille annoncée");

// ── LES CODES ───────────────────────────────────────────────────────────────

/// Ce qui a empêché un appel d'aboutir.
///
/// **`Injoignable` ET `Refuse` SONT DEUX CHOSES.** Un câble débranché et un droit
/// manquant se corrigent à des endroits opposés, et les confondre envoie chercher
/// au mauvais.
enum class Faute : std::int32_t {
    Ok = ASL_OK,
    /// Une adresse illisible, un port nul, une graine de mauvaise taille.
    Argument = ASL_ARGUMENT,
    /// Il manque un annuaire ou une racine. **Réessayer ne réparerait rien.**
    Configuration = ASL_CONFIGURATION,
    /// Personne n'a répondu.
    Injoignable = ASL_INJOIGNABLE,
    /// L'annuaire a compris, et il a dit non.
    Refuse = ASL_REFUSE,
    /// Le tampon fourni était trop petit. **La liaison le rattrape seule.**
    TamponTropPetit = ASL_TAMPON_TROP_PETIT,
    /// L'impossible, rattrapé — le processus n'a pas été tué.
    Interne = ASL_INTERNE,
    /// Cette machine n'est pas enrôlée.
    PasDIdentite = ASL_PAS_D_IDENTITE,
    /// Ce client annonce déjà.
    Deja = ASL_DEJA,
    /// L'annuaire n'a encore rien poussé. **Ce n'est pas une panne.**
    ///
    /// C'est l'état ordinaire d'un daemon qui vient d'annoncer : la sonde n'a pas
    /// fini. Un porteur qui appelle [`Client::derniere_poussee`] dans sa boucle la
    /// verra à chaque tour jusqu'au premier verdict, puis plus jamais.
    PasDePoussee = ASL_PAS_DE_POUSSEE,
};

/// Ce que la bibliothèque NATIVE dit d'une faute.
///
/// **LA PHRASE VIENT DE LÀ-BAS, ET N'EST PAS RECOPIÉE ICI.** Deux listes de
/// messages finiraient par diverger, et c'est celle qu'on oublie de corriger que
/// l'utilisateur lirait. Rien à libérer : elle est statique.
[[nodiscard]] inline const char* message(Faute faute) noexcept {
    return asl_faute_texte(static_cast<std::int32_t>(faute));
}

/// La version de la bibliothèque NATIVE, et non de cet en-tête.
///
/// C'est celle qui compte : l'en-tête n'est qu'un habillage, et deux versions qui
/// divergeraient se verraient ici.
struct Version {
    std::uint32_t majeur = 0;
    std::uint32_t mineur = 0;
    std::uint32_t correctif = 0;
};

[[nodiscard]] inline Version version() noexcept {
    Version rendue;
    asl_version(&rendue.majeur, &rendue.mineur, &rendue.correctif);
    return rendue;
}

// ── CE QUI TRAVERSE ─────────────────────────────────────────────────────────

/// Le protocole d'un point d'écoute.
enum class Protocole : std::uint8_t {
    Tcp = ASL_TCP,
    Udp = ASL_UDP,
};

/// D'où vient une adresse.
enum class Origine : std::uint8_t {
    /// L'annuaire nous a VU sous cette adresse.
    Reflexif = ASL_REFLEXIF,
    /// Le daemon l'a annoncée lui-même.
    Annonce = ASL_ANNONCE,
};

/// Ce que l'annuaire sait d'un point d'écoute.
///
/// **TROIS DE CES QUATRE VALEURS NE VEULENT PAS DIRE « ÇA NE MARCHE PAS ».**
/// `EnCours` n'affirme rien — l'annuaire répond avant d'avoir sondé, pour ne pas
/// faire attendre le démarrage d'un daemon. `NonSonde` dit qu'il ne mesurera pas :
/// UDP n'a pas de poignée de main, donc une sonde n'y distinguerait pas « écoute
/// et ignore » de « rien n'écoute ».
///
/// C'est pourquoi `Candidat` n'a pas de `joignable()` : il serait juste une fois
/// sur deux, et ferait écarter un candidat parfaitement bon.
enum class Verdict : std::uint8_t {
    Joignable = ASL_JOIGNABLE,
    Injoignable = ASL_INJOIGNABLE_POINT,
    NonSonde = ASL_NON_SONDE,
    EnCours = ASL_EN_COURS,
};

/// Cette machine est-elle derrière un NAT ?
///
/// **TROIS VALEURS, ET NON UN BOOLÉEN.** Un daemon qui n'a annoncé aucune adresse
/// locale ne donne rien à comparer à l'adresse réflexive, et répondre « non »
/// serait affirmer ce qui n'a pas été mesuré.
enum class VerdictNat : std::uint8_t {
    /// L'adresse sous laquelle l'annuaire nous voit est une des nôtres.
    Non = ASL_NAT_NON,
    /// Elle n'en est aucune : quelque chose traduit entre nous et lui.
    Oui = ASL_NAT_OUI,
    /// Rien à comparer. **Aucune conclusion n'en découle.**
    Indetermine = ASL_NAT_INDETERMINE,
};

/// Un point d'écoute à annoncer.
struct Point {
    Protocole protocole = Protocole::Tcp;
    std::uint16_t port = 0;
};

/// Où joindre un service, et ce que l'annuaire en sait.
struct Candidat {
    Protocole protocole = Protocole::Tcp;
    /// L'adresse, en ordre réseau. **Les quatre premiers octets en IPv4.**
    std::array<std::uint8_t, 16> adresse{};
    /// `4` ou `6`.
    std::uint8_t famille = 4;
    std::uint16_t port = 0;
    Origine origine = Origine::Reflexif;
    Verdict verdict = Verdict::EnCours;

    /// La forme qu'on recopie dans une commande — **avec ses crochets en IPv6**.
    ///
    /// Sans eux, `2001:db8::1:8080` est ambigu : le dernier `:` sépare-t-il un
    /// port ou un groupe d'adresse ?
    [[nodiscard]] std::string texte() const {
        std::string rendu;
        if (famille == 6) {
            rendu += '[';
            rendu += adresse_texte();
            rendu += ']';
        } else {
            rendu += adresse_texte();
        }
        rendu += ':';
        rendu += std::to_string(port);
        return rendu;
    }

    /// L'adresse seule, sans le port.
    [[nodiscard]] std::string adresse_texte() const {
        if (famille != 6) {
            std::string rendu;
            for (std::size_t rang = 0; rang < 4; ++rang) {
                if (rang != 0) {
                    rendu += '.';
                }
                rendu += std::to_string(adresse[rang]);
            }
            return rendu;
        }
        // La forme longue, sans abréger les zéros. **On n'écrit pas `::` ici** :
        // la compression de la RFC 5952 a des règles (une seule série, la plus
        // longue, la première en cas d'égalité) qu'une implémentation hâtive rate,
        // et une adresse mal abrégée est pire qu'une adresse verbeuse.
        static const char* const chiffres = "0123456789abcdef";
        std::string rendu;
        for (std::size_t groupe = 0; groupe < 8; ++groupe) {
            if (groupe != 0) {
                rendu += ':';
            }
            const unsigned haut = adresse[groupe * 2];
            const unsigned bas = adresse[groupe * 2 + 1];
            rendu += chiffres[(haut >> 4) & 0xF];
            rendu += chiffres[haut & 0xF];
            rendu += chiffres[(bas >> 4) & 0xF];
            rendu += chiffres[bas & 0xF];
        }
        return rendu;
    }
};

/// Ce que l'annonce a fait jusqu'ici.
struct Etat {
    /// L'annuaire nous connaît EN CE MOMENT : authentifiés ET annoncés.
    ///
    /// **Ce n'est pas « la socket est ouverte »** : une connexion qui s'ouvre puis
    /// se fait refuser l'authentification n'annonce rien.
    bool attachee = false;
    /// Combien de fois on s'est attaché depuis le départ.
    std::uint64_t attaches = 0;
    /// Combien de fois une attache établie s'est rompue.
    std::uint64_t ruptures = 0;
    /// La tâche a renoncé, et ne réessaiera pas.
    ///
    /// **Elle ne renonce que sur une faute de configuration.** Jamais sur une
    /// panne de réseau, quelle qu'en soit la durée. C'est le seul état dont un
    /// humain doit être averti.
    bool abandonnee = false;
};

/// Ce que l'annuaire a mesuré APRÈS coup, et poussé.
///
/// **ELLE N'A NI SERVICE NI BAIL** — elle ne répond à aucune question, elle
/// corrige ce qu'une réponse antérieure disait « en cours ». C'est pourquoi elle
/// n'a pas la forme de ce que rend [`Client::ou`].
struct Poussee {
    /// La liste ENTIÈRE des candidats, dans l'ordre, et non un delta.
    std::vector<Candidat> candidats;
    VerdictNat derriere_nat = VerdictNat::Indetermine;
};

/// L'identité rendue par un enrôlement. **Conservez les deux.**
///
/// La clé est générée sur cette machine et sa moitié privée n'en sort pas ; ce
/// couple est le seul justificatif durable, et le code est dépensé.
struct Identite {
    std::string machine;
    std::array<std::uint8_t, ASL_GRAINE_OCTETS> graine{};
};

namespace interne {

/// Combien de candidats on demande d'emblée.
///
/// **LE DIMENSIONNEMENT EN DEUX TEMPS DU C COÛTERAIT DEUX ALLERS-RETOURS** :
/// `asl_ou` refait la requête à chaque appel, il ne garde pas de résultat. On
/// demande donc large — le protocole borne un service à huit points d'écoute.
constexpr std::size_t kCandidatsDEmblee = 8;

/// Une chaîne C, ou rien.
///
/// **UN `string_view` N'EST PAS TERMINÉ PAR NUL**, et passer son `data()` ferait
/// lire au C tout ce qui suit dans le tampon d'origine. On copie, donc — une
/// allocation sur un chemin qui fait déjà une entrée-sortie réseau.
///
/// Un NUL au milieu est refusé plutôt que transmis : le C s'arrêterait au
/// premier, et l'annuaire recevrait un nom plus court que celui qu'on croit lui
/// avoir donné.
/// Ce qu'on rend d'un `asl_candidat` brut.
///
/// Factorisé parce que [`Client::ou`] et [`Client::derniere_poussee`] rendent la
/// MÊME chose : deux recopies divergeraient au premier champ ajouté.
[[nodiscard]] inline Candidat candidat(const asl_candidat& lu) {
    Candidat rendu;
    rendu.protocole = static_cast<Protocole>(lu.protocole);
    std::memcpy(rendu.adresse.data(), lu.adresse, rendu.adresse.size());
    rendu.famille = lu.famille;
    rendu.port = lu.port;
    rendu.origine = static_cast<Origine>(lu.origine);
    rendu.verdict = static_cast<Verdict>(lu.verdict);
    return rendu;
}

[[nodiscard]] inline bool chaine(const std::string& texte, std::string& sortie) {
    if (texte.find('\0') != std::string::npos) {
        return false;
    }
    sortie = texte;
    return true;
}

}  // namespace interne

// ── LE CLIENT ───────────────────────────────────────────────────────────────

/// Un client d'annuaire : il annonce, il résout, il tient sa connexion.
///
/// **LE DÉTRUIRE RETIRE L'ANNONCE.** La connexion EST le bail : il n'y a pas de
/// « retrait » séparé à appeler. C'est le comportement qu'on veut — le pire des
/// deux mondes serait une annonce que plus personne ne tient et que l'annuaire
/// continue de publier.
///
/// Déplaçable, non copiable : deux `Client` qui partageraient un pointeur le
/// libéreraient deux fois.
class Client {
public:
    /// Un client vide, qui ne tient rien. Voir [`ouvrir`].
    Client() noexcept = default;

    /// Monte un client. **Il n'ouvre aucune connexion** : un annuaire injoignable
    /// ne doit pas empêcher un daemon de démarrer.
    [[nodiscard]] static Faute ouvrir(Client& sortie) noexcept {
        asl_client* brut = nullptr;
        const auto code = static_cast<Faute>(asl_client_neuf(&brut));
        if (code != Faute::Ok) {
            return code;
        }
        sortie = Client(brut);
        return Faute::Ok;
    }

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    Client(Client&& autre) noexcept : brut_(std::exchange(autre.brut_, nullptr)) {}

    Client& operator=(Client&& autre) noexcept {
        if (this != &autre) {
            fermer();
            brut_ = std::exchange(autre.brut_, nullptr);
        }
        return *this;
    }

    ~Client() { fermer(); }

    /// Ferme le client, **et retire l'annonce en le faisant**.
    ///
    /// Elle est retirée PROPREMENT, ce qui épargne à l'annuaire la minute
    /// d'inactivité pendant laquelle il donnerait une adresse morte. Cet appel
    /// peut donc prendre jusqu'à deux secondes.
    ///
    /// Appeler deux fois ne fait rien la seconde.
    void fermer() noexcept {
        if (brut_ != nullptr) {
            asl_client_libere(std::exchange(brut_, nullptr));
        }
    }

    /// Ce client tient-il encore quelque chose ?
    [[nodiscard]] bool ouvert() const noexcept { return brut_ != nullptr; }
    explicit operator bool() const noexcept { return ouvert(); }

    // ── La configuration ────────────────────────────────────────────────────

    /// Ajoute un annuaire à essayer. **Répétable, et l'ordre compte.**
    ///
    /// `adresse` est LITTÉRALE — `"203.0.113.7:6630"` ou `"[2001:db8::1]:6630"` —,
    /// jamais un nom d'hôte : **la résolution appartient à l'appelant**, qui a
    /// déjà un résolveur et sa politique de cache.
    ///
    /// `nom` est celui qu'on EXIGE du certificat. Il n'est pas déduit de
    /// l'adresse : le déduire reviendrait à faire confiance à qui répond à cette
    /// adresse.
    ///
    /// L'IPv6 est essayé d'abord quel que soit l'ordre des appels.
    [[nodiscard]] Faute ajouter_annuaire(const std::string& adresse,
                                         const std::string& nom) noexcept {
        if (brut_ == nullptr) {
            return Faute::Argument;
        }
        std::string a;
        std::string n;
        if (!interne::chaine(adresse, a) || !interne::chaine(nom, n)) {
            return Faute::Argument;
        }
        return static_cast<Faute>(asl_client_annuaire(brut_, a.c_str(), n.c_str()));
    }

    /// Pose les certificats d'autorité, en PEM.
    ///
    /// **IL N'Y A PAS DE REPLI SUR LE MAGASIN DU SYSTÈME** : les annuaires sont
    /// signés par LEUR autorité, et se rabattre en silence sur les centaines de
    /// racines d'un système ferait accepter un certificat qu'aucune n'aurait émis.
    [[nodiscard]] Faute poser_racines(const std::uint8_t* pem, std::size_t taille) noexcept {
        if (brut_ == nullptr) {
            return Faute::Argument;
        }
        return static_cast<Faute>(asl_client_racines(brut_, pem, taille));
    }

    /// La même chose, depuis ce qu'on vient de lire dans un fichier.
    [[nodiscard]] Faute poser_racines(const std::string& pem) noexcept {
        return poser_racines(reinterpret_cast<const std::uint8_t*>(pem.data()), pem.size());
    }

    /// Installe l'identité de cette machine.
    ///
    /// **LA GRAINE EST LE SECRET**, et sa conservation appartient à l'appelant :
    /// elle n'est pas chiffrée, et quiconque la lit devient cette machine.
    [[nodiscard]] Faute poser_identite(const Identite& identite) noexcept {
        if (brut_ == nullptr) {
            return Faute::Argument;
        }
        std::string machine;
        if (!interne::chaine(identite.machine, machine)) {
            return Faute::Argument;
        }
        return static_cast<Faute>(
            asl_client_identite(brut_, machine.c_str(), identite.graine.data()));
    }

    // ── Les verbes ──────────────────────────────────────────────────────────

    /// Présente un code d'enrôlement, et rend l'identité obtenue.
    ///
    /// L'identité est installée dans ce client au passage.
    ///
    /// **Cet appel bloque** — jusqu'à vingt secondes s'il faut attendre.
    [[nodiscard]] Faute enroler(const std::string& code, Identite& sortie) noexcept {
        if (brut_ == nullptr) {
            return Faute::Argument;
        }
        std::string c;
        if (!interne::chaine(code, c)) {
            return Faute::Argument;
        }
        std::array<char, ASL_IDENTIFIANT_OCTETS> machine{};
        Identite obtenue;
        const auto issue = static_cast<Faute>(
            asl_enroler(brut_, c.c_str(), machine.data(), obtenue.graine.data()));
        if (issue != Faute::Ok) {
            return issue;
        }
        obtenue.machine.assign(machine.data());
        sortie = std::move(obtenue);
        return Faute::Ok;
    }

    /// Annonce ce service, et **rend la main tout de suite**.
    ///
    /// L'annonce est ensuite tenue par un fil natif, aussi longtemps que ce client
    /// vit : elle se réauthentifie et se réannonce seule à chaque reconnexion, et
    /// bascule sur l'autre annuaire racine quand le premier tombe.
    ///
    /// **UN CLIENT N'ANNONCE QU'UNE FOIS** : un second appel rend `Faute::Deja`
    /// plutôt que de remplacer la première en silence, ce qui la retirerait.
    [[nodiscard]] Faute annoncer(const std::string& service,
                                 const std::vector<Point>& points) noexcept {
        if (brut_ == nullptr || points.empty()) {
            return Faute::Argument;
        }
        std::string s;
        if (!interne::chaine(service, s)) {
            return Faute::Argument;
        }
        std::vector<asl_point> bruts;
        bruts.reserve(points.size());
        for (const Point& point : points) {
            asl_point brut{};
            brut.port = point.port;
            brut.protocole = static_cast<std::uint8_t>(point.protocole);
            brut.reserve = 0;
            bruts.push_back(brut);
        }
        return static_cast<Faute>(
            asl_annoncer(brut_, s.c_str(), bruts.data(), bruts.size()));
    }

    /// Où en est l'annonce. Un client qui n'a jamais annoncé rend tout à zéro.
    [[nodiscard]] Faute etat(Etat& sortie) const noexcept {
        if (brut_ == nullptr) {
            return Faute::Argument;
        }
        asl_etat_t brut{};
        const auto issue = static_cast<Faute>(asl_etat(brut_, &brut));
        if (issue != Faute::Ok) {
            return issue;
        }
        sortie.attachee = brut.attachee != 0;
        sortie.attaches = brut.attaches;
        sortie.ruptures = brut.ruptures;
        sortie.abandonnee = brut.abandonnee != 0;
        return Faute::Ok;
    }

    /// Demande où joindre un service, et rend les candidats **dans l'ordre**.
    ///
    /// L'ordre est celui qu'un client doit suivre — IPv6 d'abord, adresse observée
    /// avant adresse annoncée — et il n'est pas à l'appelant de le deviner.
    ///
    /// **`Faute::TamponTropPetit` NE REMONTE PAS** : la liaison redemande avec la
    /// taille qu'on lui a dite. C'est tout ce qu'un porteur veut savoir.
    [[nodiscard]] Faute ou(const std::string& machine, const std::string& service,
                           std::vector<Candidat>& sortie) noexcept {
        if (brut_ == nullptr) {
            return Faute::Argument;
        }
        std::string m;
        std::string s;
        if (!interne::chaine(machine, m) || !interne::chaine(service, s)) {
            return Faute::Argument;
        }

        std::vector<asl_candidat> bruts(interne::kCandidatsDEmblee);
        std::size_t combien = 0;
        auto issue = static_cast<Faute>(
            asl_ou(brut_, m.c_str(), s.c_str(), bruts.data(), bruts.size(), &combien));

        if (issue == Faute::TamponTropPetit) {
            bruts.assign(combien == 0 ? 1 : combien, asl_candidat{});
            issue = static_cast<Faute>(
                asl_ou(brut_, m.c_str(), s.c_str(), bruts.data(), bruts.size(), &combien));
        }
        if (issue != Faute::Ok) {
            return issue;
        }

        sortie.clear();
        sortie.reserve(combien);
        for (std::size_t rang = 0; rang < combien; ++rang) {
            sortie.push_back(interne::candidat(bruts[rang]));
        }
        return Faute::Ok;
    }

    /// Combien de poussées sont arrivées depuis le départ.
    ///
    /// **C'EST LE COMPTEUR QU'ON SURVEILLE, PAS LE CONTENU.** Une poussée porte
    /// toute la liste : la relire sans qu'il ait bougé rend deux fois la même
    /// chose. Le voir croître est le seul signal qu'il y a du neuf.
    [[nodiscard]] Faute poussees_recues(std::uint64_t& sortie) const noexcept {
        if (brut_ == nullptr) {
            return Faute::Argument;
        }
        return static_cast<Faute>(asl_poussees_recues(brut_, &sortie));
    }

    /// Ce que l'annuaire a mesuré depuis, et poussé sur la connexion tenue.
    ///
    /// **`Faute::PasDePoussee` N'EST PAS UNE PANNE** : tant que la sonde n'a rien
    /// conclu, il n'y a rien à rendre, et c'est le cas au démarrage de tout
    /// daemon. `sortie` n'est alors pas touchée.
    ///
    /// Comme pour [`ou`], `Faute::TamponTropPetit` ne remonte pas.
    [[nodiscard]] Faute derniere_poussee(Poussee& sortie) const noexcept {
        if (brut_ == nullptr) {
            return Faute::Argument;
        }

        std::vector<asl_candidat> bruts(interne::kCandidatsDEmblee);
        std::size_t combien = 0;
        std::uint8_t nat = ASL_NAT_INDETERMINE;
        auto issue = static_cast<Faute>(
            asl_derniere_poussee(brut_, bruts.data(), bruts.size(), &combien, &nat));

        if (issue == Faute::TamponTropPetit) {
            bruts.assign(combien == 0 ? 1 : combien, asl_candidat{});
            issue = static_cast<Faute>(
                asl_derniere_poussee(brut_, bruts.data(), bruts.size(), &combien, &nat));
        }
        if (issue != Faute::Ok) {
            return issue;
        }

        Poussee rendue;
        rendue.derriere_nat = static_cast<VerdictNat>(nat);
        rendue.candidats.reserve(combien);
        for (std::size_t rang = 0; rang < combien; ++rang) {
            rendue.candidats.push_back(interne::candidat(bruts[rang]));
        }
        sortie = std::move(rendue);
        return Faute::Ok;
    }

private:
    explicit Client(asl_client* brut) noexcept : brut_(brut) {}

    asl_client* brut_ = nullptr;
};

}  // namespace asl

#endif  // ASL_HPP
