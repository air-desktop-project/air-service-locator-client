// Les essais de la liaison C++.
//
// CE QU'ILS ÉPROUVENT, ET QUI NE L'EST NULLE PART AILLEURS
// ========================================================
//
// Ce qui est derrière l'ABI est couvert. Ce qui ne l'est nulle part est ce que
// C++ ajoute : le déplacement d'un `Client` (deux objets qui partageraient un
// pointeur le libéreraient deux fois), un `Client` par défaut sur lequel tout
// doit refuser plutôt que déréférencer, et la mise en texte d'une adresse.
//
// **ET, POUR LA PREMIÈRE FOIS, `asl.h` EST COMPILÉ.** Les liaisons Python et Ruby
// recopient l'en-tête et comparent ; aucune ne le fait LIRE à un compilateur.
// `check-abi.sh` disait ne pas juger le type des arguments : ce fichier le juge,
// puisqu'il ne lie pas si une signature a bougé.
//
// PAS DE CADRE D'ESSAI TIERS
// ==========================
//
// Ni GoogleTest ni Catch2 : ce dépôt n'impose de dépendance à personne, pas même
// pour ses propres essais. Trente lignes de macro font le même travail, et le
// compilateur du porteur n'a rien à télécharger.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "asl.hpp"

namespace {

int echecs = 0;
int verifications = 0;

void rapporter(bool tenu, const char* quoi, const char* fichier, int ligne) {
    ++verifications;
    if (tenu) {
        return;
    }
    ++echecs;
    std::fprintf(stderr, "ÉCHEC %s:%d — %s\n", fichier, ligne, quoi);
}

#define VERIFIE(expression) ::rapporter((expression), #expression, __FILE__, __LINE__)

// Un identifiant de machine VALIDE — préfixe et somme de contrôle compris.
//
// Recopié plutôt que calculé : le calculer demanderait de réimplémenter
// l'alphabet de Crockford d'`asl-id` ici, c'est-à-dire d'en faire une copie qui
// divergerait. Si `asl-id` change de forme, cet essai le dira.
const char* const kMachine = "m-0H248H248H248H248H248H248H";

asl::Identite identite_d_essai() {
    asl::Identite identite;
    identite.machine = kMachine;
    for (std::size_t rang = 0; rang < identite.graine.size(); ++rang) {
        identite.graine[rang] = static_cast<std::uint8_t>(rang);
    }
    return identite;
}

/// Un client dont la racine est illisible : de quoi atteindre `Configuration`.
asl::Faute client_configure(asl::Client& client, bool avec_identite) {
    if (auto faute = asl::Client::ouvrir(client); faute != asl::Faute::Ok) {
        return faute;
    }
    if (auto faute = client.ajouter_annuaire("127.0.0.1:1", "localhost");
        faute != asl::Faute::Ok) {
        return faute;
    }
    const std::string pas_un_pem = "pas un PEM";
    if (auto faute = client.poser_racines(pas_un_pem); faute != asl::Faute::Ok) {
        return faute;
    }
    if (avec_identite) {
        if (auto faute = client.poser_identite(identite_d_essai());
            faute != asl::Faute::Ok) {
            return faute;
        }
    }
    return asl::Faute::Ok;
}

// ── LA VERSION ET LES MESSAGES ─────────────────────────────────────────────

void la_version_vient_de_la_bibliotheque_native() {
    const asl::Version lue = asl::version();
    VERIFIE(lue.majeur == 0);
    VERIFIE(lue.mineur == 1);
    VERIFIE(lue.correctif == 0);
}

void chaque_faute_a_sa_phrase_et_aucune_n_est_partagee() {
    // **UNE PHRASE PARTAGÉE EST UN CODE PERDU** : deux causes différentes que
    // l'appelant lirait pareil.
    const asl::Faute codes[] = {
        asl::Faute::Ok,           asl::Faute::Argument,        asl::Faute::Configuration,
        asl::Faute::Injoignable,  asl::Faute::Refuse,          asl::Faute::TamponTropPetit,
        asl::Faute::Interne,      asl::Faute::PasDIdentite,    asl::Faute::Deja,
    };
    std::vector<std::string> vues;
    for (const asl::Faute code : codes) {
        const char* phrase = asl::message(code);
        VERIFIE(phrase != nullptr);
        if (phrase == nullptr) {
            continue;
        }
        VERIFIE(std::strlen(phrase) > 0);
        const std::string texte = phrase;
        bool deja = false;
        for (const std::string& autre : vues) {
            deja = deja || autre == texte;
        }
        VERIFIE(!deja);
        vues.push_back(texte);
    }
}

// ── LA CONSTRUCTION ────────────────────────────────────────────────────────

void un_client_neuf_n_ouvre_rien_et_son_etat_est_a_zero() {
    asl::Client client;
    VERIFIE(asl::Client::ouvrir(client) == asl::Faute::Ok);
    VERIFIE(client.ouvert());
    VERIFIE(static_cast<bool>(client));

    asl::Etat etat;
    VERIFIE(client.etat(etat) == asl::Faute::Ok);
    VERIFIE(!etat.attachee);
    VERIFIE(etat.attaches == 0);
    VERIFIE(etat.ruptures == 0);
    // N'avoir rien tenté n'est pas avoir renoncé.
    VERIFIE(!etat.abandonnee);
}

void un_client_par_defaut_refuse_au_lieu_de_dereferencer_le_neant() {
    // **DÉRÉFÉRENCER UN POINTEUR NUL TUERAIT LE PROCESSUS DE L'HÔTE.** Ici la
    // sanction est un code, et `fermer` sur un client vide est un non-événement,
    // comme `delete nullptr`.
    asl::Client vide;
    VERIFIE(!vide.ouvert());
    VERIFIE(vide.ajouter_annuaire("127.0.0.1:1", "localhost") == asl::Faute::Argument);
    VERIFIE(vide.poser_racines(std::string("x")) == asl::Faute::Argument);
    VERIFIE(vide.poser_identite(identite_d_essai()) == asl::Faute::Argument);
    VERIFIE(vide.annoncer("depot", {{asl::Protocole::Tcp, 8080}}) == asl::Faute::Argument);

    asl::Etat etat;
    VERIFIE(vide.etat(etat) == asl::Faute::Argument);
    std::vector<asl::Candidat> candidats;
    VERIFIE(vide.ou(kMachine, "depot", candidats) == asl::Faute::Argument);

    asl::Identite obtenue;
    VERIFIE(vide.enroler("4K9M2P7R1T", obtenue) == asl::Faute::Argument);

    vide.fermer();
    vide.fermer();
}

void une_adresse_illisible_est_refusee() {
    asl::Client client;
    VERIFIE(asl::Client::ouvrir(client) == asl::Faute::Ok);

    const char* const mauvaises[] = {
        "nitrogen.example:6630",  // un NOM : la résolution appartient à l'appelant
        "203.0.113.7",            // pas de port
        "2001:db8::1:6630",       // sans crochets, c'est ambigu
        "",
    };
    for (const char* mauvaise : mauvaises) {
        VERIFIE(client.ajouter_annuaire(mauvaise, "localhost") == asl::Faute::Argument);
    }

    VERIFIE(client.ajouter_annuaire("203.0.113.7:6630", "nitrogen.example") ==
            asl::Faute::Ok);
    VERIFIE(client.ajouter_annuaire("[2001:db8::1]:6630", "nitrogen.example") ==
            asl::Faute::Ok);
    // Un nom vide ne vérifie aucun certificat.
    VERIFIE(client.ajouter_annuaire("203.0.113.7:6630", "") == asl::Faute::Argument);
}

void un_nul_au_milieu_d_une_chaine_est_refuse() {
    // **`std::string` PEUT EN CONTENIR ; LE C S'ARRÊTERAIT AU PREMIER.**
    // L'annuaire recevrait un nom plus court que celui qu'on croit lui donner.
    asl::Client client;
    VERIFIE(asl::Client::ouvrir(client) == asl::Faute::Ok);

    std::string tricherie = "127.0.0.1:1";
    tricherie.push_back('\0');
    tricherie += "et la suite";
    VERIFIE(client.ajouter_annuaire(tricherie, "localhost") == asl::Faute::Argument);

    std::string service = "depot";
    service.push_back('\0');
    VERIFIE(client.annoncer(service, {{asl::Protocole::Tcp, 8080}}) ==
            asl::Faute::Argument);
}

// ── L'ANNONCE ──────────────────────────────────────────────────────────────

void sans_identite_on_ne_peut_rien_signer() {
    asl::Client client;
    VERIFIE(client_configure(client, false) == asl::Faute::Ok);
    VERIFIE(client.annoncer("depot", {{asl::Protocole::Tcp, 8080}}) ==
            asl::Faute::PasDIdentite);
}

void une_annonce_sans_point_n_annonce_rien() {
    asl::Client client;
    VERIFIE(client_configure(client, true) == asl::Faute::Ok);
    VERIFIE(client.annoncer("depot", {}) == asl::Faute::Argument);
}

void un_client_n_annonce_qu_une_fois() {
    asl::Client client;
    VERIFIE(client_configure(client, true) == asl::Faute::Ok);
    VERIFIE(client.annoncer("depot", {{asl::Protocole::Tcp, 8080}}) == asl::Faute::Ok);
    VERIFIE(client.annoncer("depot", {{asl::Protocole::Tcp, 8081}}) == asl::Faute::Deja);
}

void le_fil_natif_tourne_sans_que_personne_l_attende() {
    // **C'EST L'ESSAI QUI COMPTE LE PLUS.** `annoncer` a rendu la main et
    // l'appelant est parti ; si le fil natif ne tournait pas, `abandonnee` ne
    // passerait jamais à vrai — et tout compilerait.
    asl::Client client;
    VERIFIE(client_configure(client, true) == asl::Faute::Ok);
    VERIFIE(client.annoncer("depot", {{asl::Protocole::Tcp, 8080}}) == asl::Faute::Ok);

    asl::Etat etat;
    for (int tour = 0; tour < 250; ++tour) {
        VERIFIE(client.etat(etat) == asl::Faute::Ok);
        if (etat.abandonnee) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    VERIFIE(etat.abandonnee);
    VERIFIE(!etat.attachee);
    VERIFIE(etat.attaches == 0);
}

void l_identite_survit_a_l_annonce() {
    // L'annonce CONSOMME une identité côté Rust ; si le client la perdait, `ou`
    // répondrait « aucune identité » à un daemon qui vient de s'annoncer.
    asl::Client client;
    VERIFIE(client_configure(client, true) == asl::Faute::Ok);
    VERIFIE(client.annoncer("depot", {{asl::Protocole::Tcp, 8080}}) == asl::Faute::Ok);

    std::vector<asl::Candidat> candidats;
    const asl::Faute issue = client.ou(kMachine, "depot", candidats);
    VERIFIE(issue != asl::Faute::PasDIdentite);
    VERIFIE(issue == asl::Faute::Configuration);
}

// ── LA DURÉE DE VIE ────────────────────────────────────────────────────────

void un_client_deplace_laisse_l_original_vide() {
    // **DEUX `Client` QUI PARTAGERAIENT UN POINTEUR LE LIBÉRERAIENT DEUX FOIS**,
    // et une double libération est un usage-après-libération.
    asl::Client premier;
    VERIFIE(asl::Client::ouvrir(premier) == asl::Faute::Ok);
    VERIFIE(premier.ouvert());

    asl::Client second = std::move(premier);
    VERIFIE(second.ouvert());
    VERIFIE(!premier.ouvert());  // NOLINT(bugprone-use-after-move)

    asl::Etat etat;
    VERIFIE(second.etat(etat) == asl::Faute::Ok);
    VERIFIE(premier.etat(etat) == asl::Faute::Argument);
}

void une_affectation_par_deplacement_ferme_ce_qu_elle_remplace() {
    asl::Client garde;
    VERIFIE(asl::Client::ouvrir(garde) == asl::Faute::Ok);
    {
        asl::Client remplace;
        VERIFIE(asl::Client::ouvrir(remplace) == asl::Faute::Ok);
        // Ce que `remplace` tenait doit être rendu ici, et non fuir.
        remplace = std::move(garde);
        VERIFIE(remplace.ouvert());
        VERIFIE(!garde.ouvert());  // NOLINT(bugprone-use-after-move)
    }
}

// ── LA MISE EN TEXTE ───────────────────────────────────────────────────────

void un_candidat_v6_porte_ses_crochets() {
    // Sans eux, `2001:db8::1:8080` est ambigu, et ce qu'on affiche ne se recopie
    // pas dans une commande.
    asl::Candidat six;
    six.famille = 6;
    six.port = 8080;
    const std::uint8_t brut[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                   0,    0,    0,    0,    0, 0, 0, 1};
    std::memcpy(six.adresse.data(), brut, sizeof(brut));
    VERIFIE(six.texte() == "[2001:0db8:0000:0000:0000:0000:0000:0001]:8080");

    asl::Candidat quatre;
    quatre.famille = 4;
    quatre.port = 8080;
    quatre.adresse[0] = 203;
    quatre.adresse[1] = 0;
    quatre.adresse[2] = 113;
    quatre.adresse[3] = 7;
    VERIFIE(quatre.texte() == "203.0.113.7:8080");
}

// ── LE CONTRAT, LU PAR LE COMPILATEUR ──────────────────────────────────────

void les_enums_valent_les_macros_de_l_entete() {
    // **CE SONT DES `static_assert`**, donc déjà tranchés à la compilation. Ils
    // sont ici pour être LUS : c'est la seule chose que Python et Ruby doivent
    // vérifier à l'exécution, et que C++ obtient gratuitement.
    static_assert(static_cast<std::int32_t>(asl::Faute::Ok) == ASL_OK, "");
    static_assert(static_cast<std::int32_t>(asl::Faute::Argument) == ASL_ARGUMENT, "");
    static_assert(static_cast<std::int32_t>(asl::Faute::Refuse) == ASL_REFUSE, "");
    static_assert(static_cast<std::int32_t>(asl::Faute::Injoignable) == ASL_INJOIGNABLE, "");
    static_assert(static_cast<std::uint8_t>(asl::Protocole::Tcp) == ASL_TCP, "");
    static_assert(static_cast<std::uint8_t>(asl::Verdict::EnCours) == ASL_EN_COURS, "");
    static_assert(static_cast<std::uint8_t>(asl::Origine::Reflexif) == ASL_REFLEXIF, "");
    static_assert(sizeof(asl::Identite{}.graine) == ASL_GRAINE_OCTETS, "");
    VERIFIE(true);
}

}  // namespace

int main() {
    la_version_vient_de_la_bibliotheque_native();
    chaque_faute_a_sa_phrase_et_aucune_n_est_partagee();
    un_client_neuf_n_ouvre_rien_et_son_etat_est_a_zero();
    un_client_par_defaut_refuse_au_lieu_de_dereferencer_le_neant();
    une_adresse_illisible_est_refusee();
    un_nul_au_milieu_d_une_chaine_est_refuse();
    sans_identite_on_ne_peut_rien_signer();
    une_annonce_sans_point_n_annonce_rien();
    un_client_n_annonce_qu_une_fois();
    le_fil_natif_tourne_sans_que_personne_l_attende();
    l_identite_survit_a_l_annonce();
    un_client_deplace_laisse_l_original_vide();
    une_affectation_par_deplacement_ferme_ce_qu_elle_remplace();
    un_candidat_v6_porte_ses_crochets();
    les_enums_valent_les_macros_de_l_entete();

    std::printf("%d vérifications, %d échec(s)\n", verifications, echecs);
    return echecs == 0 ? 0 : 1;
}
