//! La reprise et l'identité.
//!
//! **La reprise se pilote ici sans attendre une seconde.** C'est ce que
//! l'absence d'entrée-sortie achète : éprouver soixante-dix échecs consécutifs
//! coûte une boucle, alors qu'un vrai recul exponentiel y mettrait des années.

use core::net::{IpAddr, Ipv4Addr};

use asl_cle::{Defi, LiaisonDeCanal};
use asl_client::{BRUIT_CENTIEMES, Faute, Identite, RECUL_INITIAL_MS, Reprise};
use asl_id::{Genre, Identifiant};
use asl_proto::{NomService, PointEcoute, Port, Protocole};

fn machine() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Machine, [0x11; 16])
}

fn identite() -> Identite {
    Identite::nouvelle(machine(), [0x42; 32]).expect("identité d'essai")
}

/// Le plafond employé partout ici : quinze secondes, la cadence proposée.
const PLAFOND: u64 = 15_000;

// ── La reprise ──────────────────────────────────────────────────────────────

#[test]
fn un_plafond_nul_est_refuse() {
    // Il ferait tourner la reprise en boucle serrée.
    assert_eq!(Reprise::nouvelle(0).map(|_| ()), Err(Faute::PlafondNul));
    assert!(Reprise::nouvelle(1).is_ok());
}

#[test]
fn le_recul_est_exponentiel_puis_plafonne() {
    // Sans bruit — `alea` au milieu de sa plage rendrait exactement 100 %, mais
    // l'arithmétique entière ne le garantit pas ; on encadre plutôt.
    let mut reprise = Reprise::nouvelle(PLAFOND).unwrap();
    let mut precedent = 0_u64;
    for essai in 0..4_u32 {
        let delai = reprise.prochain_delai(u16::MAX / 2);
        let attendu = RECUL_INITIAL_MS << essai;
        assert!(
            delai >= attendu * (100 - BRUIT_CENTIEMES) / 100
                && delai <= attendu * (100 + BRUIT_CENTIEMES) / 100,
            "essai {essai} : {delai} hors de ±20 % de {attendu}"
        );
        assert!(delai > precedent, "le recul doit croître");
        precedent = delai;
    }
}

#[test]
fn le_delai_ne_depasse_jamais_le_plafond_bruite() {
    let mut reprise = Reprise::nouvelle(PLAFOND).unwrap();
    let maximum = PLAFOND * (100 + BRUIT_CENTIEMES) / 100;
    for essai in 0..100_u32 {
        let delai = reprise.prochain_delai(u16::MAX);
        assert!(delai <= maximum, "essai {essai} : {delai} > {maximum}");
    }
}

#[test]
fn le_delai_n_est_jamais_nul() {
    // **Un délai nul serait la boucle serrée que la reprise existe pour
    // éviter.** Éprouvé sur tout l'intervalle du bruit, et sur un plafond
    // minuscule où l'arithmétique entière pourrait tout ramener à zéro.
    for plafond in [1_u64, 2, 5, 10, PLAFOND] {
        for alea in [0_u16, 1, u16::MAX / 2, u16::MAX] {
            let mut reprise = Reprise::nouvelle(plafond).unwrap();
            for _ in 0..40 {
                assert!(
                    reprise.prochain_delai(alea) >= 1,
                    "plafond {plafond}, alea {alea}"
                );
            }
        }
    }
}

#[test]
fn elle_n_abandonne_jamais_meme_apres_des_milliers_d_echecs() {
    // Le compteur SATURE au lieu de déborder : après soixante-quatre échecs, un
    // décalage non saturé rendrait un délai nul.
    let mut reprise = Reprise::nouvelle(PLAFOND).unwrap();
    let maximum = PLAFOND * (100 + BRUIT_CENTIEMES) / 100;
    for _ in 0..5_000 {
        let delai = reprise.prochain_delai(u16::MAX / 3);
        assert!(delai >= 1 && delai <= maximum);
    }
    assert_eq!(reprise.essais(), 5_000);

    // Et au-delà de ce qu'un `u32` peut compter, rien ne casse.
    for _ in 0..10 {
        assert!(reprise.prochain_delai(0) >= 1);
    }
}

#[test]
fn une_reussite_remet_le_recul_a_zero() {
    let mut reprise = Reprise::nouvelle(PLAFOND).unwrap();
    for _ in 0..5 {
        let _ = reprise.prochain_delai(0);
    }
    assert_eq!(reprise.essais(), 5);

    reprise.reussite();
    assert_eq!(reprise.essais(), 0);

    let delai = reprise.prochain_delai(u16::MAX / 2);
    assert!(delai <= RECUL_INITIAL_MS * (100 + BRUIT_CENTIEMES) / 100);
}

#[test]
fn le_bruit_couvre_bien_quatre_vingts_a_cent_vingt_pour_cent() {
    // La propriété qui rend la reprise inoffensive pour l'annuaire : deux
    // daemons qui échouent au même instant ne réessaient pas au même instant.
    let plafond = 10_000_u64;
    let bas = {
        let mut reprise = Reprise::nouvelle(plafond).unwrap();
        for _ in 0..20 {
            let _ = reprise.prochain_delai(0);
        }
        reprise.prochain_delai(0)
    };
    let haut = {
        let mut reprise = Reprise::nouvelle(plafond).unwrap();
        for _ in 0..20 {
            let _ = reprise.prochain_delai(u16::MAX);
        }
        reprise.prochain_delai(u16::MAX)
    };
    assert_eq!(bas, plafond * 80 / 100);
    assert_eq!(haut, plafond * 120 / 100);
    assert!(haut > bas, "le bruit doit écarter les réessais");
}

// ── L'identité ──────────────────────────────────────────────────────────────

#[test]
fn une_identite_exige_un_identifiant_de_machine() {
    for genre in [
        Genre::Utilisateur,
        Genre::Appareil,
        Genre::Service,
        Genre::Autorisation,
        Genre::Annuaire,
    ] {
        let autre = Identifiant::depuis_entropie(genre, [0x11; 16]);
        assert_eq!(
            Identite::nouvelle(autre, [0x42; 32]).map(|_| ()),
            Err(Faute::PasUneMachine { obtenu: genre })
        );
    }
    assert_eq!(identite().machine(), machine());
}

#[test]
fn la_reponse_au_defi_verifie_avec_la_cle_publique() {
    // Le tour complet, du côté du daemon : il signe, l'annuaire vérifie.
    let identite = identite();
    let defi = Defi::depuis_octets([0x07; 32]);
    let liaison = LiaisonDeCanal::depuis_octets([0x08; 32]);

    let signature = identite.repondre(&defi, &liaison).expect("signature");
    assert!(
        identite
            .publique()
            .verifie(machine(), &defi, &liaison, &signature)
    );

    // Une autre liaison de canal ne vérifie pas : c'est ce qui ferme le relais.
    let autre = LiaisonDeCanal::depuis_octets([0x09; 32]);
    assert!(
        !identite
            .publique()
            .verifie(machine(), &defi, &autre, &signature)
    );
}

#[test]
fn la_meme_entropie_donne_la_meme_cle() {
    // Un ré-enrôlement avec la même entropie ne doit pas changer d'identité.
    let une = Identite::nouvelle(machine(), [0x42; 32]).unwrap();
    let autre = Identite::nouvelle(machine(), [0x42; 32]).unwrap();
    assert_eq!(une.publique(), autre.publique());

    let differente = Identite::nouvelle(machine(), [0x43; 32]).unwrap();
    assert_ne!(une.publique(), differente.publique());
}

#[test]
fn l_annonce_est_validee_avant_tout_aller_retour_reseau() {
    // Le daemon apprend ICI qu'il annonce deux fois le même point, et non après
    // un aller-retour.
    let identite = identite();
    let nom = NomService::analyser("depot").unwrap();
    let port = Port::depuis_u16(49_152).unwrap();
    let bon = [PointEcoute::nouveau(Protocole::Tcp, port)];
    let adresses = [IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))];

    let annonce = identite.annoncer(nom, &bon, &adresses).expect("annonce");
    assert_eq!(annonce.machine, machine());
    assert_eq!(annonce.points.len(), 1);

    // Aucun point : refusé.
    assert!(matches!(
        identite.annoncer(nom, &[], &adresses),
        Err(Faute::Protocole(_))
    ));

    // Deux fois le même point : refusé.
    let doublon = [
        PointEcoute::nouveau(Protocole::Tcp, port),
        PointEcoute::nouveau(Protocole::Tcp, port),
    ];
    assert!(matches!(
        identite.annoncer(nom, &doublon, &adresses),
        Err(Faute::Protocole(_))
    ));
}

// ── L'enrôlement ────────────────────────────────────────────────────────────

use asl_client::{ENROLEMENT_OCTETS, ETIQUETTE_LIAISON, Enrolement, liaison_exportee};

/// Un défi et une liaison, pour les essais.
fn defi_et_liaison() -> (Defi, LiaisonDeCanal) {
    (
        Defi::depuis_octets([0x5A; 32]),
        liaison_exportee([0x11; 32]),
    )
}

#[test]
fn le_corps_d_un_enrolement_porte_ses_trois_champs_de_longueur_fixe() {
    let (defi, liaison) = defi_et_liaison();
    let enrolement = Enrolement::nouveau([0x42; 32]);
    let corps = enrolement
        .corps("0123456789", &defi, &liaison)
        .expect("un code juste");

    assert_eq!(corps.len(), ENROLEMENT_OCTETS);
    assert_eq!(corps.len(), 10 + 32 + 64);
    assert_eq!(&corps[..10], b"0123456789", "le code, en forme canonique");
    assert_eq!(
        &corps[10..42],
        &enrolement.publique().octets(),
        "puis la clé qu'on présente"
    );
}

#[test]
fn la_preuve_prouve_la_possession_de_la_cle_presentee() {
    // **C'EST TOUT L'OBJET DU TROISIÈME CHAMP.** Sans lui, n'importe qui
    // pourrait présenter la clé d'un autre avec un code volé.
    let (defi, liaison) = defi_et_liaison();
    let enrolement = Enrolement::nouveau([0x42; 32]);
    let corps = enrolement
        .corps("0123456789", &defi, &liaison)
        .expect("un code juste");

    let mut brute = [0_u8; 64];
    brute.copy_from_slice(&corps[42..]);
    let signature = asl_cle::Signature::depuis_octets(brute);

    assert!(
        enrolement
            .publique()
            .prouve_sa_possession(&defi, &liaison, &signature),
        "la preuve doit valoir pour la clé présentée"
    );
}

#[test]
fn une_preuve_faite_pour_une_autre_connexion_ne_vaut_pas() {
    // **LE RELAIS, DANS LE CHEMIN D'ENRÔLEMENT.** Un intermédiaire qui
    // rapporterait la preuve d'une autre poignée de main ne passe pas.
    let (defi, liaison) = defi_et_liaison();
    let enrolement = Enrolement::nouveau([0x42; 32]);
    let corps = enrolement
        .corps("0123456789", &defi, &liaison)
        .expect("un code juste");

    let mut brute = [0_u8; 64];
    brute.copy_from_slice(&corps[42..]);
    let signature = asl_cle::Signature::depuis_octets(brute);

    let ailleurs = liaison_exportee([0x22; 32]);
    assert!(
        !enrolement
            .publique()
            .prouve_sa_possession(&defi, &ailleurs, &signature),
        "une preuve faite pour une autre connexion a été acceptée"
    );

    let autre_defi = Defi::depuis_octets([0x5B; 32]);
    assert!(
        !enrolement
            .publique()
            .prouve_sa_possession(&autre_defi, &liaison, &signature),
        "une preuve faite pour un autre défi a été acceptée"
    );
}

#[test]
fn le_code_est_canonise_avant_de_partir() {
    // **INDISPENSABLE, ET NON COMMODE** : l'annuaire cherche par l'empreinte de
    // la forme canonique. Un `O` envoyé pour un `0` ne trouverait rien.
    let (defi, liaison) = defi_et_liaison();
    let enrolement = Enrolement::nouveau([0x42; 32]);

    let reference = enrolement
        .corps("0123456789", &defi, &liaison)
        .expect("un code juste");

    for variante in ["O123456789", "o123456789", "0I23456789", "0l23456789"] {
        let corps = enrolement
            .corps(variante, &defi, &liaison)
            .unwrap_or_else(|_| panic!("{variante} devrait être rattrapé"));
        assert_eq!(&corps[..10], &reference[..10], "{variante}");
    }
}

#[test]
fn le_tiret_d_affichage_se_retape_ou_s_omet() {
    // C'est la forme qu'on lit sur l'écran du téléphone.
    let (defi, liaison) = defi_et_liaison();
    let enrolement = Enrolement::nouveau([0x42; 32]);

    let sans = enrolement
        .corps("4K9M2P7R1T", &defi, &liaison)
        .expect("sans tiret");
    let avec = enrolement
        .corps("4K9M2-P7R1T", &defi, &liaison)
        .expect("avec tiret");
    assert_eq!(&sans[..10], &avec[..10]);
    assert_eq!(&sans[..10], b"4K9M2P7R1T");
}

#[test]
fn un_code_mal_forme_est_refuse_avant_toute_signature() {
    let (defi, liaison) = defi_et_liaison();
    let enrolement = Enrolement::nouveau([0x42; 32]);

    for texte in ["", "012345678", "01234567890", "01234U6789", "4K9M2P-7R1T"] {
        assert!(
            matches!(
                enrolement.corps(texte, &defi, &liaison),
                Err(asl_client::Faute::CodeRefuse(_))
            ),
            "{texte:?} devrait être refusé"
        );
    }
}

#[test]
fn l_annuaire_nomme_la_machine_et_la_cle_ne_change_pas() {
    // **C'EST LE POINT DE CETTE TRANSITION.** La clé que l'annuaire vient de
    // lier est celle qui signera ; en fabriquer une neuve ici la perdrait.
    let enrolement = Enrolement::nouveau([0x42; 32]);
    let publique = enrolement.publique();

    let identite = enrolement.nommee(machine()).expect("une machine");
    assert_eq!(identite.machine(), machine());
    assert_eq!(identite.publique(), publique, "la clé a survécu au baptême");
}

#[test]
fn un_enrolement_ne_se_laisse_pas_nommer_par_autre_chose_qu_une_machine() {
    for genre in [
        Genre::Utilisateur,
        Genre::Appareil,
        Genre::Service,
        Genre::Autorisation,
        Genre::Annuaire,
    ] {
        let quoi = Identifiant::depuis_entropie(genre, [7; 16]);
        assert_eq!(
            Enrolement::nouveau([0x42; 32]).nommee(quoi).map(|_| ()),
            Err(asl_client::Faute::PasUneMachine { obtenu: genre }),
            "{genre:?}"
        );
    }
}

#[test]
fn l_etiquette_de_liaison_est_celle_du_serveur() {
    // **RÉEXPORTÉE POUR QUE PERSONNE N'EN INVENTE UNE.** Si les deux camps
    // n'employaient pas la même, aucune signature ne vérifierait, et la panne
    // serait indiscernable d'une clé fausse.
    assert_eq!(ETIQUETTE_LIAISON, asl_cle::ETIQUETTE_LIAISON);
}

// ── La tournée des annuaires ────────────────────────────────────────────────

use asl_client::{Etape, Tournee, place_en_ordre};
use core::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Un annuaire en IPv4, reconnaissable à son dernier octet.
fn v4(marque: u8) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, marque), 6630))
}

/// Un annuaire en IPv6, reconnaissable à son dernier groupe.
fn v6(marque: u16) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, marque),
        6630,
        0,
        0,
    ))
}

/// La liste dans l'ordre où la tournée la parcourt.
fn parcours(annuaires: &[SocketAddr]) -> Vec<SocketAddr> {
    (0..annuaires.len())
        .map(|rang| annuaires[place_en_ordre(annuaires, rang).expect("dans la liste")])
        .collect()
}

#[test]
fn l_ipv6_passe_avant_l_ipv4_quel_que_soit_l_ordre_ecrit() {
    // **LA DÉCISION DE PRODUIT** : les annuaires racines publient les deux
    // familles, donc « les deux existent » est le cas ordinaire, et essayer
    // l'IPv4 d'abord prendrait le chemin dégradé à chaque fois.
    let ecrit = [v4(1), v6(1), v4(2), v6(2)];
    assert_eq!(parcours(&ecrit), vec![v6(1), v6(2), v4(1), v4(2)]);

    // Écrite dans l'autre sens, la liste se parcourt pareil.
    let inverse = [v6(1), v6(2), v4(1), v4(2)];
    assert_eq!(parcours(&inverse), vec![v6(1), v6(2), v4(1), v4(2)]);
}

#[test]
fn l_ordre_de_l_operateur_survit_a_l_interieur_de_chaque_famille() {
    // Sa liste est sa préférence ; la seule chose qui la réécrit est IPv6.
    let ecrit = [v4(9), v4(3), v4(7)];
    assert_eq!(parcours(&ecrit), vec![v4(9), v4(3), v4(7)]);

    let six = [v6(9), v6(3), v6(7)];
    assert_eq!(parcours(&six), vec![v6(9), v6(3), v6(7)]);
}

#[test]
fn un_rang_hors_de_la_liste_ne_designe_personne() {
    // C'est ce qui dit à la tournée qu'un tour complet vient d'échouer.
    let annuaires = [v6(1), v4(1)];
    assert_eq!(place_en_ordre(&annuaires, 2), None);
    assert_eq!(place_en_ordre(&annuaires, 400), None);
    assert_eq!(place_en_ordre(&[], 0), None);

    // Et sur une liste d'une seule famille, des deux côtés de la coupure.
    assert_eq!(place_en_ordre(&[v6(1)], 1), None);
    assert_eq!(place_en_ordre(&[v4(1)], 1), None);
}

#[test]
fn une_liste_vide_est_une_configuration_et_non_un_echec() {
    // **Un daemon sans annuaire doit l'apprendre, pas tourner en rond.**
    let mut tournee = Tournee::nouvelle(Reprise::nouvelle(PLAFOND).unwrap());
    assert_eq!(tournee.prochaine(&[], 0), None);
    // Et rien n'a bougé : ce n'est pas un échec, donc pas un tour perdu.
    assert_eq!(tournee.tours_perdus(), 0);
}

#[test]
fn le_tour_s_enchaine_sans_attendre_puis_recule() {
    // **LA DÉCISION QUI DONNE À CE TYPE SA RAISON D'EXISTER.** Reculer entre
    // deux annuaires rendrait la bascule vers le second annuaire racine plus
    // lente que la panne du premier.
    let annuaires = [v6(1), v4(1), v4(2)];
    let mut tournee = Tournee::nouvelle(Reprise::nouvelle(PLAFOND).unwrap());

    for attendu in 0..3_usize {
        let etape = tournee.prochaine(&annuaires, 0).expect("un annuaire");
        assert_eq!(
            etape,
            Etape {
                place: attendu,
                attendre_ms: 0
            },
            "le tour ne doit RIEN attendre"
        );
    }
    assert_eq!(tournee.tours_perdus(), 0, "le tour n'est pas encore bouclé");

    // Le tour est bouclé : c'est ici, et nulle part ailleurs, qu'on attend.
    let etape = tournee.prochaine(&annuaires, u16::MAX / 2).expect("encore");
    assert_eq!(etape.place, 0, "et l'on repart du premier");
    assert!(etape.attendre_ms >= 1, "le tour bouclé doit reculer");
    assert_eq!(tournee.tours_perdus(), 1);
}

#[test]
fn le_recul_ne_compte_que_les_tours_et_non_les_annuaires() {
    // La grandeur dont dépend le recul est « le service entier est
    // injoignable », pas « une machine n'a pas répondu ».
    let quatre = [v6(1), v6(2), v4(1), v4(2)];
    let mut tournee = Tournee::nouvelle(Reprise::nouvelle(PLAFOND).unwrap());
    for _ in 0..12 {
        let _ = tournee.prochaine(&quatre, 0).expect("un annuaire");
    }
    assert_eq!(tournee.tours_perdus(), 2, "douze essais, trois tours");

    // Avec un seul annuaire, chaque essai EST un tour.
    let seul = [v6(1)];
    let mut tournee = Tournee::nouvelle(Reprise::nouvelle(PLAFOND).unwrap());
    for _ in 0..12 {
        let etape = tournee.prochaine(&seul, 0).expect("le seul");
        assert_eq!(etape.place, 0);
    }
    assert_eq!(tournee.tours_perdus(), 11);
}

#[test]
fn une_reussite_repart_du_haut_et_remet_le_recul_a_zero() {
    // **LE PRIX DE L'ORDRE ANNONCÉ, PAYÉ EXPRÈS.** Rester sur le second parce
    // qu'il a marché une fois ferait de « IPv6 d'abord » une phrase fausse dès
    // la première panne, sans que personne s'en aperçoive.
    let annuaires = [v6(1), v4(1)];
    let mut tournee = Tournee::nouvelle(Reprise::nouvelle(PLAFOND).unwrap());

    // Le premier est éteint, le second répond.
    assert_eq!(tournee.prochaine(&annuaires, 0).unwrap().place, 0);
    let deuxieme = tournee.prochaine(&annuaires, 0).unwrap();
    assert_eq!(deuxieme.place, 1);
    tournee.reussite();

    // La connexion tombe : on recommence par le premier, et sans attendre.
    let apres = tournee.prochaine(&annuaires, 0).expect("on repart");
    assert_eq!(
        apres,
        Etape {
            place: 0,
            attendre_ms: 0
        }
    );
    assert_eq!(tournee.tours_perdus(), 0);
}

#[test]
fn elle_n_abandonne_jamais_et_le_recul_reste_borne() {
    // Le pendant, pour la tournée, de ce que `Reprise` garantit seule.
    let annuaires = [v6(1), v4(1)];
    let mut tournee = Tournee::nouvelle(Reprise::nouvelle(PLAFOND).unwrap());
    let maximum = PLAFOND * (100 + BRUIT_CENTIEMES) / 100;

    for _ in 0..10_000 {
        let etape = tournee
            .prochaine(&annuaires, u16::MAX)
            .expect("jamais None");
        assert!(etape.place < annuaires.len());
        assert!(etape.attendre_ms <= maximum);
    }
    assert_eq!(tournee.tours_perdus(), 4_999);
}

#[test]
fn la_liste_peut_changer_de_taille_entre_deux_tours() {
    // Un annuaire retiré de la configuration ne doit pas faire sortir la
    // tournée de la liste — le rang est ramené dans les bornes à chaque tour.
    let mut tournee = Tournee::nouvelle(Reprise::nouvelle(PLAFOND).unwrap());
    let quatre = [v6(1), v6(2), v4(1), v4(2)];
    for _ in 0..3 {
        let _ = tournee.prochaine(&quatre, 0).expect("un annuaire");
    }

    let un_seul = [v4(1)];
    let etape = tournee.prochaine(&un_seul, 0).expect("le seul");
    assert_eq!(etape.place, 0);
    assert!(etape.attendre_ms >= 1, "le rang était hors de la liste");
}
