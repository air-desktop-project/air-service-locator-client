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
