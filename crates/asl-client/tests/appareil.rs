//! Ce qu'un appareil compose, recoupé avec ce que le serveur vérifie.
//!
//! **La clé secrète d'appareil n'existe ici que parce que c'est un essai** :
//! sur un téléphone, elle vit dans le matériel, et c'est lui qui signe. Ce
//! qu'on éprouve est que les octets composés par `asl_client::appareil` sont
//! exactement ceux que `asl_cle::CleAppareil` vérifie.

use asl_cle::{CleSecreteAppareil, Defi, LiaisonDeCanal, SignatureAppareil};
use asl_client::appareil::{
    FauteAppareil, PREUVE_AUTHENTIFICATION_OCTETS, Plateforme, cle_publique, corps_de_compte,
    message_d_authentification, message_de_possession, message_pour_attestation,
    preuve_d_authentification,
};
use asl_id::{Genre, Identifiant};

fn secrete() -> CleSecreteAppareil {
    let mut entropie = [0_u8; 32];
    for (place, octet) in entropie.iter_mut().enumerate() {
        *octet = u8::try_from(place.wrapping_mul(7).wrapping_add(3)).unwrap_or(1);
    }
    CleSecreteAppareil::depuis_entropie(entropie).expect("une entropie non nulle fait un scalaire")
}

fn defi() -> Defi {
    Defi::depuis_octets([0xAA; 32])
}

fn liaison() -> LiaisonDeCanal {
    LiaisonDeCanal::depuis_octets([0xBB; 32])
}

#[test]
fn la_preuve_de_possession_verifie_sous_la_cle_presentee() {
    let secrete = secrete();
    let publique = secrete.publique().octets();

    let message = message_de_possession(&publique, &defi(), &liaison()).expect("une vraie clé");
    // Ce que le matériel ferait : signer ces octets, et rendre `r ‖ s`.
    let signature = secrete.prouver_la_possession(&defi(), &liaison());

    // Le serveur vérifie la signature sur le MÊME message — sinon rien ne tient.
    let cle = cle_publique(&publique).expect("la même clé");
    assert!(cle.prouve_sa_possession(&defi(), &liaison(), &signature));
    assert_eq!(message.len(), asl_cle::MESSAGE_POSSESSION_APPAREIL_OCTETS);
    assert!(message.starts_with(asl_cle::DOMAINE_POSSESSION));
}

#[test]
fn le_message_d_authentification_est_celui_des_machines_avec_le_genre_a() {
    let appareil = Identifiant::depuis_entropie(Genre::Appareil, [5; 16]);
    let message = message_d_authentification(appareil, &defi(), &liaison()).expect("un appareil");
    assert_eq!(
        message,
        asl_cle::message_a_signer(appareil, &defi(), &liaison())
    );
    assert_eq!(message[asl_cle::DOMAINE.len()], b'a');

    let machine = Identifiant::depuis_entropie(Genre::Machine, [5; 16]);
    assert_eq!(
        message_d_authentification(machine, &defi(), &liaison()),
        Err(FauteAppareil::PasUnAppareil {
            obtenu: Genre::Machine
        })
    );
}

#[test]
fn la_preuve_d_authentification_fait_quatre_vingt_un_octets() {
    let appareil = Identifiant::depuis_entropie(Genre::Appareil, [9; 16]);
    let signature = [0x42; 64];
    let corps = preuve_d_authentification(appareil, &signature).expect("un appareil");
    assert_eq!(corps.len(), PREUVE_AUTHENTIFICATION_OCTETS);
    assert_eq!(corps[0], b'a');
    assert_eq!(&corps[1..17], appareil.octets());
    assert_eq!(&corps[17..], &signature);
}

#[test]
fn le_corps_de_compte_porte_la_plate_forme_puis_la_cle_puis_la_preuve() {
    let publique = secrete().publique().octets();
    let preuve = [0x11; 64];
    let mut sortie = [0_u8; asl_api::corps::COMPTE_CORPS_MAX];

    let combien = corps_de_compte(Plateforme::Aucune, &publique, &preuve, &[], &mut sortie)
        .expect("aucune attestation, aucun octet derrière");
    assert_eq!(combien, 98);
    assert_eq!(sortie[0], 0);
    assert_eq!(&sortie[1..34], &publique);
    assert_eq!(&sortie[34..98], &preuve);

    // Apple exige une attestation ; « aucune » en refuse une.
    assert!(matches!(
        corps_de_compte(Plateforme::Apple, &publique, &preuve, &[], &mut sortie),
        Err(FauteAppareil::Corps(_))
    ));
    assert!(matches!(
        corps_de_compte(
            Plateforme::Aucune,
            &publique,
            &preuve,
            &[1, 2, 3],
            &mut sortie
        ),
        Err(FauteAppareil::Corps(_))
    ));
    let combien = corps_de_compte(
        Plateforme::Google,
        &publique,
        &preuve,
        &[7; 100],
        &mut sortie,
    )
    .expect("une attestation Google");
    assert_eq!(combien, 198);
    assert_eq!(sortie[0], 2);
}

#[test]
fn une_cle_hors_de_la_courbe_est_refusee_a_la_lecture() {
    let mut fausse = [0xFF; 33];
    fausse[0] = 0x02;
    assert_eq!(
        cle_publique(&fausse),
        Err(FauteAppareil::ClePubliqueInvalide)
    );
    assert_eq!(
        message_pour_attestation(&fausse, &defi(), &liaison()),
        Err(FauteAppareil::ClePubliqueInvalide)
    );
    let mauvais_prefixe = [0x04; 33];
    assert_eq!(
        cle_publique(&mauvais_prefixe),
        Err(FauteAppareil::ClePubliqueInvalide)
    );
}

#[test]
fn les_plates_formes_font_l_aller_retour_sur_leur_octet() {
    for plateforme in [Plateforme::Aucune, Plateforme::Apple, Plateforme::Google] {
        assert_eq!(Plateforme::depuis(plateforme.etiquette()), Some(plateforme));
    }
    assert_eq!(Plateforme::depuis(3), None);
}

#[test]
fn une_signature_r_s_se_relit_telle_quelle() {
    // Ce que l'application rend : soixante-quatre octets, et rien à déplier.
    let signature = SignatureAppareil::depuis_octets([0x5A; 64]);
    assert_eq!(signature.octets(), &[0x5A; 64]);
}
