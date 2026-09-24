//! Ce que l'ABI GARDE entre deux appels : le défi de la connexion en cours.
//!
//! # POURQUOI CET ESSAI A BESOIN D'UNE VRAIE CONNEXION
//!
//! Les autres essais de cette frontière se passent de socket : un pointeur nul,
//! une clé hors de la courbe, une requête sans connexion se jugent sur place.
//! Celui-ci ne le peut pas. Le défi n'existe que sur une connexion ouverte, il
//! est rangé dans le handle, et la question posée ici — **survit-il à un geste
//! que le porteur refuse ?** — ne se pose qu'entre deux appels séparés.
//!
//! C'est la classe de défaut qu'aucun essai de frontière n'attrape, et elle a
//! coûté une clé en production le 2026-09-23 : sur un Fairphone 5, le défi
//! était jeté AVANT que le signataire soit appelé, si bien qu'une empreinte
//! refusée condamnait une clé déjà née avec son attestation.
//!
//! Le banc est celui d'`asl-client-tokio`, inclus par chemin : un banc recopié
//! est un banc qui diverge, et son en-tête dit ce qu'il éprouve et ce qu'il
//! feint.

#[path = "../../asl-client-tokio/tests/banc/mod.rs"]
mod banc;

use core::ffi::c_void;
use std::ffi::CString;
use std::ptr;

use asl_client_ffi::appareil::{
    ASL_CLE_APPAREIL_OCTETS, ASL_DEFI_OCTETS, ASL_SIGNATURE_OCTETS, AslAppareil,
    asl_appareil_annuaire, asl_appareil_cle, asl_appareil_connecter, asl_appareil_defi,
    asl_appareil_identite, asl_appareil_liaison, asl_appareil_libere, asl_appareil_neuf,
    asl_appareil_racines,
};
use asl_client_ffi::{ASL_INJOIGNABLE, ASL_NON_CONNECTE, ASL_OK, ASL_SIGNATURE_REFUSEE};
use asl_id::{Genre, Identifiant};
use banc::{FauxAnnuaire, lever, materiel};

/// Une vraie clé publique P-256 — le banc ne la vérifie pas, `asl_appareil_cle`
/// si.
fn cle_valide() -> [u8; ASL_CLE_APPAREIL_OCTETS] {
    asl_cle::CleSecreteAppareil::depuis_entropie([0x51; 32])
        .expect("un scalaire")
        .publique()
        .octets()
}

/// Le porteur refuse la PREMIÈRE fois, puis pose son doigt.
///
/// C'est le geste réel qu'on rejoue : une invite annulée, ou laissée expirer,
/// puis la même invite acceptée. Le contexte compte les sollicitations — une
/// par appel, jamais deux.
unsafe extern "C" fn refuse_puis_signe(
    contexte: *mut c_void,
    _message: *const u8,
    _taille: usize,
    signature: *mut u8,
) -> i32 {
    // SAFETY : le contexte est le compteur que l'essai a posé.
    unsafe {
        let compteur = contexte.cast::<u32>();
        let deja = compteur.read();
        compteur.write(deja.saturating_add(1));
        if deja == 0 {
            // Toute valeur non nulle veut dire « le porteur n'a pas signé ».
            return -1;
        }
        for i in 0..ASL_SIGNATURE_OCTETS {
            signature.add(i).write(0x42);
        }
    }
    0
}

/// La liaison de canal de la connexion en cours — elle change avec elle, et
/// c'est ce qui permet de dire, du dehors, si la connexion est la même.
fn liaison(brut: *mut AslAppareil) -> [u8; ASL_DEFI_OCTETS] {
    let mut octets = [0_u8; ASL_DEFI_OCTETS];
    assert_eq!(
        unsafe { asl_appareil_liaison(brut, octets.as_mut_ptr()) },
        ASL_OK
    );
    octets
}

/// Un geste refusé ne dépense pas le défi ; un geste accepté, si.
///
/// **LA PREUVE EST LA LIAISON DE CANAL.** Si le défi survit, le second essai
/// prouve sur LA MÊME connexion — celle qui a vu naître la clé — et sa liaison
/// ne bouge pas. S'il avait été jeté, `asl_appareil_connecter` n'aurait plus eu
/// de défi à porter : il aurait fermé cette connexion, en aurait ouvert une
/// neuve, et la liaison aurait changé. C'est exactement ce qui condamnait la
/// clé d'un appareil en train de rejoindre, dont l'attestation ne vaut que sur
/// le défi de sa connexion.
#[test]
fn un_geste_refuse_garde_le_defi_un_geste_accepte_le_depense() {
    let (_atelier, autorite, cert, cle) = materiel("defi-refus");
    let moteur = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("un moteur");
    // Le banc tourne sur SES fils : les appels d'ABI qui suivent bloquent celui
    // de l'essai, et un ordonnanceur à un seul fil ne progresserait plus.
    let (adresse, tache) = moteur.block_on(async { lever(cert, cle, FauxAnnuaire).await });

    let mut brut: *mut AslAppareil = ptr::null_mut();
    assert_eq!(unsafe { asl_appareil_neuf(&raw mut brut) }, ASL_OK);
    let ou = CString::new(adresse.to_string()).expect("une adresse");
    let mut compteur: u32 = 0;
    unsafe {
        assert_eq!(
            asl_appareil_annuaire(brut, ou.as_ptr(), c"localhost".as_ptr()),
            ASL_OK
        );
        assert_eq!(
            asl_appareil_racines(brut, autorite.as_ptr(), autorite.len()),
            ASL_OK
        );
        assert_eq!(
            asl_appareil_cle(
                brut,
                cle_valide().as_ptr(),
                Some(refuse_puis_signe),
                (&raw mut compteur).cast::<c_void>(),
            ),
            ASL_OK
        );

        // Nue : c'est l'état d'où l'on rejoint, et le porteur n'est pas encore
        // sollicité.
        assert_eq!(asl_appareil_connecter(brut), ASL_OK);
        let avant = liaison(brut);
        assert_eq!(compteur, 0, "une connexion nue ne demande aucun geste");

        // Le défi, tiré AVANT la clé sur un vrai téléphone.
        let mut defi = [0_u8; ASL_DEFI_OCTETS];
        assert_eq!(asl_appareil_defi(brut, defi.as_mut_ptr()), ASL_OK);

        // L'ancien appareil a apporté la clé : on connaît enfin son `a-…`.
        let identite = Identifiant::depuis_entropie(Genre::Appareil, [0x9E; 16]);
        let texte = CString::new(identite.texte().as_str()).expect("un identifiant");
        assert_eq!(asl_appareil_identite(brut, texte.as_ptr()), ASL_OK);

        // LE REFUS. Rien n'est parti : l'annuaire n'a rien vu.
        assert_eq!(asl_appareil_connecter(brut), ASL_SIGNATURE_REFUSEE);
        assert_eq!(compteur, 1, "le porteur a été sollicité une fois");
        assert_eq!(
            liaison(brut),
            avant,
            "un refus ne touche pas à la connexion"
        );

        // LE SECOND ESSAI, sans nouveau défi et sans nouvelle clé.
        assert_eq!(asl_appareil_connecter(brut), ASL_OK);
        assert_eq!(compteur, 2, "un second geste, et un seul");
        assert_eq!(
            liaison(brut),
            avant,
            "la preuve est portée sur la connexion qui a vu naître la clé"
        );

        // ET MAINTENANT LE DÉFI EST BIEN DÉPENSÉ — c'est l'autre moitié de la
        // règle, et la corriger d'un côté ne doit pas la casser de l'autre.
        // Sans défi à porter, `connecter` ferme la connexion en cours et en
        // ouvre une neuve ; ce banc n'en sert qu'UNE à la fois, si bien que
        // l'injoignabilité est ici la trace même de la réouverture.
        assert_eq!(asl_appareil_connecter(brut), ASL_INJOIGNABLE);
        assert_eq!(
            compteur, 2,
            "rien à signer tant qu'aucune connexion n'est ouverte"
        );
        let mut perdue = [0_u8; ASL_DEFI_OCTETS];
        assert_eq!(
            asl_appareil_liaison(brut, perdue.as_mut_ptr()),
            ASL_NON_CONNECTE,
            "l'ancienne connexion a bien été fermée avant la tentative"
        );

        asl_appareil_libere(brut);
    }
    tache.abort();
}
