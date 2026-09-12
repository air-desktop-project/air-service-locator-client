//! La frontière de la voie mobile, appelée comme C l'appelle.
//!
//! Ce qui est derrière est déjà éprouvé de bout en bout dans
//! `asl-client-tokio` ; ce qui ne l'est nulle part ailleurs est la frontière
//! elle-même — un pointeur nul, une clé hors de la courbe, une requête sans
//! connexion, un rappel qui refuse.

use core::ffi::{c_char, c_void};
use std::ptr;

use asl_client_ffi::appareil::{
    ASL_ATTESTATION_MAX, ASL_CLE_APPAREIL_OCTETS, ASL_DEFI_OCTETS, ASL_MESSAGE_MAX,
    ASL_PLATEFORME_APPLE, ASL_PLATEFORME_AUCUNE, ASL_PLATEFORME_GOOGLE, ASL_SIGNATURE_OCTETS,
    AslAppareil, asl_appareil_annuaire, asl_appareil_cle, asl_appareil_connecter,
    asl_appareil_creer_compte, asl_appareil_deconnecter, asl_appareil_defi,
    asl_appareil_identifiant, asl_appareil_identite, asl_appareil_liaison, asl_appareil_libere,
    asl_appareil_message_pour_attestation, asl_appareil_neuf, asl_appareil_racines,
    asl_appareil_requete,
};
use asl_client_ffi::{
    ASL_ARGUMENT, ASL_CONFIGURATION, ASL_IDENTIFIANT_OCTETS, ASL_NON_CONNECTE, ASL_OK,
    ASL_PAS_D_IDENTITE,
};
use asl_id::{Genre, Identifiant};

fn appareil() -> *mut AslAppareil {
    let mut brut: *mut AslAppareil = ptr::null_mut();
    assert_eq!(unsafe { asl_appareil_neuf(&raw mut brut) }, ASL_OK);
    assert!(!brut.is_null());
    brut
}

/// Une vraie clé publique P-256, pour qu'`asl_appareil_cle` l'accepte.
fn cle_valide() -> [u8; ASL_CLE_APPAREIL_OCTETS] {
    asl_cle::CleSecreteAppareil::depuis_entropie([0x33; 32])
        .expect("un scalaire")
        .publique()
        .octets()
}

/// Un signataire qui dit toujours oui, et compte combien de fois on l'a appelé.
unsafe extern "C" fn signe_tout(
    contexte: *mut c_void,
    _message: *const u8,
    _taille: usize,
    signature: *mut u8,
) -> i32 {
    // SAFETY : le contexte est le compteur que l'essai a posé.
    unsafe {
        let compteur = contexte.cast::<u32>();
        compteur.write(compteur.read().saturating_add(1));
        for i in 0..ASL_SIGNATURE_OCTETS {
            signature.add(i).write(0x42);
        }
    }
    0
}

#[test]
fn les_constantes_sont_celles_de_l_en_tete() {
    assert_eq!(ASL_CLE_APPAREIL_OCTETS, 33);
    assert_eq!(ASL_SIGNATURE_OCTETS, 64);
    assert_eq!(ASL_DEFI_OCTETS, 32);
    assert_eq!(ASL_MESSAGE_MAX, 138);
    assert_eq!(ASL_ATTESTATION_MAX, 8192);
    assert_eq!(
        (
            ASL_PLATEFORME_AUCUNE,
            ASL_PLATEFORME_APPLE,
            ASL_PLATEFORME_GOOGLE
        ),
        (0, 1, 2)
    );
}

#[test]
fn les_pointeurs_nuls_rendent_argument_et_ne_tuent_personne() {
    unsafe {
        assert_eq!(asl_appareil_neuf(ptr::null_mut()), ASL_ARGUMENT);
        assert_eq!(
            asl_appareil_annuaire(ptr::null_mut(), c"[::1]:6630".as_ptr(), c"x".as_ptr()),
            ASL_ARGUMENT
        );
        assert_eq!(
            asl_appareil_racines(ptr::null_mut(), [0].as_ptr(), 1),
            ASL_ARGUMENT
        );
        assert_eq!(
            asl_appareil_cle(
                ptr::null_mut(),
                cle_valide().as_ptr(),
                Some(signe_tout),
                ptr::null_mut()
            ),
            ASL_ARGUMENT
        );
        assert_eq!(asl_appareil_connecter(ptr::null_mut()), ASL_ARGUMENT);
        assert_eq!(asl_appareil_deconnecter(ptr::null_mut()), ASL_ARGUMENT);
        assert_eq!(
            asl_appareil_identifiant(ptr::null(), ptr::null_mut()),
            ASL_ARGUMENT
        );
        asl_appareil_libere(ptr::null_mut());
    }
}

#[test]
fn une_cle_hors_de_la_courbe_ou_sans_rappel_est_refusee() {
    let brut = appareil();
    let mut compteur = 0_u32;
    let contexte = (&raw mut compteur).cast::<c_void>();
    unsafe {
        let fausse = [0xFF; ASL_CLE_APPAREIL_OCTETS];
        assert_eq!(
            asl_appareil_cle(brut, fausse.as_ptr(), Some(signe_tout), contexte),
            ASL_ARGUMENT
        );
        assert_eq!(
            asl_appareil_cle(brut, cle_valide().as_ptr(), None, contexte),
            ASL_ARGUMENT
        );
        assert_eq!(
            asl_appareil_cle(brut, ptr::null(), Some(signe_tout), contexte),
            ASL_ARGUMENT
        );
        assert_eq!(
            asl_appareil_cle(brut, cle_valide().as_ptr(), Some(signe_tout), contexte),
            ASL_OK
        );
        asl_appareil_libere(brut);
    }
    // Poser une clé n'a rien fait signer.
    assert_eq!(compteur, 0);
}

#[test]
fn une_identite_doit_etre_un_appareil() {
    let brut = appareil();
    let machine = Identifiant::depuis_entropie(Genre::Machine, [1; 16]);
    let appareil_id = Identifiant::depuis_entropie(Genre::Appareil, [1; 16]);
    let m = std::ffi::CString::new(machine.texte().as_str()).unwrap();
    let a = std::ffi::CString::new(appareil_id.texte().as_str()).unwrap();
    let mut sortie = [0 as c_char; ASL_IDENTIFIANT_OCTETS];
    unsafe {
        assert_eq!(
            asl_appareil_identifiant(brut, sortie.as_mut_ptr()),
            ASL_PAS_D_IDENTITE
        );
        assert_eq!(asl_appareil_identite(brut, m.as_ptr()), ASL_ARGUMENT);
        assert_eq!(
            asl_appareil_identite(brut, c"pas un identifiant".as_ptr()),
            ASL_ARGUMENT
        );
        assert_eq!(asl_appareil_identite(brut, a.as_ptr()), ASL_OK);
        assert_eq!(asl_appareil_identifiant(brut, sortie.as_mut_ptr()), ASL_OK);
        let relu = core::ffi::CStr::from_ptr(sortie.as_ptr()).to_str().unwrap();
        assert_eq!(relu, appareil_id.texte().as_str());
        asl_appareil_libere(brut);
    }
}

#[test]
fn sans_connexion_tout_verbe_le_dit() {
    let brut = appareil();
    let mut ecrit = 0_usize;
    let mut statut = 0_u16;
    let mut octets = [0_u8; ASL_DEFI_OCTETS];
    let mut compte = [0 as c_char; ASL_IDENTIFIANT_OCTETS];
    let mut app = [0 as c_char; ASL_IDENTIFIANT_OCTETS];
    unsafe {
        assert_eq!(
            asl_appareil_requete(
                brut,
                c"GET".as_ptr(),
                c"/v1/autorisations".as_ptr(),
                ptr::null(),
                0,
                ptr::null_mut(),
                0,
                &raw mut ecrit,
                &raw mut statut
            ),
            ASL_NON_CONNECTE
        );
        assert_eq!(
            asl_appareil_liaison(brut, octets.as_mut_ptr()),
            ASL_NON_CONNECTE
        );
        assert_eq!(
            asl_appareil_defi(brut, octets.as_mut_ptr()),
            ASL_NON_CONNECTE
        );
        assert_eq!(
            asl_appareil_creer_compte(
                brut,
                ASL_PLATEFORME_AUCUNE,
                ptr::null(),
                0,
                compte.as_mut_ptr(),
                app.as_mut_ptr()
            ),
            ASL_NON_CONNECTE
        );
        assert_eq!(
            asl_appareil_message_pour_attestation(brut, ptr::null_mut(), 0, &raw mut ecrit),
            ASL_NON_CONNECTE
        );
        // Se déconnecter sans connexion n'est pas une faute.
        assert_eq!(asl_appareil_deconnecter(brut), ASL_OK);
        asl_appareil_libere(brut);
    }
}

#[test]
fn une_requete_mal_formee_est_refusee_avant_de_chercher_une_connexion() {
    let brut = appareil();
    let mut ecrit = 0_usize;
    let mut statut = 0_u16;
    unsafe {
        // Une méthode inconnue, un chemin hors de `/v1/`, un corps nul avec une
        // taille, un `ecrit` nul : chacun est une faute d'appelant.
        assert_eq!(
            asl_appareil_requete(
                brut,
                c"FETCH".as_ptr(),
                c"/v1/x".as_ptr(),
                ptr::null(),
                0,
                ptr::null_mut(),
                0,
                &raw mut ecrit,
                &raw mut statut
            ),
            ASL_ARGUMENT
        );
        assert_eq!(
            asl_appareil_requete(
                brut,
                c"GET".as_ptr(),
                c"/v2/x".as_ptr(),
                ptr::null(),
                0,
                ptr::null_mut(),
                0,
                &raw mut ecrit,
                &raw mut statut
            ),
            ASL_ARGUMENT
        );
        assert_eq!(
            asl_appareil_requete(
                brut,
                c"GET".as_ptr(),
                c"/v1/x".as_ptr(),
                ptr::null(),
                4,
                ptr::null_mut(),
                0,
                &raw mut ecrit,
                &raw mut statut
            ),
            ASL_ARGUMENT
        );
        assert_eq!(
            asl_appareil_requete(
                brut,
                c"GET".as_ptr(),
                c"/v1/x".as_ptr(),
                ptr::null(),
                0,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &raw mut statut
            ),
            ASL_ARGUMENT
        );
        // Une plate-forme inconnue, une attestation sans octets, une attestation
        // trop longue.
        let mut compte = [0 as c_char; ASL_IDENTIFIANT_OCTETS];
        let mut app = [0 as c_char; ASL_IDENTIFIANT_OCTETS];
        assert_eq!(
            asl_appareil_creer_compte(
                brut,
                9,
                ptr::null(),
                0,
                compte.as_mut_ptr(),
                app.as_mut_ptr()
            ),
            ASL_ARGUMENT
        );
        assert_eq!(
            asl_appareil_creer_compte(
                brut,
                ASL_PLATEFORME_APPLE,
                ptr::null(),
                12,
                compte.as_mut_ptr(),
                app.as_mut_ptr()
            ),
            ASL_ARGUMENT
        );
        let trop = vec![0_u8; ASL_ATTESTATION_MAX + 1];
        assert_eq!(
            asl_appareil_creer_compte(
                brut,
                ASL_PLATEFORME_APPLE,
                trop.as_ptr(),
                trop.len(),
                compte.as_mut_ptr(),
                app.as_mut_ptr()
            ),
            ASL_ARGUMENT
        );
        asl_appareil_libere(brut);
    }
}

#[test]
fn se_connecter_sans_annuaire_est_une_configuration_et_sans_reponse_une_injoignabilite() {
    let brut = appareil();
    unsafe {
        assert_eq!(asl_appareil_connecter(brut), ASL_CONFIGURATION);
        // Un nom, et non une adresse : refusé à la pose.
        assert_eq!(
            asl_appareil_annuaire(brut, c"annuaire.example:6630".as_ptr(), c"x".as_ptr()),
            ASL_ARGUMENT
        );
        assert_eq!(
            asl_appareil_annuaire(brut, c"[::1]:6630".as_ptr(), c"".as_ptr()),
            ASL_ARGUMENT
        );
        // Un annuaire posé sans racine : la configuration ne tient toujours pas.
        assert_eq!(
            asl_appareil_annuaire(brut, c"127.0.0.1:9".as_ptr(), c"localhost".as_ptr()),
            ASL_OK
        );
        assert_eq!(asl_appareil_connecter(brut), ASL_CONFIGURATION);
        asl_appareil_libere(brut);
    }
}
