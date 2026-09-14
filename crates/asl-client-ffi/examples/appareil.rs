//! Un téléphone de papier : la voie mobile jouée de bout en bout contre un
//! annuaire réel, avec une clé LOGICIELLE et la signature par rappel.
//!
//! **Ce n'est pas un téléphone**, et c'est le point : la clé n'est protégée
//! par rien, et personne ne pose son doigt. Ce que cet exemple prouve est
//! que l'ABI enchaîne ce qu'il faut — connexion, défi, preuve, compte,
//! requêtes — et que l'annuaire l'accepte. Le matériel, c'est l'affaire de
//! l'application.
//!
//!     cargo run -p asl-client-ffi --example appareil -- \
//!         192.168.1.102:6630 speedy racine.pem

use core::ffi::{c_char, c_void};
use std::ffi::{CStr, CString};

use asl_client_ffi::appareil::{
    ASL_PLATEFORME_AUCUNE, ASL_SIGNATURE_OCTETS, asl_appareil_annuaire, asl_appareil_cle,
    asl_appareil_connecter, asl_appareil_creer_compte, asl_appareil_identifiant,
    asl_appareil_libere, asl_appareil_neuf, asl_appareil_racines, asl_appareil_requete,
};
use asl_client_ffi::{ASL_IDENTIFIANT_OCTETS, ASL_OK, asl_faute_texte};

/// Ce que le matériel ferait : signer les octets qu'on lui tend.
unsafe extern "C" fn signer(
    contexte: *mut c_void,
    message: *const u8,
    taille: usize,
    signature: *mut u8,
) -> i32 {
    use p256::ecdsa::signature::Signer as _;
    // SAFETY : le contexte est la clé secrète posée par `main`.
    let secrete = unsafe { &*contexte.cast::<p256::ecdsa::SigningKey>() };
    // SAFETY : contrat du rappel.
    let octets = unsafe { core::slice::from_raw_parts(message, taille) };
    // Le message porte son domaine ; possession ou authentification, la clé
    // signe l'un comme l'autre — ECDSA sur SHA-256, comme le matériel.
    let signee: p256::ecdsa::Signature = secrete.sign(octets);
    // SAFETY : contrat du rappel.
    unsafe {
        core::ptr::copy_nonoverlapping(signee.to_bytes().as_ptr(), signature, ASL_SIGNATURE_OCTETS);
    }
    println!("  [rappel] {taille} octets signés");
    0
}

fn texte(code: i32) -> String {
    // SAFETY : la chaîne est statique.
    unsafe { CStr::from_ptr(asl_faute_texte(code)) }
        .to_string_lossy()
        .into_owned()
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let [_, adresse, nom, racines] = arguments.as_slice() else {
        eprintln!("usage : appareil <adresse:port> <nom du certificat> <racines.pem>");
        std::process::exit(2);
    };
    let pem = std::fs::read(racines).expect("le fichier de racines se lit");

    let mut entropie = [0_u8; 32];
    for (place, octet) in entropie.iter_mut().enumerate() {
        *octet = u8::try_from(place.wrapping_mul(29).wrapping_add(11)).unwrap_or(1);
    }
    let secrete = Box::new(p256::ecdsa::SigningKey::from_slice(&entropie).expect("un scalaire"));
    let publique: Vec<u8> = secrete
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let contexte = Box::into_raw(secrete).cast::<c_void>();

    let mut appareil = core::ptr::null_mut();
    let adresse = CString::new(adresse.as_str()).unwrap();
    let nom = CString::new(nom.as_str()).unwrap();
    // SAFETY : chaque pointeur est valide pour la durée de l'appel.
    unsafe {
        assert_eq!(asl_appareil_neuf(&raw mut appareil), ASL_OK);
        assert_eq!(
            asl_appareil_annuaire(appareil, adresse.as_ptr(), nom.as_ptr()),
            ASL_OK
        );
        assert_eq!(
            asl_appareil_racines(appareil, pem.as_ptr(), pem.len()),
            ASL_OK
        );
        assert_eq!(
            asl_appareil_cle(appareil, publique.as_ptr(), Some(signer), contexte),
            ASL_OK
        );

        println!("connexion nue…");
        let code = asl_appareil_connecter(appareil);
        println!("  → {code} ({})", texte(code));
        assert_eq!(code, ASL_OK);

        println!("création du compte (POST /v1/comptes)…");
        let mut compte = [0 as c_char; ASL_IDENTIFIANT_OCTETS];
        let mut identifiant = [0 as c_char; ASL_IDENTIFIANT_OCTETS];
        let code = asl_appareil_creer_compte(
            appareil,
            ASL_PLATEFORME_AUCUNE,
            core::ptr::null(),
            0,
            compte.as_mut_ptr(),
            identifiant.as_mut_ptr(),
        );
        println!("  → {code} ({})", texte(code));
        assert_eq!(code, ASL_OK);
        println!(
            "  compte   = {}",
            CStr::from_ptr(compte.as_ptr()).to_string_lossy()
        );
        println!(
            "  appareil = {}",
            CStr::from_ptr(identifiant.as_ptr()).to_string_lossy()
        );

        let mut relu = [0 as c_char; ASL_IDENTIFIANT_OCTETS];
        assert_eq!(
            asl_appareil_identifiant(appareil, relu.as_mut_ptr()),
            ASL_OK
        );

        for (methode, chemin, corps) in [
            ("GET", "/v1/autorisations", ""),
            (
                "POST",
                "/v1/machines",
                r#"{"nom":"grenier","capacites":["annonce"]}"#,
            ),
            ("PUT", "/v1/alias", r#"{"alias":"papier"}"#),
            ("GET", "/v1/alias/papier", ""),
            ("GET", "/v1/vu", ""),
        ] {
            let m = CString::new(methode).unwrap();
            let c = CString::new(chemin).unwrap();
            let mut sortie = vec![0_u8; 64 * 1024];
            let mut ecrit = 0_usize;
            let mut statut = 0_u16;
            let pointeur = if corps.is_empty() {
                core::ptr::null()
            } else {
                corps.as_ptr()
            };
            let code = asl_appareil_requete(
                appareil,
                m.as_ptr(),
                c.as_ptr(),
                pointeur,
                corps.len(),
                sortie.as_mut_ptr(),
                sortie.len(),
                &raw mut ecrit,
                &raw mut statut,
            );
            let rendu = String::from_utf8_lossy(&sortie[..ecrit.min(sortie.len())]);
            println!(
                "{methode} {chemin} → {code} ({}) statut {statut} : {rendu}",
                texte(code)
            );
        }

        // Une seconde connexion, cette fois AUTHENTIFIÉE par l'identité posée :
        // le rappel est appelé sur le message d'authentification.
        println!("reconnexion authentifiée…");
        let code = asl_appareil_connecter(appareil);
        println!("  → {code} ({})", texte(code));
        assert_eq!(code, ASL_OK);
        let m = CString::new("GET").unwrap();
        let c = CString::new("/v1/autorisations").unwrap();
        let mut sortie = vec![0_u8; 4096];
        let (mut ecrit, mut statut) = (0_usize, 0_u16);
        let code = asl_appareil_requete(
            appareil,
            m.as_ptr(),
            c.as_ptr(),
            core::ptr::null(),
            0,
            sortie.as_mut_ptr(),
            sortie.len(),
            &raw mut ecrit,
            &raw mut statut,
        );
        println!(
            "GET /v1/autorisations → {code} statut {statut} : {}",
            String::from_utf8_lossy(&sortie[..ecrit])
        );

        asl_appareil_libere(appareil);
        drop(Box::from_raw(contexte.cast::<p256::ecdsa::SigningKey>()));
    }
    println!("OK");
}
