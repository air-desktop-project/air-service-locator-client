//! `GET /v1/nouvelles` à travers l'ABI, appelée comme C l'appelle — et comme
//! une application l'appellera : un fil qui attend, un autre qui requête.
//!
//! # POURQUOI CET ESSAI A BESOIN D'UNE VRAIE CONNEXION
//!
//! Le transport est éprouvé dans `asl-client-tokio` (`tests/nouvelles.rs`). Ce
//! qui ne l'est nulle part ailleurs est ce que la frontière promet d'un appel à
//! l'autre : qu'une attente rende `ASL_PAS_DE_POUSSEE` à son échéance, qu'un
//! tampon trop petit laisse la ligne EN TÊTE au lieu de la perdre, qu'un `409`
//! devienne `ASL_DEJA` — et que `asl_appareil_requete` passe pendant qu'un
//! autre fil attend sur le MÊME handle, ce que l'en-tête affirme.
//!
//! Le banc est celui d'`asl-client-tokio`, inclus par chemin (voir
//! `tests/rejoindre.rs`).

#[path = "../../asl-client-tokio/tests/banc/mod.rs"]
mod banc;

use std::ffi::CString;
use std::ptr;
use std::time::{Duration, Instant};

use ams_proto_http::{Method, StatusCode};
use asl_client_ffi::appareil::{
    ASL_ADRESSE_OCTETS, ASL_NOUVELLE_MAX, AslAppareil, asl_appareil_annuaire,
    asl_appareil_connecter, asl_appareil_deconnecter, asl_appareil_distante, asl_appareil_libere,
    asl_appareil_neuf, asl_appareil_nouvelle, asl_appareil_nouvelles_ouvrir,
    asl_appareil_nouvelles_recues, asl_appareil_racines, asl_appareil_requete,
};
use asl_client_ffi::{
    ASL_DEJA, ASL_NON_CONNECTE, ASL_OK, ASL_PAS_DE_POUSSEE, ASL_REFUSE, ASL_TAMPON_TROP_PETIT,
};
use banc::{lever, lever_qui_pousse, materiel};

/// Un annuaire qui tient le PREMIER `GET /v1/nouvelles` ouvert, et rend `409`
/// aux suivants — la règle « un par connexion » de `protocole.md`.
#[derive(Debug, Default)]
struct AnnuaireQuiNotifie {
    ouverts: u32,
}

impl ams_h3::Service for AnnuaireQuiNotifie {
    fn serve<'o>(
        &mut self,
        tete: &ams_proto_http::RequestHead<'_>,
        _corps: &[u8],
        sortie: &'o mut [u8],
    ) -> ams_h3::Reponse<'o> {
        match (tete.method(), tete.path()) {
            (Method::Get, b"/v1/nouvelles") => {
                self.ouverts = self.ouverts.saturating_add(1);
                if self.ouverts == 1 {
                    ams_h3::Reponse::new(StatusCode::OK, &[]).tenue()
                } else {
                    ams_h3::Reponse::new(StatusCode::CONFLICT, &[])
                }
            }
            (Method::Get, b"/v1/autorisations") => {
                let place = sortie.get_mut(..2).unwrap_or_default();
                place.copy_from_slice(b"[]");
                ams_h3::Reponse::new(StatusCode::OK, place)
            }
            _ => ams_h3::Reponse::new(StatusCode::NOT_FOUND, &[]),
        }
    }
}

/// Un annuaire pour qui cet appareil a été révoqué depuis sa preuve.
struct Revoque;

impl ams_h3::Service for Revoque {
    fn serve<'o>(
        &mut self,
        _tete: &ams_proto_http::RequestHead<'_>,
        _corps: &[u8],
        _sortie: &'o mut [u8],
    ) -> ams_h3::Reponse<'o> {
        ams_h3::Reponse::new(StatusCode::UNAUTHORIZED, &[])
    }
}

const AUTORISATION: &[u8] = br#"{"quoi":"autorisation"}"#;

/// Le handle, tel qu'un autre fil le reçoit : **un entier**, parce qu'un
/// pointeur brut n'est pas `Send` — et l'en-tête dit précisément que ce
/// partage-là est permis.
#[derive(Clone, Copy)]
struct Partage(usize);

impl Partage {
    fn pointeur(self) -> *const AslAppareil {
        self.0 as *const AslAppareil
    }
}

/// Un moteur pour le banc : il tourne sur SES fils, pendant que les appels
/// d'ABI bloquent celui de l'essai.
fn moteur() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("un moteur")
}

/// Un appareil connecté — nu : le banc ne vérifie rien, et c'est le flux qu'on
/// éprouve, pas la preuve.
fn connecte(adresse: std::net::SocketAddr, autorite: &[u8]) -> *mut AslAppareil {
    let mut brut: *mut AslAppareil = ptr::null_mut();
    let ou = CString::new(adresse.to_string()).expect("une adresse");
    unsafe {
        assert_eq!(asl_appareil_neuf(&raw mut brut), ASL_OK);
        assert_eq!(
            asl_appareil_annuaire(brut, ou.as_ptr(), c"localhost".as_ptr()),
            ASL_OK
        );
        assert_eq!(
            asl_appareil_racines(brut, autorite.as_ptr(), autorite.len()),
            ASL_OK
        );
        assert_eq!(asl_appareil_connecter(brut), ASL_OK);
    }
    brut
}

/// Une attente, sur ce handle, dans ce tampon.
fn attendre(brut: *const AslAppareil, attente_ms: u32, tampon: &mut [u8]) -> (i32, usize) {
    let mut ecrit = 0_usize;
    let sortie = if tampon.is_empty() {
        ptr::null_mut()
    } else {
        tampon.as_mut_ptr()
    };
    let code =
        unsafe { asl_appareil_nouvelle(brut, attente_ms, sortie, tampon.len(), &raw mut ecrit) };
    (code, ecrit)
}

#[test]
fn une_ligne_arrive_une_attente_rend_rien_et_un_second_flux_est_deja_la() {
    let (_atelier, autorite, cert, cle) = materiel("abi-nouvelles");
    let moteur = moteur();
    let (adresse, tache, voie) =
        moteur.block_on(async { lever_qui_pousse(cert, cle, AnnuaireQuiNotifie::default()).await });
    let brut = connecte(adresse, &autorite);
    let mut ligne = [0_u8; ASL_NOUVELLE_MAX];

    // Pas encore ouvert : l'attente ne dort pas pour rien.
    assert_eq!(attendre(brut, 10_000, &mut ligne).0, ASL_NON_CONNECTE);

    assert_eq!(unsafe { asl_appareil_nouvelles_ouvrir(brut) }, ASL_OK);

    // ── L'ÉCHÉANCE : « rien », et c'est le code des verdicts poussés ─────────
    let avant = Instant::now();
    assert_eq!(attendre(brut, 400, &mut ligne).0, ASL_PAS_DE_POUSSEE);
    let ecoule = avant.elapsed();
    assert!(ecoule >= Duration::from_millis(400), "rendue trop tôt");
    assert!(
        ecoule < Duration::from_secs(5),
        "rendue bien après l'échéance"
    );

    // ── UN SECOND FLUX : `409`, et le premier vit ────────────────────────────
    assert_eq!(unsafe { asl_appareil_nouvelles_ouvrir(brut) }, ASL_DEJA);

    // ── UNE LIGNE, ET UN TAMPON TROP PETIT QUI NE LA PERD PAS ────────────────
    voie.send([AUTORISATION, b"\n"].concat())
        .expect("le banc écoute");
    let mut petit = [0_u8; 4];
    assert_eq!(
        attendre(brut, 10_000, &mut petit),
        (ASL_TAMPON_TROP_PETIT, AUTORISATION.len())
    );
    // Sans tampon du tout : la même taille, toujours sans la prendre.
    assert_eq!(
        attendre(brut, 0, &mut []),
        (ASL_TAMPON_TROP_PETIT, AUTORISATION.len())
    );
    let (code, ecrit) = attendre(brut, 0, &mut ligne);
    assert_eq!(code, ASL_OK);
    assert_eq!(ligne.get(..ecrit), Some(AUTORISATION));
    // Prise : elle n'est plus là.
    assert_eq!(attendre(brut, 0, &mut ligne).0, ASL_PAS_DE_POUSSEE);
    let mut recues = 0_u64;
    assert_eq!(
        unsafe { asl_appareil_nouvelles_recues(brut, &raw mut recues) },
        ASL_OK
    );
    assert_eq!(recues, 1);

    // ── UN FIL ATTEND, L'AUTRE REQUÊTE, SUR LE MÊME HANDLE ───────────────────
    let partage = Partage(brut as usize);
    let attente = std::thread::spawn(move || {
        let mut ligne = [0_u8; ASL_NOUVELLE_MAX];
        let (code, ecrit) = attendre(partage.pointeur(), 10_000, &mut ligne);
        (code, ligne.get(..ecrit).unwrap_or_default().to_vec())
    });
    let avant = Instant::now();
    let mut corps = [0_u8; 64];
    let mut ecrit = 0_usize;
    let mut statut = 0_u16;
    assert_eq!(
        unsafe {
            asl_appareil_requete(
                brut,
                c"GET".as_ptr(),
                c"/v1/autorisations".as_ptr(),
                ptr::null(),
                0,
                corps.as_mut_ptr(),
                corps.len(),
                &raw mut ecrit,
                &raw mut statut,
            )
        },
        ASL_OK
    );
    assert_eq!((statut, corps.get(..ecrit)), (200, Some(b"[]".as_slice())));
    assert!(
        avant.elapsed() < Duration::from_secs(5),
        "la requête a attendu l'attente"
    );
    assert!(!attente.is_finished(), "rien n'a encore été poussé");
    voie.send([AUTORISATION, b"\n"].concat())
        .expect("le banc écoute");
    assert_eq!(
        attente.join().expect("le fil rend"),
        (ASL_OK, AUTORISATION.to_vec())
    );

    // ── DÉCONNECTÉ : le flux est parti avec la connexion ─────────────────────
    unsafe {
        assert_eq!(asl_appareil_deconnecter(brut), ASL_OK);
        assert_eq!(attendre(brut, 10_000, &mut ligne).0, ASL_NON_CONNECTE);
        asl_appareil_libere(brut);
    }
    tache.abort();
}

#[test]
fn un_appareil_revoque_se_voit_refuser_le_flux() {
    let (_atelier, autorite, cert, cle) = materiel("abi-nouvelles-401");
    let moteur = moteur();
    let (adresse, tache) = moteur.block_on(async { lever(cert, cle, Revoque).await });
    let brut = connecte(adresse, &autorite);
    let mut ligne = [0_u8; ASL_NOUVELLE_MAX];
    unsafe {
        assert_eq!(asl_appareil_nouvelles_ouvrir(brut), ASL_REFUSE);
        assert_eq!(attendre(brut, 10_000, &mut ligne).0, ASL_NON_CONNECTE);
        asl_appareil_libere(brut);
    }
    tache.abort();
}

/// L'adresse jointe, telle que l'ABI la rend.
fn distante(brut: *const AslAppareil) -> (i32, String) {
    let mut sortie = [0 as core::ffi::c_char; ASL_ADRESSE_OCTETS];
    let code = unsafe { asl_appareil_distante(brut, sortie.as_mut_ptr()) };
    let texte = unsafe { core::ffi::CStr::from_ptr(sortie.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    (code, texte)
}

#[test]
fn l_adresse_jointe_se_lit_meme_pendant_qu_un_fil_attend() {
    // **C'EST CE QUI DIT QUELLE RACINE A RÉPONDU** sous un nom qui en rend
    // plusieurs : le banc n'a qu'une adresse, et c'est elle qui doit revenir,
    // écrite comme `SocketAddr` l'écrit. Et comme l'en-tête le range parmi les
    // verbes qui ne font que lire, il doit passer pendant une attente.
    let (_atelier, autorite, cert, cle) = materiel("abi-distante");
    let moteur = moteur();
    let (adresse, tache, _voie) =
        moteur.block_on(async { lever_qui_pousse(cert, cle, AnnuaireQuiNotifie::default()).await });
    let brut = connecte(adresse, &autorite);
    assert_eq!(distante(brut), (ASL_OK, adresse.to_string()));

    assert_eq!(unsafe { asl_appareil_nouvelles_ouvrir(brut) }, ASL_OK);
    let partage = Partage(brut as usize);
    let attente = std::thread::spawn(move || {
        let mut ligne = [0_u8; ASL_NOUVELLE_MAX];
        attendre(partage.pointeur(), 2_000, &mut ligne).0
    });
    let avant = Instant::now();
    assert_eq!(distante(brut), (ASL_OK, adresse.to_string()));
    assert!(
        avant.elapsed() < Duration::from_secs(1),
        "la lecture a attendu l'attente"
    );
    assert!(!attente.is_finished(), "l'attente court toujours");
    assert_eq!(attente.join().expect("le fil rend"), ASL_PAS_DE_POUSSEE);

    unsafe {
        assert_eq!(asl_appareil_deconnecter(brut), ASL_OK);
    }
    assert_eq!(distante(brut).0, ASL_NON_CONNECTE);
    unsafe { asl_appareil_libere(brut) };
    tache.abort();
}
