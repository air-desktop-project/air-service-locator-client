//! Le handle MACHINE (`asl_client_*`) qui vise un annuaire par son identité
//! (`asl_client_annuaire_identifie`, décisions 58 et 59), appelé comme C
//! l'appelle, contre un vrai banc.
//!
//! # POURQUOI CET ESSAI
//!
//! Jusqu'ici, seul le handle appareil savait dire « cette adresse, cette
//! identité ». Un daemon — ou l'application macOS qui enrôle son Mac comme
//! machine — ne savait parler qu'à un annuaire nommé et signé par une
//! autorité : face à un annuaire qui ne sert que son certificat d'identité, il
//! n'aurait rien trouvé à croire. Ce qui est éprouvé ici, c'est que
//! l'identité posée par la frontière arrive jusqu'à la poignée de main — et
//! qu'une autre identité ne passe pas.
//!
//! **Aucun nom n'est résolu** (C20) : le banc écoute sur `127.0.0.1`, et c'est
//! une adresse qu'on passe.

#[path = "../../asl-client-tokio/tests/banc/mod.rs"]
mod banc;

use std::ffi::CString;
use std::ptr;
use std::time::{Duration, Instant};

use asl_cle::CleSecrete;
use asl_client_ffi::{
    ASL_ARGUMENT, ASL_GRAINE_OCTETS, ASL_OK, ASL_TCP, AslClient, AslEtat, AslPoint, asl_annoncer,
    asl_client_annuaire_identifie, asl_client_identite, asl_client_libere, asl_client_neuf,
    asl_etat,
};
use banc::{FauxAnnuaire, lever};

fn moteur() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("un moteur pour le banc")
}

/// Encode en PEM — ce que le banc lit.
fn pem(etiquette: &str, der: &[u8]) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const DECALAGES_OCTETS: [u32; 3] = [16, 8, 0];
    const DECALAGES_SIGNES: [u32; 4] = [18, 12, 6, 0];
    let mut b64 = Vec::new();
    for bloc in der.chunks(3) {
        let n = bloc
            .iter()
            .zip(DECALAGES_OCTETS)
            .fold(0_u32, |acc, (&o, decalage)| {
                acc | (u32::from(o) << decalage)
            });
        for (i, decalage) in DECALAGES_SIGNES.into_iter().enumerate() {
            if i <= bloc.len() {
                let rang = usize::try_from((n >> decalage) & 0x3f).expect("six bits");
                b64.push(TABLE[rang]);
            } else {
                b64.push(b'=');
            }
        }
    }
    let mut sortie = format!("-----BEGIN {etiquette}-----\n").into_bytes();
    for ligne in b64.chunks(64) {
        sortie.extend_from_slice(ligne);
        sortie.push(b'\n');
    }
    sortie.extend_from_slice(format!("-----END {etiquette}-----\n").as_bytes());
    sortie
}

/// Un client machine qui vise ce locateur sous cette identité, et qui a son
/// identité de machine.
fn client_identifie(locateur: &str, n: &str) -> *mut AslClient {
    let mut client = ptr::null_mut();
    assert_eq!(unsafe { asl_client_neuf(&raw mut client) }, ASL_OK);
    let locateur = CString::new(locateur).expect("sans NUL");
    let n = CString::new(n).expect("sans NUL");
    assert_eq!(
        unsafe { asl_client_annuaire_identifie(client, locateur.as_ptr(), n.as_ptr()) },
        ASL_OK
    );
    let machine = CString::new(banc::machine().texte().as_str()).expect("sans NUL");
    let graine = [0x42_u8; ASL_GRAINE_OCTETS];
    assert_eq!(
        unsafe { asl_client_identite(client, machine.as_ptr(), graine.as_ptr()) },
        ASL_OK
    );
    client
}

/// Annonce un service, et attend que l'attache se dise établie.
fn s_attache(client: *mut AslClient, patience: Duration) -> bool {
    let point = AslPoint {
        port: 8080,
        protocole: ASL_TCP,
        reserve: 0,
    };
    assert_eq!(
        unsafe { asl_annoncer(client, c"depot".as_ptr(), &raw const point, 1) },
        ASL_OK
    );
    let depart = Instant::now();
    while depart.elapsed() < patience {
        let mut etat = AslEtat {
            attaches: 0,
            ruptures: 0,
            attachee: 0,
            abandonnee: 0,
            reserve: [0; 6],
        };
        assert_eq!(unsafe { asl_etat(client, &raw mut etat) }, ASL_OK);
        if etat.attachee == 1 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn une_machine_s_annonce_a_un_annuaire_qui_ne_sert_que_son_identite() {
    let banc = moteur();
    let cle = CleSecrete::depuis_entropie([0x31; 32]);
    let (ecoute, tache) = banc.block_on(lever(
        pem("CERTIFICATE", &asl_cle::certificat_d_identite(&cle)),
        pem("PRIVATE KEY", &asl_cle::cle_pkcs8(&cle)),
        FauxAnnuaire,
    ));
    let n = asl_cle::identifiant_de_racine(&cle.publique());

    // **AUCUNE AUTORITÉ** n'est posée : seule la clé fait croire.
    let client = client_identifie(&format!("127.0.0.1:{}", ecoute.port()), n.texte().as_str());
    assert!(
        s_attache(client, Duration::from_secs(10)),
        "une machine qui vise l'identité du banc doit s'y attacher"
    );
    unsafe { asl_client_libere(client) };
    tache.abort();
}

#[test]
fn une_machine_qui_attend_une_autre_identite_ne_s_attache_pas() {
    let banc = moteur();
    let cle = CleSecrete::depuis_entropie([0x32; 32]);
    let (ecoute, tache) = banc.block_on(lever(
        pem("CERTIFICATE", &asl_cle::certificat_d_identite(&cle)),
        pem("PRIVATE KEY", &asl_cle::cle_pkcs8(&cle)),
        FauxAnnuaire,
    ));
    // Le banc présente la clé 0x32 ; on attend celle de 0x33.
    let autre = CleSecrete::depuis_entropie([0x33; 32]);
    let attendue = asl_cle::identifiant_de_racine(&autre.publique());

    let client = client_identifie(
        &format!("127.0.0.1:{}", ecoute.port()),
        attendue.texte().as_str(),
    );
    assert!(
        !s_attache(client, Duration::from_secs(3)),
        "une autre clé que celle attendue ne doit rien faire croire"
    );
    unsafe { asl_client_libere(client) };
    tache.abort();
}

#[test]
fn un_locateur_ou_une_identite_de_travers_rendent_argument() {
    let mut client = ptr::null_mut();
    assert_eq!(unsafe { asl_client_neuf(&raw mut client) }, ASL_OK);
    let n = c"n-0PWT8HZD80QMSPPDZ5CQXXYHQC";
    unsafe {
        assert_eq!(
            asl_client_annuaire_identifie(ptr::null_mut(), c"[::1]:6630".as_ptr(), n.as_ptr()),
            ASL_ARGUMENT
        );
        assert_eq!(
            asl_client_annuaire_identifie(client, ptr::null(), n.as_ptr()),
            ASL_ARGUMENT
        );
        assert_eq!(
            asl_client_annuaire_identifie(client, c"[::1]:6630".as_ptr(), ptr::null()),
            ASL_ARGUMENT
        );
        // Un NOM n'est pas un locateur (C20) : il se résout chez l'appelant.
        assert_eq!(
            asl_client_annuaire_identifie(
                client,
                c"nitrogen.air-desktop.org:6630".as_ptr(),
                n.as_ptr()
            ),
            ASL_ARGUMENT
        );
        // Un identifiant d'un autre genre n'est pas celui d'un annuaire.
        let machine = CString::new(banc::machine().texte().as_str()).expect("sans NUL");
        assert_eq!(
            asl_client_annuaire_identifie(client, c"[::1]:6630".as_ptr(), machine.as_ptr()),
            ASL_ARGUMENT
        );
        assert_eq!(
            asl_client_annuaire_identifie(client, c"[::1]:6630".as_ptr(), n.as_ptr()),
            ASL_OK
        );
        asl_client_libere(client);
    }
}
