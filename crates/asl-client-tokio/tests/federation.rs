//! Le renvoi vers un annuaire local, suivi sur de vraies sockets.
//!
//! # CE QUE CES ESSAIS PROUVENT
//!
//! La politique — un seul saut, un retour qui se paie — est éprouvée dans
//! `asl-client` (`tests/renvoi.rs`), sans attendre une seconde. Ici, on
//! éprouve qu'elle est **obéie** : qu'une racine qui répond `421` fait
//! s'annoncer le daemon chez l'annuaire local qu'elle désigne, sous la
//! confiance TLS que le porteur a donnée (`--roots`), et qu'un membre mort de
//! la paire ne retient pas l'autre.
//!
//! **Le banc est celui des autres essais** : une vraie poignée de main, une
//! sémantique feinte. Ce qu'il permet de prouver est l'enchaînement du
//! client ; que la racine ait raison de renvoyer est prouvé côté serveur.

mod banc;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ams_proto_http::{Method, StatusCode};
use asl_client::Identite;
use asl_client_tokio::{Annuaire, Attache, Reglages};
use asl_id::{Genre, Identifiant};
use banc::{FauxAnnuaire, adresse_morte, lever, materiel};

/// Le plafond de recul employé partout ici.
const PLAFOND_MS: u64 = 15_000;

fn alea() -> Arc<dyn Fn() -> [u8; 16] + Send + Sync> {
    Arc::new(|| [0x5A; 16])
}

fn identite() -> Identite {
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x11; 16]);
    Identite::nouvelle(machine, [0x42; 32]).expect("une identité d'essai")
}

fn annuaire(adresse: std::net::SocketAddr) -> Annuaire {
    Annuaire {
        adresse,
        nom: "localhost".to_owned(),
    }
}

/// L'annuaire local que la racine désigne.
fn local() -> Identifiant {
    Identifiant::depuis_entropie(Genre::Annuaire, [0x6C; 16])
}

/// Le corps d'un `421`, tel que la racine l'écrit.
fn renvoi(ports: &[u16]) -> Vec<u8> {
    let adresses: Vec<String> = ports.iter().map(|p| format!("\"localhost:{p}\"")).collect();
    format!(
        r#"{{"annuaire":"{}","adresses":[{}]}}"#,
        local().texte().as_str(),
        adresses.join(",")
    )
    .into_bytes()
}

async fn jusqu_a(patience_ms: u64, mut condition: impl FnMut() -> bool) -> bool {
    let depart = Instant::now();
    while depart.elapsed() < Duration::from_millis(patience_ms) {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    condition()
}

/// Une racine qui renvoie toute annonce vers un annuaire local.
struct Renvoyeur {
    corps: Vec<u8>,
    annonces: Arc<AtomicUsize>,
}

impl ams_h3::Service for Renvoyeur {
    fn serve<'o>(
        &mut self,
        tete: &ams_proto_http::RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> ams_h3::Reponse<'o> {
        if matches!(tete.method(), Method::Post) && tete.path() == b"/v1/annonce" {
            self.annonces.fetch_add(1, Ordering::Relaxed);
            let place = sortie.get_mut(..self.corps.len()).unwrap_or_default();
            place.copy_from_slice(&self.corps);
            let mal_adressee = StatusCode::new(421).expect("un code d'état");
            return ams_h3::Reponse::new(mal_adressee, place);
        }
        FauxAnnuaire.serve(tete, corps, sortie)
    }
}

/// Un annuaire local qui accepte, et compte ce qu'on lui annonce.
struct Compteur {
    annonces: Arc<AtomicUsize>,
}

impl ams_h3::Service for Compteur {
    fn serve<'o>(
        &mut self,
        tete: &ams_proto_http::RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> ams_h3::Reponse<'o> {
        if matches!(tete.method(), Method::Post) && tete.path() == b"/v1/annonce" {
            self.annonces.fetch_add(1, Ordering::Relaxed);
        }
        FauxAnnuaire.serve(tete, corps, sortie)
    }
}

/// Les deux autorités, comme `--roots` les porte : celle des racines, puis
/// celle que le propriétaire a frappée pour son annuaire local (décision 50).
fn deux_autorites(racines: &[u8], proprietaire: &[u8]) -> Vec<u8> {
    let mut les_deux = racines.to_vec();
    les_deux.extend_from_slice(proprietaire);
    les_deux
}

#[tokio::test]
async fn une_racine_qui_renvoie_fait_s_annoncer_chez_l_annuaire_local() {
    let (_a, autorite_racine, cert_r, cle_r) = materiel("racine-421");
    let (_b, autorite_locale, cert_l, cle_l) = materiel("local-421");
    let chez_lui = Arc::new(AtomicUsize::new(0));
    let (local_ecoute, tache_l) = lever(
        cert_l,
        cle_l,
        Compteur {
            annonces: Arc::clone(&chez_lui),
        },
    )
    .await;
    let a_la_racine = Arc::new(AtomicUsize::new(0));
    let (racine, tache_r) = lever(
        cert_r,
        cle_r,
        Renvoyeur {
            corps: renvoi(&[local_ecoute.port()]),
            annonces: Arc::clone(&a_la_racine),
        },
    )
    .await;

    let reglages = Reglages::nouveaux(
        vec![annuaire(racine)],
        deux_autorites(&autorite_racine, &autorite_locale),
        PLAFOND_MS,
    )
    .expect("la configuration est bonne");
    let attache = Attache::annoncer(reglages, identite(), vec![b"{}".to_vec()], alea());

    assert!(
        jusqu_a(10_000, || attache.etat().attachee).await,
        "elle aurait dû s'attacher chez l'annuaire local : {:?}",
        attache.etat()
    );
    let etat = attache.etat();
    assert_eq!(etat.renvois, 1);
    assert_eq!(
        a_la_racine.load(Ordering::Relaxed),
        1,
        "la racine a renvoyé une fois"
    );
    assert_eq!(
        chez_lui.load(Ordering::Relaxed),
        1,
        "l'annonce est chez l'annuaire local"
    );
    assert_eq!(
        attache.annuaire_local().as_deref(),
        Some(local().texte().as_str())
    );

    tokio::time::timeout(Duration::from_secs(5), attache.retirer())
        .await
        .expect("le retrait ne doit pas pendre");
    tache_l.abort();
    tache_r.abort();
}

#[tokio::test]
async fn un_membre_mort_de_la_paire_ne_retient_pas_l_autre() {
    let (_a, autorite_racine, cert_r, cle_r) = materiel("racine-paire");
    let (_b, autorite_locale, cert_l, cle_l) = materiel("local-paire");
    let mort = adresse_morte().await;
    let chez_b = Arc::new(AtomicUsize::new(0));
    let (membre_b, tache_l) = lever(
        cert_l,
        cle_l,
        Compteur {
            annonces: Arc::clone(&chez_b),
        },
    )
    .await;
    let (racine, tache_r) = lever(
        cert_r,
        cle_r,
        Renvoyeur {
            // Le membre A (mort) d'abord : c'est lui qu'on essaiera en premier.
            corps: renvoi(&[mort.port(), membre_b.port()]),
            annonces: Arc::new(AtomicUsize::new(0)),
        },
    )
    .await;

    let reglages = Reglages::nouveaux(
        vec![annuaire(racine)],
        deux_autorites(&autorite_racine, &autorite_locale),
        PLAFOND_MS,
    )
    .expect("la configuration est bonne");
    let depart = Instant::now();
    let attache = Attache::annoncer(reglages, identite(), vec![b"{}".to_vec()], alea());
    assert!(
        jusqu_a(10_000, || attache.etat().attachee).await,
        "le membre B aurait dû porter l'annonce : {:?}",
        attache.etat()
    );
    // **SANS PAYER DE RECUL** : un membre mort ne retarde pas l'autre — le
    // recul initial est d'une seconde, et il n'a pas dû être payé.
    assert!(
        depart.elapsed() < Duration::from_millis(asl_client::RECUL_INITIAL_MS * 3),
        "la bascule vers B a pris {:?}",
        depart.elapsed()
    );
    assert_eq!(chez_b.load(Ordering::Relaxed), 1);

    tokio::time::timeout(Duration::from_secs(5), attache.retirer())
        .await
        .expect("le retrait ne doit pas pendre");
    tache_l.abort();
    tache_r.abort();
}

#[tokio::test]
async fn un_annuaire_local_injoignable_ne_fait_ni_attache_ni_abandon_ni_boucle() {
    let (_a, autorite, cert_r, cle_r) = materiel("racine-muet");
    let mort = adresse_morte().await;
    let a_la_racine = Arc::new(AtomicUsize::new(0));
    let (racine, tache_r) = lever(
        cert_r,
        cle_r,
        Renvoyeur {
            corps: renvoi(&[mort.port()]),
            annonces: Arc::clone(&a_la_racine),
        },
    )
    .await;

    let reglages = Reglages::nouveaux(vec![annuaire(racine)], autorite, PLAFOND_MS)
        .expect("la configuration est bonne");
    let attache = Attache::annoncer(reglages, identite(), vec![b"{}".to_vec()], alea());

    assert!(
        jusqu_a(10_000, || attache.etat().renvois >= 1).await,
        "le renvoi aurait dû être suivi : {:?}",
        attache.etat()
    );
    // **PAS D'ABANDON** : un annuaire local muet est une panne, pas une
    // configuration — la tâche revient aux racines et recommence.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let etat = attache.etat();
    assert!(!etat.attachee);
    assert!(!etat.abandonnee, "une panne ne fait jamais renoncer");
    // **PAS DE BOUCLE SERRÉE** : le retour aux racines se paie d'un recul.
    assert!(
        a_la_racine.load(Ordering::Relaxed) <= 2,
        "la racine a été sollicitée {} fois en une seconde et demie",
        a_la_racine.load(Ordering::Relaxed)
    );

    tokio::time::timeout(Duration::from_secs(5), attache.retirer())
        .await
        .expect("le retrait ne doit pas pendre");
    tache_r.abort();
}

#[tokio::test]
async fn un_annuaire_local_hors_de_la_confiance_du_porteur_n_est_pas_cru() {
    // **LA CONFIANCE N'EST PAS RELÂCHÉE PAR LE RENVOI** : la racine dit où
    // aller, pas qui croire. Sans l'autorité du propriétaire dans `--roots`,
    // l'annuaire local ne se fait pas accepter, quoi que la racine ait dit.
    let (_a, autorite_racine, cert_r, cle_r) = materiel("racine-confiance");
    let (_b, _autorite_etrangere, cert_l, cle_l) = materiel("local-etranger");
    let chez_lui = Arc::new(AtomicUsize::new(0));
    let (local_ecoute, tache_l) = lever(
        cert_l,
        cle_l,
        Compteur {
            annonces: Arc::clone(&chez_lui),
        },
    )
    .await;
    let (racine, tache_r) = lever(
        cert_r,
        cle_r,
        Renvoyeur {
            corps: renvoi(&[local_ecoute.port()]),
            annonces: Arc::new(AtomicUsize::new(0)),
        },
    )
    .await;

    let reglages = Reglages::nouveaux(vec![annuaire(racine)], autorite_racine, PLAFOND_MS)
        .expect("la configuration est bonne");
    let attache = Attache::annoncer(reglages, identite(), vec![b"{}".to_vec()], alea());
    assert!(jusqu_a(10_000, || attache.etat().renvois >= 1).await);
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let etat = attache.etat();
    assert!(!etat.attachee, "un certificat hors de --roots a été cru");
    assert!(!etat.abandonnee);
    assert_eq!(
        chez_lui.load(Ordering::Relaxed),
        0,
        "rien n'a été annoncé chez lui"
    );

    tokio::time::timeout(Duration::from_secs(5), attache.retirer())
        .await
        .expect("le retrait ne doit pas pendre");
    tache_l.abort();
    tache_r.abort();
}

#[tokio::test]
async fn un_renvoi_illisible_est_un_refus_et_non_une_direction() {
    let (_a, autorite, cert_r, cle_r) = materiel("racine-illisible");
    let (racine, tache_r) = lever(
        cert_r,
        cle_r,
        Renvoyeur {
            corps: br#"{"annuaire":"pas-un-annuaire","adresses":[]}"#.to_vec(),
            annonces: Arc::new(AtomicUsize::new(0)),
        },
    )
    .await;
    let reglages = Reglages::nouveaux(vec![annuaire(racine)], autorite, PLAFOND_MS)
        .expect("la configuration est bonne");
    let attache = Attache::annoncer(reglages, identite(), vec![b"{}".to_vec()], alea());
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let etat = attache.etat();
    assert_eq!(etat.renvois, 0, "un corps illisible n'emmène nulle part");
    assert!(!etat.attachee);
    assert!(!etat.abandonnee);
    assert_eq!(attache.annuaire_local(), None);
    tache_r.abort();
}
