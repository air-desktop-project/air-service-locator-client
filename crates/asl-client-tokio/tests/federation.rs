//! Le renvoi vers un annuaire local, suivi sur de vraies sockets.
//!
//! # CE QUE CES ESSAIS PROUVENT
//!
//! La politique — un seul saut, un retour qui se paie — est éprouvée dans
//! `asl-client` (`tests/renvoi.rs`), sans attendre une seconde. Ici, on
//! éprouve qu'elle est **obéie** : qu'une racine qui répond `421` fait
//! s'annoncer le daemon chez l'annuaire local qu'elle désigne, sous
//! l'identité que le `421` nomme (décision 53), et qu'un membre mort de la
//! paire ne retient pas l'autre.
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

fn annuaire(adresse: std::net::SocketAddr, identite: Identifiant) -> Annuaire {
    Annuaire {
        adresse,
        nom: "localhost".to_owned(),
        identite,
    }
}

/// Le corps d'un `421`, tel que la racine l'écrit : il nomme `local`.
fn renvoi(local: Identifiant, ports: &[u16]) -> Vec<u8> {
    let adresses: Vec<String> = ports.iter().map(|p| format!("\"localhost:{p}\"")).collect();
    format!(
        r#"{{"annuaire":"{}","adresses":[{}]}}"#,
        local.texte().as_str(),
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

#[tokio::test]
async fn une_racine_qui_renvoie_fait_s_annoncer_chez_l_annuaire_local() {
    let (id_racine, cert_r, cle_r) = materiel("racine-421");
    let (id_local, cert_l, cle_l) = materiel("local-421");
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
            corps: renvoi(id_local, &[local_ecoute.port()]),
            annonces: Arc::clone(&a_la_racine),
        },
    )
    .await;

    let reglages = Reglages::nouveaux(vec![annuaire(racine, id_racine)], PLAFOND_MS)
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
        Some(id_local.texte().as_str())
    );

    tokio::time::timeout(Duration::from_secs(5), attache.retirer())
        .await
        .expect("le retrait ne doit pas pendre");
    tache_l.abort();
    tache_r.abort();
}

#[tokio::test]
async fn un_membre_mort_de_la_paire_ne_retient_pas_l_autre() {
    let (id_racine, cert_r, cle_r) = materiel("racine-paire");
    let (id_local, cert_l, cle_l) = materiel("local-paire");
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
            corps: renvoi(id_local, &[mort.port(), membre_b.port()]),
            annonces: Arc::new(AtomicUsize::new(0)),
        },
    )
    .await;

    let reglages = Reglages::nouveaux(vec![annuaire(racine, id_racine)], PLAFOND_MS)
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
    let (id_racine, cert_r, cle_r) = materiel("racine-muet");
    let (id_local, _, _) = materiel("local-muet");
    let mort = adresse_morte().await;
    let a_la_racine = Arc::new(AtomicUsize::new(0));
    let (racine, tache_r) = lever(
        cert_r,
        cle_r,
        Renvoyeur {
            corps: renvoi(id_local, &[mort.port()]),
            annonces: Arc::clone(&a_la_racine),
        },
    )
    .await;

    let reglages = Reglages::nouveaux(vec![annuaire(racine, id_racine)], PLAFOND_MS)
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
async fn un_annuaire_local_qui_n_a_pas_la_cle_nommee_n_est_pas_cru() {
    // **LA CONFIANCE N'EST PAS RELÂCHÉE PAR LE RENVOI** : le `421` nomme un
    // `n-…`, et c'est cette clé qu'on doit trouver au bout de l'adresse. Un
    // annuaire qui en présente une autre ne se fait pas accepter, quoi que la
    // racine ait dit de l'endroit où aller.
    let (id_racine, cert_r, cle_r) = materiel("racine-confiance");
    let (id_nomme, _, _) = materiel("local-nomme");
    let (_id_etranger, cert_l, cle_l) = materiel("local-etranger");
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
            corps: renvoi(id_nomme, &[local_ecoute.port()]),
            annonces: Arc::new(AtomicUsize::new(0)),
        },
    )
    .await;

    let reglages = Reglages::nouveaux(vec![annuaire(racine, id_racine)], PLAFOND_MS)
        .expect("la configuration est bonne");
    let attache = Attache::annoncer(reglages, identite(), vec![b"{}".to_vec()], alea());
    assert!(jusqu_a(10_000, || attache.etat().renvois >= 1).await);
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let etat = attache.etat();
    assert!(
        !etat.attachee,
        "une clé que le renvoi ne nomme pas a été crue"
    );
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
    let (id_racine, cert_r, cle_r) = materiel("racine-illisible");
    let (racine, tache_r) = lever(
        cert_r,
        cle_r,
        Renvoyeur {
            corps: br#"{"annuaire":"pas-un-annuaire","adresses":[]}"#.to_vec(),
            annonces: Arc::new(AtomicUsize::new(0)),
        },
    )
    .await;
    let reglages = Reglages::nouveaux(vec![annuaire(racine, id_racine)], PLAFOND_MS)
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
