//! La reprise, avec de vraies sockets et de vrais annuaires qu'on éteint.
//!
//! # CE QUE CES ESSAIS PROUVENT, ET QU'AUCUN AUTRE NE PROUVE
//!
//! La POLITIQUE — IPv6 d'abord, l'attente entre les tours, le recul qui ne
//! repart de zéro que sur une réussite — est éprouvée dans `asl-client`, sur des
//! listes littérales et sans attendre une seconde. Ce n'est pas ce qui est
//! éprouvé ici.
//!
//! Ici, on éprouve qu'elle est **obéie** : qu'un annuaire mort ne retarde pas
//! le suivant, qu'une attache perdue se refait ailleurs, et qu'une faute de
//! configuration ne devient pas une boucle silencieuse. Aucune de ces trois
//! choses ne se voit sans une socket.
//!
//! # POURQUOI CHAQUE ESSAI EST BORNÉ PAR UN `timeout`
//!
//! Ce qu'on éprouve est du code qui **n'abandonne jamais**. Un essai qui se
//! tromperait ne le dirait donc pas : il tournerait, et la CI le tuerait au bout
//! de son quart d'heure sans dire lequel. La borne est ce qui transforme une
//! boucle infinie en un échec nommé.

mod banc;

use std::sync::Arc;
use std::time::{Duration, Instant};

use asl_client::Identite;
use asl_client_tokio::{Annuaire, Attache, Faute, Reglages, joindre};
use asl_id::{Genre, Identifiant};
use banc::{FauxAnnuaire, adresse_morte, lever, materiel};

/// Le plafond de recul employé partout ici.
const PLAFOND_MS: u64 = 15_000;

/// L'aléa des essais : constant, ce qui suffit — le bruit n'a pas besoin d'être
/// imprévisible, seulement d'être réparti.
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

/// Attend que la condition se réalise, ou rend `false` au bout du temps donné.
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

// ── La configuration, refusée dans la main ──────────────────────────────────

#[test]
fn une_configuration_fautive_est_refusee_avant_qu_une_tache_parte() {
    // **CE NE SONT PAS DES PANNES.** Les rendre à qui a écrit la configuration
    // est la seule façon qu'il l'apprenne : une tâche de fond qui les
    // découvrirait toute seule ne parlerait à personne.
    let mort = "127.0.0.1:1".parse().expect("une adresse");
    assert!(matches!(
        Reglages::nouveaux(vec![], b"x".to_vec(), PLAFOND_MS),
        Err(Faute::SansAnnuaire)
    ));
    assert!(matches!(
        Reglages::nouveaux(vec![annuaire(mort)], b"x".to_vec(), 0),
        Err(Faute::PlafondNul)
    ));
    assert!(Reglages::nouveaux(vec![annuaire(mort)], b"x".to_vec(), PLAFOND_MS).is_ok());
}

// ── La bascule ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn un_annuaire_mort_ne_retarde_pas_le_suivant() {
    // **C'EST LA DÉCISION QUI DONNE À `Tournee` SA RAISON D'EXISTER**, et elle
    // ne se voit que d'ici : reculer entre deux annuaires rendrait la bascule
    // vers le second annuaire racine plus lente que la panne du premier.
    let (_atelier, autorite, cert, cle) = materiel("bascule");
    let (vivant, tache) = lever(cert, cle, FauxAnnuaire).await;
    let mort = adresse_morte().await;

    let reglages = Reglages::nouveaux(vec![annuaire(mort), annuaire(vivant)], autorite, PLAFOND_MS)
        .expect("la configuration est bonne");

    let depart = Instant::now();
    let connexion =
        tokio::time::timeout(Duration::from_secs(10), joindre(&reglages, &|| [0x5A; 16]))
            .await
            .expect("la tournée ne doit pas tourner en rond")
            .expect("le second annuaire répond");
    let ecoule = depart.elapsed();

    assert!(connexion.vivante());
    // Le recul initial est d'une seconde. Le tour n'étant pas bouclé, il n'a pas
    // dû être payé.
    assert!(
        ecoule < Duration::from_millis(asl_client::RECUL_INITIAL_MS),
        "la bascule a attendu {ecoule:?} — le recul a été payé entre deux annuaires"
    );

    tache.abort();
}

#[tokio::test]
async fn une_racine_illisible_arrete_la_tournee_au_lieu_de_la_faire_tourner() {
    // **UNE FAUTE DE CONFIGURATION RÉESSAYÉE À L'INFINI EST UNE PANNE MUETTE** :
    // le porteur voit un daemon qui « cherche », alors qu'il ne trouvera jamais.
    let mort = adresse_morte().await;
    let reglages = Reglages::nouveaux(vec![annuaire(mort)], b"pas un PEM".to_vec(), PLAFOND_MS)
        .expect("la liste, elle, est bonne");

    let issue = tokio::time::timeout(Duration::from_secs(3), joindre(&reglages, &|| [0x5A; 16]))
        .await
        .expect("elle ne doit pas réessayer une racine illisible")
        .expect_err("aucune racine à qui faire confiance");
    assert!(matches!(issue, Faute::Tls(_)), "{issue}");
}

// ── L'attache ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn l_attache_rend_la_main_avant_d_avoir_trouve_quoi_que_ce_soit() {
    // **`protocole.md` §1.4** : un annuaire injoignable ne doit pas empêcher un
    // daemon de démarrer. Le daemon écoute déjà pendant que l'attache cherche.
    let (_atelier, autorite, _cert, _cle) = materiel("main-rendue");
    let mort = adresse_morte().await;
    let reglages = Reglages::nouveaux(vec![annuaire(mort)], autorite, PLAFOND_MS)
        .expect("la configuration est bonne");

    let depart = Instant::now();
    let attache = Attache::annoncer(reglages, identite(), vec![], alea());
    let ecoule = depart.elapsed();

    assert!(
        ecoule < Duration::from_millis(50),
        "elle a mis {ecoule:?} à rendre la main"
    );
    let etat = attache.etat();
    assert!(
        !etat.attachee,
        "rien n'est attaché, et elle ne le prétend pas"
    );
    assert!(!etat.abandonnee);
    assert_eq!(etat.attaches, 0);
}

#[tokio::test]
async fn l_attache_renonce_sur_une_configuration_fautive_et_le_dit() {
    // Le seul cas où elle renonce — et il doit se VOIR, sans quoi c'est une
    // tâche morte dont personne ne sait qu'elle est morte.
    let mort = adresse_morte().await;
    let reglages = Reglages::nouveaux(vec![annuaire(mort)], b"pas un PEM".to_vec(), PLAFOND_MS)
        .expect("la liste, elle, est bonne");
    let attache = Attache::annoncer(reglages, identite(), vec![], alea());

    assert!(
        jusqu_a(3_000, || attache.etat().abandonnee).await,
        "elle aurait dû renoncer et le dire"
    );
    assert!(!attache.etat().attachee);
}

#[tokio::test]
async fn l_attache_s_authentifie_puis_annonce_et_tient() {
    let (_atelier, autorite, cert, cle) = materiel("attache");
    let (vivant, tache) = lever(cert, cle, FauxAnnuaire).await;
    let reglages = Reglages::nouveaux(vec![annuaire(vivant)], autorite, PLAFOND_MS)
        .expect("la configuration est bonne");

    // Une annonce déjà encodée : c'est ce que la tâche répétera.
    let attache = Attache::annoncer(reglages, identite(), vec![b"{}".to_vec()], alea());

    assert!(
        jusqu_a(10_000, || attache.etat().attachee).await,
        "elle aurait dû s'attacher"
    );
    let etat = attache.etat();
    assert_eq!(etat.attaches, 1);
    assert_eq!(etat.ruptures, 0);
    assert!(!etat.abandonnee);

    // **ELLE TIENT SANS RIEN RÉANNONCER** : la connexion est le bail.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(attache.etat().attachee);
    assert_eq!(attache.etat().attaches, 1, "rien n'a été refait pour rien");

    tokio::time::timeout(Duration::from_secs(5), attache.retirer())
        .await
        .expect("le retrait ne doit pas pendre");
    tache.abort();
}

#[tokio::test]
async fn une_attache_perdue_se_refait_sur_l_autre_annuaire() {
    // **C'EST LE PLAN DE HAUTE DISPONIBILITÉ DU PRODUIT, EN ENTIER.**
    // `annuaires.md` §3 : rien n'est répliqué côté serveur, et c'est ce
    // mouvement-ci — se reconnecter ailleurs et tout réannoncer — qui reconstruit
    // l'état. Il n'y a pas d'autre bascule.
    let (_atelier, autorite, cert, cle) = materiel("haute-dispo");
    let (premier, tache_une) = lever(cert.clone(), cle.clone(), FauxAnnuaire).await;
    let (second, tache_deux) = lever(cert, cle, FauxAnnuaire).await;

    let reglages = Reglages::nouveaux(
        vec![annuaire(premier), annuaire(second)],
        autorite,
        PLAFOND_MS,
    )
    .expect("la configuration est bonne");
    let attache = Attache::annoncer(reglages, identite(), vec![b"{}".to_vec()], alea());

    assert!(
        jusqu_a(10_000, || attache.etat().attachee).await,
        "elle aurait dû s'attacher au premier"
    );
    assert_eq!(attache.etat().attaches, 1);

    // Le premier annuaire racine tombe.
    tache_une.abort();

    // Elle doit se rattacher — au second, puisque le premier ne répond plus.
    assert!(
        jusqu_a(20_000, || attache.etat().attaches >= 2).await,
        "elle aurait dû se rattacher ailleurs : {:?}",
        attache.etat()
    );
    let etat = attache.etat();
    assert!(etat.attachee, "et être attachée pour de bon : {etat:?}");
    assert_eq!(etat.ruptures, 1, "une rupture, et une seule");
    assert!(
        !etat.abandonnee,
        "une panne de réseau ne fait jamais renoncer"
    );

    tache_deux.abort();
}
