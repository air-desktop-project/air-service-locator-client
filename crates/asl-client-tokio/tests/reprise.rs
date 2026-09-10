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
use asl_client_tokio::{Annuaire, Attache, Connexion, Faute, Reglages, joindre};
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

// ── Le flux des verdicts ────────────────────────────────────────────────────

use banc::lever_qui_pousse;

#[tokio::test]
async fn un_verdict_pousse_apres_coup_arrive_au_client() {
    // **C'EST LA LACUNE QUE `asl` AVAIT NOMMÉE**, comblée de bout en bout.
    // L'annuaire répond `en_cours` pour ne pas faire attendre le démarrage d'un
    // daemon ; le verdict arrive ensuite, sur la connexion déjà tenue. Sans ce
    // flux, il n'arrivait jamais — et rien ne plantait, ce qui est pire.
    let (_atelier, autorite, cert, cle) = materiel("poussees");
    let (adresse, tache, pousser) = lever_qui_pousse(cert, cle, FauxAnnuaire).await;

    let reglages = Reglages::nouveaux(vec![annuaire(adresse)], autorite, PLAFOND_MS)
        .expect("la configuration est bonne");
    let mut connexion =
        tokio::time::timeout(Duration::from_secs(10), joindre(&reglages, &|| [0x5A; 16]))
            .await
            .expect("elle ne doit pas tourner en rond")
            .expect("l'annuaire répond");

    connexion
        .ecouter_les_poussees()
        .await
        .expect("le flux s'ouvre");
    assert!(connexion.ecoute_les_poussees());

    // Laisser l'annuaire servir la requête : le flux n'est tenu qu'après.
    for _ in 0..6 {
        connexion.entretenir(50).await.expect("elle vit");
    }

    // **RIEN N'EST UNE RÉPONSE, ET C'EST LA PLUS FRÉQUENTE** : une sonde met des
    // secondes, et cette fonction se rappelle à chaque tour de boucle.
    assert!(
        connexion.poussees().expect("rien à découper").is_empty(),
        "aucune sonde n'a encore parlé"
    );

    pousser
        .send(br#"{"verdict":"joignable"}"#.to_vec())
        .expect("le banc accepte");
    pousser
        .send(br#"{"verdict":"injoignable"}"#.to_vec())
        .expect("le banc accepte");

    let mut recues = Vec::new();
    for _ in 0..40 {
        connexion.entretenir(50).await.expect("elle vit");
        recues.extend(connexion.poussees().expect("elles se découpent"));
        if recues.len() >= 2 {
            break;
        }
    }

    assert_eq!(recues.len(), 2, "les deux poussées devaient arriver");
    assert_eq!(recues[0].as_slice(), br#"{"verdict":"joignable"}"#);
    assert_eq!(recues[1].as_slice(), br#"{"verdict":"injoignable"}"#);

    tache.abort();
}

#[tokio::test]
async fn un_objet_coupe_par_un_datagramme_attend_sa_suite() {
    // **C'EST LE CAS ORDINAIRE D'UN FLUX**, et le refuser ferait rejeter une
    // poussée parfaitement valide parce qu'un paquet n'est pas encore arrivé.
    let (_atelier, autorite, cert, cle) = materiel("poussees-coupees");
    let (adresse, tache, pousser) = lever_qui_pousse(cert, cle, FauxAnnuaire).await;

    let reglages = Reglages::nouveaux(vec![annuaire(adresse)], autorite, PLAFOND_MS)
        .expect("la configuration est bonne");
    let mut connexion =
        tokio::time::timeout(Duration::from_secs(10), joindre(&reglages, &|| [0x5A; 16]))
            .await
            .expect("elle ne doit pas tourner en rond")
            .expect("l'annuaire répond");
    connexion.ecouter_les_poussees().await.expect("il s'ouvre");
    for _ in 0..6 {
        connexion.entretenir(50).await.expect("elle vit");
    }

    // La moitié d'un objet : rien ne doit sortir, et rien ne doit échouer.
    pousser
        .send(br#"{"verdict":"joi"#.to_vec())
        .expect("le banc accepte");
    for _ in 0..10 {
        connexion.entretenir(50).await.expect("elle vit");
        assert!(
            connexion.poussees().expect("pas une faute").is_empty(),
            "un objet incomplet ne doit rien rendre"
        );
    }

    // Et la suite le complète.
    pousser
        .send(br#"gnable"}"#.to_vec())
        .expect("le banc accepte");
    let mut recues = Vec::new();
    for _ in 0..40 {
        connexion.entretenir(50).await.expect("elle vit");
        recues.extend(connexion.poussees().expect("elles se découpent"));
        if !recues.is_empty() {
            break;
        }
    }
    assert_eq!(recues.len(), 1);
    assert_eq!(recues[0].as_slice(), br#"{"verdict":"joignable"}"#);

    tache.abort();
}

#[tokio::test]
async fn sans_flux_ouvert_il_n_y_a_rien_a_lire_et_ce_n_est_pas_une_faute() {
    let (_atelier, autorite, cert, cle) = materiel("poussees-fermees");
    let (adresse, tache) = lever(cert, cle, FauxAnnuaire).await;

    let reglages = Reglages::nouveaux(vec![annuaire(adresse)], autorite, PLAFOND_MS)
        .expect("la configuration est bonne");
    let mut connexion =
        tokio::time::timeout(Duration::from_secs(10), joindre(&reglages, &|| [0x5A; 16]))
            .await
            .expect("elle ne doit pas tourner en rond")
            .expect("l'annuaire répond");

    assert!(!connexion.ecoute_les_poussees(), "on n'a rien demandé");
    assert!(connexion.poussees().expect("pas une faute").is_empty());

    // Et l'ouvrir deux fois ne rouvre rien.
    connexion.ecouter_les_poussees().await.expect("il s'ouvre");
    connexion.ecouter_les_poussees().await.expect("et reste");
    assert!(connexion.ecoute_les_poussees());

    tache.abort();
}

#[tokio::test]
async fn l_attache_ouvre_le_flux_et_retient_la_derniere_poussee() {
    // **UN DAEMON QUI S'ANNONCE A DES VERDICTS À APPRENDRE**, et `Attache` existe
    // pour tenir l'annonce : elle ouvre donc le flux après avoir annoncé. Qui
    // n'en veut pas emploie `joindre` et conduit sa connexion lui-même.
    let (_atelier, autorite, cert, cle) = materiel("attache-poussees");
    let (adresse, tache, pousser) = lever_qui_pousse(cert, cle, FauxAnnuaire).await;

    let reglages = Reglages::nouveaux(vec![annuaire(adresse)], autorite, PLAFOND_MS)
        .expect("la configuration est bonne");
    let attache = Attache::annoncer(reglages, identite(), vec![b"{}".to_vec()], alea());

    assert!(
        jusqu_a(10_000, || attache.etat().attachee).await,
        "elle aurait dû s'attacher"
    );
    // **AUCUNE POUSSÉE N'EST LE CAS ORDINAIRE** : l'annuaire ne pousse que ce
    // qui a CHANGÉ, et rien n'a encore changé.
    assert_eq!(attache.etat().poussees, 0);
    assert!(attache.derniere_poussee().is_none());

    pousser
        .send(br#"{"verdict":"joignable"}"#.to_vec())
        .expect("le banc accepte");
    assert!(
        jusqu_a(10_000, || attache.etat().poussees >= 1).await,
        "la poussée aurait dû arriver : {:?}",
        attache.etat()
    );
    assert_eq!(
        attache.derniere_poussee().as_deref(),
        Some(br#"{"verdict":"joignable"}"#.as_slice())
    );

    // **CHACUNE PORTE LA LISTE ENTIÈRE** : la dernière remplace tout ce qui
    // précède, et en garder une file obligerait à décider quoi faire de celles
    // qu'on n'a pas lues.
    pousser
        .send(br#"{"verdict":"injoignable"}"#.to_vec())
        .expect("le banc accepte");
    assert!(
        jusqu_a(10_000, || attache.etat().poussees >= 2).await,
        "la seconde aussi"
    );
    assert_eq!(
        attache.derniere_poussee().as_deref(),
        Some(br#"{"verdict":"injoignable"}"#.as_slice()),
        "la dernière remplace la précédente"
    );

    tokio::time::timeout(Duration::from_secs(5), attache.retirer())
        .await
        .expect("le retrait ne doit pas pendre");
    tache.abort();
}

#[tokio::test]
async fn on_apprend_d_ou_l_annuaire_nous_voit_sans_rien_annoncer() {
    // **C'EST LA PREMIÈRE CHOSE QU'ON REGARDE** quand personne n'arrive à
    // joindre un port. La réponse à une annonce porte déjà le candidat
    // réflexif, mais il faut avoir annoncé pour l'obtenir — donc porter la
    // capacité d'annonce, et avoir un service à publier.
    let (_atelier, autorite, cert, cle) = materiel("vu");
    let (adresse, tache) = lever(cert, cle, FauxAnnuaire).await;

    let mut connexion = Connexion::ouvrir(adresse, "localhost", &autorite, &|| [0x31; 16])
        .await
        .expect("la poignée de main");
    let corps = connexion.vu().await.expect("l'annuaire répond");
    let texte = String::from_utf8_lossy(&corps).into_owned();
    assert!(texte.contains(r#""adresse":"2001:db8::1c2d""#), "{texte}");
    assert!(texte.contains(r#""port":49152"#), "{texte}");
    // **LA FAMILLE EST ÉCRITE**, pour qu'aucune liaison n'ait à la déduire :
    // chercher un `:` marche jusqu'à `::ffff:203.0.113.7`.
    assert!(texte.contains(r#""famille":6"#), "{texte}");

    let _ = connexion.fermer().await;
    tache.abort();
}

#[tokio::test]
async fn un_annuaire_qui_ne_sert_pas_cette_route_le_dit_par_son_statut() {
    // **ET NON PAR UN CORPS VIDE** : un annuaire plus ancien ne connaît pas
    // `/v1/vu`, et un diagnostic doit pouvoir distinguer « il ne sait pas » de
    // « il n'a rien vu ». `FauxAnnuaire` rend `404` pour tout le reste.
    let (_atelier, autorite, cert, cle) = materiel("vu-absente");
    let (adresse, tache) = lever(cert, cle, FauxAnnuaire).await;

    let mut connexion = Connexion::ouvrir(adresse, "localhost", &autorite, &|| [0x32; 16])
        .await
        .expect("la poignée de main");
    let issue = connexion
        .requete(b"GET", b"/v1/inconnue", &[], b"")
        .await
        .expect("l'annuaire répond quand même");
    assert!(issue.exige(200).is_err(), "un 404 n'est pas un 200");

    let _ = connexion.fermer().await;
    tache.abort();
}

// ── LE MAINTIEN, ET D'OÙ VIENT SA CADENCE ───────────────────────────────────

#[tokio::test]
async fn la_cadence_de_maintien_vient_du_bail_que_l_annuaire_annonce() {
    // ── CE QUE CET ESSAI PROUVE ─────────────────────────────────────────────
    //
    // `modele.md` §4.1 : les deux valeurs du bail viennent du SERVEUR,
    // précisément pour qu'on puisse les changer sans mettre à jour les daemons
    // installés chez des tiers. Figer la cadence dans le client aurait rendu la
    // mesure inutile le jour où elle a eu lieu.
    //
    // Le banc annonce sept secondes — une valeur qui ne ressemble à aucun
    // défaut, pour qu'en la retrouvant on prouve qu'elle a VOYAGÉ.
    let (_atelier, autorite, cert, cle) = materiel("maintien");
    let (adresse, tache) = lever(cert, cle, FauxAnnuaire).await;

    let mut connexion = Connexion::ouvrir(adresse, "localhost", &autorite, &|| [0x41; 16])
        .await
        .expect("la poignée de main");
    assert_eq!(
        connexion.maintien_us(),
        0,
        "rien ne se maintient avant d'avoir annoncé : il n'y a pas de bail"
    );

    let corps = connexion
        .annoncer_encodee(b"peu importe : le banc ne le lit pas")
        .await
        .expect("le banc prend l'annonce");
    let cadence = asl_client_tokio::cadence_du_bail(&corps).expect("le bail se lit");
    assert_eq!(cadence, banc::CADENCE_DU_BANC);

    connexion.maintenir(cadence);
    assert_eq!(
        connexion.maintien_us(),
        u64::from(banc::CADENCE_DU_BANC) * 1_000_000,
        "la cadence annoncée doit atteindre la connexion"
    );

    // **ZÉRO ARRÊTE LE MAINTIEN**, et c'est ce qui permet de le couper sans
    // fermer la connexion.
    connexion.maintenir(0);
    assert_eq!(connexion.maintien_us(), 0);

    let _ = connexion.fermer().await;
    tache.abort();
}

#[tokio::test]
async fn une_reponse_illisible_ne_regle_aucune_cadence() {
    // **ET NE ROMPT PAS L'ATTACHE** : l'annuaire a rendu 200, l'annonce est
    // prise. Ce qu'on perd est le maintien — la connexion vit quand même, elle
    // se refait simplement à chaque délai d'inactivité, ce qui était le
    // comportement d'avant. Refuser ici retirerait un service qui écoute.
    for corps in [&b""[..], &b"{"[..], &[0x5A_u8; 4][..]] {
        assert!(
            asl_client_tokio::cadence_du_bail(corps).is_err(),
            "{corps:?} n'est pas une réponse d'annonce"
        );
    }
}
