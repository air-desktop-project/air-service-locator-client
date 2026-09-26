//! Ce que le client fait d'un REFUS, et non d'une panne.
//!
//! # POURQUOI CE FICHIER EST À PART
//!
//! Deux raisons, et la seconde n'est pas de la cosmétique.
//!
//! D'abord le sujet : `reprise.rs` éprouve ce qu'on fait quand personne ne
//! répond ; ici, quelqu'un répond, et dit non. Ce sont deux régimes différents.
//!
//! Ensuite le coût : cet essai lève DEUX annuaires et fait deux poignées de
//! main, et `reprise.rs` contient un essai qui mesure des temps
//! (`un_annuaire_mort_ne_retarde_pas_le_suivant`). Les faire tourner côte à
//! côte rendait ce voisin faux-négatif sous charge — il mesurait la machine,
//! pas le recul. Il compare désormais un écart et non une durée, ce qui le
//! rend bien moins sensible ; la séparation reste, parce qu'un essai ne doit
//! pas rendre son voisin instable.

mod banc;

use std::sync::Arc;
use std::time::Duration;

use asl_client::Identite;
use asl_client_tokio::{Annuaire, Attache, Reglages};
use asl_id::{Genre, Identifiant};
use banc::{FauxAnnuaire, SansCetteMachine, lever, materiel};

/// Le plafond du recul, tel que le CLI et les daemons le posent.
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

/// Attend que la condition devienne vraie, ou rend `false` au bout du délai.
async fn jusqu_a(patience_ms: u64, mut condition: impl FnMut() -> bool) -> bool {
    let depart = std::time::Instant::now();
    while depart.elapsed() < Duration::from_millis(patience_ms) {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    condition()
}

#[tokio::test]
async fn un_401_sur_une_racine_n_est_pas_definitif() {
    // **`replication.md` §6, la nuance du daemon.** Une machine tout juste
    // enrôlée chez une racine n'est pas encore connue de l'autre : celle-ci
    // refuse sa preuve. Ce `401` ne doit PAS arrêter la tournée — on essaie
    // l'autre, et l'on ne recule qu'ensuite.
    //
    // Ce que cet essai éprouve vraiment : qu'un refus d'authentification laisse
    // la tournée AVANCER d'un cran au lieu de repartir du haut. Une boucle qui
    // rappellerait `tournee.reussite()` sur une connexion seulement ouverte
    // réessaierait le refusant à l'infini, et le daemon ne s'attacherait jamais
    // — la panne serait muette, puisque la socket, elle, s'ouvre.
    let (_atelier, autorite, cert, cle) = materiel("401-pas-definitif");
    let (refusant, tache_une) = lever(cert.clone(), cle.clone(), SansCetteMachine).await;
    let (accueillant, tache_deux) = lever(cert, cle, FauxAnnuaire).await;

    let reglages = Reglages::nouveaux(
        vec![annuaire(refusant), annuaire(accueillant)],
        autorite,
        PLAFOND_MS,
    )
    .expect("la configuration est bonne");

    let attache = Attache::annoncer(reglages, identite(), vec![b"{}".to_vec()], alea());

    assert!(
        jusqu_a(10_000, || attache.etat().attachee).await,
        "un 401 sur la première racine a empêché l'attache sur la seconde"
    );
    assert_eq!(attache.etat().attaches, 1);
    assert!(
        !attache.etat().abandonnee,
        "un 401 n'est pas une configuration"
    );

    tokio::time::timeout(Duration::from_secs(5), attache.retirer())
        .await
        .expect("le retrait ne doit pas pendre");
    tache_une.abort();
    tache_deux.abort();
}
