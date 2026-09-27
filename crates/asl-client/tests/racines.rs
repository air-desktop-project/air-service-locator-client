//! Ce que le client attend de la liste embarquée qu'il reprend du serveur
//! (`asl-racines`). Le jugement d'une liste, lui, s'éprouve là-bas, une fois.

use asl_cle::identifiant_de_racine;
use asl_client::racines::RACINES;

#[test]
fn chaque_cle_embarquee_se_deduit_en_son_identifiant() {
    // Une clé recopiée de travers ne passerait pas : l'identifiant écrit à côté
    // est celui qu'on a relevé sur le banc.
    for racine in RACINES {
        let cle = racine.cle_publique().expect("un point de la courbe");
        assert_eq!(
            identifiant_de_racine(&cle).texte().as_str(),
            racine.identifiant
        );
        assert_eq!(racine.identite(), Some(identifiant_de_racine(&cle)));
    }
}

#[test]
fn chaque_racine_embarquee_a_une_adresse_ipv6_et_une_ipv4_litterales() {
    // C20 : le chemin par défaut ne garde que les adresses, et il en faut une
    // de chaque famille — IPv6 d'abord, IPv4 pour un réseau qui n'a que ça.
    for racine in RACINES {
        let adresses: Vec<std::net::SocketAddr> = racine
            .locateurs
            .iter()
            .filter_map(|texte| texte.parse().ok())
            .collect();
        assert!(adresses.first().is_some_and(std::net::SocketAddr::is_ipv6));
        assert!(adresses.iter().any(std::net::SocketAddr::is_ipv4));
    }
}
