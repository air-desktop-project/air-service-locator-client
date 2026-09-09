//! **UN VRAI ANNUAIRE EN FACE, SUR UNE VRAIE SOCKET.**
//!
//! # CE QUE CET ESSAI PROUVE, ET QU'AUCUN AUTRE NE PROUVE
//!
//! Les pièces sont éprouvées chacune de son côté : la connexion QUIC cliente et
//! le conducteur HTTP/3 client le sont chez `air-mail-server`, sous son régime
//! de couverture. **Rien ne dit qu'elles s'emboîtent avec une socket au milieu.**
//! Un ALPN oublié, une famille d'adresses qui ne correspond pas, un flux relu au
//! mauvais moment : chacune de ces fautes laisse tout compiler et tous les essais
//! unitaires passer.
//!
//! # POURQUOI LE SERVEUR EST CELUI D'`air-mail-server`, ET NON L'ANNUAIRE
//!
//! L'annuaire vit dans l'autre dépôt, et cette bibliothèque ne peut pas en
//! dépendre — ce serait faire embarquer sa base de données par un daemon tiers.
//! Ce qui est éprouvé ici est le TRANSPORT, et le transport est le même : la
//! même poignée de main, le même cadrage, les mêmes flux. Un serveur HTTP/3 réel
//! suffit, et il refuse exactement ce que l'annuaire refuserait.

mod banc;

use asl_client_tokio::{Connexion, Faute};
use banc::{Echo, lever, materiel};
use tokio::net::UdpSocket;

#[tokio::test]
async fn une_requete_traverse_la_socket_et_la_reponse_revient() {
    let (_atelier, autorite, cert, cle) = materiel("bout-en-bout");
    let (adresse, tache) = lever(cert, cle, Echo).await;

    let mut connexion = Connexion::ouvrir(adresse, "localhost", &autorite, &|| [0x5A; 16])
        .await
        .expect("la connexion s'ouvre");

    let reponse = connexion
        .requete(b"GET", b"/v1/defi", &[], b"")
        .await
        .expect("la réponse revient");
    assert_eq!(reponse.statut, 200);
    assert_eq!(reponse.corps, b"/v1/defi".to_vec());

    // **LA LIAISON DE CANAL EST CELLE DE CETTE CONNEXION**, et elle n'est pas
    // nulle : c'est ce que l'exportateur TLS a dérivé de la poignée de main.
    assert_ne!(
        connexion.liaison().octets(),
        &[0_u8; asl_cle::LIAISON_OCTETS],
        "la liaison doit être exportée, et non laissée à sa valeur de passage"
    );
    assert!(connexion.vivante());

    tache.abort();
}

#[tokio::test]
async fn deux_connexions_au_meme_annuaire_ont_deux_liaisons() {
    // **C'EST CE QUI FERME LE RELAIS**, et cela ne se voit que d'ici : une
    // empreinte de certificat aurait donné la même valeur aux deux.
    let (_atelier, autorite, cert, cle) = materiel("deux-liaisons");
    let (adresse, tache) = lever(cert.clone(), cle.clone(), Echo).await;
    let une = Connexion::ouvrir(adresse, "localhost", &autorite, &|| [0x11; 16])
        .await
        .expect("la première s'ouvre");
    tache.abort();

    let (adresse, tache) = lever(cert, cle, Echo).await;
    let autre = Connexion::ouvrir(adresse, "localhost", &autorite, &|| [0x22; 16])
        .await
        .expect("la seconde s'ouvre");
    tache.abort();

    assert_ne!(
        une.liaison().octets(),
        autre.liaison().octets(),
        "le MÊME certificat, et pourtant deux liaisons"
    );
}

#[tokio::test]
async fn un_annuaire_qui_ne_repond_pas_rend_un_delai_et_non_une_panne() {
    // **CE N'EST PAS UNE FAUTE DU PAIR** : la connexion dit seulement qu'elle
    // n'a rien obtenu, et c'est à `asl_client::Reprise` d'en tirer une
    // conséquence — elle n'abandonne jamais.
    let (_atelier, autorite, _cert, _cle) = materiel("muet");
    // Une socket qui écoute et ne répond à rien.
    let muet = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = muet.local_addr().expect("une adresse");

    let issue = Connexion::ouvrir(adresse, "localhost", &autorite, &|| [0x33; 16])
        .await
        .expect_err("personne ne répond");
    assert!(matches!(issue, Faute::Delai), "{issue}");
}

#[tokio::test]
async fn une_racine_vide_se_refuse_avant_la_socket() {
    // Un client qui ne fait confiance à personne ne chiffrerait pas, il
    // accepterait n'importe qui. **Le refus vient avant l'ouverture.**
    let issue = Connexion::ouvrir(
        "127.0.0.1:1".parse().expect("une adresse"),
        "localhost",
        b"",
        &|| [0; 16],
    )
    .await
    .expect_err("aucune racine");
    assert!(matches!(issue, Faute::Tls(_)), "{issue}");
}
