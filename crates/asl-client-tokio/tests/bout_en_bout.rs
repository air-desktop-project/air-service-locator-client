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

use std::net::SocketAddr;
use std::sync::Arc;

use ams_proto_http::StatusCode;
use ams_proto_quic::StreamId;
use asl_client_tokio::{Connexion, Faute};
use tokio::net::UdpSocket;

/// Ce que l'annuaire de banc répond : le chemin qu'on lui a demandé.
struct Echo;

impl ams_h3::Service for Echo {
    fn serve<'o>(
        &mut self,
        tete: &ams_proto_http::RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> ams_h3::Reponse<'o> {
        let chemin = tete.path();
        let combien = chemin.len().min(sortie.len());
        sortie
            .get_mut(..combien)
            .expect("la borne vient d'être prise")
            .copy_from_slice(chemin.get(..combien).unwrap_or_default());
        let fin = combien.saturating_add(corps.len()).min(sortie.len());
        let place = sortie.get_mut(combien..fin).unwrap_or_default();
        let pris = place.len();
        place.copy_from_slice(corps.get(..pris).unwrap_or_default());
        ams_h3::Reponse::new(StatusCode::OK, sortie.get(..fin).unwrap_or_default())
    }
}

/// L'horloge que la pile attend : des microsecondes.
fn maintenant() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|ecoule| u64::try_from(ecoule.as_micros()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Lève un annuaire de banc : une connexion à la fois, ce qui suffit ici.
async fn lever(chaine: Vec<u8>, cle: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let tache = tokio::spawn(async move {
        let mut config = ams_tls::quic_server_config(&chaine, &cle).expect("la paire est bonne");
        config.alpn_protocols = ams_tls::alpn_h3();
        let config = Arc::new(config);

        let mut connexion: Option<ams_quic_tls::Connection> = None;
        let mut h3 = ams_h3::Http3::new();
        let mut service = Echo;
        let mut recu = vec![0_u8; 1_500];
        let mut place = vec![0_u8; 1_500];

        loop {
            let attente = tokio::time::Duration::from_millis(50);
            let arrivee = tokio::time::timeout(attente, socket.recv_from(&mut recu)).await;

            if let Ok(Ok((lus, pair))) = arrivee {
                let mut datagramme = recu.get(..lus).unwrap_or_default().to_vec();
                if connexion.is_none() {
                    let entrant =
                        ams_quic::Incoming::read(&datagramme, 0).expect("un premier paquet");
                    let local = ams_proto_quic::ConnectionId::new(&[9_u8; 8])
                        .expect("un identifiant qui tient");
                    let mut neuve = ams_quic_tls::Connection::accept(
                        Arc::clone(&config),
                        &entrant,
                        local,
                        entrant.source(),
                        ams_quic_tls::INACTIVITE_US,
                        maintenant(),
                    )
                    .expect("le serveur accepte");
                    neuve
                        .on_datagram(&mut datagramme, maintenant())
                        .expect("le premier datagramme");
                    connexion = Some(neuve);
                } else if let Some(quic) = connexion.as_mut() {
                    let _ = quic.on_datagram(&mut datagramme, maintenant());
                }

                if let Some(quic) = connexion.as_mut() {
                    if quic.is_established() {
                        let mut pont = asl_client_tokio::Pont(quic);
                        let _ = h3.on_established(&mut pont);
                    }
                    let vivants: Vec<StreamId> = quic.streams_alive().collect();
                    for flux in vivants {
                        let mut pont = asl_client_tokio::Pont(quic);
                        let _ = h3.on_readable(&mut pont, &mut service, flux);
                    }
                }

                if let Some(quic) = connexion.as_mut() {
                    loop {
                        match quic.poll_transmit(&mut place, maintenant()) {
                            Ok(0) | Err(_) => break,
                            Ok(ecrit) => {
                                let _ = socket
                                    .send_to(place.get(..ecrit).unwrap_or_default(), pair)
                                    .await;
                            }
                        }
                    }
                }
            } else if let Some(quic) = connexion.as_mut() {
                quic.on_timeout(maintenant());
            }
        }
    });

    (adresse, tache)
}

/// Le matériel de banc : une autorité, un certificat, une clé.
fn materiel(nom: &str) -> (ams_quic_client::Atelier, Vec<u8>, Vec<u8>, Vec<u8>) {
    let atelier = ams_quic_client::atelier(nom);
    let (autorite, cert, cle) =
        ams_quic_client::materiel(atelier.chemin()).expect("`openssl` est requis pour cet essai");
    (atelier, autorite, cert, cle)
}

#[tokio::test]
async fn une_requete_traverse_la_socket_et_la_reponse_revient() {
    let (_atelier, autorite, cert, cle) = materiel("bout-en-bout");
    let (adresse, tache) = lever(cert, cle).await;

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
    let (adresse, tache) = lever(cert.clone(), cle.clone()).await;
    let une = Connexion::ouvrir(adresse, "localhost", &autorite, &|| [0x11; 16])
        .await
        .expect("la première s'ouvre");
    tache.abort();

    let (adresse, tache) = lever(cert, cle).await;
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
