//! Le banc : un vrai serveur QUIC et HTTP/3, sur une vraie socket.
//!
//! # POURQUOI CE MODULE EST PARTAGÉ
//!
//! Deux fichiers d'essais en ont besoin — celui du transport et celui de la
//! reprise —, et un banc recopié est un banc qui diverge : le jour où l'un des
//! deux corrige une poignée de main, l'autre continue d'éprouver l'ancienne.
//!
//! # CE QUE CE BANC EST, ET CE QU'IL N'EST PAS
//!
//! Le TRANSPORT y est vrai : la même poignée de main, le même cadrage, les mêmes
//! flux qu'en production, et il refuse ce qu'un annuaire refuserait. C'est ce
//! qu'on veut éprouver ici.
//!
//! **La SÉMANTIQUE, elle, est feinte** : [`FauxAnnuaire`] rend les codes qu'il
//! faut sans rien vérifier — il n'a ni registre, ni clés, ni sessions. Ce qu'il
//! permet de prouver est l'enchaînement du client (s'authentifier, puis
//! annoncer, et tout refaire à chaque reconnexion), jamais que l'annuaire a
//! raison de répondre cela. Cette preuve-là est dans le dépôt serveur, sous son
//! régime de couverture.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use ams_proto_http::{Method, StatusCode};
use ams_proto_quic::StreamId;
use tokio::net::UdpSocket;

/// Ce que le banc répond : le chemin qu'on lui a demandé.
pub struct Echo;

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

/// Un annuaire qui rend les bons codes, et ne vérifie rien.
///
/// **IL DIT TOUJOURS OUI**, et c'est ce qu'on lui demande : ce qui est éprouvé
/// avec lui est que le client s'authentifie AVANT d'annoncer, et qu'il refait
/// les deux à chaque reconnexion. Un annuaire qui refuserait ne prouverait que
/// la moitié de cela.
#[derive(Debug, Default)]
pub struct FauxAnnuaire;

impl ams_h3::Service for FauxAnnuaire {
    fn serve<'o>(
        &mut self,
        tete: &ams_proto_http::RequestHead<'_>,
        _corps: &[u8],
        sortie: &'o mut [u8],
    ) -> ams_h3::Reponse<'o> {
        let (code, combien) = match (tete.method(), tete.path()) {
            // Un défi : trente-deux octets, ni plus ni moins.
            (Method::Get, b"/v1/defi") => (StatusCode::OK, asl_cle::DEFI_OCTETS),
            // La preuve est acceptée, et il n'y a rien à dire de plus.
            (Method::Post, b"/v1/defi") => (StatusCode::NO_CONTENT, 0),
            (Method::Post, b"/v1/annonce") => (StatusCode::OK, 4),
            _ => (StatusCode::NOT_FOUND, 0),
        };
        let place = sortie.get_mut(..combien).unwrap_or_default();
        place.fill(0x5A);
        ams_h3::Reponse::new(code, place)
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
pub async fn lever<S>(
    chaine: Vec<u8>,
    cle: Vec<u8>,
    mut service: S,
) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    S: ams_h3::Service + Send + 'static,
{
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let tache = tokio::spawn(async move {
        let mut config = ams_tls::quic_server_config(&chaine, &cle).expect("la paire est bonne");
        config.alpn_protocols = ams_tls::alpn_h3();
        let config = Arc::new(config);

        let mut connexion: Option<ams_quic_tls::Connection> = None;
        let mut h3 = ams_h3::Http3::new();
        let mut recu = vec![0_u8; 1_500];
        let mut place = vec![0_u8; 1_500];

        loop {
            let attente = tokio::time::Duration::from_millis(50);
            let arrivee = tokio::time::timeout(attente, socket.recv_from(&mut recu)).await;

            if let Ok(Ok((lus, pair))) = arrivee {
                let mut datagramme = recu.get(..lus).unwrap_or_default().to_vec();
                if connexion.is_none() {
                    let Ok(entrant) = ams_quic::Incoming::read(&datagramme, 0) else {
                        continue;
                    };
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
pub fn materiel(nom: &str) -> (ams_quic_client::Atelier, Vec<u8>, Vec<u8>, Vec<u8>) {
    let atelier = ams_quic_client::atelier(nom);
    let (autorite, cert, cle) =
        ams_quic_client::materiel(atelier.chemin()).expect("`openssl` est requis pour cet essai");
    (atelier, autorite, cert, cle)
}

/// Une adresse où plus rien n'écoute.
///
/// **UN PORT FERMÉ, ET NON UN PAIR MUET** : le noyau rend alors un refus tout de
/// suite, ce qui est le cas dont dépendent les essais de bascule — un pair muet
/// coûterait le délai de poignée de main entier.
pub async fn adresse_morte() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");
    drop(socket);
    adresse
}
