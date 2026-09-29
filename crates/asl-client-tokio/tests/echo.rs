//! **LA SOCKET PARTAGÉE** (`protocole.md` §3 quater, décision 90 ; E2) : le
//! bail et l'écho sur une seule socket UDP, non connectée, triée au premier
//! octet.
//!
//! # CE QUE CES ESSAIS PROUVENT
//!
//! Que le tri tient sur une vraie socket, avec un vrai annuaire en face : le
//! QUIC de l'annuaire va à la connexion, l'écho d'où qu'il vienne est mis de
//! côté pour le porteur, et le reste — du QUIC d'un inconnu — est jeté sans
//! déranger la connexion. Que la file est bornée. Que la réponse part de la
//! même socket, donc du même port. Et que la socket survit à la connexion :
//! la suivante s'ouvre dessus.

mod banc;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use asl_client_tokio::{
    Annuaire, Confiance, Connexion, ECHOS_EN_ATTENTE_MAX, Reglages, joindre_sur,
};
use banc::{AnnuaireDEcho, Echo, cle_de_banc, lever, lever_a_plusieurs, materiel};
use tokio::net::UdpSocket;

/// Un annuaire d'écho sur un banc à plusieurs connexions.
async fn lever_l_annuaire(
    nom: &str,
) -> (asl_id::Identifiant, SocketAddr, tokio::task::JoinHandle<()>) {
    let (identite, cert, cle) = materiel(nom);
    let machine =
        |marque| asl_id::Identifiant::depuis_entropie(asl_id::Genre::Machine, [marque; 16]);
    let service = AnnuaireDEcho {
        cle: Arc::new(cle_de_banc(nom)),
        echo: (
            machine(0x70),
            asl_cle::CleSecrete::depuis_entropie([0x33; 32]).publique(),
        ),
        sondeur: (
            machine(0x80),
            asl_cle::CleSecrete::depuis_entropie([0x44; 32]).publique(),
        ),
        compte: asl_id::Identifiant::depuis_entropie(asl_id::Genre::Utilisateur, [0x55; 16]),
        sans_droit: Vec::new(),
        etat: Arc::default(),
        version: None,
    };
    let (adresse, tache) = lever_a_plusieurs(cert, cle, service).await;
    (identite, adresse, tache)
}

/// La socket de l'écho : **double pile** quand la machine a IPv6 — c'est ce
/// que `asl echo` lie —, sinon IPv4.
async fn socket_d_echo() -> Arc<UdpSocket> {
    let socket = match UdpSocket::bind("[::]:0").await {
        Ok(socket) => socket,
        Err(_) => UdpSocket::bind("0.0.0.0:0").await.expect("une socket"),
    };
    Arc::new(socket)
}

/// Où joindre la socket de l'écho depuis la boucle locale.
fn sur_la_boucle(socket: &UdpSocket) -> SocketAddr {
    let port = socket.local_addr().expect("une adresse").port();
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Lit ce qui arrive pendant un moment.
async fn laisser_arriver(connexion: &mut Connexion) {
    for _ in 0..6 {
        connexion.entretenir(50).await.expect("la connexion tient");
    }
}

#[tokio::test]
async fn le_bail_et_l_echo_partagent_une_socket_triee_au_premier_octet() {
    let (identite, adresse, tache) = lever_l_annuaire("echo-socket").await;
    let socket = socket_d_echo().await;
    let mut connexion = Connexion::ouvrir_sur(
        Arc::clone(&socket),
        adresse,
        "localhost",
        &Confiance::par_identites(&[identite]),
        &|| [0x61; 16],
    )
    .await
    .expect("la connexion s'ouvre sur la socket partagée");

    // **LA CLÉ QUE LA POIGNÉE DE MAIN A JUGÉE** : celle sous laquelle l'écho
    // croira la sonde de cet annuaire.
    assert_eq!(
        connexion.cle_distante(),
        Some(cle_de_banc("echo-socket").publique())
    );
    assert_eq!(connexion.distante().expect("l'annuaire"), adresse);

    // Un inconnu envoie un datagramme d'écho, puis du QUIC.
    let inconnu = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let ici = sur_la_boucle(&socket);
    inconnu
        .send_to(&[0x0A, 0x01, 0xEE], ici)
        .await
        .expect("envoyé");
    inconnu
        .send_to(&[0xC3, 0, 0, 0, 1], ici)
        .await
        .expect("envoyé");
    laisser_arriver(&mut connexion).await;

    let echos = connexion.echos();
    assert_eq!(echos.len(), 1, "l'écho seul est mis de côté : {echos:?}");
    let (octets, source) = &echos[0];
    assert_eq!(octets, &[0x0A, 0x01, 0xEE]);
    assert_eq!(
        SocketAddr::new(source.ip().to_canonical(), source.port()),
        inconnu.local_addr().unwrap()
    );
    assert!(connexion.echos().is_empty(), "lus une fois");

    // **LE QUIC DE L'INCONNU N'A RIEN DÉRANGÉ** : la connexion répond.
    let reponse = connexion
        .requete(b"GET", b"/v1/defi", &[], b"")
        .await
        .expect("la connexion tient");
    assert_eq!(reponse.statut, 200);

    // **LA RÉPONSE PART DE LA MÊME SOCKET**, donc du port de l'écho.
    connexion
        .envoyer_a(&[0x0A, 0x81], inconnu.local_addr().unwrap())
        .await
        .expect("envoyé");
    let mut recu = [0_u8; 16];
    let (lus, de) = tokio::time::timeout(Duration::from_secs(2), inconnu.recv_from(&mut recu))
        .await
        .expect("arrivé à temps")
        .expect("reçu");
    assert_eq!(recu.get(..lus), Some(&[0x0A, 0x81][..]));
    assert_eq!(de.port(), ici.port());

    // **LA FILE EST BORNÉE** : ce qui vient de n'importe qui ne s'accumule pas.
    for n in 0..(ECHOS_EN_ATTENTE_MAX + 36) {
        let _ = inconnu
            .send_to(&[0x0A, 0x02, u8::try_from(n % 256).unwrap()], ici)
            .await;
    }
    for _ in 0..40 {
        connexion.entretenir(20).await.expect("la connexion tient");
    }
    let echos = connexion.echos();
    assert!(
        !echos.is_empty() && echos.len() <= ECHOS_EN_ATTENTE_MAX,
        "au plus {ECHOS_EN_ATTENTE_MAX} : {}",
        echos.len()
    );

    let _ = connexion.fermer().await;
    tache.abort();
}

#[tokio::test]
async fn la_socket_survit_a_la_connexion_et_la_suivante_garde_le_port() {
    let (identite, adresse, tache) = lever_l_annuaire("echo-reprise").await;
    let socket = socket_d_echo().await;
    let port = socket.local_addr().unwrap().port();
    let reglages = Reglages::nouveaux(
        vec![Annuaire {
            adresse,
            nom: "localhost".to_owned(),
            identite,
        }],
        1_000,
    )
    .expect("des réglages");

    let mut premiere = joindre_sur(&reglages, &socket, &|| [0x62; 16])
        .await
        .expect("jointe");
    let _ = premiere.fermer().await;
    drop(premiere);

    let mut seconde = joindre_sur(&reglages, &socket, &|| [0x63; 16])
        .await
        .expect("rejointe, sur la même socket");
    assert_eq!(seconde.locale().unwrap().port(), port, "le même port");
    assert_eq!(
        seconde
            .requete(b"GET", b"/v1/defi", &[], b"")
            .await
            .unwrap()
            .statut,
        200
    );
    let _ = seconde.fermer().await;
    tache.abort();
}

#[tokio::test]
async fn une_connexion_ordinaire_n_a_ni_echo_ni_envoi_ailleurs() {
    let (identite, cert, cle) = materiel("echo-ordinaire");
    let (adresse, tache) = lever(cert, cle, Echo).await;
    let mut connexion = Connexion::ouvrir(adresse, "localhost", identite, &|| [0x64; 16])
        .await
        .expect("ouverte");
    assert!(connexion.echos().is_empty());
    assert!(connexion.envoyer_a(&[0x0A], adresse).await.is_err());
    assert_eq!(
        connexion.cle_distante(),
        Some(cle_de_banc("echo-ordinaire").publique())
    );
    let _ = connexion.fermer().await;
    tache.abort();
}
