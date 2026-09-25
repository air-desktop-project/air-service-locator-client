//! `GET /v1/nouvelles` sur une connexion tenue, de bout en bout sur une vraie
//! socket.
//!
//! Ce qui est éprouvé est le TRANSPORT : que le flux s'ouvre et que son statut
//! se lise alors que la réponse ne finit jamais, que les lignes arrivent entières
//! quel que soit le découpage des datagrammes, qu'une attente rende « rien » à
//! son échéance, et qu'elle ne retienne pas les requêtes de l'écran. Que
//! l'annuaire ait raison d'écrire une ligne, ou de refuser un second flux, est
//! éprouvé côté serveur.

mod banc;

use std::time::{Duration, Instant};

use ams_proto_http::{Method, StatusCode};
use asl_client_tokio::{Connexion, Faute, NOUVELLE_MAX, Nouvelle, Tenue};
use banc::{lever, lever_qui_pousse, materiel};

/// Un annuaire qui tient le PREMIER `GET /v1/nouvelles` ouvert, et rend `409`
/// aux suivants — la règle « un par connexion » de `protocole.md`.
#[derive(Debug, Default)]
struct AnnuaireQuiNotifie {
    ouverts: u32,
}

impl ams_h3::Service for AnnuaireQuiNotifie {
    fn serve<'o>(
        &mut self,
        tete: &ams_proto_http::RequestHead<'_>,
        _corps: &[u8],
        sortie: &'o mut [u8],
    ) -> ams_h3::Reponse<'o> {
        match (tete.method(), tete.path()) {
            (Method::Get, b"/v1/nouvelles") => {
                self.ouverts = self.ouverts.saturating_add(1);
                if self.ouverts == 1 {
                    ams_h3::Reponse::new(StatusCode::OK, &[]).tenue()
                } else {
                    ams_h3::Reponse::new(StatusCode::CONFLICT, &[])
                }
            }
            (Method::Get, b"/v1/autorisations") => {
                let place = sortie.get_mut(..2).unwrap_or_default();
                place.copy_from_slice(b"[]");
                ams_h3::Reponse::new(StatusCode::OK, place)
            }
            _ => ams_h3::Reponse::new(StatusCode::NOT_FOUND, &[]),
        }
    }
}

/// Un annuaire pour qui cet appareil a été révoqué depuis sa preuve.
struct Revoque;

impl ams_h3::Service for Revoque {
    fn serve<'o>(
        &mut self,
        _tete: &ams_proto_http::RequestHead<'_>,
        _corps: &[u8],
        _sortie: &'o mut [u8],
    ) -> ams_h3::Reponse<'o> {
        ams_h3::Reponse::new(StatusCode::UNAUTHORIZED, &[])
    }
}

const AUTORISATION: &[u8] = br#"{"quoi":"autorisation"}"#;

/// Assez pour qu'un banc chargé pousse, jamais assez pour masquer une attente
/// qui ne se réveillerait pas.
const PATIENCE: Duration = Duration::from_secs(10);

async fn tenue(adresse: std::net::SocketAddr, autorite: &[u8], graine: u8) -> Tenue {
    let connexion = Connexion::ouvrir(adresse, "localhost", autorite, &|| [graine; 16])
        .await
        .expect("la connexion s'ouvre");
    Tenue::tenir(connexion)
}

#[tokio::test]
async fn un_flux_recoit_ses_lignes_entieres_quel_que_soit_le_decoupage() {
    let (_atelier, autorite, cert, cle) = materiel("nouvelles");
    let (adresse, tache, voie) = lever_qui_pousse(cert, cle, AnnuaireQuiNotifie::default()).await;
    let tenue = tenue(adresse, &autorite, 0x61).await;

    // Rien n'est ouvert : l'attente le dit tout de suite, sans attendre.
    assert_eq!(tenue.nouvelle(PATIENCE).await, Nouvelle::Ferme);

    tenue.ecouter_les_nouvelles().await.expect("200");
    assert_eq!(tenue.nouvelles_recues(), 0);

    // UNE LIGNE COUPÉE EN DEUX POUSSÉES, puis une ligne vide, puis un genre que
    // ce transport ne lit pas — c'est l'application qui le saute.
    voie.send(br#"{"quoi":"autori"#.to_vec())
        .expect("le banc écoute");
    voie.send(b"sation\"}\n\n{\"quoi\":\"inconnu\"}\r\n".to_vec())
        .expect("le banc écoute");
    assert_eq!(
        tenue.nouvelle(PATIENCE).await,
        Nouvelle::Ligne(AUTORISATION.to_vec())
    );
    assert_eq!(
        tenue.nouvelle(PATIENCE).await,
        Nouvelle::Ligne(br#"{"quoi":"inconnu"}"#.to_vec())
    );
    assert_eq!(tenue.nouvelles_recues(), 2);

    // UNE LIGNE TROP LONGUE EST SAUTÉE, et celle qui la suit arrive.
    let mut longue = vec![b'x'; NOUVELLE_MAX.saturating_add(10)];
    longue.push(b'\n');
    longue.extend_from_slice(AUTORISATION);
    longue.push(b'\n');
    voie.send(longue).expect("le banc écoute");
    assert_eq!(
        tenue.nouvelle(PATIENCE).await,
        Nouvelle::Ligne(AUTORISATION.to_vec())
    );
    assert_eq!(tenue.nouvelles_recues(), 3);

    // UNE ATTENTE NE RETIENT PAS L'ÉCRAN : une requête passe pendant qu'une
    // attente dort, et c'est la ligne poussée ensuite qui la réveille.
    let attente = {
        let tenue = tenue.clone();
        tokio::spawn(async move { tenue.nouvelle(PATIENCE).await })
    };
    let avant = Instant::now();
    let liste = tenue
        .requete("GET", "/v1/autorisations", &[])
        .await
        .expect("l'annuaire répond");
    assert_eq!(liste.statut, 200);
    assert!(
        avant.elapsed() < Duration::from_secs(5),
        "la requête a attendu l'attente"
    );
    assert!(!attente.is_finished(), "rien n'a encore été poussé");
    voie.send([AUTORISATION, b"\n"].concat())
        .expect("le banc écoute");
    assert_eq!(
        attente.await.expect("l'attente rend"),
        Nouvelle::Ligne(AUTORISATION.to_vec())
    );

    // FERMÉE, LA TENUE LE DIT à l'attente, et refuse de rouvrir.
    tenue.clone().fermer().await;
    assert_eq!(tenue.nouvelle(PATIENCE).await, Nouvelle::Ferme);
    assert!(matches!(
        tenue.ecouter_les_nouvelles().await,
        Err(Faute::Delai)
    ));
    tache.abort();
}

#[tokio::test]
async fn une_attente_rend_rien_a_son_echeance() {
    let (_atelier, autorite, cert, cle) = materiel("nouvelles-rien");
    let (adresse, tache) = lever(cert, cle, AnnuaireQuiNotifie::default()).await;
    let tenue = tenue(adresse, &autorite, 0x62).await;
    tenue.ecouter_les_nouvelles().await.expect("200");

    let avant = Instant::now();
    assert_eq!(
        tenue.nouvelle(Duration::from_millis(400)).await,
        Nouvelle::Rien
    );
    let ecoule = avant.elapsed();
    assert!(ecoule >= Duration::from_millis(400), "rendue trop tôt");
    assert!(
        ecoule < Duration::from_secs(5),
        "rendue bien après l'échéance"
    );
    // Une attente nulle ne fait que regarder.
    assert_eq!(tenue.nouvelle(Duration::ZERO).await, Nouvelle::Rien);
    assert_eq!(tenue.nouvelles_recues(), 0);
    tache.abort();
}

#[tokio::test]
async fn un_second_flux_est_refuse_en_409_et_le_premier_vit() {
    let (_atelier, autorite, cert, cle) = materiel("nouvelles-409");
    let (adresse, tache, voie) = lever_qui_pousse(cert, cle, AnnuaireQuiNotifie::default()).await;
    let tenue = tenue(adresse, &autorite, 0x63).await;

    tenue.ecouter_les_nouvelles().await.expect("200");
    assert!(matches!(
        tenue.ecouter_les_nouvelles().await,
        Err(Faute::Statut(409))
    ));
    // Le refus n'a pas touché au premier : une ligne y arrive encore.
    voie.send([AUTORISATION, b"\n"].concat())
        .expect("le banc écoute");
    assert_eq!(
        tenue.nouvelle(PATIENCE).await,
        Nouvelle::Ligne(AUTORISATION.to_vec())
    );
    tache.abort();
}

#[tokio::test]
async fn un_appareil_revoque_se_voit_refuser_le_flux_en_401() {
    let (_atelier, autorite, cert, cle) = materiel("nouvelles-401");
    let (adresse, tache) = lever(cert, cle, Revoque).await;
    let tenue = tenue(adresse, &autorite, 0x64).await;

    assert!(matches!(
        tenue.ecouter_les_nouvelles().await,
        Err(Faute::Statut(401))
    ));
    assert_eq!(tenue.nouvelle(PATIENCE).await, Nouvelle::Ferme);
    tache.abort();
}
