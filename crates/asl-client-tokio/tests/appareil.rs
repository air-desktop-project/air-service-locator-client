//! La voie mobile, de bout en bout sur une vraie socket.
//!
//! **La clé secrète d'appareil n'existe ici que parce que c'est un essai** :
//! sur un téléphone, elle vit dans le matériel. Ce qui est éprouvé est
//! l'enchaînement — défi, message composé, signature rendue, preuve portée —
//! et que la connexion tenue sert ensuite les requêtes d'un écran.

mod banc;

use ams_proto_http::{Method, StatusCode};
use asl_cle::CleSecreteAppareil;
use asl_client::appareil::{
    Plateforme, corps_de_compte, message_d_authentification, message_de_possession,
    message_pour_attestation_de_cle,
};
use asl_client_tokio::{Connexion, Faute, Tenue};
use asl_id::{Genre, Identifiant};
use banc::{lever, materiel};

/// Un annuaire qui répond à la voie mobile sans rien vérifier — la sémantique
/// est éprouvée côté serveur, sous son régime de couverture.
#[derive(Debug, Default)]
struct FauxAnnuaireMobile;

impl ams_h3::Service for FauxAnnuaireMobile {
    fn serve<'o>(
        &mut self,
        tete: &ams_proto_http::RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> ams_h3::Reponse<'o> {
        let (code, rendu): (StatusCode, Vec<u8>) = match (tete.method(), tete.path()) {
            (Method::Get, b"/v1/defi") => (StatusCode::OK, vec![0x5A; asl_cle::DEFI_OCTETS]),
            // Quatre-vingt-un octets, ou ce n'est pas une preuve d'appareil.
            (Method::Post, b"/v1/defi") if corps.len() == 81 && corps[0] == b'a' => {
                (StatusCode::NO_CONTENT, Vec::new())
            }
            (Method::Post, b"/v1/defi") => (StatusCode::UNAUTHORIZED, Vec::new()),
            // La preuve d'un appareil qui rejoint, puis la plate-forme, puis
            // la chaîne. Une chaîne qui commence par `0xFF` est « refusée » —
            // le banc feint la posture exigée : `403`.
            (Method::Post, b"/v1/attestation") if corps.len() >= 82 && corps[0] == b'a' => {
                match (corps[81], corps.get(82)) {
                    (0, None) => (StatusCode::NO_CONTENT, Vec::new()),
                    (2, Some(0xFF)) => (StatusCode::FORBIDDEN, Vec::new()),
                    (2, Some(_)) => (StatusCode::NO_CONTENT, Vec::new()),
                    _ => (StatusCode::BAD_REQUEST, Vec::new()),
                }
            }
            (Method::Post, b"/v1/attestation") => (StatusCode::UNAUTHORIZED, Vec::new()),
            // Un corps de compte sans attestation fait exactement 98 octets.
            (Method::Post, b"/v1/comptes") if corps.len() == 98 && corps[0] == 0 => (
                StatusCode::CREATED,
                br#"{"compte":"u-0123456789ABCDEFGHJKMNPQRS","appareil":"a-0123456789ABCDEFGHJKMNPQRS"}"#.to_vec(),
            ),
            (Method::Post, b"/v1/comptes") => (StatusCode::BAD_REQUEST, Vec::new()),
            (Method::Get, b"/v1/autorisations") => (StatusCode::OK, b"[]".to_vec()),
            (Method::Post, b"/v1/machines") => (StatusCode::CREATED, corps.to_vec()),
            (Method::Delete, _) => (StatusCode::NO_CONTENT, Vec::new()),
            _ => (StatusCode::NOT_FOUND, Vec::new()),
        };
        let place = sortie.get_mut(..rendu.len()).unwrap_or_default();
        place.copy_from_slice(&rendu);
        ams_h3::Reponse::new(code, place)
    }
}

fn secrete() -> CleSecreteAppareil {
    let mut entropie = [0_u8; 32];
    for (place, octet) in entropie.iter_mut().enumerate() {
        *octet = u8::try_from(place.wrapping_mul(13).wrapping_add(1)).unwrap_or(1);
    }
    CleSecreteAppareil::depuis_entropie(entropie).expect("un scalaire")
}

#[tokio::test]
async fn un_appareil_enrole_prouve_sa_cle_sur_la_connexion() {
    let (_atelier, autorite, cert, cle) = materiel("appareil");
    let (adresse, tache) = lever(cert, cle, FauxAnnuaireMobile).await;
    let mut connexion = Connexion::ouvrir(adresse, "localhost", &autorite, &|| [0x11; 16])
        .await
        .expect("la connexion s'ouvre");

    let appareil = Identifiant::depuis_entropie(Genre::Appareil, [7; 16]);
    let defi = connexion.defi().await.expect("un défi");
    // Ce que le matériel du téléphone ferait : signer le message composé.
    let message =
        message_d_authentification(appareil, &defi, &connexion.liaison()).expect("un appareil");
    let signature = secrete()
        .signer(appareil, &defi, &connexion.liaison())
        .expect("un appareil");
    assert_eq!(
        message,
        asl_cle::message_a_signer(appareil, &defi, &connexion.liaison())
    );
    connexion
        .prouver_appareil(appareil, signature.octets())
        .await
        .expect("la preuve est portée, et le banc dit oui");

    // Une machine à la place d'un appareil est refusée AVANT de partir.
    let machine = Identifiant::depuis_entropie(Genre::Machine, [7; 16]);
    assert!(matches!(
        connexion
            .prouver_appareil(machine, signature.octets())
            .await,
        Err(Faute::Illisible)
    ));
    tache.abort();
}

#[tokio::test]
async fn creer_un_compte_puis_servir_un_ecran_sur_la_connexion_tenue() {
    let (_atelier, autorite, cert, cle) = materiel("compte");
    let (adresse, tache) = lever(cert, cle, FauxAnnuaireMobile).await;
    let mut connexion = Connexion::ouvrir(adresse, "localhost", &autorite, &|| [0x22; 16])
        .await
        .expect("la connexion s'ouvre");

    let secrete = secrete();
    let publique = secrete.publique().octets();
    let defi = connexion.defi().await.expect("un défi");
    let liaison = connexion.liaison();
    let message = message_de_possession(&publique, &defi, &liaison).expect("une vraie clé");
    assert_eq!(
        message,
        asl_cle::message_de_possession_appareil(&secrete.publique(), &defi, &liaison)
    );
    let preuve = secrete.prouver_la_possession(&defi, &liaison);
    let mut corps = vec![0_u8; asl_api::corps::COMPTE_CORPS_MAX];
    let combien = corps_de_compte(
        Plateforme::Aucune,
        &publique,
        preuve.octets(),
        &[],
        &mut corps,
    )
    .expect("un corps sans attestation");
    corps.truncate(combien);

    let cree = connexion
        .creer_compte(&corps)
        .await
        .expect("le compte est créé");
    assert_eq!(cree.compte.genre(), Genre::Utilisateur);
    assert_eq!(cree.appareil.genre(), Genre::Appareil);

    // La connexion passe à la tenue : les requêtes d'un écran, une à une.
    let tenue = Tenue::tenir(connexion);
    assert_eq!(tenue.liaison(), liaison);
    let liste = tenue
        .requete("GET", "/v1/autorisations", &[])
        .await
        .expect("une liste");
    assert_eq!(
        (liste.statut, liste.corps.as_slice()),
        (200, b"[]".as_slice())
    );
    let declaree = tenue
        .requete(
            "POST",
            "/v1/machines",
            br#"{"nom":"grenier","capacites":["annonce"]}"#,
        )
        .await
        .expect("une machine");
    assert_eq!(declaree.statut, 201);
    assert_eq!(
        declaree.corps,
        br#"{"nom":"grenier","capacites":["annonce"]}"#.to_vec()
    );
    // **UN `404` EST UNE RÉPONSE**, rendue telle quelle — jamais une faute.
    let absent = tenue
        .requete("GET", "/v1/rien", &[])
        .await
        .expect("l'annuaire a répondu");
    assert_eq!(absent.statut, 404);
    assert!(tenue.vivante());

    tenue.clone().fermer().await;
    // Après la fermeture, la tâche est partie : une requête le dit.
    assert!(matches!(
        tenue.requete("GET", "/v1/autorisations", &[]).await,
        Err(Faute::Delai)
    ));
    tache.abort();
}

#[tokio::test]
async fn un_appareil_qui_rejoint_prouve_et_atteste_sur_la_connexion_du_defi() {
    let (_atelier, autorite, cert, cle) = materiel("rejoindre");
    let (adresse, tache) = lever(cert, cle, FauxAnnuaireMobile).await;
    let mut connexion = Connexion::ouvrir(adresse, "localhost", &autorite, &|| [0x33; 16])
        .await
        .expect("la connexion s'ouvre");

    // **L'ORDRE DE `protocole.md` §2.2** : le défi d'abord, sur la connexion
    // nue ; le condensat du message d'attestation de clé entre dans la
    // génération de la clé ; l'ancien appareil apporte la clé et rend `a-…`.
    let defi = connexion.defi().await.expect("un défi");
    let liaison = connexion.liaison();
    let _condensat_pour_le_keystore = message_pour_attestation_de_cle(&defi, &liaison);
    let appareil = Identifiant::depuis_entropie(Genre::Appareil, [8; 16]);

    // Puis la preuve — la même signature que `POST /v1/defi` — et la chaîne,
    // sur la MÊME connexion.
    let signature = secrete()
        .signer(appareil, &defi, &liaison)
        .expect("un appareil");
    connexion
        .attester(
            appareil,
            signature.octets(),
            Plateforme::Android,
            &[0x30; 200],
        )
        .await
        .expect("la preuve tient, la chaîne est jugée, et le banc dit oui");

    // Une chaîne refusée sous une posture exigée : `403`, rendu tel quel.
    assert!(matches!(
        connexion
            .attester(
                appareil,
                signature.octets(),
                Plateforme::Android,
                &[0xFF; 200]
            )
            .await,
        Err(Faute::Statut(403))
    ));
    // Sans chaîne, sous « aucune » : le verbe vaut `POST /v1/defi`.
    connexion
        .attester(appareil, signature.octets(), Plateforme::Aucune, &[])
        .await
        .expect("une preuve nue");
    // Une chaîne sous « aucune » ne part pas : refusée avant de composer.
    assert!(matches!(
        connexion
            .attester(appareil, signature.octets(), Plateforme::Aucune, &[1])
            .await,
        Err(Faute::Illisible)
    ));
    // Une machine n'atteste rien.
    let machine = Identifiant::depuis_entropie(Genre::Machine, [8; 16]);
    assert!(matches!(
        connexion
            .attester(machine, signature.octets(), Plateforme::Aucune, &[])
            .await,
        Err(Faute::Illisible)
    ));
    tache.abort();
}
