//! L'identité par la clé, sur de vraies sockets (`protocole.md` §0,
//! décisions 53 à 58).
//!
//! # CE QUE CES ESSAIS PROUVENT
//!
//! Qu'un annuaire qui ne présente QUE son certificat d'identité — auto-signé
//! par sa clé, sans autorité ni nom — est cru par sa clé et par elle seule ;
//! que la forme d'hier (une chaîne sous `--roots`, au nom exigé) l'est encore
//! le temps de la bascule ; que la liste des racines se lit et se juge ; et
//! qu'un `421` se suit par l'identité qu'il nomme.
//!
//! **Aucun nom DNS n'est résolu ici** (C20) : les bancs écoutent sur
//! `127.0.0.1`, et c'est une adresse qu'on vise.

mod banc;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ams_proto_http::{Method, StatusCode};
use asl_api::annuaire::RacineRendue;
use asl_cle::CleSecrete;
use asl_client::Identite;
use asl_client_tokio::{
    Annuaire, Attache, Confiance, Connexion, Faute, Forme, Reglages, apprendre_les_racines,
};
use asl_id::{Genre, Identifiant};
use banc::{FauxAnnuaire, lever, materiel};

const PLAFOND_MS: u64 = 15_000;

fn alea() -> [u8; 16] {
    [0x5A; 16]
}

/// Encode en PEM — ce que `ams_tls::quic_server_config` lit.
fn pem(etiquette: &str, der: &[u8]) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // Sans arithmétique libre : trois octets donnent vingt-quatre bits, lus
    // par quatre décalages fixes.
    const DECALAGES_OCTETS: [u32; 3] = [16, 8, 0];
    const DECALAGES_SIGNES: [u32; 4] = [18, 12, 6, 0];
    let mut b64 = Vec::new();
    for bloc in der.chunks(3) {
        let n = bloc
            .iter()
            .zip(DECALAGES_OCTETS)
            .fold(0_u32, |acc, (&o, decalage)| {
                acc | (u32::from(o) << decalage)
            });
        for (i, decalage) in DECALAGES_SIGNES.into_iter().enumerate() {
            if i <= bloc.len() {
                let rang = usize::try_from((n >> decalage) & 0x3f).expect("six bits");
                b64.push(TABLE[rang]);
            } else {
                b64.push(b'=');
            }
        }
    }
    let mut sortie = format!("-----BEGIN {etiquette}-----\n").into_bytes();
    for ligne in b64.chunks(64) {
        sortie.extend_from_slice(ligne);
        sortie.push(b'\n');
    }
    sortie.extend_from_slice(format!("-----END {etiquette}-----\n").as_bytes());
    sortie
}

/// Le certificat d'identité et sa clé, en PEM : ce que sert un annuaire sous
/// la forme nouvelle.
fn materiel_d_identite(cle: &CleSecrete) -> (Vec<u8>, Vec<u8>) {
    (
        pem("CERTIFICATE", &asl_cle::certificat_d_identite(cle)),
        pem("PRIVATE KEY", &asl_cle::cle_pkcs8(cle)),
    )
}

fn identite_de(cle: &CleSecrete) -> Identifiant {
    asl_cle::identifiant_de_racine(&cle.publique())
}

/// Un annuaire qui rend une liste de racines, et fait le faux annuaire pour
/// le reste.
struct Liste(Vec<u8>);

impl ams_h3::Service for Liste {
    fn serve<'o>(
        &mut self,
        tete: &ams_proto_http::RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> ams_h3::Reponse<'o> {
        if matches!(tete.method(), Method::Get) && tete.path() == b"/v1/racines" {
            let place = sortie.get_mut(..self.0.len()).unwrap_or_default();
            place.copy_from_slice(&self.0);
            return ams_h3::Reponse::new(StatusCode::OK, place);
        }
        FauxAnnuaire.serve(tete, corps, sortie)
    }
}

fn liste(racines: &[(Identifiant, [u8; 32])]) -> Vec<u8> {
    let mut sortie = vec![b'['];
    for (rang, (annuaire, cle)) in racines.iter().enumerate() {
        if rang > 0 {
            sortie.push(b',');
        }
        let mut tampon = vec![0_u8; 512];
        let combien = RacineRendue {
            annuaire: *annuaire,
            cle: *cle,
            locateurs: &["[2001:db8::1]:6630", "192.0.2.1:6630"],
        }
        .encoder(&mut tampon)
        .expect("une racine s'encode");
        sortie.extend_from_slice(&tampon[..combien]);
    }
    sortie.push(b']');
    sortie
}

#[tokio::test]
async fn un_annuaire_qui_ne_sert_que_son_identite_est_cru_par_sa_cle() {
    let cle = CleSecrete::depuis_entropie([0x21; 32]);
    let (certificat, secrete) = materiel_d_identite(&cle);
    let (ecoute, tache) = lever(certificat, secrete, FauxAnnuaire).await;

    // Aucune autorité, aucun nom : l'identité seule.
    let confiance = Confiance::par_identites(&[identite_de(&cle)]);
    let mut connexion = Connexion::ouvrir_confiance(ecoute, "127.0.0.1", &confiance, &alea)
        .await
        .expect("sa clé est celle qu'on attend");
    assert_eq!(connexion.forme(), Some(Forme::Identite));
    assert_eq!(connexion.vu().await.map(|_| ()).ok(), Some(()));
    let _ = connexion.fermer().await;
    tache.abort();
}

#[tokio::test]
async fn une_autre_cle_que_celle_attendue_est_refusee() {
    let cle = CleSecrete::depuis_entropie([0x22; 32]);
    let autre = CleSecrete::depuis_entropie([0x23; 32]);
    let (certificat, secrete) = materiel_d_identite(&cle);
    let (ecoute, tache) = lever(certificat, secrete, FauxAnnuaire).await;

    let confiance = Confiance::par_identites(&[identite_de(&autre)]);
    let refus = Connexion::ouvrir_confiance(ecoute, "127.0.0.1", &confiance, &alea).await;
    assert!(refus.is_err(), "une autre clé ne doit pas ouvrir");
    tache.abort();
}

#[tokio::test]
async fn pendant_la_bascule_les_deux_formes_sont_crues_et_se_disent() {
    // La forme nouvelle, avec une autorité d'hier configurée aussi : le nom
    // part dans le SNI, l'annuaire ne sert que son identité, on la croit.
    let cle = CleSecrete::depuis_entropie([0x24; 32]);
    let (certificat, secrete) = materiel_d_identite(&cle);
    let (ecoute, tache) = lever(certificat, secrete, FauxAnnuaire).await;
    let (_atelier, autorite, chaine, cle_chaine) = materiel("bascule-identite");
    let confiance = Confiance::par_identites(&[identite_de(&cle)]).avec_autorite(&autorite);
    let mut connexion = Connexion::ouvrir_confiance(ecoute, "localhost", &confiance, &alea)
        .await
        .expect("son identité passe, autorité ou non");
    assert_eq!(connexion.forme(), Some(Forme::Identite));
    let _ = connexion.fermer().await;
    tache.abort();

    // La forme d'hier : une chaîne sous l'autorité, au nom exigé.
    let (ecoute, tache) = lever(chaine.clone(), cle_chaine.clone(), FauxAnnuaire).await;
    let mut connexion = Connexion::ouvrir_confiance(ecoute, "localhost", &confiance, &alea)
        .await
        .expect("la chaîne d'hier passe le temps de la bascule");
    assert_eq!(connexion.forme(), Some(Forme::Autorite));
    let _ = connexion.fermer().await;
    tache.abort();

    // Sans autorité, la chaîne d'hier ne vaut plus rien : elle ne porte pas
    // la clé attendue.
    let (ecoute, tache) = lever(chaine, cle_chaine, FauxAnnuaire).await;
    let seule = Confiance::par_identites(&[identite_de(&cle)]);
    assert!(
        Connexion::ouvrir_confiance(ecoute, "localhost", &seule, &alea)
            .await
            .is_err()
    );
    tache.abort();
}

#[tokio::test]
async fn la_liste_des_racines_s_apprend_et_une_cle_fausse_la_refuse() {
    let racine = CleSecrete::depuis_entropie([0x25; 32]);
    let autre = CleSecrete::depuis_entropie([0x26; 32]);
    let (certificat, secrete) = materiel_d_identite(&racine);
    let juste = liste(&[
        (identite_de(&racine), racine.publique().octets()),
        (identite_de(&autre), autre.publique().octets()),
    ]);
    let (ecoute, tache) = lever(certificat.clone(), secrete.clone(), Liste(juste)).await;
    let confiance = Confiance::par_identites(&[identite_de(&racine)]);
    let mut connexion = Connexion::ouvrir_confiance(ecoute, "127.0.0.1", &confiance, &alea)
        .await
        .expect("la racine attendue");
    let apprises = apprendre_les_racines(&mut connexion)
        .await
        .expect("une liste juste");
    assert_eq!(apprises.len(), 2);
    assert_eq!(apprises[0].identifiant, identite_de(&racine));
    assert_eq!(apprises[1].locateurs[0], "[2001:db8::1]:6630");
    let _ = connexion.fermer().await;
    tache.abort();

    // La seconde racine porte l'identifiant de la première : la liste ment.
    let menteuse = liste(&[
        (identite_de(&racine), racine.publique().octets()),
        (identite_de(&racine), autre.publique().octets()),
    ]);
    let (ecoute, tache) = lever(certificat, secrete, Liste(menteuse)).await;
    let mut connexion = Connexion::ouvrir_confiance(ecoute, "127.0.0.1", &confiance, &alea)
        .await
        .expect("la racine attendue");
    assert!(matches!(
        apprendre_les_racines(&mut connexion).await,
        Err(Faute::Illisible)
    ));
    let _ = connexion.fermer().await;
    tache.abort();
}

/// Une racine qui renvoie toute annonce vers un annuaire local.
struct Renvoyeur {
    corps: Vec<u8>,
}

impl ams_h3::Service for Renvoyeur {
    fn serve<'o>(
        &mut self,
        tete: &ams_proto_http::RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> ams_h3::Reponse<'o> {
        if matches!(tete.method(), Method::Post) && tete.path() == b"/v1/annonce" {
            let place = sortie.get_mut(..self.corps.len()).unwrap_or_default();
            place.copy_from_slice(&self.corps);
            let mal_adressee = StatusCode::new(421).expect("un code d'état");
            return ams_h3::Reponse::new(mal_adressee, place);
        }
        FauxAnnuaire.serve(tete, corps, sortie)
    }
}

/// Un annuaire local qui accepte, et compte ce qu'on lui annonce.
struct Compteur {
    annonces: Arc<AtomicUsize>,
}

impl ams_h3::Service for Compteur {
    fn serve<'o>(
        &mut self,
        tete: &ams_proto_http::RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> ams_h3::Reponse<'o> {
        if matches!(tete.method(), Method::Post) && tete.path() == b"/v1/annonce" {
            self.annonces.fetch_add(1, Ordering::Relaxed);
        }
        FauxAnnuaire.serve(tete, corps, sortie)
    }
}

#[tokio::test]
async fn un_renvoi_se_suit_par_l_identite_qu_il_nomme_sans_autorite() {
    // La racine et l'annuaire local ne servent que leur identité ; le porteur
    // n'a AUCUNE autorité : le `421` nomme l'annuaire, c'est sa clé qu'on
    // croit (décision 50 renversée).
    let racine = CleSecrete::depuis_entropie([0x27; 32]);
    let local = CleSecrete::depuis_entropie([0x28; 32]);
    let chez_lui = Arc::new(AtomicUsize::new(0));
    let (cert_l, cle_l) = materiel_d_identite(&local);
    let (ecoute_l, tache_l) = lever(
        cert_l,
        cle_l,
        Compteur {
            annonces: Arc::clone(&chez_lui),
        },
    )
    .await;
    let corps = format!(
        r#"{{"annuaire":"{}","adresses":["127.0.0.1:{}"]}}"#,
        identite_de(&local).texte().as_str(),
        ecoute_l.port()
    )
    .into_bytes();
    let (cert_r, cle_r) = materiel_d_identite(&racine);
    let (ecoute_r, tache_r) = lever(cert_r, cle_r, Renvoyeur { corps }).await;

    let reglages = Reglages::nouveaux(
        vec![Annuaire {
            adresse: ecoute_r,
            nom: "127.0.0.1".to_owned(),
            identite: Some(identite_de(&racine)),
        }],
        Vec::new(),
        PLAFOND_MS,
    )
    .expect("la configuration est bonne");
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x11; 16]);
    let identite = Identite::nouvelle(machine, [0x42; 32]).expect("une identité d'essai");
    let attache = Attache::annoncer(reglages, identite, vec![b"{}".to_vec()], Arc::new(alea));

    let depart = Instant::now();
    while chez_lui.load(Ordering::Relaxed) == 0 && depart.elapsed() < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        chez_lui.load(Ordering::Relaxed) >= 1,
        "l'annonce n'est pas arrivée chez l'annuaire local"
    );
    assert_eq!(
        attache.annuaire_local().as_deref(),
        Some(identite_de(&local).texte().as_str())
    );
    tokio::time::timeout(Duration::from_secs(5), attache.retirer())
        .await
        .expect("le retrait rend la main");
    tache_l.abort();
    tache_r.abort();
}

/// Une racine qui renvoie vers une PAIRE dont le premier membre est mort, et
/// dont le second — au bout de sa propre adresse — présente la clé `presentee`
/// alors que le `421` y annonce `nommee`. Rend le nombre d'annonces arrivées
/// chez le second membre dans le temps donné.
async fn suivre_la_paire(
    titulaire: &CleSecrete,
    presentee: &CleSecrete,
    nommee: &CleSecrete,
    patience: Duration,
) -> usize {
    let chez_le_second = Arc::new(AtomicUsize::new(0));
    let (cert_s, cle_s) = materiel_d_identite(presentee);
    let (ecoute_s, tache_s) = lever(
        cert_s,
        cle_s,
        Compteur {
            annonces: Arc::clone(&chez_le_second),
        },
    )
    .await;
    let mort = banc::adresse_morte().await;
    // **LE 421 DE 0.31.0** (décision 59) : le i-ème `n-…` est l'identité du
    // membre au bout de la i-ème adresse.
    let corps = format!(
        r#"{{"annuaire":"{t}","adresses":["{mort}","127.0.0.1:{port}"],"identites":"{t} {n}"}}"#,
        t = identite_de(titulaire).texte().as_str(),
        port = ecoute_s.port(),
        n = identite_de(nommee).texte().as_str(),
    )
    .into_bytes();
    let racine = CleSecrete::depuis_entropie([0x40; 32]);
    let (cert_r, cle_r) = materiel_d_identite(&racine);
    let (ecoute_r, tache_r) = lever(cert_r, cle_r, Renvoyeur { corps }).await;

    let reglages = Reglages::nouveaux(
        vec![Annuaire {
            adresse: ecoute_r,
            nom: "127.0.0.1".to_owned(),
            identite: Some(identite_de(&racine)),
        }],
        Vec::new(),
        PLAFOND_MS,
    )
    .expect("la configuration est bonne");
    let machine = Identifiant::depuis_entropie(Genre::Machine, [0x11; 16]);
    let identite = Identite::nouvelle(machine, [0x42; 32]).expect("une identité d'essai");
    let attache = Attache::annoncer(reglages, identite, vec![b"{}".to_vec()], Arc::new(alea));

    let depart = Instant::now();
    while chez_le_second.load(Ordering::Relaxed) == 0 && depart.elapsed() < patience {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let arrivees = chez_le_second.load(Ordering::Relaxed);
    tokio::time::timeout(Duration::from_secs(5), attache.retirer())
        .await
        .expect("le retrait rend la main");
    tache_s.abort();
    tache_r.abort();
    arrivees
}

#[tokio::test]
async fn chaque_membre_d_une_paire_est_joint_sous_sa_propre_cle() {
    // speedy (le titulaire) est mort ; helium, second membre, a SA clé et le
    // `421` la nomme à côté de son adresse. Un client qui attendrait la clé du
    // titulaire partout refuserait helium, et la paire ne servirait à rien.
    let speedy = CleSecrete::depuis_entropie([0x41; 32]);
    let helium = CleSecrete::depuis_entropie([0x42; 32]);
    assert!(
        suivre_la_paire(&speedy, &helium, &helium, Duration::from_secs(10)).await >= 1,
        "le second membre, sous sa propre clé, doit recevoir l'annonce"
    );
}

#[tokio::test]
async fn un_membre_qui_presente_la_cle_de_l_autre_est_refuse() {
    // Au bout de l'adresse d'helium, quelqu'un présente la clé de SPEEDY : le
    // `421` y annonce helium. C'est un imposteur — une clé juste, au mauvais
    // endroit —, et il n'est pas cru.
    let speedy = CleSecrete::depuis_entropie([0x43; 32]);
    let helium = CleSecrete::depuis_entropie([0x44; 32]);
    assert_eq!(
        suivre_la_paire(&speedy, &speedy, &helium, Duration::from_secs(3)).await,
        0,
        "la clé d'un autre membre ne fait pas croire celui-ci"
    );
}
