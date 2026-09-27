//! Les racines embarquées, et le jugement d'une liste de `GET /v1/racines`.

use asl_api::annuaire::RacineRendue;
use asl_client::racines::{FauteDeListe, RACINES, RacineEmbarquee, lire_la_liste};
use asl_id::{Genre, Identifiant};

/// Encode une liste comme une racine la rend.
fn liste(racines: &[(Identifiant, [u8; 32], &[&str])]) -> Vec<u8> {
    let mut sortie = vec![b'['];
    for (rang, (annuaire, cle, locateurs)) in racines.iter().enumerate() {
        if rang > 0 {
            sortie.push(b',');
        }
        let mut tampon = vec![0_u8; 1024];
        let combien = RacineRendue {
            annuaire: *annuaire,
            cle: *cle,
            locateurs,
        }
        .encoder(&mut tampon)
        .expect("une racine s'encode");
        sortie.extend_from_slice(&tampon[..combien]);
    }
    sortie.push(b']');
    sortie
}

fn embarquees() -> Vec<(Identifiant, [u8; 32], &'static [&'static str])> {
    RACINES
        .iter()
        .map(|racine| {
            (
                racine.identite().expect("une identité juste"),
                racine.cle,
                racine.locateurs,
            )
        })
        .collect()
}

#[test]
fn chaque_cle_embarquee_se_deduit_en_son_identifiant() {
    // Une clé recopiée de travers ne passerait pas : l'identifiant écrit à côté
    // est celui qu'on a relevé sur le banc.
    for racine in RACINES {
        let identite = racine.identite().expect("la clé donne l'identifiant");
        assert_eq!(identite.texte().as_str(), racine.identifiant);
    }
}

#[test]
fn les_locateurs_embarques_sont_des_adresses_litterales_ipv6_d_abord() {
    // C20 : aucun chemin par défaut ne passe par un résolveur.
    for racine in RACINES {
        let adresses: Vec<std::net::SocketAddr> = racine
            .locateurs
            .iter()
            .map(|texte| texte.parse().expect("une adresse littérale"))
            .collect();
        assert!(!adresses.is_empty());
        assert!(
            adresses[0].is_ipv6(),
            "IPv6 d'abord : {:?}",
            racine.locateurs
        );
        assert!(adresses.iter().any(std::net::SocketAddr::is_ipv4));
    }
}

#[test]
fn une_liste_juste_se_lit() {
    let corps = liste(&embarquees());
    let lue = lire_la_liste(&corps).expect("une liste juste");
    let identites: Vec<Identifiant> = lue.racines().map(|racine| racine.annuaire).collect();
    let attendues: Vec<Identifiant> = embarquees().iter().map(|(id, _, _)| *id).collect();
    assert_eq!(identites, attendues);
}

#[test]
fn une_seule_cle_fausse_refuse_la_liste_entiere() {
    let mut racines = embarquees();
    // La première racine garde son identifiant, mais porte la clé de l'autre.
    racines[0].1 = racines[1].1;
    assert_eq!(
        lire_la_liste(&liste(&racines)).err(),
        Some(FauteDeListe::Mensonge)
    );
}

/// **`[0x02; 32]` N'EST PAS UN POINT** — trouvé par le dépôt serveur
/// (`asl-cle/tests/signature.rs`) : `[0xFF; 32]`, qu'on croirait choisir,
/// en est un valide.
#[test]
fn une_cle_qui_n_est_pas_un_point_est_un_mensonge() {
    let mut racines = embarquees();
    racines[1].1 = [0x02; 32];
    assert_eq!(
        lire_la_liste(&liste(&racines)).err(),
        Some(FauteDeListe::Mensonge)
    );
}

#[test]
fn des_octets_quelconques_ne_se_lisent_pas() {
    assert_eq!(
        lire_la_liste(b"pas une liste").err(),
        Some(FauteDeListe::Illisible)
    );
    assert_eq!(lire_la_liste(b"[]").err(), Some(FauteDeListe::Illisible));
}

#[test]
fn une_racine_embarquee_de_travers_est_un_mensonge() {
    let vraie = RACINES[0];
    let mal_ecrite = RacineEmbarquee {
        identifiant: "pas-un-identifiant",
        ..vraie
    };
    assert_eq!(mal_ecrite.identite().err(), Some(FauteDeListe::Mensonge));
    let autre_cle = RacineEmbarquee {
        cle: RACINES[1].cle,
        ..vraie
    };
    assert_eq!(autre_cle.identite().err(), Some(FauteDeListe::Mensonge));
    let pas_un_point = RacineEmbarquee {
        cle: [0x02; 32],
        ..vraie
    };
    assert_eq!(pas_un_point.identite().err(), Some(FauteDeListe::Mensonge));
    // Un identifiant d'un autre genre n'en est pas un d'annuaire.
    let machine = Identifiant::depuis_entropie(Genre::Machine, [1; 16]);
    let mauvais_genre = RacineEmbarquee {
        identifiant: Box::leak(machine.texte().as_str().to_owned().into_boxed_str()),
        ..vraie
    };
    assert_eq!(mauvais_genre.identite().err(), Some(FauteDeListe::Mensonge));
}

#[test]
fn les_fautes_se_disent() {
    assert!(!FauteDeListe::Illisible.to_string().is_empty());
    assert!(FauteDeListe::Mensonge.to_string().contains("refusée"));
}
