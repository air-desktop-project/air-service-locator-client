//! SSDP : la recherche, et ce qu'on croit d'une réponse.

use core::net::IpAddr;

use asl_upnp::ssdp::{
    CIBLES, FauteSsdp, GROUPE_V4, GROUPE_V6, PORT, REPONSE_MAX, Reponse, lire, passerelle,
    recherche,
};
use asl_upnp::url::FauteUrl;

fn ip(texte: &str) -> IpAddr {
    texte.parse().expect("une adresse")
}

/// Une réponse comme miniupnpd l'écrit.
fn reponse(location: &str, st: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: {st}\r\n\
         USN: uuid:1234::{st}\r\nEXT:\r\nSERVER: Linux UPnP/2.0 MiniUPnPd/2.3\r\n\
         LOCATION: {location}\r\n\r\n"
    )
    .into_bytes()
}

#[test]
fn la_recherche_vise_une_passerelle_sur_le_lien() {
    assert_eq!(PORT, 1900);
    assert_eq!(GROUPE_V4.to_string(), "239.255.255.250");
    assert_eq!(GROUPE_V6.to_string(), "ff02::c");
    let texte = String::from_utf8(recherche(CIBLES[0], "239.255.255.250:1900")).unwrap();
    assert_eq!(
        texte,
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n\
         MX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n\r\n"
    );
    assert!(CIBLES[1].ends_with(":1"));
}

#[test]
fn une_reponse_de_box_donne_sa_description() {
    let octets = reponse("http://192.168.1.1:5000/rootDesc.xml", CIBLES[1]);
    assert_eq!(
        lire(&octets),
        Ok(Reponse {
            location: "http://192.168.1.1:5000/rootDesc.xml",
            cible: CIBLES[1],
        })
    );
    let url = passerelle(&octets, ip("192.168.1.1")).expect("elle est suivie");
    assert_eq!(url.to_string(), "http://192.168.1.1:5000/rootDesc.xml");
    // Des lignes finies par `\n` seul, sans ligne vide : lues aussi.
    let nue = format!(
        "HTTP/1.1 200 OK\nST: {}\nLocation: http://10.0.0.1/d.xml\n",
        CIBLES[0]
    );
    assert_eq!(
        lire(nue.as_bytes()).unwrap().location,
        "http://10.0.0.1/d.xml"
    );
    // La source peut être une IPv4 enfouie.
    assert!(passerelle(&octets, ip("::ffff:192.168.1.1")).is_ok());
}

#[test]
fn une_location_ailleurs_que_chez_qui_repond_n_est_pas_suivie() {
    let ailleurs = reponse("http://192.168.1.9:5000/d.xml", CIBLES[0]);
    assert_eq!(
        passerelle(&ailleurs, ip("192.168.1.1")),
        Err(FauteSsdp::HoteDifferent)
    );
    let dehors = reponse("http://203.0.113.9/d.xml", CIBLES[0]);
    assert_eq!(
        passerelle(&dehors, ip("203.0.113.9")),
        Err(FauteSsdp::HoteNonLocal)
    );
    let nom = reponse("http://box.lan/d.xml", CIBLES[0]);
    assert_eq!(
        passerelle(&nom, ip("192.168.1.1")),
        Err(FauteSsdp::Url(FauteUrl::Nom))
    );
    assert_eq!(passerelle(b"", ip("192.168.1.1")), Err(FauteSsdp::Longueur));
}

#[test]
fn ce_qui_n_est_pas_une_reponse_de_passerelle_est_ecarte() {
    let trop = vec![b'a'; REPONSE_MAX.saturating_add(1)];
    assert_eq!(lire(&trop), Err(FauteSsdp::Longueur));
    assert_eq!(lire(&[0xff, 0xfe]), Err(FauteSsdp::PasDuTexte));
    assert_eq!(
        lire(b"HTTP/1.1 404 Not Found\r\n\r\n"),
        Err(FauteSsdp::Statut)
    );
    assert_eq!(
        lire(b"HTTP/1.1 200 OK\r\nST: x\r\n\r\n"),
        Err(FauteSsdp::Incomplete)
    );
    let imprimante = reponse(
        "http://192.168.1.5/d.xml",
        "urn:schemas-upnp-org:device:Printer:1",
    );
    assert_eq!(lire(&imprimante), Err(FauteSsdp::PasUnePasserelle));
    let deux_location = format!(
        "HTTP/1.1 200 OK\r\nST: {0}\r\nLOCATION: http://10.0.0.1/a\r\nLocation: http://10.0.0.2/b\r\n\r\n",
        CIBLES[0]
    );
    assert!(matches!(
        lire(deux_location.as_bytes()),
        Err(FauteSsdp::Tete(_))
    ));
    let deux_st = format!(
        "HTTP/1.1 200 OK\r\nST: {0}\r\nST: {0}\r\nLOCATION: http://10.0.0.1/a\r\n\r\n",
        CIBLES[0]
    );
    assert!(matches!(lire(deux_st.as_bytes()), Err(FauteSsdp::Tete(_))));
}

/// La tête commune à SSDP et HTTP : stricte.
#[test]
fn la_tete_est_lue_strictement() {
    for tete in [
        "HTTP/2 200 OK",
        "HTTP/1.1 20 OK",
        "HTTP/1.1 2x0 OK",
        "HTTP/1.1 099 OK",
        "HTTP/1.1 600 OK",
        "NOTIFY * HTTP/1.1",
        "HTTP/1.1 200 OK\r\nsans deux-points",
        "HTTP/1.1 200 OK\r\n: vide",
        "HTTP/1.1 200 OK\r\nLOC ATION: x",
        "HTTP/1.1 200 OK\r\n folded: x",
    ] {
        let octets = format!("{tete}\r\n\r\n");
        assert!(
            matches!(lire(octets.as_bytes()), Err(FauteSsdp::Tete(_))),
            "{tete}"
        );
    }
    let mut beaucoup = String::from("HTTP/1.1 200 OK\r\n");
    for rang in 0..49 {
        beaucoup.push_str(&format!("X-{rang}: y\r\n"));
    }
    beaucoup.push_str("\r\n");
    assert!(matches!(lire(beaucoup.as_bytes()), Err(FauteSsdp::Tete(_))));
    let dix = "HTTP/1.0 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: http://10.0.0.1/\r\n\r\n";
    assert!(lire(dix.as_bytes()).is_ok(), "HTTP/1.0 se lit");
}

#[test]
fn les_fautes_se_comparent_et_se_montrent() {
    let faute = FauteSsdp::Statut;
    assert_eq!(faute, faute.clone());
    assert!(format!("{faute:?}").contains("Statut"));
}
