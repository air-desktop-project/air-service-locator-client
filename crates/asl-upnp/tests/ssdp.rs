//! SSDP : la recherche, et ce qu'on croit d'une réponse.

use core::net::{IpAddr, Ipv6Addr};

use asl_upnp::ssdp::{
    Admission, CIBLES, FauteSsdp, GROUPE_V4, GROUPE_V6, PORT, REPONSE_MAX, Reponse, lire,
    passerelle, recherche,
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
    let (url, admission) = passerelle(&octets, ip("192.168.1.1"), &[]).expect("elle est suivie");
    assert_eq!(admission, Admission::MemeHote);
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
    assert!(passerelle(&octets, ip("::ffff:192.168.1.1"), &[]).is_ok());
}

#[test]
fn une_location_ailleurs_que_chez_qui_repond_n_est_pas_suivie() {
    let ailleurs = reponse("http://192.168.1.9:5000/d.xml", CIBLES[0]);
    assert_eq!(
        passerelle(&ailleurs, ip("192.168.1.1"), &[]),
        Err(FauteSsdp::HoteDifferent)
    );
    let dehors = reponse("http://203.0.113.9/d.xml", CIBLES[0]);
    assert_eq!(
        passerelle(&dehors, ip("203.0.113.9"), &[]),
        Err(FauteSsdp::HoteNonLocal)
    );
    let nom = reponse("http://box.lan/d.xml", CIBLES[0]);
    assert_eq!(
        passerelle(&nom, ip("192.168.1.1"), &[]),
        Err(FauteSsdp::Url(FauteUrl::Nom))
    );
    assert_eq!(
        passerelle(b"", ip("192.168.1.1"), &[]),
        Err(FauteSsdp::Longueur)
    );
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

/// Nos adresses de lien, comme l'appelant les passe : l'adresse globale du
/// Mac de l'essai réel, dans le `/64` de la Livebox.
fn nos_liens() -> Vec<(Ipv6Addr, u8)> {
    vec![(
        "2a01:cb19:d27:2f00:1c2b:3a4d:5e6f:7081".parse().unwrap(),
        64,
    )]
}

/// La réponse de la Livebox, exactement : `fe80::2ef2:a5ff:fe6e:7b40`, qui
/// se décrit à son adresse globale, dans notre `/64`, avec le même
/// identifiant d'interface.
fn livebox() -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\n\
         LOCATION: http://[2a01:cb19:0d27:2f00:2ef2:a5ff:fe6e:7b40]:60000/9f8b85cb/gatedesc.xml\r\n\
         SERVER: Unspecified, UPnP/1.0, SoftAtHome\r\nST: {}\r\nUSN: uuid:x::{}\r\n\r\n",
        CIBLES[1], CIBLES[1]
    )
    .into_bytes()
}

#[test]
fn la_livebox_repond_de_son_lien_local_et_se_decrit_a_son_adresse_globale() {
    let source = ip("fe80::2ef2:a5ff:fe6e:7b40");
    let (url, admission) = passerelle(&livebox(), source, &nos_liens()).expect("elle est suivie");
    assert_eq!(
        url.hote,
        ip("2a01:cb19:d27:2f00:2ef2:a5ff:fe6e:7b40"),
        "l'adresse globale, jointe telle quelle"
    );
    assert_eq!(url.portee, 0);
    assert_eq!(url.port, 60_000);
    assert_eq!(url.chemin, "/9f8b85cb/gatedesc.xml");
    assert_eq!(
        admission,
        Admission::SurLeLien {
            lien: nos_liens()[0],
            meme_identifiant: true,
        }
    );
    // Un autre identifiant, dans le même préfixe : admis, et dit.
    let voisin = String::from_utf8(livebox())
        .unwrap()
        .replace("2ef2:a5ff:fe6e:7b40]", ":1]");
    assert_eq!(
        passerelle(voisin.as_bytes(), source, &nos_liens())
            .unwrap()
            .1,
        Admission::SurLeLien {
            lien: nos_liens()[0],
            meme_identifiant: false,
        }
    );
    // Un préfixe plus court que /64 (un /56 délégué) : il suffit qu'il
    // contienne l'hôte.
    let court = [("2a01:cb19:d27:2f99::1".parse::<Ipv6Addr>().unwrap(), 56)];
    assert!(passerelle(&livebox(), source, &court).is_ok());
}

#[test]
fn hors_de_nos_liens_le_lien_local_ne_suffit_pas() {
    let source = ip("fe80::2ef2:a5ff:fe6e:7b40");
    // **LE MÊME IDENTIFIANT, AILLEURS** : une source forgée porte celui qu'on
    // veut ; seul le préfixe, lu chez nous, dit « sur le lien ».
    let ailleurs = String::from_utf8(livebox())
        .unwrap()
        .replace("2a01:cb19:0d27:2f00:", "2001:db8:1:2:");
    assert_eq!(
        passerelle(ailleurs.as_bytes(), source, &nos_liens()),
        Err(FauteSsdp::HoteNonLocal)
    );
    // Sans adresse à nous connue, rien ne dit le lien.
    assert_eq!(
        passerelle(&livebox(), source, &[]),
        Err(FauteSsdp::HoteNonLocal)
    );
    // Des longueurs qui ne désignent pas un lien.
    for longueur in [0, 129] {
        let liens = [(nos_liens()[0].0, longueur)];
        assert_eq!(
            passerelle(&livebox(), source, &liens),
            Err(FauteSsdp::HoteNonLocal),
            "/{longueur}"
        );
    }
}

#[test]
fn hors_du_lien_local_l_egalite_reste_stricte() {
    // L'hôte est l'une de nos adresses : on ne se fait pas envoyer chez soi.
    let chez_nous = reponse(
        "http://[2a01:cb19:d27:2f00:1c2b:3a4d:5e6f:7081]:5000/d.xml",
        CIBLES[0],
    );
    assert_eq!(
        passerelle(&chez_nous, ip("fe80::1"), &nos_liens()),
        Err(FauteSsdp::HoteDifferent)
    );
    // Une source globale, une IPv4, ou un hôte de lien local, de boucle,
    // multicast, non spécifié, IPv4 : l'égalité stricte.
    let globale = livebox();
    for (location, source) in [
        (None, "2a01:cb19:d27:2f00::1"),
        (None, "192.168.1.1"),
        (
            Some("http://[fe80::9]:5000/d.xml"),
            "fe80::2ef2:a5ff:fe6e:7b40",
        ),
        (Some("http://[::1]:5000/d.xml"), "fe80::1"),
        (Some("http://[ff02::c]:5000/d.xml"), "fe80::1"),
        (Some("http://[::]:5000/d.xml"), "fe80::1"),
        (Some("http://192.168.1.1:5000/d.xml"), "fe80::1"),
    ] {
        let octets = location.map_or_else(|| globale.clone(), |l| reponse(l, CIBLES[0]));
        assert_eq!(
            passerelle(&octets, ip(source), &nos_liens()),
            Err(FauteSsdp::HoteDifferent),
            "{location:?} depuis {source}"
        );
    }
}
