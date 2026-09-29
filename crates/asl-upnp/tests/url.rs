//! Les URL : un littéral, jamais un nom ; le même hôte, toujours.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use asl_upnp::url::{FauteUrl, Url, externe_privee, lire, locale, meme_hote};

fn ip(texte: &str) -> IpAddr {
    texte.parse().expect("une adresse")
}

#[test]
fn une_url_ipv4_se_lit_avec_ou_sans_port_ni_chemin() {
    let url = lire("http://192.168.1.1:5000/rootDesc.xml").expect("elle se lit");
    assert_eq!(url.hote, ip("192.168.1.1"));
    assert_eq!(
        (url.portee, url.port, url.chemin.as_str()),
        (0, 5000, "/rootDesc.xml")
    );
    let nue = lire("HTTP://10.0.0.1").expect("le schéma se lit sans casse");
    assert_eq!((nue.port, nue.chemin.as_str()), (80, "/"));
    assert_eq!(nue.to_string(), "http://10.0.0.1:80/");
}

#[test]
fn une_url_ipv6_garde_une_portee_numerique_et_oublie_un_nom_d_interface() {
    let url = lire("http://[fe80::1%253]:49000/igd.xml").expect("elle se lit");
    assert_eq!((url.hote, url.portee, url.port), (ip("fe80::1"), 3, 49000));
    assert_eq!(url.to_string(), "http://[fe80::1%253]:49000/igd.xml");
    assert_eq!(
        url.hote_http(),
        "[fe80::1]:49000",
        "la zone ne va pas dans Host"
    );
    assert_eq!(
        url.socket(),
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            49000,
            0,
            3
        ))
    );
    let nommee = lire("http://[fe80::1%25eth0]/d.xml").expect("elle se lit");
    assert_eq!((nommee.portee, nommee.port), (0, 80));
    assert_eq!(nommee.to_string(), "http://[fe80::1]:80/d.xml");
    let v4 = lire("http://192.168.1.1:80/").unwrap();
    assert_eq!(v4.socket(), SocketAddr::new(ip("192.168.1.1"), 80));
}

#[test]
fn ce_qui_ne_se_lit_pas_dit_pourquoi() {
    let long = format!("http://192.168.1.1/{}", "a".repeat(600));
    for (texte, faute) in [
        ("", FauteUrl::Longueur),
        (long.as_str(), FauteUrl::Longueur),
        ("http://192.168.1.1/a b", FauteUrl::Caractere),
        ("http://192.168.1.1/\r\nX: y", FauteUrl::Caractere),
        ("http://192.168.1.1/é", FauteUrl::Caractere),
        ("ftp://192.168.1.1/", FauteUrl::Schema),
        ("http:/", FauteUrl::Schema),
        ("http://box.lan:5000/d.xml", FauteUrl::Nom),
        ("http://1.2.3/", FauteUrl::Hote),
        ("http://[fe80::1/", FauteUrl::Hote),
        ("http://[zz::]/", FauteUrl::Hote),
        ("http://192.168.1.1:/", FauteUrl::Port),
        ("http://192.168.1.1:+80/", FauteUrl::Port),
        ("http://192.168.1.1:0/", FauteUrl::Port),
        ("http://192.168.1.1:99999/", FauteUrl::Port),
        ("http://192.168.1.1:123456/", FauteUrl::Port),
        ("http://[::1]x/", FauteUrl::Port),
    ] {
        assert_eq!(lire(texte), Err(faute), "{texte}");
    }
}

#[test]
fn une_url_de_controle_se_resout_contre_la_description() {
    let description = lire("http://192.168.1.1:5000/desc/root.xml").unwrap();
    let absolue = description.joindre("/ctl/IPConn").unwrap();
    assert_eq!(absolue.to_string(), "http://192.168.1.1:5000/ctl/IPConn");
    let relative = description.joindre("ctl/IPConn").unwrap();
    assert_eq!(
        relative.to_string(),
        "http://192.168.1.1:5000/desc/ctl/IPConn"
    );
    let complete = description
        .joindre("http://192.168.1.1:5001/upnp/control")
        .unwrap();
    assert_eq!(complete.to_string(), "http://192.168.1.1:5001/upnp/control");
    assert_eq!(
        description.joindre("http://192.168.1.9:5000/ctl"),
        Err(FauteUrl::AutreHote),
        "une box ne renvoie pas l'écho parler à quelqu'un d'autre"
    );
    assert_eq!(
        description.joindre("http://routeur/ctl"),
        Err(FauteUrl::Nom)
    );
    assert_eq!(description.joindre(""), Err(FauteUrl::Longueur));
    assert_eq!(
        description.joindre(&"a".repeat(513)),
        Err(FauteUrl::Longueur)
    );
    assert_eq!(description.joindre("ctl IP"), Err(FauteUrl::Caractere));
}

#[test]
fn un_lien_local_garde_sa_portee_en_se_resolvant() {
    let mut description = lire("http://[fe80::1]:5000/root.xml").unwrap();
    description.portee = 4;
    let complete = description.joindre("http://[fe80::1]:5000/ctl").unwrap();
    assert_eq!(complete.portee, 4, "la portée de la source");
    let sienne = description
        .joindre("http://[fe80::1%257]:5000/ctl")
        .unwrap();
    assert_eq!(sienne.portee, 7, "une portée dite se garde");
    assert_eq!(description.joindre("ctl").unwrap().portee, 4);
}

#[test]
fn chaque_faute_se_dit() {
    for faute in [
        FauteUrl::Longueur,
        FauteUrl::Caractere,
        FauteUrl::Schema,
        FauteUrl::Nom,
        FauteUrl::Hote,
        FauteUrl::Port,
        FauteUrl::AutreHote,
    ] {
        assert!(faute.to_string().starts_with("une URL"), "{faute:?}");
    }
}

#[test]
fn le_meme_hote_se_juge_sur_l_adresse_canonique() {
    assert!(meme_hote(ip("::ffff:192.168.1.1"), ip("192.168.1.1")));
    assert!(!meme_hote(ip("192.168.1.2"), ip("192.168.1.1")));
}

#[test]
fn locale_veut_dire_le_reseau_d_ici() {
    for oui in [
        "192.168.1.1",
        "10.1.2.3",
        "172.16.0.1",
        "169.254.1.1",
        "127.0.0.1",
        "::ffff:192.168.1.1",
        "::1",
        "fe80::1",
        "fd12:3456::1",
    ] {
        assert!(locale(ip(oui)), "{oui}");
    }
    for non in ["203.0.113.7", "100.64.0.1", "2001:db8::1", "2a01:cb00::1"] {
        assert!(!locale(ip(non)), "{non}");
    }
}

#[test]
fn une_adresse_externe_privee_trahit_un_second_nat() {
    for oui in [
        "10.0.0.1",
        "192.168.0.1",
        "100.64.0.1",
        "100.127.255.254",
        "169.254.3.4",
        "127.0.0.1",
        "0.0.0.0",
    ] {
        assert!(externe_privee(oui.parse::<Ipv4Addr>().unwrap()), "{oui}");
    }
    for non in ["203.0.113.7", "100.128.0.1", "100.63.0.1", "90.1.2.3"] {
        assert!(!externe_privee(non.parse::<Ipv4Addr>().unwrap()), "{non}");
    }
}

#[test]
fn une_url_se_clone_et_se_compare() {
    let url = lire("http://192.168.1.1/").unwrap();
    let copie: Url = url.clone();
    assert_eq!(copie, url);
    assert!(format!("{url:?}").contains("192.168.1.1"));
}
