//! La mémoire de ce que l'écho a ouvert : écrite, relue, et rien d'autre.

use asl_upnp::memoire::{FauteMemoire, MEMOIRE_MAX, OUVERTURES_MAX, Ouverture, ecrire, lire};
use asl_upnp::url::{self, FauteUrl};

fn redirection(port: u16) -> Ouverture {
    Ouverture::Redirection {
        controle: url::lire("http://192.168.1.1:5000/ctl/IPConn").unwrap(),
        service: "urn:schemas-upnp-org:service:WANIPConnection:1".to_owned(),
        port,
    }
}

fn trou(identifiant: u16) -> Ouverture {
    Ouverture::Trou {
        controle: url::lire("http://[fe80::1%252]:5000/ctl/IP6FCtl").unwrap(),
        service: "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1".to_owned(),
        identifiant,
    }
}

#[test]
fn ce_qui_est_ecrit_se_relit() {
    let ouvertures = vec![redirection(51377), trou(0), trou(7)];
    let texte = ecrire(&ouvertures);
    assert!(texte.starts_with("# asl echo"));
    assert!(texte.contains(
        "\nredirection 51377 urn:schemas-upnp-org:service:WANIPConnection:1 http://192.168.1.1:5000/ctl/IPConn\n"
    ));
    assert!(texte.contains("\ntrou 7 urn:schemas-upnp-org:service:WANIPv6FirewallControl:1 http://[fe80::1%252]:5000/ctl/IP6FCtl\n"));
    assert_eq!(lire(texte.as_bytes()), Ok(ouvertures));
    assert_eq!(lire(ecrire(&[]).as_bytes()), Ok(Vec::new()));
    assert_eq!(lire(b"\n\n# rien\n"), Ok(Vec::new()));
}

#[test]
fn une_memoire_abimee_se_refuse() {
    let service = "urn:schemas-upnp-org:service:WANIPConnection:1";
    let controle = "http://192.168.1.1/c";
    for (ligne, faute) in [
        (format!("redirection 1 {service}"), FauteMemoire::Ligne),
        (
            format!("redirection 1 {service} {controle} en-trop"),
            FauteMemoire::Ligne,
        ),
        (
            format!("redirection  1 {service} {controle}"),
            FauteMemoire::Ligne,
        ),
        (format!("autre 1 {service} {controle}"), FauteMemoire::Ligne),
        (
            format!("redirection 0 {service} {controle}"),
            FauteMemoire::Ligne,
        ),
        (
            format!("redirection 01 {service} {controle}"),
            FauteMemoire::Nombre,
        ),
        (
            format!("redirection x {service} {controle}"),
            FauteMemoire::Nombre,
        ),
        (
            format!("redirection 99999 {service} {controle}"),
            FauteMemoire::Nombre,
        ),
        (
            format!("redirection 123456 {service} {controle}"),
            FauteMemoire::Nombre,
        ),
        (
            format!("redirection 1 urn:autre {controle}"),
            FauteMemoire::Service,
        ),
        (
            format!("redirection 1 {service}\u{7} {controle}"),
            FauteMemoire::Service,
        ),
        (
            format!("redirection 1 {service} http://box/c"),
            FauteMemoire::Url(FauteUrl::Nom),
        ),
    ] {
        assert_eq!(lire(ligne.as_bytes()), Err(faute), "{ligne}");
    }
    assert_eq!(lire(&[0xff]), Err(FauteMemoire::PasDuTexte));
    assert_eq!(
        lire(&vec![b'#'; MEMOIRE_MAX.saturating_add(1)]),
        Err(FauteMemoire::TropLong)
    );
    let trop: Vec<Ouverture> = (1..=u16::try_from(OUVERTURES_MAX).unwrap().saturating_add(1))
        .map(redirection)
        .collect();
    assert_eq!(
        lire(ecrire(&trop).as_bytes()),
        Err(FauteMemoire::TropDOuvertures)
    );
}

#[test]
fn une_ouverture_se_clone_et_se_montre() {
    let ouverture = trou(3);
    assert_eq!(ouverture.clone(), ouverture);
    assert!(format!("{ouverture:?}").contains("Trou"));
    let faute = FauteMemoire::Ligne;
    assert_eq!(faute.clone(), faute);
    assert!(format!("{faute:?}").contains("Ligne"));
}
