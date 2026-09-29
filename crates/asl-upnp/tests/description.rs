//! La description d'une box, et le service qu'on en choisit.

use asl_upnp::description::{
    Choix, Description, PARE_FEU_6, SERVICES_MAX, Service, WAN_IP_1, WAN_IP_2, WAN_PPP_1, choisir,
    lire,
};
use asl_upnp::url;
use asl_upnp::xml::FauteXml;

const IGD2: &[u8] = include_bytes!("fixtures/igd2-miniupnpd.xml");
const IGD1: &[u8] = include_bytes!("fixtures/igd1-relatif.xml");

#[test]
fn une_box_igd2_donne_la_redirection_et_le_pare_feu() {
    let description = lire(IGD2).expect("elle se lit");
    assert_eq!(description.base, None);
    assert_eq!(description.services.len(), 4);
    let location = url::lire("http://192.168.1.1:5000/rootDesc.xml").unwrap();
    let choix = choisir(&description, &location);
    let (connexion, genre) = choix.connexion.expect("une redirection");
    assert_eq!(genre, WAN_IP_2);
    assert_eq!(connexion.to_string(), "http://192.168.1.1:5000/ctl/IPConn");
    assert_eq!(
        choix.pare_feu.expect("un pare-feu").to_string(),
        "http://192.168.1.1:5000/ctl/IP6FCtl"
    );
}

#[test]
fn une_box_igd1_prefere_ip_a_ppp_et_resout_contre_urlbase() {
    let description = lire(IGD1).expect("elle se lit");
    assert_eq!(
        description.base.as_deref(),
        Some("http://192.168.1.254:49000/")
    );
    assert_eq!(
        description.services,
        vec![
            Service {
                genre: WAN_PPP_1.to_owned(),
                controle: "upnp/control/WANPPPConn1".to_owned(),
            },
            Service {
                genre: WAN_IP_1.to_owned(),
                controle: "upnp/control/WANIPConn1".to_owned(),
            },
        ]
    );
    let location = url::lire("http://192.168.1.254:49000/igddesc.xml").unwrap();
    let choix = choisir(&description, &location);
    let (connexion, genre) = choix.connexion.clone().expect("une redirection");
    assert_eq!(genre, WAN_IP_1);
    assert_eq!(
        connexion.to_string(),
        "http://192.168.1.254:49000/upnp/control/WANIPConn1"
    );
    assert_eq!(choix.pare_feu, None);
    assert_eq!(choix.clone(), choix);
}

#[test]
fn une_urlbase_ailleurs_est_ignoree_et_un_controle_ailleurs_est_saute() {
    let description = Description {
        base: Some("http://10.9.9.9/".to_owned()),
        services: vec![
            Service {
                genre: WAN_IP_2.to_owned(),
                controle: "http://203.0.113.1/ctl".to_owned(),
            },
            Service {
                genre: WAN_PPP_1.to_owned(),
                controle: "ctl/ppp".to_owned(),
            },
            Service {
                genre: PARE_FEU_6.to_owned(),
                controle: "http://box/ctl".to_owned(),
            },
        ],
    };
    let location = url::lire("http://192.168.1.1/d/root.xml").unwrap();
    let choix = choisir(&description, &location);
    let (connexion, genre) = choix.connexion.expect("le suivant");
    assert_eq!(genre, WAN_PPP_1);
    assert_eq!(connexion.to_string(), "http://192.168.1.1:80/d/ctl/ppp");
    assert_eq!(choix.pare_feu, None, "un nom n'est pas suivi");
    assert_eq!(
        choisir(&Description::default(), &location),
        Choix::default()
    );
}

#[test]
fn un_service_incomplet_ou_imbrique_n_est_pas_retenu() {
    let texte = "<root><URLBase>http://10.0.0.1/</URLBase><a><URLBase>ignorée</URLBase></a>\
                 <serviceType>hors service</serviceType>\
                 <service><serviceType>x</serviceType></service>\
                 <service><controlURL>/c</controlURL></service>\
                 <service><service><serviceType>t</serviceType><controlURL>/i</controlURL></service></service>\
                 </root>";
    let description = lire(texte.as_bytes()).expect("il se lit");
    assert_eq!(description.base.as_deref(), Some("http://10.0.0.1/"));
    assert_eq!(
        description.services,
        vec![Service {
            genre: "t".to_owned(),
            controle: "/i".to_owned(),
        }]
    );
}

#[test]
fn les_services_sont_bornes() {
    let un = "<service><serviceType>t</serviceType><controlURL>/c</controlURL></service>";
    let texte = format!("<root>{}</root>", un.repeat(SERVICES_MAX.saturating_add(5)));
    assert_eq!(lire(texte.as_bytes()).unwrap().services.len(), SERVICES_MAX);
}

#[test]
fn un_xml_fautif_se_dit() {
    assert_eq!(lire(&[0xff]), Err(FauteXml::PasDuTexte));
    assert_eq!(lire(b"<root>"), Err(FauteXml::Fin));
    let description = lire(IGD2).unwrap();
    assert!(format!("{description:?}").contains("WANIPConnection"));
}
