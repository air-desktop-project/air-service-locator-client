//! SOAP : huit actions, leurs réponses et leurs fautes.

use core::net::{Ipv4Addr, Ipv6Addr};

use asl_upnp::soap::{
    self, Action, BAIL_S, DESCRIPTION, FauteSoap, Retour, VALEURS_MAX, adresse_externe, ajouter,
    ajouter_n_importe_lequel, ajouter_un_trou, booleen, code, etat_du_pare_feu, ipv4, lire, port,
    renouveler_le_trou, retirer, retirer_le_trou,
};
use asl_upnp::xml::FauteXml;

const IP1: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

/// Le corps d'une enveloppe, entre `<s:Body>` et `</s:Body>`.
fn corps(action: &Action, service: &str) -> String {
    let enveloppe = action.enveloppe(service);
    assert!(enveloppe.starts_with("<?xml version=\"1.0\"?>\r\n<s:Envelope "));
    assert!(enveloppe.ends_with("</s:Body></s:Envelope>\r\n"));
    let (_, apres) = enveloppe.split_once("<s:Body>").unwrap();
    let (dedans, _) = apres.split_once("</s:Body>").unwrap();
    dedans.to_owned()
}

#[test]
fn une_redirection_est_toujours_udp_et_dit_qui_l_a_demandee() {
    let client = Ipv4Addr::new(192, 168, 1, 20);
    let attendu = |nom: &str, bail: u32| {
        format!(
            "<u:{nom} xmlns:u=\"{IP1}\"><NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>6634</NewExternalPort><NewProtocol>UDP</NewProtocol>\
             <NewInternalPort>6634</NewInternalPort><NewInternalClient>192.168.1.20</NewInternalClient>\
             <NewEnabled>1</NewEnabled><NewPortMappingDescription>asl-echo</NewPortMappingDescription>\
             <NewLeaseDuration>{bail}</NewLeaseDuration></u:{nom}>"
        )
    };
    let action = ajouter(6634, 6634, client, BAIL_S);
    assert_eq!(action.nom, "AddPortMapping");
    assert_eq!(corps(&action, IP1), attendu("AddPortMapping", 3600));
    assert_eq!(
        corps(&ajouter(6634, 6634, client, 0), IP1),
        attendu("AddPortMapping", 0),
        "le permanent, quand la box l'exige"
    );
    assert_eq!(
        corps(&ajouter_n_importe_lequel(6634, 6634, client, BAIL_S), IP1),
        attendu("AddAnyPortMapping", 3600)
    );
    assert_eq!(
        corps(&retirer(51377), IP1),
        format!(
            "<u:DeletePortMapping xmlns:u=\"{IP1}\"><NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>51377</NewExternalPort><NewProtocol>UDP</NewProtocol></u:DeletePortMapping>"
        )
    );
    assert_eq!(
        corps(&adresse_externe(), IP1),
        format!("<u:GetExternalIPAddress xmlns:u=\"{IP1}\"></u:GetExternalIPAddress>")
    );
    assert_eq!(DESCRIPTION, "asl-echo");
}

#[test]
fn un_trou_ipv6_est_udp_vers_une_seule_adresse() {
    let service = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1";
    let client: Ipv6Addr = "2a01:cb00::20".parse().unwrap();
    assert_eq!(
        corps(&ajouter_un_trou(client, 6634, BAIL_S), service),
        format!(
            "<u:AddPinhole xmlns:u=\"{service}\"><RemoteHost></RemoteHost><RemotePort>0</RemotePort>\
             <InternalClient>2a01:cb00::20</InternalClient><InternalPort>6634</InternalPort>\
             <Protocol>17</Protocol><LeaseTime>3600</LeaseTime></u:AddPinhole>"
        )
    );
    assert!(
        corps(&renouveler_le_trou(7, BAIL_S), service)
            .contains("<UniqueID>7</UniqueID><NewLeaseTime>3600</NewLeaseTime>")
    );
    assert!(corps(&retirer_le_trou(7), service).contains("<u:DeletePinhole"));
    assert!(corps(&etat_du_pare_feu(), service).contains("<u:GetFirewallStatus"));
}

#[test]
fn le_service_s_echappe() {
    let texte = corps(&adresse_externe(), "a<b>&\"'c");
    assert!(
        texte.contains("xmlns:u=\"a&lt;b&gt;&amp;&quot;&apos;c\""),
        "{texte}"
    );
}

#[test]
fn une_reponse_rend_ses_valeurs() {
    let reponse = b"<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
        <s:Body><u:GetExternalIPAddressResponse xmlns:u=\"urn:x\">\
        <NewExternalIPAddress> 203.0.113.7 </NewExternalIPAddress><Vide/>\
        </u:GetExternalIPAddressResponse></s:Body></s:Envelope>";
    let retour = lire(reponse, "GetExternalIPAddress").expect("elle se lit");
    assert_eq!(
        retour,
        Retour::Reussi(vec![
            ("NewExternalIPAddress".to_owned(), "203.0.113.7".to_owned()),
            ("Vide".to_owned(), String::new()),
        ])
    );
    assert_eq!(retour.valeur("NewExternalIPAddress"), Some("203.0.113.7"));
    assert_eq!(retour.valeur("Autre"), None);
    assert_eq!(ipv4("203.0.113.7"), Some(Ipv4Addr::new(203, 0, 113, 7)));
    assert_eq!(ipv4("box"), None);
    let vide = b"<Envelope><Body><DeletePinholeResponse/></Body></Envelope>";
    assert_eq!(lire(vide, "DeletePinhole"), Ok(Retour::Reussi(Vec::new())));
}

#[test]
fn une_faute_upnp_rend_son_code() {
    let faute = b"<s:Envelope xmlns:s=\"x\"><s:Body><s:Fault><faultcode>s:Client</faultcode>\
        <faultstring>UPnPError</faultstring><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\
        <errorCode>718</errorCode><errorDescription>ConflictInMappingEntry</errorDescription>\
        </UPnPError></detail></s:Fault></s:Body></s:Envelope>";
    let retour = lire(faute, "AddPortMapping").expect("elle se lit");
    assert_eq!(
        retour,
        Retour::Refus {
            code: code::CONFLIT,
            description: "ConflictInMappingEntry".to_owned(),
        }
    );
    assert_eq!(retour.valeur("NewReservedPort"), None);
    let illisible = b"<Envelope><Body><Fault><detail><UPnPError><errorCode>sept</errorCode>\
        </UPnPError></detail></Fault></Body></Envelope>";
    assert_eq!(
        lire(illisible, "AddPortMapping"),
        Ok(Retour::Refus {
            code: 0,
            description: String::new(),
        })
    );
    assert_eq!(
        [
            code::ACTION_INCONNUE,
            code::NON_AUTORISEE,
            code::MEME_PORT,
            code::PERMANENT_SEULEMENT
        ],
        [401, 606, 724, 725]
    );
}

#[test]
fn ni_reponse_ni_faute_c_est_illisible() {
    assert_eq!(
        lire(
            b"<Envelope><Body><AutreResponse/></Body></Envelope>",
            "AddPortMapping"
        ),
        Err(FauteSoap::SansReponse)
    );
    assert_eq!(
        lire(&[0xff], "X"),
        Err(FauteSoap::Xml(FauteXml::PasDuTexte))
    );
    assert_eq!(lire(b"<a>", "X"), Err(FauteSoap::Xml(FauteXml::Fin)));
    let valeurs: String = (0..=VALEURS_MAX)
        .map(|rang| format!("<v{rang}>1</v{rang}>"))
        .collect();
    let trop = format!("<XResponse>{valeurs}</XResponse>");
    assert_eq!(lire(trop.as_bytes(), "X"), Err(FauteSoap::TropDeValeurs));
    // Du texte directement dans la réponse n'est la valeur de personne.
    assert_eq!(
        lire(b"<XResponse>bruit<v>1</v></XResponse>", "X"),
        Ok(Retour::Reussi(vec![("v".to_owned(), "1".to_owned())]))
    );
}

#[test]
fn les_valeurs_se_lisent_strictement() {
    assert_eq!(port("51377"), Some(51377));
    for non in ["0", "", "+80", "70000", "8a"] {
        assert_eq!(port(non), None, "{non}");
    }
    for (texte, valeur) in [
        ("1", Some(true)),
        ("TRUE", Some(true)),
        ("yes", Some(true)),
        ("0", Some(false)),
        ("false", Some(false)),
        ("No", Some(false)),
        ("peut-être", None),
    ] {
        assert_eq!(booleen(texte), valeur, "{texte}");
    }
}

#[test]
fn une_action_se_clone_et_se_montre() {
    let action = soap::retirer(1);
    assert_eq!(action.clone(), action);
    assert!(format!("{action:?}").contains("DeletePortMapping"));
    let faute = FauteSoap::SansReponse;
    assert_eq!(faute.clone(), faute);
    assert!(format!("{faute:?}").contains("SansReponse"));
}
