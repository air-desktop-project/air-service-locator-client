//! SOAP : les actions que l'écho sait demander à la box, et ce qu'elle
//! répond.
//!
//! # HUIT ACTIONS, ET PAS UNE DE PLUS
//!
//! Redirection (IGD v1 et v2) : [`ajouter_n_importe_lequel`]
//! (`AddAnyPortMapping`), [`ajouter`] (`AddPortMapping`), [`retirer`]
//! (`DeletePortMapping`), [`adresse_externe`] (`GetExternalIPAddress`). Trou
//! IPv6 : [`etat_du_pare_feu`] (`GetFirewallStatus`), [`ajouter_un_trou`]
//! (`AddPinhole`), [`renouveler_le_trou`] (`UpdatePinhole`), [`retirer_le_trou`]
//! (`DeletePinhole`).
//!
//! **Le protocole est UDP, toujours, et la description `asl-echo`** : aucun
//! constructeur ne prend un protocole en paramètre, et c'est voulu — l'écho
//! ne sait demander que `(UDP, son port, son adresse)` (§3 quater, « La
//! sécurité »).
//!
//! # CE QU'UNE RÉPONSE REND
//!
//! [`lire`] rend les valeurs de `<ActionResponse>` ([`Retour::Reussi`]) ou le
//! code d'une faute UPnP ([`Retour::Refus`]) — `718` un conflit, `725` une
//! box qui n'accepte que le permanent, `606` une action refusée ([`code`]).

use core::fmt::Write as _;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::xml::{Evenement, FauteXml, Lecteur};

/// Ce qu'on écrit dans `NewPortMappingDescription` : ce que l'interface de la
/// box montrera, pour qu'on sache qui a ouvert.
pub const DESCRIPTION: &str = "asl-echo";

/// Le bail demandé : une heure (décision 95 ; E18), renouvelé à mi-course.
pub const BAIL_S: u32 = 3_600;

/// Les valeurs d'une réponse, au plus.
pub const VALEURS_MAX: usize = 16;

/// Les codes d'erreur UPnP que l'écho distingue.
pub mod code {
    /// `401 Invalid Action` : la box ne connaît pas cette action.
    pub const ACTION_INCONNUE: u16 = 401;
    /// `606 Action not authorized`.
    pub const NON_AUTORISEE: u16 = 606;
    /// `718 ConflictInMappingEntry` : ce port externe est déjà pris.
    pub const CONFLIT: u16 = 718;
    /// `724 SamePortValuesRequired` : le port externe doit être le port
    /// interne.
    pub const MEME_PORT: u16 = 724;
    /// `725 OnlyPermanentLeasesSupported` : la box n'accepte que le bail
    /// permanent.
    pub const PERMANENT_SEULEMENT: u16 = 725;
}

/// Une action, prête à être mise dans une enveloppe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// Son nom, tel que SOAP le veut.
    pub nom: &'static str,
    /// Ses arguments, **dans l'ordre de la spécification** — des box le
    /// veulent.
    arguments: Vec<(&'static str, String)>,
}

/// `AddAnyPortMapping` (IGD v2) : la box choisit le port externe, en
/// commençant par celui qu'on propose, et le rend dans `NewReservedPort`.
#[must_use]
pub fn ajouter_n_importe_lequel(
    externe: u16,
    interne: u16,
    client: Ipv4Addr,
    bail_s: u32,
) -> Action {
    Action {
        nom: "AddAnyPortMapping",
        arguments: redirection(externe, interne, client, bail_s),
    }
}

/// `AddPortMapping` (IGD v1) : ce port externe-là ; `bail_s` à zéro demande
/// le permanent.
#[must_use]
pub fn ajouter(externe: u16, interne: u16, client: Ipv4Addr, bail_s: u32) -> Action {
    Action {
        nom: "AddPortMapping",
        arguments: redirection(externe, interne, client, bail_s),
    }
}

/// Les arguments d'une redirection UDP.
fn redirection(
    externe: u16,
    interne: u16,
    client: Ipv4Addr,
    bail_s: u32,
) -> Vec<(&'static str, String)> {
    vec![
        ("NewRemoteHost", String::new()),
        ("NewExternalPort", externe.to_string()),
        ("NewProtocol", "UDP".to_owned()),
        ("NewInternalPort", interne.to_string()),
        ("NewInternalClient", client.to_string()),
        ("NewEnabled", "1".to_owned()),
        ("NewPortMappingDescription", DESCRIPTION.to_owned()),
        ("NewLeaseDuration", bail_s.to_string()),
    ]
}

/// `DeletePortMapping` : retire la redirection UDP de ce port externe.
#[must_use]
pub fn retirer(externe: u16) -> Action {
    Action {
        nom: "DeletePortMapping",
        arguments: vec![
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", externe.to_string()),
            ("NewProtocol", "UDP".to_owned()),
        ],
    }
}

/// `GetExternalIPAddress`.
#[must_use]
pub const fn adresse_externe() -> Action {
    Action {
        nom: "GetExternalIPAddress",
        arguments: Vec::new(),
    }
}

/// `GetFirewallStatus` : le pare-feu IPv6 est-il actif, et les trous
/// permis ?
#[must_use]
pub const fn etat_du_pare_feu() -> Action {
    Action {
        nom: "GetFirewallStatus",
        arguments: Vec::new(),
    }
}

/// `AddPinhole` : un trou UDP vers `client`, port `port`, de n'importe quelle
/// adresse distante et de n'importe quel port.
#[must_use]
pub fn ajouter_un_trou(client: Ipv6Addr, port: u16, bail_s: u32) -> Action {
    Action {
        nom: "AddPinhole",
        arguments: vec![
            ("RemoteHost", String::new()),
            ("RemotePort", "0".to_owned()),
            ("InternalClient", client.to_string()),
            ("InternalPort", port.to_string()),
            ("Protocol", "17".to_owned()),
            ("LeaseTime", bail_s.to_string()),
        ],
    }
}

/// `UpdatePinhole` : prolonge le trou `identifiant`.
#[must_use]
pub fn renouveler_le_trou(identifiant: u16, bail_s: u32) -> Action {
    Action {
        nom: "UpdatePinhole",
        arguments: vec![
            ("UniqueID", identifiant.to_string()),
            ("NewLeaseTime", bail_s.to_string()),
        ],
    }
}

/// `DeletePinhole` : retire le trou `identifiant`.
#[must_use]
pub fn retirer_le_trou(identifiant: u16) -> Action {
    Action {
        nom: "DeletePinhole",
        arguments: vec![("UniqueID", identifiant.to_string())],
    }
}

impl Action {
    /// L'enveloppe SOAP de cette action, pour le service `service` (son URN).
    #[must_use]
    pub fn enveloppe(&self, service: &str) -> String {
        let mut corps = format!(
            "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{} xmlns:u=\"{}\">",
            self.nom,
            echapper(service)
        );
        for (nom, valeur) in &self.arguments {
            let _ = write!(corps, "<{nom}>{}</{nom}>", echapper(valeur));
        }
        let _ = write!(corps, "</u:{}></s:Body></s:Envelope>\r\n", self.nom);
        corps
    }
}

/// Échappe un texte pour un élément ou un attribut.
fn echapper(texte: &str) -> String {
    let mut sortie = String::with_capacity(texte.len());
    for caractere in texte.chars() {
        match caractere {
            '<' => sortie.push_str("&lt;"),
            '>' => sortie.push_str("&gt;"),
            '&' => sortie.push_str("&amp;"),
            '"' => sortie.push_str("&quot;"),
            '\'' => sortie.push_str("&apos;"),
            autre => sortie.push(autre),
        }
    }
    sortie
}

/// Ce que la box a répondu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retour {
    /// L'action a réussi : les valeurs de sa réponse, dans l'ordre.
    Reussi(Vec<(String, String)>),
    /// Une faute UPnP : son code (`0` s'il ne se lit pas) et ce qu'elle dit.
    Refus {
        /// Le code, `718`, `725`, `606`…
        code: u16,
        /// La description de la box, telle quelle.
        description: String,
    },
}

impl Retour {
    /// La valeur `nom` d'une réponse réussie.
    #[must_use]
    pub fn valeur(&self, nom: &str) -> Option<&str> {
        match self {
            Self::Reussi(valeurs) => valeurs
                .iter()
                .find(|(sien, _)| sien == nom)
                .map(|(_, valeur)| valeur.as_str()),
            Self::Refus { .. } => None,
        }
    }
}

/// Pourquoi une réponse SOAP ne se lit pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FauteSoap {
    /// Le XML ne se lit pas.
    Xml(FauteXml),
    /// Ni la réponse attendue, ni une faute UPnP.
    SansReponse,
    /// Plus de [`VALEURS_MAX`] valeurs.
    TropDeValeurs,
}

/// Lit la réponse à l'action `action`.
///
/// # Erreurs
///
/// Voir [`FauteSoap`].
pub fn lire(octets: &[u8], action: &str) -> Result<Retour, FauteSoap> {
    let attendu = format!("{action}Response");
    let mut lecteur = Lecteur::nouveau(octets).map_err(FauteSoap::Xml)?;
    let mut chemin: Vec<&str> = Vec::new();
    let mut valeurs: Vec<(String, String)> = Vec::new();
    let mut reponse = false;
    let mut code: Option<String> = None;
    let mut description = String::new();
    while let Some(evenement) = lecteur.suivant().map_err(FauteSoap::Xml)? {
        match evenement {
            Evenement::Ouvre(nom) => {
                if chemin.last() == Some(&attendu.as_str()) {
                    if valeurs.len() >= VALEURS_MAX {
                        return Err(FauteSoap::TropDeValeurs);
                    }
                    valeurs.push((nom.to_owned(), String::new()));
                }
                reponse |= nom == attendu;
                chemin.push(nom);
            }
            Evenement::Ferme(_) => {
                chemin.pop();
            }
            Evenement::Texte(texte) => {
                let mut ancetres = chemin.iter().rev();
                let (ici, parent) = (ancetres.next().copied(), ancetres.next().copied());
                // Sous un enfant de la réponse, le texte est la valeur de
                // cet enfant — le dernier ouvert.
                match (parent == Some(attendu.as_str()), valeurs.last_mut(), ici) {
                    (true, Some((_, valeur)), _) => valeur.push_str(&texte),
                    (_, _, Some("errorCode")) => {
                        code.get_or_insert_with(String::new).push_str(&texte);
                    }
                    (_, _, Some("errorDescription")) => description.push_str(&texte),
                    _ => {}
                }
            }
        }
    }
    if let Some(code) = code {
        return Ok(Retour::Refus {
            code: code.trim().parse().unwrap_or(0),
            description: description.trim().to_owned(),
        });
    }
    if !reponse {
        return Err(FauteSoap::SansReponse);
    }
    Ok(Retour::Reussi(
        valeurs
            .into_iter()
            .map(|(nom, valeur)| (nom, valeur.trim().to_owned()))
            .collect(),
    ))
}

/// Un port, de 1 à 65535, écrit en décimal.
#[must_use]
pub fn port(texte: &str) -> Option<u16> {
    texte
        .bytes()
        .all(|octet| octet.is_ascii_digit())
        .then(|| texte.parse::<u16>().ok())
        .flatten()
        .filter(|&port| port != 0)
}

/// Un booléen UPnP : `1`/`0`, `true`/`false`, `yes`/`no`.
#[must_use]
pub fn booleen(texte: &str) -> Option<bool> {
    match texte.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

/// Une adresse IPv4 écrite en décimal pointé.
#[must_use]
pub fn ipv4(texte: &str) -> Option<Ipv4Addr> {
    texte.parse().ok()
}
