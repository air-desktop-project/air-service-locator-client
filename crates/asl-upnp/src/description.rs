//! La description de la box : ses services, et celui qu'on emploie.
//!
//! # CE QU'ON Y CHERCHE
//!
//! Chaque `<service>`, où qu'il soit dans l'arbre des appareils — un IGD les
//! range sous `WANDevice` puis `WANConnectionDevice` —, avec son
//! `serviceType` et son `controlURL`, et l'`URLBase` éventuelle. Le reste —
//! fabricant, modèle, icônes — n'est pas lu.
//!
//! # LE CHOIX (§3 quater, « IPv4 »)
//!
//! Pour la redirection : `WANIPConnection:2`, sinon `:1`, sinon
//! `WANPPPConnection:1`. Pour le trou IPv6 : `WANIPv6FirewallControl:1`, s'il
//! y est. Chaque URL de contrôle se résout contre l'URL de la description
//! ([`crate::url::Url::joindre`]) : **le même hôte, toujours**.

use crate::url::Url;
use crate::xml::{Evenement, FauteXml, Lecteur};

/// IGD v2 : la redirection, avec `AddAnyPortMapping`.
pub const WAN_IP_2: &str = "urn:schemas-upnp-org:service:WANIPConnection:2";

/// IGD v1 : la redirection, avec `AddPortMapping`.
pub const WAN_IP_1: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

/// IGD v1 sur PPP : les mêmes actions que `WANIPConnection:1`.
pub const WAN_PPP_1: &str = "urn:schemas-upnp-org:service:WANPPPConnection:1";

/// Le pare-feu IPv6 d'IGD v2 : `AddPinhole` et les siens.
pub const PARE_FEU_6: &str = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1";

/// Les services retenus d'une description, au plus.
pub const SERVICES_MAX: usize = 32;

/// Un service de la box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// Son `serviceType`.
    pub genre: String,
    /// Son `controlURL`, tel qu'écrit.
    pub controle: String,
}

/// Ce que la description porte.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Description {
    /// L'`URLBase`, si elle est dite.
    pub base: Option<String>,
    /// Les services, au plus [`SERVICES_MAX`], dans l'ordre du document.
    pub services: Vec<Service>,
}

/// Lit une description.
///
/// # Erreurs
///
/// Celles du lecteur [`crate::xml`].
pub fn lire(octets: &[u8]) -> Result<Description, FauteXml> {
    let mut lecteur = Lecteur::nouveau(octets)?;
    let mut chemin: Vec<&str> = Vec::new();
    let mut description = Description::default();
    let mut courant: Option<Service> = None;
    while let Some(evenement) = lecteur.suivant()? {
        match evenement {
            Evenement::Ouvre(nom) => {
                if nom == "service" {
                    courant = Some(Service {
                        genre: String::new(),
                        controle: String::new(),
                    });
                }
                chemin.push(nom);
            }
            Evenement::Ferme(nom) => {
                chemin.pop();
                if nom == "service"
                    && let Some(service) = courant.take()
                    && !service.genre.trim().is_empty()
                    && !service.controle.trim().is_empty()
                    && description.services.len() < SERVICES_MAX
                {
                    description.services.push(Service {
                        genre: service.genre.trim().to_owned(),
                        controle: service.controle.trim().to_owned(),
                    });
                }
            }
            Evenement::Texte(texte) => {
                let mut ancetres = chemin.iter().rev();
                let (ici, parent) = (ancetres.next().copied(), ancetres.next().copied());
                match (ici, parent, courant.as_mut()) {
                    (Some("URLBase"), Some(_), _) if chemin.len() == 2 => {
                        description.base = Some(texte.trim().to_owned());
                    }
                    (Some("serviceType"), Some("service"), Some(service)) => {
                        service.genre.push_str(&texte);
                    }
                    (Some("controlURL"), Some("service"), Some(service)) => {
                        service.controle.push_str(&texte);
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(description)
}

/// Ce qu'on emploiera de la box.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Choix {
    /// Le service de redirection, résolu, et son type.
    pub connexion: Option<(Url, &'static str)>,
    /// Le service du pare-feu IPv6, résolu.
    pub pare_feu: Option<Url>,
}

/// Choisit, dans une description venue de `location`.
///
/// Une URL de contrôle qui ne se résout pas — un autre hôte, un nom — fait
/// passer au service suivant, comme s'il n'était pas là.
#[must_use]
pub fn choisir(description: &Description, location: &Url) -> Choix {
    let base = description
        .base
        .as_deref()
        .and_then(|base| location.joindre(base).ok())
        .unwrap_or_else(|| location.clone());
    let trouver = |genre: &str| {
        description
            .services
            .iter()
            .filter(|service| service.genre == genre)
            .find_map(|service| base.joindre(&service.controle).ok())
    };
    let connexion = [WAN_IP_2, WAN_IP_1, WAN_PPP_1]
        .into_iter()
        .find_map(|genre| trouver(genre).map(|url| (url, genre)));
    Choix {
        connexion,
        pare_feu: trouver(PARE_FEU_6),
    }
}
