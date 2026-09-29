//! Ce que l'écho a ouvert sur la box, **écrit dans son répertoire d'état**
//! pour être retiré au démarrage suivant d'un arrêt brutal (décision 95 ;
//! E18).
//!
//! # LE FORMAT
//!
//! Du texte, une ouverture par ligne, les champs séparés d'une espace :
//!
//! ```text
//! # asl echo — ce que la passerelle a accordé ; retiré au prochain démarrage s'il reste
//! redirection 51377 urn:schemas-upnp-org:service:WANIPConnection:1 http://192.168.1.1:5000/ctl/IPConn
//! trou 7 urn:schemas-upnp-org:service:WANIPv6FirewallControl:1 http://192.168.1.1:5000/ctl/IP6FCtl
//! ```
//!
//! Le protocole n'y est pas : c'est UDP, toujours. Le fichier est celui de
//! l'écho, mais il se relit comme une entrée : un disque abîmé, une main qui
//! l'a édité — **le lecteur est strict et borné**, et fuzzé comme les autres.

use core::fmt::Write as _;

use crate::url::{self, FauteUrl, Url};

/// La taille du fichier, au plus.
pub const MEMOIRE_MAX: usize = 4_096;

/// Les ouvertures retenues, au plus : une redirection et un trou, et de la
/// marge.
pub const OUVERTURES_MAX: usize = 8;

/// Le préfixe que l'URN d'un service doit porter.
const PREFIXE_SERVICE: &str = "urn:schemas-upnp-org:service:";

/// Ce que l'écho a ouvert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ouverture {
    /// Une redirection UDP, de ce port externe.
    Redirection {
        /// L'URL de contrôle du service qui l'a accordée.
        controle: Url,
        /// L'URN de ce service.
        service: String,
        /// Le port externe accordé.
        port: u16,
    },
    /// Un trou IPv6.
    Trou {
        /// L'URL de contrôle du service qui l'a accordé.
        controle: Url,
        /// L'URN de ce service.
        service: String,
        /// Son `UniqueID`.
        identifiant: u16,
    },
}

/// Pourquoi la mémoire ne se relit pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FauteMemoire {
    /// Plus de [`MEMOIRE_MAX`] octets.
    TropLong,
    /// Pas du texte UTF-8.
    PasDuTexte,
    /// Une ligne qui n'a pas la forme attendue.
    Ligne,
    /// Un nombre illisible.
    Nombre,
    /// Une URN de service illisible.
    Service,
    /// Une URL illisible.
    Url(FauteUrl),
    /// Plus de [`OUVERTURES_MAX`] ouvertures.
    TropDOuvertures,
}

/// Écrit la mémoire de ces ouvertures.
#[must_use]
pub fn ecrire(ouvertures: &[Ouverture]) -> String {
    let mut texte = String::from(
        "# asl echo — ce que la passerelle a accordé ; retiré au prochain démarrage s'il reste\n",
    );
    for ouverture in ouvertures {
        let _ = match ouverture {
            Ouverture::Redirection {
                controle,
                service,
                port,
            } => writeln!(texte, "redirection {port} {service} {controle}"),
            Ouverture::Trou {
                controle,
                service,
                identifiant,
            } => writeln!(texte, "trou {identifiant} {service} {controle}"),
        };
    }
    texte
}

/// Relit une mémoire.
///
/// # Erreurs
///
/// Voir [`FauteMemoire`].
pub fn lire(octets: &[u8]) -> Result<Vec<Ouverture>, FauteMemoire> {
    if octets.len() > MEMOIRE_MAX {
        return Err(FauteMemoire::TropLong);
    }
    let texte = core::str::from_utf8(octets).map_err(|_| FauteMemoire::PasDuTexte)?;
    let mut ouvertures = Vec::new();
    for ligne in texte.lines() {
        if ligne.is_empty() || ligne.starts_with('#') {
            continue;
        }
        if ouvertures.len() >= OUVERTURES_MAX {
            return Err(FauteMemoire::TropDOuvertures);
        }
        let champs: Vec<&str> = ligne.split(' ').collect();
        let [genre, nombre, service, controle] = champs.as_slice() else {
            return Err(FauteMemoire::Ligne);
        };
        let nombre = nombre_positif(nombre).ok_or(FauteMemoire::Nombre)?;
        if !service.starts_with(PREFIXE_SERVICE) || !service.bytes().all(|o| o.is_ascii_graphic()) {
            return Err(FauteMemoire::Service);
        }
        let controle = url::lire(controle).map_err(FauteMemoire::Url)?;
        let service = (*service).to_owned();
        ouvertures.push(match *genre {
            "redirection" if nombre != 0 => Ouverture::Redirection {
                controle,
                service,
                port: nombre,
            },
            "trou" => Ouverture::Trou {
                controle,
                service,
                identifiant: nombre,
            },
            _ => return Err(FauteMemoire::Ligne),
        });
    }
    Ok(ouvertures)
}

/// Un nombre décimal de 0 à 65535, sans signe ni zéro de tête superflu.
fn nombre_positif(texte: &str) -> Option<u16> {
    let propre = !texte.is_empty()
        && texte.len() <= 5
        && texte.bytes().all(|octet| octet.is_ascii_digit())
        && (texte == "0" || !texte.starts_with('0'));
    propre.then(|| texte.parse::<u16>().ok()).flatten()
}
