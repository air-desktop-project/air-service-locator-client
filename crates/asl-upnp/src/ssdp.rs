//! SSDP : trouver la box sur le réseau local (UPnP Device Architecture 2.0,
//! §1.3).
//!
//! # SUR LE LIEN LOCAL SEULEMENT
//!
//! Un `M-SEARCH` part vers `239.255.255.250:1900` en IPv4 et `[ff02::c]:1900`
//! en IPv6 (lien local), pour `InternetGatewayDevice:2` puis `:1`. Aucun tiers
//! n'est appelé (C19), aucun nom n'est résolu (C20).
//!
//! # CE QUE L'ON CROIT D'UNE RÉPONSE
//!
//! **Rien, sinon qu'elle vient d'une adresse du réseau local.** La réponse
//! donne `LOCATION`, l'URL de la description ; elle n'est suivie ([`passerelle`])
//! que si son hôte est **une adresse littérale égale à celle qui a répondu**,
//! et locale. Un appareil qui dirait « ma description est chez
//! 203.0.113.9 » — ou chez un nom — ne fait rien faire à l'écho.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::tete::{FauteTete, Tete};
use crate::url::{self, FauteUrl, Url};

/// Le port de SSDP.
pub const PORT: u16 = 1_900;

/// Le groupe SSDP d'IPv4.
pub const GROUPE_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

/// Le groupe SSDP d'IPv6, portée du lien.
pub const GROUPE_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xc);

/// Ce que l'on cherche : une passerelle IGD v2, puis v1 — dans cet ordre.
pub const CIBLES: [&str; 2] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
];

/// Le préfixe qu'une réponse doit porter dans `ST`.
const PREFIXE_IGD: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:";

/// Les secondes qu'une box peut prendre pour répondre (`MX`).
pub const ATTENTE_S: u8 = 2;

/// La taille d'une réponse, au plus : une réponse SSDP tient en quelques
/// centaines d'octets.
pub const REPONSE_MAX: usize = 2_048;

/// Le `M-SEARCH` pour `cible`, adressé à `hote` — `239.255.255.250:1900`,
/// `[FF02::C]:1900`, ou l'adresse d'une passerelle interrogée directement.
#[must_use]
pub fn recherche(cible: &str, hote: &str) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {hote}\r\nMAN: \"ssdp:discover\"\r\nMX: {ATTENTE_S}\r\nST: {cible}\r\n\r\n"
    )
    .into_bytes()
}

/// Pourquoi une réponse SSDP est écartée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FauteSsdp {
    /// Vide, ou plus longue que [`REPONSE_MAX`].
    Longueur,
    /// Pas du texte UTF-8.
    PasDuTexte,
    /// La tête ne se lit pas.
    Tete(FauteTete),
    /// Une réponse qui n'est pas `200`.
    Statut,
    /// Ni `LOCATION`, ni `ST`.
    Incomplete,
    /// `ST` ne dit pas une passerelle IGD.
    PasUnePasserelle,
    /// `LOCATION` ne se lit pas.
    Url(FauteUrl),
    /// `LOCATION` nomme une autre adresse que celle qui a répondu.
    HoteDifferent,
    /// L'adresse n'est pas sur le réseau local.
    HoteNonLocal,
}

/// Ce qu'une réponse annonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reponse<'a> {
    /// `LOCATION` : l'URL de la description.
    pub location: &'a str,
    /// `ST` : ce qui a été trouvé.
    pub cible: &'a str,
}

/// Lit une réponse à un `M-SEARCH`.
///
/// # Erreurs
///
/// Voir [`FauteSsdp`].
pub fn lire(octets: &[u8]) -> Result<Reponse<'_>, FauteSsdp> {
    if octets.is_empty() || octets.len() > REPONSE_MAX {
        return Err(FauteSsdp::Longueur);
    }
    let texte = core::str::from_utf8(octets).map_err(|_| FauteSsdp::PasDuTexte)?;
    // La tête s'arrête à la ligne vide ; ce qui suit — rien, d'habitude —
    // n'est pas lu.
    let tete = texte
        .split_once("\r\n\r\n")
        .map_or(texte.trim_end_matches(['\r', '\n']), |(tete, _)| tete);
    let tete = Tete::lire(tete).map_err(FauteSsdp::Tete)?;
    if tete.statut != 200 {
        return Err(FauteSsdp::Statut);
    }
    let location = tete.champ("LOCATION").map_err(FauteSsdp::Tete)?;
    let cible = tete.champ("ST").map_err(FauteSsdp::Tete)?;
    let (Some(location), Some(cible)) = (location, cible) else {
        return Err(FauteSsdp::Incomplete);
    };
    if !cible.starts_with(PREFIXE_IGD) {
        return Err(FauteSsdp::PasUnePasserelle);
    }
    Ok(Reponse { location, cible })
}

/// Lit une réponse venue de `source`, et rend l'URL de la description — **si
/// et seulement si** elle est une adresse littérale, égale à `source`, et
/// locale.
///
/// # Erreurs
///
/// Voir [`FauteSsdp`].
pub fn passerelle(octets: &[u8], source: IpAddr) -> Result<Url, FauteSsdp> {
    let reponse = lire(octets)?;
    let location = url::lire(reponse.location).map_err(FauteSsdp::Url)?;
    if !url::meme_hote(location.hote, source) {
        return Err(FauteSsdp::HoteDifferent);
    }
    if !url::locale(location.hote) {
        return Err(FauteSsdp::HoteNonLocal);
    }
    Ok(location)
}
