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
//! et locale — ou, pour une réponse venue d'un lien local IPv6, **une adresse
//! de notre lien** (ci-dessous). Un appareil qui dirait « ma description est
//! chez 203.0.113.9 » — ou chez un nom — ne fait rien faire à l'écho.
//!
//! # LA BOX QUI RÉPOND DE SON LIEN LOCAL ET SE DÉCRIT À SON ADRESSE GLOBALE
//!
//! Vu sur une Livebox (`SERVER: Unspecified, UPnP/1.0, SoftAtHome`), à
//! chaque `M-SEARCH` IPv6 : la réponse part de `fe80::2ef2:a5ff:fe6e:7b40`,
//! et `LOCATION` vaut `http://[2a01:cb19:d27:2f00:2ef2:a5ff:fe6e:7b40]:60000/…`
//! — l'adresse globale de la box, dans le `/64` du réseau local. L'égalité
//! stricte l'écartait. Elle est admise ([`Admission::SurLeLien`]) quand :
//!
//! - la source est **de lien local** (`fe80::/10`) : elle ne traverse aucun
//!   routeur, c'est un voisin ;
//! - l'hôte est une adresse IPv6 **unicast, ni de lien local, ni de boucle**,
//!   et tombe dans **un préfixe de nos propres adresses** — celles que
//!   l'appelant passe (`liens`, adresse et longueur de préfixe) : il est sur
//!   un lien où nous sommes, pas dans l'Internet ;
//! - et il n'est **pas l'une de nos adresses** : on ne se fait pas envoyer
//!   parler à soi-même.
//!
//! **Pourquoi le préfixe est exigé, et l'identifiant d'interface seulement
//! dit.** Les 64 bits bas de l'hôte sont souvent ceux de la source (la box
//! dérive les deux de son adresse MAC) ; mais la source d'une réponse UDP se
//! forge sur le lien aussi facilement que le reste, et un identifiant égal à
//! celui d'une source forgée ne dit donc rien. Seul, il admettrait n'importe
//! quelle adresse de l'Internet qui le porte. Le préfixe, lui, se lit chez
//! nous. L'identifiant partagé est rendu ([`Admission::SurLeLien`]), pour
//! le journal.

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
    /// `LOCATION` nomme une autre adresse que celle qui a répondu, hors du
    /// cas du lien local IPv6 — ou l'une de nos propres adresses.
    HoteDifferent,
    /// L'adresse n'est pas sur le réseau local, ni sur l'un de nos liens.
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

/// Pourquoi une `LOCATION` est suivie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Son hôte est l'adresse qui a répondu, et elle est locale.
    MemeHote,
    /// La source est de lien local, et l'hôte est sur l'un de nos liens —
    /// voir l'en-tête du module.
    SurLeLien {
        /// Celle de nos adresses dont le préfixe le contient, et sa longueur.
        lien: (Ipv6Addr, u8),
        /// L'hôte porte les 64 bits bas de la source.
        meme_identifiant: bool,
    },
}

/// Lit une réponse venue de `source`, et rend l'URL de la description — **si
/// et seulement si** elle est une adresse littérale, égale à `source`, et
/// locale ; ou, la source étant de lien local IPv6, une adresse de l'un des
/// préfixes de `liens` (nos adresses, et leur longueur de préfixe) qui n'est
/// pas l'une d'elles.
///
/// # Erreurs
///
/// Voir [`FauteSsdp`].
pub fn passerelle(
    octets: &[u8],
    source: IpAddr,
    liens: &[(Ipv6Addr, u8)],
) -> Result<(Url, Admission), FauteSsdp> {
    let reponse = lire(octets)?;
    let location = url::lire(reponse.location).map_err(FauteSsdp::Url)?;
    if url::meme_hote(location.hote, source) {
        if !url::locale(location.hote) {
            return Err(FauteSsdp::HoteNonLocal);
        }
        return Ok((location, Admission::MemeHote));
    }
    match (source.to_canonical(), location.hote.to_canonical()) {
        (IpAddr::V6(source), IpAddr::V6(hote))
            if source.is_unicast_link_local()
                && !hote.is_unicast_link_local()
                && !hote.is_loopback()
                && !hote.is_multicast()
                && !hote.is_unspecified() =>
        {
            if liens.iter().any(|(notre, _)| *notre == hote) {
                return Err(FauteSsdp::HoteDifferent);
            }
            let lien = liens
                .iter()
                .copied()
                .find(|(notre, longueur)| meme_prefixe(*notre, hote, *longueur))
                .ok_or(FauteSsdp::HoteNonLocal)?;
            let meme_identifiant = identifiant(hote) == identifiant(source);
            Ok((
                location,
                Admission::SurLeLien {
                    lien,
                    meme_identifiant,
                },
            ))
        }
        _ => Err(FauteSsdp::HoteDifferent),
    }
}

/// Les 64 bits bas d'une adresse IPv6 : son identifiant d'interface.
fn identifiant(adresse: Ipv6Addr) -> u64 {
    // Les 64 bits bas d'un `u128` tiennent dans un `u64` : la troncature est
    // le but.
    u64::try_from(adresse.to_bits() & u128::from(u64::MAX)).unwrap_or(0)
}

/// Les `longueur` premiers bits de deux adresses sont-ils égaux ? Une
/// longueur nulle ou au-delà de 128 ne désigne pas un lien : non.
fn meme_prefixe(une: Ipv6Addr, autre: Ipv6Addr, longueur: u8) -> bool {
    if longueur == 0 || longueur > 128 {
        return false;
    }
    let masque = u128::MAX << (128_u32.saturating_sub(u32::from(longueur)));
    une.to_bits() & masque == autre.to_bits() & masque
}
