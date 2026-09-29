//! Une URL `http://` à **adresse littérale**, et rien d'autre.
//!
//! # AUCUN NOM (C20)
//!
//! La réponse SSDP donne une URL `LOCATION`, la description des URL de
//! contrôle. Suivre un nom, ce serait demander au DNS où aller sur la parole
//! d'un appareil que personne n'authentifie : **un nom est refusé**
//! ([`FauteUrl::Nom`]), seul un littéral IPv4 ou `[IPv6]` se lit. Et le
//! littéral doit être celui qui a répondu ([`meme_hote`]), sur le réseau local
//! ([`locale`]) : l'écho ne suit pas une box qui l'enverrait parler à une
//! adresse de l'Internet.
//!
//! # CE QUI N'EST PAS LU
//!
//! Ni `https` (aucune box ne le parle pour IGD), ni utilisateur, ni requête
//! décodée : le chemin est gardé tel quel, et ne porte que des caractères
//! ASCII visibles — **un espace, un retour à la ligne, et le chemin
//! s'arrêterait au milieu d'une ligne de requête HTTP** : c'est une injection
//! d'en-tête, et c'est refusé ici plutôt qu'échappé là-bas.

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

/// La longueur d'une URL, au plus.
pub const URL_MAX: usize = 512;

/// Une URL `http://` à adresse littérale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// L'hôte : une adresse, jamais un nom.
    pub hote: IpAddr,
    /// La portée d'une adresse IPv6 de lien local (l'interface), `0` sinon.
    ///
    /// Une `LOCATION` en `fe80::` ne se joint que par l'interface d'où elle
    /// est venue : c'est la source de la réponse SSDP qui la donne, pas le
    /// texte de l'URL.
    pub portee: u32,
    /// Le port, `80` s'il n'est pas dit.
    pub port: u16,
    /// Le chemin, commençant par `/`, tel quel.
    pub chemin: String,
}

/// Pourquoi une URL ne se lit pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FauteUrl {
    /// Vide, ou plus longue que [`URL_MAX`].
    Longueur,
    /// Un caractère hors de l'ASCII visible : espace, contrôle, non-ASCII.
    Caractere,
    /// Pas `http://`.
    Schema,
    /// L'hôte est un nom — refusé (C20).
    Nom,
    /// L'hôte n'est pas un littéral bien formé.
    Hote,
    /// Le port n'est pas un nombre de 1 à 65535.
    Port,
    /// Une URL de contrôle vers un autre hôte que celui de la description.
    AutreHote,
}

impl fmt::Display for FauteUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Longueur => "une URL vide ou trop longue",
            Self::Caractere => "une URL qui porte un caractère interdit",
            Self::Schema => "une URL qui n'est pas http://",
            Self::Nom => "une URL qui nomme un hôte au lieu d'une adresse",
            Self::Hote => "une URL dont l'adresse ne se lit pas",
            Self::Port => "une URL dont le port ne se lit pas",
            Self::AutreHote => "une URL de contrôle vers un autre hôte que la box",
        })
    }
}

/// Lit une URL absolue.
///
/// # Erreurs
///
/// Voir [`FauteUrl`].
pub fn lire(texte: &str) -> Result<Url, FauteUrl> {
    if texte.is_empty() || texte.len() > URL_MAX {
        return Err(FauteUrl::Longueur);
    }
    if !texte.bytes().all(|octet| octet.is_ascii_graphic()) {
        return Err(FauteUrl::Caractere);
    }
    let reste = sans_schema(texte).ok_or(FauteUrl::Schema)?;
    let (autorite, chemin) = match reste.find('/') {
        Some(barre) => reste.split_at(barre),
        None => (reste, "/"),
    };
    let (hote, portee, port) = lire_autorite(autorite)?;
    Ok(Url {
        hote,
        portee,
        port,
        chemin: chemin.to_owned(),
    })
}

/// Le reste de l'URL après `http://`, quelle que soit la casse du schéma.
fn sans_schema(texte: &str) -> Option<&str> {
    let schema = texte.get(..7)?;
    schema
        .eq_ignore_ascii_case("http://")
        .then(|| texte.get(7..))
        .flatten()
}

/// `192.168.1.1`, `192.168.1.1:5000`, `[fe80::1]:5000`, `[fe80::1%253]:80`.
fn lire_autorite(autorite: &str) -> Result<(IpAddr, u32, u16), FauteUrl> {
    if let Some(entre) = autorite.strip_prefix('[') {
        let (dedans, apres) = entre.split_once(']').ok_or(FauteUrl::Hote)?;
        // **LA ZONE (`%25eth0`, RFC 6874) N'EST PAS CRUE** : un nombre se
        // garde, un nom d'interface ne dit rien qu'on puisse employer sans C,
        // et c'est de toute façon la source de la réponse qui fait foi.
        let (adresse, portee) = match dedans.split_once("%25") {
            Some((adresse, zone)) => (adresse, zone.parse::<u32>().unwrap_or(0)),
            None => (dedans, 0),
        };
        let v6: Ipv6Addr = adresse.parse().map_err(|_| FauteUrl::Hote)?;
        return Ok((IpAddr::V6(v6), portee, lire_port(apres)?));
    }
    let (hote, apres) = match autorite.find(':') {
        Some(deux_points) => autorite.split_at(deux_points),
        None => (autorite, ""),
    };
    let v4: Ipv4Addr = hote.parse().map_err(|_| {
        if hote.bytes().any(|octet| octet.is_ascii_alphabetic()) {
            FauteUrl::Nom
        } else {
            FauteUrl::Hote
        }
    })?;
    Ok((IpAddr::V4(v4), 0, lire_port(apres)?))
}

/// `""` (80) ou `":<chiffres>"`, de 1 à 65535.
fn lire_port(apres: &str) -> Result<u16, FauteUrl> {
    if apres.is_empty() {
        return Ok(80);
    }
    let chiffres = apres.strip_prefix(':').ok_or(FauteUrl::Port)?;
    // `u16::from_str` admet un `+` : on ne le veut pas.
    if chiffres.is_empty() || chiffres.len() > 5 || !chiffres.bytes().all(|o| o.is_ascii_digit()) {
        return Err(FauteUrl::Port);
    }
    match chiffres.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(FauteUrl::Port),
    }
}

impl Url {
    /// Où ouvrir la connexion : l'adresse, le port, et la portée d'un lien
    /// local.
    #[must_use]
    pub fn socket(&self) -> SocketAddr {
        match self.hote {
            IpAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4), self.port),
            IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, self.port, 0, self.portee)),
        }
    }

    /// L'en-tête `Host:` — **sans la zone**, que l'hôte n'a pas à connaître.
    #[must_use]
    pub fn hote_http(&self) -> String {
        match self.hote {
            IpAddr::V4(v4) => format!("{v4}:{}", self.port),
            IpAddr::V6(v6) => format!("[{v6}]:{}", self.port),
        }
    }

    /// Résout une URL de contrôle ou une `URLBase` lue dans la description,
    /// **contre celle-ci** : un chemin absolu garde l'hôte, un chemin relatif
    /// se joint au répertoire, une URL complète doit nommer **le même hôte**
    /// — une box ne renvoie pas l'écho parler à quelqu'un d'autre.
    ///
    /// # Erreurs
    ///
    /// Celles de [`lire`], et [`FauteUrl::AutreHote`].
    pub fn joindre(&self, reference: &str) -> Result<Self, FauteUrl> {
        if sans_schema(reference).is_some() {
            let mut absolue = lire(reference)?;
            if !meme_hote(absolue.hote, self.hote) {
                return Err(FauteUrl::AutreHote);
            }
            if absolue.portee == 0 {
                absolue.portee = self.portee;
            }
            return Ok(absolue);
        }
        if reference.is_empty() || reference.len() > URL_MAX {
            return Err(FauteUrl::Longueur);
        }
        if !reference.bytes().all(|octet| octet.is_ascii_graphic()) {
            return Err(FauteUrl::Caractere);
        }
        let chemin = if reference.starts_with('/') {
            reference.to_owned()
        } else {
            // Le chemin commence toujours par `/` : `rfind` le trouve.
            let repertoire = self
                .chemin
                .rfind('/')
                .and_then(|barre| self.chemin.get(..=barre))
                .unwrap_or("/");
            format!("{repertoire}{reference}")
        };
        Ok(Self {
            hote: self.hote,
            portee: self.portee,
            port: self.port,
            chemin,
        })
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.hote {
            IpAddr::V6(v6) if self.portee != 0 => write!(
                f,
                "http://[{v6}%25{}]:{}{}",
                self.portee, self.port, self.chemin
            ),
            _ => write!(f, "http://{}{}", self.hote_http(), self.chemin),
        }
    }
}

/// Deux adresses désignent-elles le même hôte ? Une IPv4 enfouie
/// (`::ffff:a.b.c.d`) est son IPv4.
#[must_use]
pub fn meme_hote(une: IpAddr, autre: IpAddr) -> bool {
    une.to_canonical() == autre.to_canonical()
}

/// **L'adresse est-elle sur le réseau local ?** Privée (RFC 1918), de lien
/// local, ULA, ou la boucle locale.
///
/// La boucle locale y est parce qu'elle est plus locale encore : une passerelle
/// qui tourne sur la machine même — un routeur qui fait tourner l'écho — ne
/// répond que d'elle. Une adresse **partagée** (`100.64.0.0/10`, celle d'un
/// NAT d'opérateur) n'y est pas : ce n'est pas une box du réseau local.
#[must_use]
pub fn locale(adresse: IpAddr) -> bool {
    match adresse.to_canonical() {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local() || v6.is_unique_local(),
    }
}

/// **Une adresse externe qui trahit un second NAT** (décision 97 ; E19) :
/// privée, partagée (`100.64.0.0/10`, RFC 6598 — le NAT de l'opérateur), de
/// lien local, de boucle, ou non spécifiée. Une box dont l'adresse externe est
/// l'une de celles-là n'est pas le dernier NAT.
#[must_use]
pub fn externe_privee(adresse: Ipv4Addr) -> bool {
    let [premier, second, ..] = adresse.octets();
    let partagee = premier == 100 && (second & 0xC0) == 64;
    adresse.is_private()
        || partagee
        || adresse.is_link_local()
        || adresse.is_loopback()
        || adresse.is_unspecified()
}
