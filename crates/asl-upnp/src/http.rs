//! HTTP/1.1, **le minimum** : une requête `GET` pour la description, une
//! requête `POST` pour SOAP, et la lecture bornée d'une réponse.
//!
//! # TROIS FAÇONS DE FINIR UN CORPS, ET PAS UNE DE PLUS
//!
//! La spécification visait « `Content-Length` seul, pas de `chunked` ». Une
//! box qui répond en HTTP/1.1 a pourtant le droit de découper son corps, et
//! la seule façon de le lui interdire serait de parler HTTP/1.0 — ce que des
//! piles UPnP refusent. Le découpage se lit donc ici, borné et fuzzé comme le
//! reste :
//!
//! - **`Content-Length`** : tant d'octets, pas un de plus ;
//! - **`Transfer-Encoding: chunked`** : des morceaux, jusqu'au morceau nul ;
//! - **ni l'un ni l'autre** : jusqu'à la fermeture — la requête dit
//!   `Connection: close`.
//!
//! **Les deux à la fois sont refusés** (RFC 9112 §6.3) : c'est la forme même
//! d'une contrebande de requête, et une box honnête ne l'écrit pas. Tout autre
//! codage aussi.
//!
//! # LA BORNE
//!
//! [`REPONSE_MAX`] en tout : une description d'IGD fait quelques kilo-octets,
//! une réponse SOAP quelques centaines d'octets. Au-delà, ce n'est pas une
//! box qui parle.

use crate::tete::{FauteTete, Tete};
use crate::url::Url;

/// La taille d'une réponse, tête et corps, au plus.
pub const REPONSE_MAX: usize = 131_072;

/// La taille d'une tête, au plus.
pub const TETE_MAX: usize = 8_192;

/// Ce que la requête dit d'elle : le client, pour le journal de la box.
const AGENT: &str = "asl-echo UPnP/2.0";

/// La requête `GET` de la description.
#[must_use]
pub fn get(url: &Url) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {AGENT}\r\nConnection: close\r\n\r\n",
        url.chemin,
        url.hote_http()
    )
    .into_bytes()
}

/// La requête `POST` d'une action SOAP : `service` est l'URN du service,
/// `action` son nom, `enveloppe` le corps que [`crate::soap::enveloppe`] a
/// écrit.
#[must_use]
pub fn soap(url: &Url, service: &str, action: &str, enveloppe: &str) -> Vec<u8> {
    let mut requete = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {AGENT}\r\nConnection: close\r\n\
         Content-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{service}#{action}\"\r\n\
         Content-Length: {}\r\n\r\n",
        url.chemin,
        url.hote_http(),
        enveloppe.len()
    );
    requete.push_str(enveloppe);
    requete.into_bytes()
}

/// Une réponse complète.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reponse {
    /// Le code d'état.
    pub statut: u16,
    /// Le corps, décodé de ses morceaux s'il l'était.
    pub corps: Vec<u8>,
}

/// Où en est la lecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lu {
    /// Il manque des octets : en lire d'autres.
    Incomplet,
    /// La réponse est là.
    Complet(Reponse),
}

/// Pourquoi une réponse ne se lit pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FauteHttp {
    /// Plus de [`REPONSE_MAX`] octets, ou une tête de plus de [`TETE_MAX`].
    TropLong,
    /// La tête n'est pas du texte.
    PasDuTexte,
    /// La tête ne se lit pas.
    Tete(FauteTete),
    /// Un `Content-Length` illisible, ou avec `Transfer-Encoding`.
    Longueur,
    /// Un `Transfer-Encoding` autre que `chunked`.
    Codage,
    /// Un morceau mal formé.
    Morceau,
    /// La connexion s'est fermée avant la fin annoncée — après avoir envoyé
    /// quelque chose.
    Tronquee,
    /// La connexion s'est fermée **sans un octet** : la box a accepté la
    /// connexion et n'a rien répondu. Vu sur une Livebox (SoftAtHome), qui
    /// annonce une description en IPv6 et ne la sert pas (`curl` : « Empty
    /// reply from server »). Ce n'est pas une réponse coupée : il n'y en a
    /// pas eu.
    Vide,
}

/// Lit ce qui est arrivé jusqu'ici ; `fin` dit que la connexion est fermée,
/// et qu'il n'en viendra pas plus.
///
/// # Erreurs
///
/// Voir [`FauteHttp`].
pub fn lire(octets: &[u8], fin: bool) -> Result<Lu, FauteHttp> {
    if fin && octets.is_empty() {
        return Err(FauteHttp::Vide);
    }
    if octets.len() > REPONSE_MAX {
        return Err(FauteHttp::TropLong);
    }
    let Some(borne) = chercher(octets, b"\r\n\r\n") else {
        if octets.len() > TETE_MAX {
            return Err(FauteHttp::TropLong);
        }
        return incomplet(fin);
    };
    let (tete, reste) = octets.split_at(borne);
    let reste = reste.get(4..).unwrap_or_default();
    if tete.len() > TETE_MAX {
        return Err(FauteHttp::TropLong);
    }
    let tete = core::str::from_utf8(tete).map_err(|_| FauteHttp::PasDuTexte)?;
    let tete = Tete::lire(tete).map_err(FauteHttp::Tete)?;
    let longueur = tete.champ("Content-Length").map_err(FauteHttp::Tete)?;
    let codage = tete.champ("Transfer-Encoding").map_err(FauteHttp::Tete)?;
    let corps = match (longueur, codage) {
        (Some(_), Some(_)) => return Err(FauteHttp::Longueur),
        (Some(longueur), None) => {
            let attendu = nombre_decimal(longueur).ok_or(FauteHttp::Longueur)?;
            match reste.get(..attendu) {
                Some(corps) => corps.to_vec(),
                None => return incomplet(fin),
            }
        }
        (None, Some(codage)) if codage.eq_ignore_ascii_case("chunked") => match morceaux(reste)? {
            Some(corps) => corps,
            None => return incomplet(fin),
        },
        (None, Some(_)) => return Err(FauteHttp::Codage),
        (None, None) if fin => reste.to_vec(),
        (None, None) => return Ok(Lu::Incomplet),
    };
    Ok(Lu::Complet(Reponse {
        statut: tete.statut,
        corps,
    }))
}

/// Il manque des octets : on attend, sauf si la connexion est fermée.
const fn incomplet(fin: bool) -> Result<Lu, FauteHttp> {
    if fin {
        Err(FauteHttp::Tronquee)
    } else {
        Ok(Lu::Incomplet)
    }
}

/// Où `motif` commence dans `octets`.
fn chercher(octets: &[u8], motif: &[u8]) -> Option<usize> {
    octets
        .windows(motif.len())
        .position(|fenetre| fenetre == motif)
}

/// Un nombre décimal d'au plus sept chiffres, et au plus [`REPONSE_MAX`].
fn nombre_decimal(texte: &str) -> Option<usize> {
    if texte.is_empty() || texte.len() > 7 || !texte.bytes().all(|octet| octet.is_ascii_digit()) {
        return None;
    }
    texte
        .parse::<usize>()
        .ok()
        .filter(|&nombre| nombre <= REPONSE_MAX)
}

/// Décode un corps découpé ; `None` s'il n'est pas encore entier.
///
/// Chaque morceau : sa taille en hexadécimal (une extension après `;` est
/// ignorée), `\r\n`, les octets, `\r\n`. Le morceau nul clôt, suivi de champs
/// de queue éventuels et d'une ligne vide — lus jusqu'à elle, et ignorés.
fn morceaux(mut reste: &[u8]) -> Result<Option<Vec<u8>>, FauteHttp> {
    let mut corps = Vec::new();
    loop {
        let Some(fin_de_ligne) = chercher(reste, b"\r\n") else {
            return Ok(None);
        };
        let (ligne, apres) = reste.split_at(fin_de_ligne);
        let apres = apres.get(2..).unwrap_or_default();
        let taille = taille_de_morceau(ligne)?;
        if taille == 0 {
            // Les champs de queue, jusqu'à la ligne vide.
            let mut queue = apres;
            loop {
                let Some(fin) = chercher(queue, b"\r\n") else {
                    return Ok(None);
                };
                if fin == 0 {
                    return Ok(Some(corps));
                }
                queue = queue.get(fin.saturating_add(2)..).unwrap_or_default();
            }
        }
        if corps.len().saturating_add(taille) > REPONSE_MAX {
            return Err(FauteHttp::TropLong);
        }
        let Some(donnees) = apres.get(..taille) else {
            return Ok(None);
        };
        let suite = apres.get(taille..).unwrap_or_default();
        match suite.get(..2) {
            Some(b"\r\n") => {}
            Some(_) => return Err(FauteHttp::Morceau),
            None => return Ok(None),
        }
        corps.extend_from_slice(donnees);
        reste = suite.get(2..).unwrap_or_default();
    }
}

/// `1a3f` ou `1a3f;nom=valeur` : au plus six chiffres hexadécimaux.
fn taille_de_morceau(ligne: &[u8]) -> Result<usize, FauteHttp> {
    let chiffres = ligne
        .split(|&octet| octet == b';')
        .next()
        .unwrap_or_default();
    let chiffres = chiffres.trim_ascii();
    // `from_str_radix` admet un `+` : on ne le veut pas.
    if chiffres.is_empty() || chiffres.len() > 6 || chiffres.first() == Some(&b'+') {
        return Err(FauteHttp::Morceau);
    }
    let texte = core::str::from_utf8(chiffres).map_err(|_| FauteHttp::Morceau)?;
    usize::from_str_radix(texte, 16).map_err(|_| FauteHttp::Morceau)
}
