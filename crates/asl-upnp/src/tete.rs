//! La tête d'une réponse HTTP/1.x — ligne d'état et champs —, commune à SSDP
//! et à HTTP.
//!
//! **STRICTE** : un champ sans deux-points, un nom vide ou qui porte un blanc,
//! une ligne repliée (l'*obs-fold* que la RFC 9112 §5.2 a retiré) — refusés.
//! Un décodeur tolérant est un décodeur qui lit deux choses différentes selon
//! qui le regarde.

/// Le nombre de champs d'une tête, au plus.
pub const CHAMPS_MAX: usize = 48;

/// Pourquoi une tête ne se lit pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FauteTete {
    /// La ligne d'état n'est pas `HTTP/1.x <code> …`.
    Statut,
    /// Un champ mal formé.
    Champ,
    /// Plus de [`CHAMPS_MAX`] champs.
    TropDeChamps,
    /// Un même champ, deux fois.
    EnDouble,
}

/// Une tête lue.
#[derive(Debug)]
pub struct Tete<'a> {
    /// Le code d'état.
    pub statut: u16,
    /// Les champs, dans l'ordre, noms tels qu'écrits.
    champs: Vec<(&'a str, &'a str)>,
}

impl<'a> Tete<'a> {
    /// Lit une tête — le texte qui précède la ligne vide, sans elle.
    pub fn lire(texte: &'a str) -> Result<Self, FauteTete> {
        let mut lignes = texte
            .split('\n')
            .map(|ligne| ligne.strip_suffix('\r').unwrap_or(ligne));
        let statut = lire_statut(lignes.next().unwrap_or_default())?;
        let mut champs = Vec::new();
        for ligne in lignes {
            if champs.len() >= CHAMPS_MAX {
                return Err(FauteTete::TropDeChamps);
            }
            let (nom, valeur) = ligne.split_once(':').ok_or(FauteTete::Champ)?;
            if nom.is_empty() || !nom.bytes().all(|octet| octet.is_ascii_graphic()) {
                return Err(FauteTete::Champ);
            }
            champs.push((nom, valeur.trim_matches([' ', '\t'])));
        }
        Ok(Self { statut, champs })
    }

    /// La valeur d'un champ, quelle que soit la casse de son nom ; `None`
    /// s'il est absent.
    ///
    /// # Erreurs
    ///
    /// [`FauteTete::EnDouble`] : deux `Content-Length`, deux `LOCATION`, et
    /// l'on ne sait plus lequel croire.
    pub fn champ(&self, nom: &str) -> Result<Option<&'a str>, FauteTete> {
        let mut trouves = self
            .champs
            .iter()
            .filter(|(sien, _)| sien.eq_ignore_ascii_case(nom))
            .map(|(_, valeur)| *valeur);
        let premier = trouves.next();
        if trouves.next().is_some() {
            return Err(FauteTete::EnDouble);
        }
        Ok(premier)
    }
}

/// `HTTP/1.1 200 OK` — la version 1.0 ou 1.1, un code de trois chiffres.
fn lire_statut(ligne: &str) -> Result<u16, FauteTete> {
    let mut morceaux = ligne.splitn(3, ' ');
    let version = morceaux.next().unwrap_or_default();
    if !version.eq_ignore_ascii_case("HTTP/1.1") && !version.eq_ignore_ascii_case("HTTP/1.0") {
        return Err(FauteTete::Statut);
    }
    let code = morceaux.next().unwrap_or_default();
    if code.len() != 3 || !code.bytes().all(|octet| octet.is_ascii_digit()) {
        return Err(FauteTete::Statut);
    }
    match code.parse::<u16>() {
        Ok(code) if (100..=599).contains(&code) => Ok(code),
        _ => Err(FauteTete::Statut),
    }
}
