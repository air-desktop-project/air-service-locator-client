//! Un lecteur XML **réduit à ce que la description d'un IGD et les réponses
//! SOAP portent** : des éléments, du texte, et c'est tout.
//!
//! # CE QU'IL LIT
//!
//! Des balises ouvrantes (leurs attributs sont lus, pour être sautés
//! correctement, puis oubliés), fermantes, vides (`<a/>`) ; du texte, avec les
//! cinq entités prédéfinies et les références numériques ; les sections
//! `CDATA` ; et il saute la déclaration `<?xml …?>`, les instructions et les
//! commentaires. Les noms sont rendus **sans leur préfixe** (`s:Envelope`
//! devient `Envelope`) : les box ne s'accordent pas sur le leur, et le
//! document ne se lit que par noms locaux.
//!
//! # CE QU'IL REFUSE, ET POURQUOI
//!
//! - **toute déclaration `<!DOCTYPE`** : c'est par elle qu'entrent les entités
//!   qui se multiplient (le « milliard de rires ») et celles qui vont lire un
//!   fichier ; un IGD n'en a pas besoin ;
//! - **une entité inconnue**, un `&` nu ;
//! - **une balise fermante qui ne ferme pas la dernière ouverte** ;
//! - **plus de [`PROFONDEUR_MAX`] niveaux**, plus de [`ATTRIBUTS_MAX`]
//!   attributs sur une balise — des bornes, pour qu'aucune entrée ne coûte plus
//!   que sa taille ;
//! - **du texte ou une seconde racine hors de la racine** ;
//! - un document qui s'arrête avant d'avoir fermé ce qu'il a ouvert.
//!
//! La taille, elle, est bornée plus haut : ce que [`crate::http`] laisse
//! passer.

use core::fmt;

/// La profondeur d'imbrication, au plus. Une description d'IGD descend à
/// sept ou huit niveaux (`root`, `device`, `deviceList`, `device`, …).
pub const PROFONDEUR_MAX: usize = 24;

/// Les attributs d'une balise, au plus.
pub const ATTRIBUTS_MAX: usize = 32;

/// Ce que le lecteur rencontre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evenement<'a> {
    /// Une balise ouvrante (ou vide) : son nom local.
    Ouvre(&'a str),
    /// Une balise fermante (ou la fin d'une vide) : son nom local.
    Ferme(&'a str),
    /// Du texte, entités résolues — jamais fait que de blancs.
    Texte(String),
}

/// Pourquoi un document ne se lit pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FauteXml {
    /// Pas du texte UTF-8.
    PasDuTexte,
    /// Une balise mal formée.
    Balise,
    /// Plus de [`PROFONDEUR_MAX`] niveaux.
    Profondeur,
    /// Plus de [`ATTRIBUTS_MAX`] attributs.
    TropDAttributs,
    /// Une fermante qui ne ferme pas la dernière ouverte.
    Desequilibre,
    /// Une entité inconnue, ou un `&` nu.
    Entite,
    /// Une déclaration `<!DOCTYPE` ou `<!…` : refusée.
    Doctype,
    /// Du texte, ou une seconde racine, hors de la racine.
    HorsRacine,
    /// Le document s'arrête au milieu, ou n'a pas de racine.
    Fin,
}

impl fmt::Display for FauteXml {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PasDuTexte => "un XML qui n'est pas de l'UTF-8",
            Self::Balise => "une balise mal formée",
            Self::Profondeur => "un XML trop profond",
            Self::TropDAttributs => "une balise qui porte trop d'attributs",
            Self::Desequilibre => "une balise fermante qui ne ferme pas la dernière ouverte",
            Self::Entite => "une entité inconnue",
            Self::Doctype => "une déclaration <!DOCTYPE>, refusée",
            Self::HorsRacine => "du contenu hors de l'élément racine",
            Self::Fin => "un XML inachevé",
        })
    }
}

/// Le lecteur : un événement à la fois.
#[derive(Debug)]
pub struct Lecteur<'a> {
    /// Le document.
    texte: &'a str,
    /// Où l'on en est, en octets.
    position: usize,
    /// Les balises ouvertes, noms entiers — une fermante doit porter le même.
    pile: Vec<&'a str>,
    /// La racine a été fermée : plus rien que des blancs, des commentaires et
    /// des instructions.
    racine_close: bool,
    /// Une balise vide vient d'être rendue ouverte : sa fermeture suit.
    a_fermer: Option<&'a str>,
}

impl<'a> Lecteur<'a> {
    /// Un lecteur pour ces octets — une marque d'ordre des octets en tête est
    /// sautée.
    ///
    /// # Erreurs
    ///
    /// [`FauteXml::PasDuTexte`].
    pub fn nouveau(octets: &'a [u8]) -> Result<Self, FauteXml> {
        let texte = core::str::from_utf8(octets).map_err(|_| FauteXml::PasDuTexte)?;
        Ok(Self {
            texte: texte.strip_prefix('\u{feff}').unwrap_or(texte),
            position: 0,
            pile: Vec::new(),
            racine_close: false,
            a_fermer: None,
        })
    }

    /// L'événement suivant ; `None` à la fin d'un document bien formé.
    ///
    /// # Erreurs
    ///
    /// Voir [`FauteXml`].
    pub fn suivant(&mut self) -> Result<Option<Evenement<'a>>, FauteXml> {
        if let Some(nom) = self.a_fermer.take() {
            return Ok(Some(Evenement::Ferme(local(nom))));
        }
        loop {
            // `position` ne s'arrête jamais qu'après un caractère ASCII lu :
            // c'est une frontière de caractère.
            let reste = self.texte.get(self.position..).unwrap_or_default();
            if reste.is_empty() {
                return if self.racine_close {
                    Ok(None)
                } else {
                    Err(FauteXml::Fin)
                };
            }
            if !reste.starts_with('<') {
                let fin = reste.find('<').unwrap_or(reste.len());
                let brut = &reste[..fin];
                self.avancer(fin);
                if brut.trim().is_empty() {
                    continue;
                }
                if self.pile.is_empty() {
                    return Err(FauteXml::HorsRacine);
                }
                return Ok(Some(Evenement::Texte(decoder(brut)?)));
            }
            if let Some(apres) = reste.strip_prefix("<?") {
                let fin = apres.find("?>").ok_or(FauteXml::Fin)?;
                self.avancer(fin.saturating_add(4));
                continue;
            }
            if let Some(apres) = reste.strip_prefix("<!--") {
                let fin = apres.find("-->").ok_or(FauteXml::Fin)?;
                self.avancer(fin.saturating_add(7));
                continue;
            }
            if let Some(apres) = reste.strip_prefix("<![CDATA[") {
                let fin = apres.find("]]>").ok_or(FauteXml::Fin)?;
                let brut = &apres[..fin];
                self.avancer(fin.saturating_add(12));
                if self.pile.is_empty() {
                    return Err(FauteXml::HorsRacine);
                }
                if brut.trim().is_empty() {
                    continue;
                }
                return Ok(Some(Evenement::Texte(brut.to_owned())));
            }
            if reste.starts_with("<!") {
                return Err(FauteXml::Doctype);
            }
            if let Some(apres) = reste.strip_prefix("</") {
                return self.fermante(apres).map(Some);
            }
            return self.ouvrante(&reste[1..]).map(Some);
        }
    }

    /// Avance de `combien` octets.
    const fn avancer(&mut self, combien: usize) {
        self.position = self.position.saturating_add(combien);
    }

    /// `</nom>` — `apres` commence après `</`.
    fn fermante(&mut self, apres: &'a str) -> Result<Evenement<'a>, FauteXml> {
        let nom = nom_en_tete(apres)?;
        let suite = &apres[nom.len()..];
        let blancs = suite.len().saturating_sub(suite.trim_start().len());
        if !suite.trim_start().starts_with('>') {
            return Err(FauteXml::Balise);
        }
        if self.pile.pop() != Some(nom) {
            return Err(FauteXml::Desequilibre);
        }
        if self.pile.is_empty() {
            self.racine_close = true;
        }
        // `</` + nom + blancs + `>`
        self.avancer(nom.len().saturating_add(blancs).saturating_add(3));
        Ok(Evenement::Ferme(local(nom)))
    }

    /// `<nom attr="v" …>` ou `<nom …/>` — `apres` commence après `<`.
    fn ouvrante(&mut self, apres: &'a str) -> Result<Evenement<'a>, FauteXml> {
        if self.racine_close {
            return Err(FauteXml::HorsRacine);
        }
        let nom = nom_en_tete(apres)?;
        if self.pile.len() >= PROFONDEUR_MAX {
            return Err(FauteXml::Profondeur);
        }
        let mut suite = &apres[nom.len()..];
        let mut attributs = 0_usize;
        loop {
            let sans_blancs = suite.trim_start();
            let a_des_blancs = sans_blancs.len() < suite.len();
            suite = sans_blancs;
            if let Some(reste) = suite.strip_prefix('>') {
                self.pile.push(nom);
                self.avancer(apres.len().saturating_sub(reste.len()).saturating_add(1));
                return Ok(Evenement::Ouvre(local(nom)));
            }
            if let Some(reste) = suite.strip_prefix("/>") {
                if self.pile.is_empty() {
                    self.racine_close = true;
                }
                self.a_fermer = Some(nom);
                self.avancer(apres.len().saturating_sub(reste.len()).saturating_add(1));
                return Ok(Evenement::Ouvre(local(nom)));
            }
            // Un attribut, précédé d'un blanc : `nom = "valeur"`.
            if suite.is_empty() {
                return Err(FauteXml::Fin);
            }
            if !a_des_blancs {
                return Err(FauteXml::Balise);
            }
            attributs = attributs.saturating_add(1);
            if attributs > ATTRIBUTS_MAX {
                return Err(FauteXml::TropDAttributs);
            }
            let nom_attribut = nom_en_tete(suite)?;
            let apres_nom = suite[nom_attribut.len()..].trim_start();
            let valeur = apres_nom
                .strip_prefix('=')
                .ok_or(FauteXml::Balise)?
                .trim_start();
            let guillemet = match valeur.chars().next() {
                Some(guillemet @ ('"' | '\'')) => guillemet,
                _ => return Err(FauteXml::Balise),
            };
            let dedans = &valeur[1..];
            let fin = dedans.find(guillemet).ok_or(FauteXml::Fin)?;
            if dedans[..fin].contains('<') {
                return Err(FauteXml::Balise);
            }
            suite = &dedans[fin.saturating_add(1)..];
        }
    }
}

/// Le nom qui commence `texte` : une lettre, `_` ou `:`, puis des lettres,
/// chiffres, `_`, `:`, `.`, `-`. ASCII seulement : un IGD ne nomme rien
/// autrement.
fn nom_en_tete(texte: &str) -> Result<&str, FauteXml> {
    let longueur = texte
        .bytes()
        .enumerate()
        .take_while(|&(rang, octet)| {
            octet.is_ascii_alphabetic()
                || octet == b'_'
                || octet == b':'
                || (rang > 0 && (octet.is_ascii_digit() || octet == b'.' || octet == b'-'))
        })
        .count();
    if longueur == 0 {
        return Err(FauteXml::Balise);
    }
    Ok(&texte[..longueur])
}

/// Le nom sans son préfixe : `s:Envelope` → `Envelope`.
fn local(nom: &str) -> &str {
    nom.rsplit(':').next().unwrap_or(nom)
}

/// Résout les entités d'un texte.
fn decoder(brut: &str) -> Result<String, FauteXml> {
    let mut sortie = String::with_capacity(brut.len());
    let mut reste = brut;
    while let Some(esperluette) = reste.find('&') {
        sortie.push_str(&reste[..esperluette]);
        let apres = &reste[esperluette.saturating_add(1)..];
        let fin = apres.find(';').ok_or(FauteXml::Entite)?;
        let caractere = match &apres[..fin] {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            numerique => reference(numerique)?,
        };
        sortie.push(caractere);
        reste = &apres[fin.saturating_add(1)..];
    }
    sortie.push_str(reste);
    Ok(sortie)
}

/// `#65` ou `#x41` : un caractère, jamais le caractère nul.
fn reference(nom: &str) -> Result<char, FauteXml> {
    let (chiffres, base) = match nom.strip_prefix("#x").or_else(|| nom.strip_prefix("#X")) {
        Some(hexa) => (hexa, 16),
        None => (nom.strip_prefix('#').ok_or(FauteXml::Entite)?, 10),
    };
    // `from_str_radix` admet un `+` : on ne le veut pas.
    if chiffres.is_empty() || chiffres.len() > 8 || chiffres.starts_with('+') {
        return Err(FauteXml::Entite);
    }
    let valeur = u32::from_str_radix(chiffres, base).map_err(|_| FauteXml::Entite)?;
    char::from_u32(valeur)
        .filter(|&caractere| caractere != '\0')
        .ok_or(FauteXml::Entite)
}
