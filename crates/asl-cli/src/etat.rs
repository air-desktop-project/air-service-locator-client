//! Où vit l'identité de cette machine, et à quelles conditions on la lit.
//!
//! # CE QUI EST POSÉ SUR LA MACHINE, ET CE QUI NE L'EST PAS
//!
//! **Aucun secret partagé** (C14). Ce qui est écrit ici est une paire de clés
//! que cette machine a générée elle-même, et dont la moitié privée n'a jamais
//! quitté ce disque. Le code d'enrôlement, lui, ne sert qu'une fois et n'est pas
//! conservé — il n'ouvre qu'une opération, lier cette clé.
//!
//! # POURQUOI CE MODULE REFUSE DE LIRE CERTAINS FICHIERS
//!
//! Un fichier de clé lisible par le groupe ou par tout le monde n'est plus une
//! clé : c'est une clé partagée avec qui sait s'asseoir sur la machine. Le
//! refuser bruyamment est la seule façon que le porteur l'apprenne — un
//! avertissement dans un journal ne sera pas lu.
//!
//! **Ce module est écrit pour Unix**, et il l'assume : c'est un utilitaire, la
//! cible est Ubuntu, et les permissions POSIX sont précisément ce qu'il vérifie.
//! La bibliothèque, elle, reste portable — elle ne lit aucun fichier.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use asl_client::{Enrolement, Identite};
use asl_id::{Genre, Identifiant};

/// Le nom du fichier qui porte l'identité.
const FICHIER: &str = "identite";

/// Ce qui peut clocher autour de l'état.
#[derive(Debug)]
pub enum Faute {
    /// Le disque a refusé.
    Disque {
        /// Ce qu'on essayait d'atteindre.
        ou: PathBuf,
        /// Ce que le système a dit.
        quoi: std::io::Error,
    },
    /// Le fichier d'identité est lisible par d'autres que son propriétaire.
    TropOuvert {
        /// Le fichier.
        ou: PathBuf,
        /// Le mode qu'il porte.
        mode: u32,
    },
    /// Le fichier d'identité ne se lit pas.
    Illisible {
        /// Le fichier.
        ou: PathBuf,
        /// Ce qui manque ou ne va pas.
        quoi: &'static str,
    },
    /// Cette machine n'est pas enrôlée.
    PasEnrolee {
        /// Là où l'on a cherché.
        ou: PathBuf,
    },
}

impl core::fmt::Display for Faute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Disque { ou, quoi } => write!(f, "{} : {quoi}", ou.display()),
            Self::TropOuvert { ou, mode } => write!(
                f,
                "{} est en {mode:04o} — une clé lisible par d'autres n'est plus une clé.\n\
                 Corrigez avec : chmod 600 {}",
                ou.display(),
                ou.display()
            ),
            Self::Illisible { ou, quoi } => write!(f, "{} : {quoi}", ou.display()),
            Self::PasEnrolee { ou } => write!(
                f,
                "cette machine n'est pas enrôlée ({} n'existe pas).\n\
                 Demandez un code à l'application, puis : asl enrole <code>",
                ou.display()
            ),
        }
    }
}

/// Le répertoire où vit l'identité.
///
/// Dans l'ordre : ce que la ligne de commande dit, puis `ASL_ETAT`, puis
/// `$XDG_CONFIG_HOME/asl`, puis `~/.config/asl`.
#[must_use]
pub fn repertoire(demande: Option<&str>) -> PathBuf {
    if let Some(ou) = demande {
        return PathBuf::from(ou);
    }
    if let Ok(ou) = std::env::var("ASL_ETAT") {
        return PathBuf::from(ou);
    }
    if let Ok(config) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(config).join("asl");
    }
    let maison = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    PathBuf::from(maison).join(".config").join("asl")
}

/// Trente-deux ou seize octets d'entropie, pris au noyau.
///
/// # POURQUOI `/dev/urandom` ET NON UNE CRATE
///
/// C'est le générateur du noyau, celui-là même qu'une crate d'entropie
/// appellerait. Sur la cible — Ubuntu —, il est ensemencé avant qu'un
/// utilisateur puisse taper quoi que ce soit, et il ne bloque pas.
///
/// **La bibliothèque, elle, ne tire rien** : `asl-client` reçoit son entropie de
/// l'appelant, précisément pour ne pas imposer de générateur à un daemon qui
/// vit dans un interpréteur Python. C'est ici, dans un processus à nous, que la
/// question se tranche.
///
/// # Erreurs
///
/// [`Faute::Disque`] si le noyau ne rend pas ses octets. **On n'invente pas de
/// repli** : une clé tirée d'une horloge serait devinable, et toute
/// l'authentification du produit repose là-dessus.
pub fn hasard<const N: usize>() -> Result<[u8; N], Faute> {
    let ou = PathBuf::from("/dev/urandom");
    let mut fichier = fs::File::open(&ou).map_err(|quoi| Faute::Disque {
        ou: ou.clone(),
        quoi,
    })?;
    let mut octets = [0_u8; N];
    fichier
        .read_exact(&mut octets)
        .map_err(|quoi| Faute::Disque { ou, quoi })?;
    Ok(octets)
}

/// Écrit l'identité, et elle seule.
///
/// # LE FICHIER NAÎT EN `0600`, ET NON CORRIGÉ APRÈS COUP
///
/// Entre un `create` permissif et un `chmod` qui suit, il existe un instant où
/// la clé est lisible par tout le monde. Il est court, il suffit, et il ne se
/// reproduit pas — donc personne ne le verrait jamais en essayant.
///
/// # Erreurs
///
/// [`Faute::Disque`].
pub fn ecrire(dossier: &Path, machine: Identifiant, graine: &[u8; 32]) -> Result<(), Faute> {
    fs::create_dir_all(dossier).map_err(|quoi| Faute::Disque {
        ou: dossier.to_path_buf(),
        quoi,
    })?;
    let ou = dossier.join(FICHIER);

    let contenu = format!(
        "# asl — l'identité de cette machine.\n\
         #\n\
         # LA MOITIÉ PRIVÉE D'UNE PAIRE DE CLÉS. Elle n'a jamais quitté ce disque,\n\
         # et elle ne le doit pas : l'annuaire ne connaît que la moitié publique.\n\
         # Ne la copiez pas sur une autre machine — enrôlez-la, c'est gratuit.\n\
         machine = {}\n\
         graine = {}\n",
        machine.texte().as_str(),
        en_hexa(graine)
    );

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    let mut fichier = options.open(&ou).map_err(|quoi| Faute::Disque {
        ou: ou.clone(),
        quoi,
    })?;
    std::io::Write::write_all(&mut fichier, contenu.as_bytes())
        .map_err(|quoi| Faute::Disque { ou, quoi })
}

/// Lit l'identité de cette machine.
///
/// # Erreurs
///
/// [`Faute::PasEnrolee`], [`Faute::TropOuvert`], [`Faute::Illisible`],
/// [`Faute::Disque`].
pub fn lire(dossier: &Path) -> Result<Identite, Faute> {
    let ou = dossier.join(FICHIER);
    if !ou.exists() {
        return Err(Faute::PasEnrolee { ou });
    }

    let details = fs::metadata(&ou).map_err(|quoi| Faute::Disque {
        ou: ou.clone(),
        quoi,
    })?;
    // **LE GROUPE ET LES AUTRES N'ONT RIEN À Y VOIR.**
    let mode = details.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Faute::TropOuvert { ou, mode });
    }

    let contenu = fs::read_to_string(&ou).map_err(|quoi| Faute::Disque {
        ou: ou.clone(),
        quoi,
    })?;
    let mut machine = None;
    let mut graine = None;
    for ligne in contenu.lines() {
        let ligne = ligne.trim();
        if ligne.is_empty() || ligne.starts_with('#') {
            continue;
        }
        let Some((clef, valeur)) = ligne.split_once('=') else {
            continue;
        };
        match clef.trim() {
            "machine" => machine = Some(valeur.trim().to_owned()),
            "graine" => graine = Some(valeur.trim().to_owned()),
            _ => {}
        }
    }

    let machine = machine.ok_or_else(|| Faute::Illisible {
        ou: ou.clone(),
        quoi: "il manque la ligne `machine =`",
    })?;
    let machine =
        Identifiant::analyser_genre(Genre::Machine, &machine).map_err(|_| Faute::Illisible {
            ou: ou.clone(),
            quoi: "la ligne `machine =` ne porte pas l'identifiant d'une machine",
        })?;

    let graine = graine.ok_or_else(|| Faute::Illisible {
        ou: ou.clone(),
        quoi: "il manque la ligne `graine =`",
    })?;
    let graine = depuis_hexa(&graine).ok_or_else(|| Faute::Illisible {
        ou: ou.clone(),
        quoi: "la ligne `graine =` n'est pas trente-deux octets en hexadécimal",
    })?;

    // **LA CLÉ EST DÉRIVÉE, ET NON STOCKÉE.** La graine est ce qu'`asl-client`
    // demande ; en garder aussi la clé dérivée ferait deux copies du même
    // secret, dont une que rien ne vérifie.
    Identite::nouvelle(machine, graine).map_err(|_| Faute::Illisible {
        ou,
        quoi: "l'identifiant n'est pas celui d'une machine",
    })
}

/// Un enrôlement neuf, et la graine qu'il faudra écrire s'il aboutit.
///
/// **LA GRAINE EST RENDUE À PART**, parce que l'enrôlement ne la redonne pas :
/// il en dérive une clé et la garde. Elle n'est écrite sur le disque qu'une fois
/// l'annuaire d'accord — sans quoi une machine refusée laisserait derrière elle
/// une identité que personne ne reconnaît.
///
/// # Erreurs
///
/// [`Faute::Disque`] si le noyau ne rend pas d'entropie.
pub fn preparer_un_enrolement() -> Result<(Enrolement, [u8; 32]), Faute> {
    let graine = hasard::<32>()?;
    Ok((Enrolement::nouveau(graine), graine))
}

/// Des octets en hexadécimal minuscule.
fn en_hexa(octets: &[u8]) -> String {
    let mut texte = String::with_capacity(octets.len().saturating_mul(2));
    for octet in octets {
        texte.push_str(&format!("{octet:02x}"));
    }
    texte
}

/// Trente-deux octets depuis de l'hexadécimal, ou rien.
fn depuis_hexa(texte: &str) -> Option<[u8; 32]> {
    let brut = texte.as_bytes();
    if brut.len() != 64 {
        return None;
    }
    let mut octets = [0_u8; 32];
    let (paires, _) = brut.as_chunks::<2>();
    for (place, paire) in octets.iter_mut().zip(paires) {
        let haut = chiffre(*paire.first()?)?;
        let bas = chiffre(*paire.get(1)?)?;
        *place = haut.checked_mul(16)?.checked_add(bas)?;
    }
    Some(octets)
}

/// Un chiffre hexadécimal, ou rien.
const fn chiffre(caractere: u8) -> Option<u8> {
    match caractere {
        b'0'..=b'9' => Some(caractere.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(caractere.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(caractere.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

#[cfg(test)]
mod essais {
    use super::*;

    #[test]
    fn l_hexadecimal_fait_l_aller_et_le_retour() {
        let graine = [0x5A_u8; 32];
        let texte = en_hexa(&graine);
        assert_eq!(texte.len(), 64);
        assert_eq!(depuis_hexa(&texte), Some(graine));

        // La casse haute se lit aussi — un humain a pu recopier le fichier.
        assert_eq!(depuis_hexa(&texte.to_uppercase()), Some(graine));
    }

    #[test]
    fn ce_qui_n_est_pas_trente_deux_octets_est_refuse() {
        for quoi in [
            "",
            "5a",
            &"5a".repeat(31),
            &"5a".repeat(33),
            &"zz".repeat(32),
        ] {
            assert_eq!(depuis_hexa(quoi), None, "{quoi}");
        }
    }

    #[test]
    fn le_repertoire_suit_l_ordre_annonce() {
        // La ligne de commande passe avant tout le reste.
        assert_eq!(repertoire(Some("/tmp/ici")), PathBuf::from("/tmp/ici"));
    }

    #[test]
    fn le_hasard_vient_du_noyau_et_n_est_pas_constant() {
        let une = hasard::<32>().expect("`/dev/urandom` est requis");
        let autre = hasard::<32>().expect("`/dev/urandom` est requis");
        assert_ne!(
            une, autre,
            "deux tirages identiques : ce n'est pas du hasard"
        );
        assert_ne!(une, [0_u8; 32]);
    }
}
