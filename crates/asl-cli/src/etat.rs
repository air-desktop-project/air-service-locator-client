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
                 Demandez un code à l'application, puis : asl enroll <code>",
                ou.display()
            ),
        }
    }
}

/// Le conteneur de groupe de l'application Service Locator et de son agent,
/// relatif au répertoire du compte (`protocole.md`, décision 93, E11 révisé).
const GROUPE: &str = "Library/Group Containers/SB7H9B6TY8.org.airdesktop.servicelocator/Library/Application Support/asl";

/// L'ancien conteneur de l'application, d'avant le bac à sable partagé : ce
/// qu'elle migre au premier lancement, et qu'on lit en attendant.
const ANCIEN_CONTENEUR: &str =
    "Library/Containers/org.airdesktop.servicelocator.mac/Data/Library/Application Support/asl";

/// D'où vient le répertoire d'état — ce que `asl identity` et `asl diagnose`
/// disent, parce qu'une identité dont on ignore la provenance ne se départage
/// pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origine {
    /// `--state`.
    Option,
    /// `ASL_STATE`.
    Environnement,
    /// Le conteneur de groupe de l'application (macOS).
    Groupe,
    /// L'ancien conteneur de l'application (macOS), en attendant sa migration.
    AncienConteneur,
    /// `$XDG_CONFIG_HOME/asl`, sinon `~/.config/asl`.
    Utilisateur,
}

impl Origine {
    /// Ce qu'on en dit, en une ligne.
    #[must_use]
    pub const fn dire(self) -> &'static str {
        match self {
            Self::Option => "--state",
            Self::Environnement => "ASL_STATE",
            Self::Groupe => "le conteneur de groupe de l'application Service Locator",
            Self::AncienConteneur => {
                "l'ancien conteneur de l'application Service Locator (à migrer)"
            }
            Self::Utilisateur => {
                "le répertoire de l'utilisateur ($XDG_CONFIG_HOME/asl, sinon ~/.config/asl)"
            }
        }
    }
}

/// Le répertoire d'état retenu, d'où il vient, et ce qu'il faut en dire.
#[derive(Debug)]
pub struct Etat {
    /// Le répertoire : l'identité, et à côté le cache des racines.
    pub dossier: PathBuf,
    /// D'où il vient.
    pub origine: Origine,
    /// Ce qu'on dit sur la sortie d'erreur, une ligne chacun, à chaque
    /// commande : l'ancien conteneur lu, deux identités qui se contredisent.
    pub avertissements: Vec<String>,
}

/// Le répertoire où vit l'identité — et le cache des racines, qui la suit.
///
/// Voir [`chercher`] pour l'ordre, et pourquoi il change sur macOS.
#[must_use]
pub fn repertoire(demande: Option<&str>) -> PathBuf {
    chercher(demande).dossier
}

/// Cherche le répertoire d'état, dans l'ordre du protocole.
///
/// **Partout** : ce que la ligne de commande dit (`--state`), puis
/// `ASL_STATE` — pris **tels quels, sans aucune recherche ni repli**. Puis :
///
/// - **sur Linux**, `$XDG_CONFIG_HOME/asl`, sinon `~/.config/asl` ;
/// - **sur macOS** (décision 93, E11 révisé), le premier qui porte une
///   `identite` parmi : le conteneur de groupe de l'application
///   (`~/Library/Group Containers/SB7H9B6TY8.org.airdesktop.servicelocator/
///   Library/Application Support/asl/`), l'ancien conteneur de l'application
///   (`~/Library/Containers/org.airdesktop.servicelocator.mac/Data/Library/
///   Application Support/asl/`, avec un avertissement), puis
///   `$XDG_CONFIG_HOME/asl`, sinon `~/.config/asl` — qui est aussi le
///   répertoire rendu quand aucun ne porte d'identité, et donc celui où
///   `asl enroll` écrit.
///
/// # POURQUOI L'APPLICATION PASSE AVANT `~/.config/asl`, SUR MAC
///
/// Sur un Mac, c'est l'application qui enrôle la machine — « Faire de ce Mac
/// une machine », sous Touch ID — et son agent `asl-echo` lit cette identité
/// depuis leur conteneur de groupe commun : elle **est** l'identité de la
/// machine. Un `~/.config/asl` qui en porterait une autre ne l'emporte plus,
/// mais il n'est pas tu : deux identités différentes sont dites à chaque
/// commande, sur la sortie d'erreur, plutôt que d'en ignorer une en silence.
#[must_use]
pub fn chercher(demande: Option<&str>) -> Etat {
    resoudre(
        demande,
        std::env::var("ASL_STATE").ok().as_deref(),
        std::env::var("XDG_CONFIG_HOME").ok().as_deref(),
        &maison(),
        cfg!(target_os = "macos"),
    )
}

/// Le répertoire du compte.
///
/// # SUR MACOS, JAMAIS LE CONTENEUR D'UN BAC À SABLE
///
/// Dans un bac à sable, `HOME` désigne le conteneur propre du processus
/// (`~/Library/Containers/<identifiant>/Data`), et les chemins du protocole
/// sont relatifs au répertoire du COMPTE. `asl` n'est pas en bac à sable ;
/// mais le jour où son code tourne dans l'agent de l'application, un `HOME`
/// de conteneur ferait chercher l'identité dans un dossier qui ne la porte
/// jamais. On remonte donc d'un tel conteneur jusqu'au compte.
///
/// **Pourquoi pas `getpwuid` directement** : ce binaire interdit `unsafe`, et
/// n'a pas de liaison au système. `std::env::home_dir` le fait pour nous quand
/// `HOME` manque ; quand `HOME` est là, c'est lui — et le conteneur s'y
/// reconnaît à sa forme.
///
/// **Sur Linux, rien ne change** : `HOME`, sinon le répertoire courant.
fn maison() -> PathBuf {
    if cfg!(target_os = "macos") {
        hors_du_bac_a_sable(&std::env::home_dir().unwrap_or_else(|| PathBuf::from(".")))
    } else {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_owned()))
    }
}

/// `…/Library/Containers/<identifiant>/Data` → `…` ; tout autre chemin, tel
/// quel.
fn hors_du_bac_a_sable(maison: &Path) -> PathBuf {
    let parties: Vec<_> = maison.components().collect();
    if let [debut @ .., bibliotheque, conteneurs, _, donnees] = parties.as_slice()
        && bibliotheque.as_os_str() == "Library"
        && conteneurs.as_os_str() == "Containers"
        && donnees.as_os_str() == "Data"
        && !debut.is_empty()
    {
        return debut.iter().collect();
    }
    maison.to_path_buf()
}

/// La règle de [`chercher`], sur ce qu'on lui donne — la maison **et** la
/// plate-forme —, pour qu'un essai l'éprouve partout, sur une maison à lui,
/// sans toucher à l'environnement du processus ni au vrai `HOME`.
fn resoudre(
    demande: Option<&str>,
    etat: Option<&str>,
    xdg: Option<&str>,
    maison: &Path,
    macos: bool,
) -> Etat {
    let tel_quel = |dossier: &str, origine| Etat {
        dossier: PathBuf::from(dossier),
        origine,
        avertissements: Vec::new(),
    };
    if let Some(ou) = demande {
        return tel_quel(ou, Origine::Option);
    }
    if let Some(ou) = etat {
        return tel_quel(ou, Origine::Environnement);
    }
    let utilisateur = xdg.map_or_else(
        || maison.join(".config").join("asl"),
        |config| PathBuf::from(config).join("asl"),
    );
    if !macos {
        return Etat {
            dossier: utilisateur,
            origine: Origine::Utilisateur,
            avertissements: Vec::new(),
        };
    }

    let candidats = [
        (Origine::Groupe, maison.join(GROUPE)),
        (Origine::AncienConteneur, maison.join(ANCIEN_CONTENEUR)),
        (Origine::Utilisateur, utilisateur),
    ];
    let (origine, dossier) = candidats
        .iter()
        .find(|(_, dossier)| dossier.join(FICHIER).exists())
        .or_else(|| candidats.last())
        .cloned()
        .unwrap_or((Origine::Utilisateur, PathBuf::from(".")));

    let mut avertissements = Vec::new();
    if origine == Origine::AncienConteneur {
        avertissements.push(format!(
            "identité lue dans l'ancien conteneur de l'application ({}) — la migration \
             n'a pas eu lieu ; lancez l'application Service Locator pour la faire.",
            dossier.display()
        ));
    }

    // **DEUX IDENTITÉS QUI SE CONTREDISENT SE DISENT, TOUJOURS.** On compare
    // les machines que nomment les fichiers présents ; deux copies de la même
    // (une migration interrompue) ne disent rien de plus que l'avertissement
    // ci-dessus.
    let machines: Vec<(PathBuf, String)> = candidats
        .iter()
        .filter_map(|(_, ou)| machine_nommee(ou).map(|machine| (ou.clone(), machine)))
        .collect();
    let retenue = machines
        .iter()
        .find(|(ou, _)| *ou == dossier)
        .map(|(_, machine)| machine.clone());
    if machines
        .iter()
        .any(|(_, machine)| Some(machine) != retenue.as_ref())
    {
        let autres: Vec<String> = machines
            .iter()
            .filter(|(ou, machine)| *ou != dossier && Some(machine) != retenue.as_ref())
            .map(|(ou, machine)| format!("{machine} dans {}", ou.display()))
            .collect();
        avertissements.push(format!(
            "identités de machine différentes : {} dans {} est retenue ; ignorée : {} — \
             seul vous pouvez les départager.",
            retenue.as_deref().unwrap_or("une identité illisible"),
            dossier.display(),
            autres.join(" ; ")
        ));
    }

    Etat {
        dossier,
        origine,
        avertissements,
    }
}

/// La machine que nomme le fichier d'identité d'un dossier, s'il existe et se
/// lit — **sans rien vérifier d'autre** : on compare, on ne s'authentifie pas.
fn machine_nommee(dossier: &Path) -> Option<String> {
    let contenu = fs::read_to_string(dossier.join(FICHIER)).ok()?;
    contenu.lines().find_map(|ligne| {
        let (clef, valeur) = ligne.trim().split_once('=')?;
        (clef.trim() == "machine").then(|| valeur.trim().to_owned())
    })
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
pub fn ecrire(
    dossier: &Path,
    machine: Identifiant,
    compte: Option<Identifiant>,
    graine: &[u8; 32],
) -> Result<(), Faute> {
    fs::create_dir_all(dossier).map_err(|quoi| Faute::Disque {
        ou: dossier.to_path_buf(),
        quoi,
    })?;
    let ou = dossier.join(FICHIER);

    // **LE COMPTE, QUAND ON LE SAIT.** Un annuaire d'avant 0.3.0 ne le rend pas
    // à l'enrôlement ; `asl diagnose` l'apprendra par `GET /v1/moi` et
    // complétera ce fichier. C'est un identifiant public, pas un secret.
    let ligne_compte = compte.map_or(String::new(), |compte| {
        format!("compte = {}\n", compte.texte().as_str())
    });
    let contenu = format!(
        "# asl — l'identité de cette machine.\n\
         #\n\
         # LA MOITIÉ PRIVÉE D'UNE PAIRE DE CLÉS. Elle n'a jamais quitté ce disque,\n\
         # et elle ne le doit pas : l'annuaire ne connaît que la moitié publique.\n\
         # Ne la copiez pas sur une autre machine — enrôlez-la, c'est gratuit.\n\
         machine = {}\n\
         {}graine = {}\n",
        machine.texte().as_str(),
        ligne_compte,
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

/// Ce que le fichier d'identité dit, une fois lu : de quoi s'authentifier, et
/// le compte pour lequel cette machine agit, s'il y est.
pub struct Fiche {
    /// La machine et sa clé — ce qu'`asl-client` demande.
    pub identite: Identite,
    /// Le compte, quand l'enrôlement ou un diagnostic l'a posé.
    pub compte: Option<Identifiant>,
}

/// Lit l'identité de cette machine.
///
/// # Erreurs
///
/// [`Faute::PasEnrolee`], [`Faute::TropOuvert`], [`Faute::Illisible`],
/// [`Faute::Disque`].
pub fn lire(dossier: &Path) -> Result<Identite, Faute> {
    lire_la_fiche(dossier).map(|fiche| fiche.identite)
}

/// Lit le fichier d'identité entier, compte compris.
///
/// # Erreurs
///
/// Celles de [`lire`].
pub fn lire_la_fiche(dossier: &Path) -> Result<Fiche, Faute> {
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
    let mut compte = None;
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
            "compte" => compte = Some(valeur.trim().to_owned()),
            _ => {}
        }
    }

    // **UN COMPTE ILLISIBLE N'EMPÊCHE PAS DE S'AUTHENTIFIER** : il ne sert
    // qu'à l'affichage, et `asl diagnose` le remettra d'aplomb.
    let compte =
        compte.and_then(|texte| Identifiant::analyser_genre(Genre::Utilisateur, &texte).ok());

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
    let identite = Identite::nouvelle(machine, graine).map_err(|_| Faute::Illisible {
        ou,
        quoi: "l'identifiant n'est pas celui d'une machine",
    })?;
    Ok(Fiche { identite, compte })
}

/// Pose le compte dans un fichier d'identité qui ne le portait pas.
///
/// Le fichier est réécrit entier, avec la même graine et le même mode : une
/// ligne ajoutée à la main laisserait deux écritures possibles du même fichier.
///
/// # Erreurs
///
/// Celles de [`lire`] et d'[`ecrire`].
pub fn completer(dossier: &Path, compte: Identifiant) -> Result<(), Faute> {
    let ou = dossier.join(FICHIER);
    let contenu = fs::read_to_string(&ou).map_err(|quoi| Faute::Disque {
        ou: ou.clone(),
        quoi,
    })?;
    let fiche = lire_la_fiche(dossier)?;
    let graine = contenu
        .lines()
        .filter_map(|ligne| ligne.trim().split_once('='))
        .find(|(clef, _)| clef.trim() == "graine")
        .and_then(|(_, valeur)| depuis_hexa(valeur.trim()))
        .ok_or(Faute::Illisible {
            ou,
            quoi: "il manque la ligne `graine =`",
        })?;
    ecrire(dossier, fiche.identite.machine(), Some(compte), &graine)
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

// ── Le cache des racines (décisions 56, 76 et 85) ────────────────────────────

/// Le nom du fichier qui garde les locateurs appris des racines, **à côté de
/// l'identité**.
///
/// # POURQUOI ICI, ET NON DANS `~/.cache`
///
/// Parce que c'est l'état de CETTE machine face aux racines, et que qui
/// déplace l'identité (`--state`, `ASL_STATE`, l'unité systemd d'un daemon)
/// veut que le reste suive : un daemon sous `/var/lib/asl` n'a pas de
/// `~/.cache`. **Rien n'y est secret** — des adresses publiques et des `n-…`
/// —, d'où le mode ordinaire ; et l'effacer ne casse rien.
pub const CACHE_DES_RACINES: &str = "racines";

/// Ce que le cache des racines dit, une fois cherché.
pub enum Cache {
    /// Aucun fichier : rien n'a encore été appris.
    Absent,
    /// Un fichier qu'on n'a pas pu lire, ou qui ne se lit pas — **ignoré**, et
    /// dit dans un diagnostic ; les racines embarquées répondent.
    Illisible(String),
    /// Les locateurs appris.
    Lu(asl_client_tokio::LocateursAppris),
}

/// Cherche le cache des racines. **Ne rend jamais d'erreur** : un cache
/// illisible est un cache qu'on ignore.
#[must_use]
pub fn lire_le_cache(dossier: &Path) -> Cache {
    let ou = dossier.join(CACHE_DES_RACINES);
    let fichier = match fs::File::open(&ou) {
        Ok(fichier) => fichier,
        Err(quoi) if quoi.kind() == std::io::ErrorKind::NotFound => return Cache::Absent,
        Err(quoi) => return Cache::Illisible(quoi.to_string()),
    };
    // Une borne à la lecture même : un fichier géant posé là n'est pas lu
    // jusqu'au bout pour être refusé ensuite.
    let borne = u64::try_from(asl_client_tokio::CACHE_MAX)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut texte = String::new();
    if let Err(quoi) = fichier.take(borne).read_to_string(&mut texte) {
        return Cache::Illisible(quoi.to_string());
    }
    match asl_client_tokio::LocateursAppris::lire(&texte) {
        Ok(appris) => Cache::Lu(appris),
        Err(quoi) => Cache::Illisible(quoi.to_string()),
    }
}

/// Écrit le cache des racines, **d'un coup** : un fichier voisin, puis un
/// renommage. Deux `asl` lancés ensemble ne se lisent jamais à moitié écrits.
///
/// # Erreurs
///
/// [`Faute::Disque`] — que l'appelant dit, sans échouer pour autant.
pub fn ecrire_le_cache(
    dossier: &Path,
    appris: &asl_client_tokio::LocateursAppris,
) -> Result<(), Faute> {
    fs::create_dir_all(dossier).map_err(|quoi| Faute::Disque {
        ou: dossier.to_path_buf(),
        quoi,
    })?;
    let ou = dossier.join(CACHE_DES_RACINES);
    let provisoire = dossier.join(format!(".{CACHE_DES_RACINES}.{}", std::process::id()));
    fs::write(&provisoire, appris.ecrire()).map_err(|quoi| Faute::Disque {
        ou: provisoire.clone(),
        quoi,
    })?;
    fs::rename(&provisoire, &ou).map_err(|quoi| {
        let _ = fs::remove_file(&provisoire);
        Faute::Disque { ou, quoi }
    })
}

/// L'heure, en secondes depuis l'époque — celle que le cache retient.
#[must_use]
pub fn maintenant() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |ecoule| ecoule.as_secs())
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

    /// Un dossier d'essai à nous.
    fn dossier(quoi: &str) -> PathBuf {
        let ou = std::env::temp_dir().join(format!("asl-etat-{}-{quoi}", std::process::id()));
        let _ = fs::remove_dir_all(&ou);
        ou
    }

    #[test]
    fn le_compte_s_ecrit_se_relit_et_se_complete() {
        let ou = dossier("compte");
        let machine = Identifiant::depuis_entropie(Genre::Machine, [0x21; 16]);
        let compte = Identifiant::depuis_entropie(Genre::Utilisateur, [0x22; 16]);
        let graine = [0x5A_u8; 32];

        // Sans compte — un annuaire d'avant 0.3.0.
        ecrire(&ou, machine, None, &graine).expect("écrit");
        let fiche = lire_la_fiche(&ou).expect("lisible");
        assert_eq!(fiche.identite.machine(), machine);
        assert_eq!(fiche.compte, None);
        assert!(
            !fs::read_to_string(ou.join(FICHIER))
                .unwrap()
                .contains("compte =")
        );

        // Complété par un diagnostic : même machine, même graine, et le compte.
        completer(&ou, compte).expect("complété");
        let fiche = lire_la_fiche(&ou).expect("lisible");
        assert_eq!(fiche.identite.machine(), machine);
        assert_eq!(fiche.compte, Some(compte));
        assert_eq!(
            lire(&ou).expect("lisible").machine(),
            machine,
            "la clé n'a pas bougé"
        );
        let mode = fs::metadata(ou.join(FICHIER)).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "le mode non plus");

        // Écrit d'emblée avec le compte.
        ecrire(&ou, machine, Some(compte), &graine).expect("écrit");
        assert_eq!(lire_la_fiche(&ou).expect("lisible").compte, Some(compte));

        let _ = fs::remove_dir_all(&ou);
    }

    #[test]
    fn un_compte_illisible_n_empeche_pas_de_s_authentifier() {
        let ou = dossier("compte-illisible");
        let machine = Identifiant::depuis_entropie(Genre::Machine, [0x21; 16]);
        ecrire(&ou, machine, None, &[0x5A; 32]).expect("écrit");
        let chemin = ou.join(FICHIER);
        let mut contenu = fs::read_to_string(&chemin).unwrap();
        contenu.push_str("compte = pas-un-identifiant\n");
        fs::write(&chemin, contenu).unwrap();
        let fiche = lire_la_fiche(&ou).expect("l'identité se lit quand même");
        assert_eq!(fiche.compte, None);
        let _ = fs::remove_dir_all(&ou);
    }

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
        let etat = chercher(Some("/tmp/ici"));
        assert_eq!(etat.origine, Origine::Option);
        assert!(etat.avertissements.is_empty());
    }

    /// Une maison d'essai, avec ses trois emplacements d'état.
    struct Maison {
        racine: PathBuf,
        groupe: PathBuf,
        ancien: PathBuf,
        usuel: PathBuf,
    }

    impl Maison {
        fn neuve(quoi: &str) -> Self {
            let racine = dossier(&format!("maison-{quoi}"));
            let maison = Self {
                groupe: racine.join(GROUPE),
                ancien: racine.join(ANCIEN_CONTENEUR),
                usuel: racine.join(".config").join("asl"),
                racine,
            };
            for ou in [&maison.groupe, &maison.ancien, &maison.usuel] {
                fs::create_dir_all(ou).expect("un dossier d'état");
            }
            maison
        }

        /// Pose l'identité d'une machine dont l'entropie tient en un octet.
        fn poser(ou: &Path, octet: u8) -> String {
            let machine = Identifiant::depuis_entropie(Genre::Machine, [octet; 16]);
            ecrire(ou, machine, None, &[0x5A; 32]).expect("écrit");
            machine.texte().as_str().to_owned()
        }

        /// La règle, sur cette maison, **comme sur un Mac**.
        fn sur_mac(&self) -> Etat {
            resoudre(None, None, None, &self.racine, true)
        }
    }

    impl Drop for Maison {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.racine);
        }
    }

    /// L'ordre de macOS, éprouvé sur une maison à nous — et donc aussi sur la
    /// CI Linux : la plate-forme est un argument de la règle.
    #[test]
    fn sur_mac_le_groupe_puis_l_ancien_conteneur_puis_l_usuel() {
        let maison = Maison::neuve("ordre");

        // Rien nulle part : l'usuel, pour que `asl enroll` y écrive.
        let etat = maison.sur_mac();
        assert_eq!(etat.dossier, maison.usuel);
        assert_eq!(etat.origine, Origine::Utilisateur);
        assert!(etat.avertissements.is_empty(), "{:?}", etat.avertissements);

        // L'usuel seul.
        Maison::poser(&maison.usuel, 0x31);
        let etat = maison.sur_mac();
        assert_eq!(
            (etat.dossier, etat.origine),
            (maison.usuel.clone(), Origine::Utilisateur)
        );

        // L'ancien conteneur, et la même machine : il passe avant, et on dit
        // que la migration n'a pas eu lieu — sans parler de conflit.
        Maison::poser(&maison.ancien, 0x31);
        let etat = maison.sur_mac();
        assert_eq!(etat.dossier, maison.ancien);
        assert_eq!(etat.origine, Origine::AncienConteneur);
        assert_eq!(etat.avertissements.len(), 1, "{:?}", etat.avertissements);
        assert!(etat.avertissements[0].contains("ancien conteneur"));
        assert!(etat.avertissements[0].contains("lancez l'application"));

        // Le groupe, même machine : il passe devant tout, en silence — deux
        // copies identiques sont une migration interrompue, que l'application
        // finira.
        Maison::poser(&maison.groupe, 0x31);
        let etat = maison.sur_mac();
        assert_eq!(
            (etat.dossier, etat.origine),
            (maison.groupe.clone(), Origine::Groupe)
        );
        assert!(etat.avertissements.is_empty(), "{:?}", etat.avertissements);

        // Un dossier de groupe sans identité ne compte pas.
        fs::remove_file(maison.groupe.join(FICHIER)).expect("effacé");
        assert_eq!(maison.sur_mac().origine, Origine::AncienConteneur);

        // `$XDG_CONFIG_HOME` remplace `~/.config`, au quatrième rang seulement.
        fs::remove_file(maison.ancien.join(FICHIER)).expect("effacé");
        let xdg = maison.racine.join("xdg");
        let etat = resoudre(
            None,
            None,
            Some(xdg.to_str().unwrap()),
            &maison.racine,
            true,
        );
        assert_eq!(
            (etat.dossier, etat.origine),
            (xdg.join("asl"), Origine::Utilisateur)
        );
        Maison::poser(&maison.groupe, 0x31);
        let etat = resoudre(
            None,
            None,
            Some(xdg.to_str().unwrap()),
            &maison.racine,
            true,
        );
        assert_eq!(etat.origine, Origine::Groupe);
    }

    #[test]
    fn deux_identites_differentes_se_disent_et_la_plus_haute_est_prise() {
        let maison = Maison::neuve("conflit");
        let groupe = Maison::poser(&maison.groupe, 0x41);
        let usuel = Maison::poser(&maison.usuel, 0x42);

        let etat = maison.sur_mac();
        assert_eq!(etat.dossier, maison.groupe, "la plus haute priorité");
        assert_eq!(etat.avertissements.len(), 1, "{:?}", etat.avertissements);
        let dit = &etat.avertissements[0];
        assert!(!dit.contains('\n'), "une ligne : {dit}");
        assert!(dit.contains(&groupe) && dit.contains(&usuel), "{dit}");
        assert!(dit.contains("retenue"), "{dit}");
        assert!(
            dit.find(&groupe) < dit.find(&usuel),
            "la retenue d'abord : {dit}"
        );

        // Trois emplacements, l'ancien conteneur retenu : les deux lignes.
        fs::remove_file(maison.groupe.join(FICHIER)).expect("effacé");
        let ancien = Maison::poser(&maison.ancien, 0x43);
        let etat = maison.sur_mac();
        assert_eq!(etat.origine, Origine::AncienConteneur);
        assert_eq!(etat.avertissements.len(), 2, "{:?}", etat.avertissements);
        assert!(etat.avertissements[1].contains(&ancien));
        assert!(etat.avertissements[1].contains(&usuel));
    }

    #[test]
    fn state_et_asl_state_sont_pris_tels_quels_sans_repli() {
        let maison = Maison::neuve("sans-repli");
        Maison::poser(&maison.groupe, 0x51);
        Maison::poser(&maison.usuel, 0x52);
        let vide = maison.racine.join("vide");

        for macos in [true, false] {
            // Un dossier qui ne porte rien reste LE dossier : pas de repli vers
            // le groupe, et rien à dire des autres.
            let etat = resoudre(
                Some(vide.to_str().unwrap()),
                None,
                None,
                &maison.racine,
                macos,
            );
            assert_eq!(
                (etat.dossier.clone(), etat.origine),
                (vide.clone(), Origine::Option)
            );
            assert!(etat.avertissements.is_empty(), "{:?}", etat.avertissements);

            let etat = resoudre(
                None,
                Some(vide.to_str().unwrap()),
                Some("/tmp/xdg"),
                &maison.racine,
                macos,
            );
            assert_eq!(
                (etat.dossier, etat.origine),
                (vide.clone(), Origine::Environnement)
            );
            assert!(etat.avertissements.is_empty());

            // `--state` passe avant `ASL_STATE`.
            let etat = resoudre(Some("/tmp/a"), Some("/tmp/b"), None, &maison.racine, macos);
            assert_eq!(etat.dossier, PathBuf::from("/tmp/a"));
        }
    }

    /// Linux ne connaît ni le groupe ni l'ancien conteneur, même s'ils portent
    /// une identité : l'ordre d'hier, sans avertissement.
    #[test]
    fn sur_linux_rien_ne_change() {
        let maison = Maison::neuve("linux");
        Maison::poser(&maison.groupe, 0x61);
        Maison::poser(&maison.ancien, 0x62);
        let etat = resoudre(None, None, None, &maison.racine, false);
        assert_eq!(
            (etat.dossier, etat.origine),
            (maison.usuel.clone(), Origine::Utilisateur)
        );
        assert!(etat.avertissements.is_empty());
        let etat = resoudre(None, None, Some("/tmp/xdg"), &maison.racine, false);
        assert_eq!(etat.dossier, PathBuf::from("/tmp/xdg/asl"));
    }

    #[test]
    fn le_conteneur_d_un_bac_a_sable_remonte_au_compte() {
        assert_eq!(
            hors_du_bac_a_sable(Path::new(
                "/Users/thierry/Library/Containers/org.airdesktop.servicelocator.mac/Data"
            )),
            PathBuf::from("/Users/thierry")
        );
        for tel_quel in [
            "/Users/thierry",
            "/home/thierry",
            "/Users/thierry/Library/Containers/x/Autre",
            "Library/Containers/x/Data",
            ".",
        ] {
            assert_eq!(
                hors_du_bac_a_sable(Path::new(tel_quel)),
                PathBuf::from(tel_quel)
            );
        }
    }

    #[test]
    fn les_origines_se_disent() {
        for origine in [
            Origine::Option,
            Origine::Environnement,
            Origine::Groupe,
            Origine::AncienConteneur,
            Origine::Utilisateur,
        ] {
            assert!(!origine.dire().is_empty());
        }
        assert!(Origine::Groupe.dire().contains("groupe"));
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

    #[test]
    fn le_cache_des_racines_absent_corrompu_ou_lu() {
        let ou = dossier("cache");
        // Absent : rien n'a été appris, et ce n'est pas une faute.
        assert!(matches!(lire_le_cache(&ou), Cache::Absent));

        // Écrit, puis relu tel quel — le dossier naît s'il manque.
        let nitrogen = asl_client::racines::RACINES[0]
            .identite()
            .expect("embarquée");
        let (appris, _) = asl_client_tokio::LocateursAppris::depuis_la_liste(
            &[asl_client_tokio::RacineApprise {
                identifiant: nitrogen,
                cle: [0; 32],
                locateurs: vec!["[2001:db8::1]:6631".to_owned()],
            }],
            1_790_000_000,
        );
        ecrire_le_cache(&ou, &appris).expect("un dossier à nous");
        match lire_le_cache(&ou) {
            Cache::Lu(relu) => assert_eq!(relu, appris),
            _ => panic!("le cache écrit doit se relire"),
        }
        // Rien ne traîne du fichier provisoire.
        let restes: Vec<_> = fs::read_dir(&ou)
            .expect("le dossier")
            .filter_map(Result::ok)
            .map(|entree| entree.file_name())
            .collect();
        assert_eq!(restes, vec![std::ffi::OsString::from(CACHE_DES_RACINES)]);

        // **CORROMPU : IGNORÉ, JAMAIS UNE PANNE** — et l'on dit pourquoi.
        fs::write(ou.join(CACHE_DES_RACINES), "n'importe quoi\n").expect("écrire");
        match lire_le_cache(&ou) {
            Cache::Illisible(quoi) => assert!(quoi.contains("ligne 1"), "{quoi}"),
            _ => panic!("un cache corrompu est illisible"),
        }
        fs::write(ou.join(CACHE_DES_RACINES), [0xFF, 0xFE]).expect("écrire");
        assert!(matches!(lire_le_cache(&ou), Cache::Illisible(_)));
        fs::write(
            ou.join(CACHE_DES_RACINES),
            "#".repeat(asl_client_tokio::CACHE_MAX + 10),
        )
        .expect("écrire");
        assert!(matches!(lire_le_cache(&ou), Cache::Illisible(_)));
        let _ = fs::remove_dir_all(&ou);
    }
}
