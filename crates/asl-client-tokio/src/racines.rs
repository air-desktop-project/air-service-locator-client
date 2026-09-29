//! Les racines embarquées, en annuaires à joindre, et la liste qu'une racine
//! rend (`GET /v1/racines`, décision 56) — et, depuis 0.21.0, **les locateurs
//! qu'on en apprend** et qu'un porteur garde en cache (décisions 76 et 85).
//!
//! # CE QU'UN CACHE A LE DROIT DE CHANGER : LES LOCATEURS, ET RIEN D'AUTRE
//!
//! La liste embarquée est l'ancre : **une racine nouvelle exige une nouvelle
//! version du client**. Ce que `GET /v1/racines` apprend ne change que les
//! adresses et les ports des racines DÉJÀ embarquées, reconnues par leur
//! `n-…` ([`LocateursAppris::depuis_la_liste`]) : une racine inconnue est
//! ignorée, et aucune racine embarquée n'est jamais retirée — ses locateurs
//! d'usine restent en secours derrière les appris ([`racines_a_essayer`]).
//! Au moins une racine écoute sur 6630, celle que la liste embarquée garantit :
//! c'est ce qui rend l'amorçage sûr même quand le cache ment ou manque.
//!
//! **Le cache ne porte aucune confiance** : chaque locateur y est rangé sous
//! l'identité qu'on doit trouver au bout, et c'est la clé embarquée qu'on juge.
//! Un cache falsifié peut faire perdre un tour de tournée, pas faire croire
//! quelqu'un d'autre.
//!
//! # SANS RÉSOLVEUR (C20)
//!
//! [`racines_embarquees`] ne rend que des adresses littérales : aucun chemin
//! par défaut ne passe par le DNS. Un nom reste un locateur qu'un porteur peut
//! écrire ; ce n'est pas celui qu'on joint quand on ne dit rien. La liste
//! embarquée (`asl-racines`, partagée avec le serveur) porte aussi le nom de
//! chaque racine : il ne se lit pas comme une adresse, et il est donc sauté.

use std::net::SocketAddr;

use asl_client::racines::{RACINES, RacineEmbarquee, verifier_la_liste};
use asl_id::{Genre, Identifiant};

use crate::{Annuaire, Connexion, Faute};

/// Les racines embarquées, en annuaires à joindre : chaque adresse de
/// chacune, avec l'identité qu'on doit trouver au bout.
///
/// **IPv6 D'ABORD, POUR TOUTES** : les adresses IPv6 des deux racines, puis
/// leurs adresses IPv4 — `modele.md` §1, et c'est ce que la tournée attend.
/// C'est [`racines_a_essayer`] sans rien d'appris.
#[must_use]
pub fn racines_embarquees() -> Vec<Annuaire> {
    racines_a_essayer(None)
        .into_iter()
        .map(|(annuaire, _)| annuaire)
        .collect()
}

/// Les racines embarquées dont la clé donne bien l'identifiant écrit à côté.
///
/// **LA CLÉ DOIT DONNER L'IDENTIFIANT ÉCRIT À CÔTÉ** : une racine embarquée
/// de travers ne se joint pas — elle ne se croirait pas.
fn embarquees() -> impl Iterator<Item = (&'static RacineEmbarquee, Identifiant)> {
    RACINES.iter().filter_map(|racine| {
        let identite = racine.identite()?;
        let cle = racine.cle_publique()?;
        (asl_cle::identifiant_de_racine(&cle) == identite).then_some((racine, identite))
    })
}

/// Les adresses LITTÉRALES d'une racine embarquée — sans résolveur (C20).
fn adresses_embarquees(racine: &RacineEmbarquee) -> impl Iterator<Item = SocketAddr> + '_ {
    racine
        .locateurs
        .iter()
        .filter_map(|texte| texte.parse::<SocketAddr>().ok())
}

/// L'identité est-elle celle d'une racine embarquée ?
///
/// C'est la condition pour croire une liste de racines : **elle n'est signée
/// que par la connexion**, et seule une connexion jugée sous la clé d'une
/// racine embarquée la rend digne d'être gardée.
#[must_use]
pub fn est_une_racine_embarquee(identite: Identifiant) -> bool {
    embarquees().any(|(_, connue)| connue == identite)
}

// ── Les locateurs appris ────────────────────────────────────────────────────

/// Au-delà de cet âge, en secondes, les locateurs appris se relisent :
/// **vingt-quatre heures**.
///
/// # POURQUOI UN JOUR, ET NON À CHAQUE CONNEXION
///
/// Ce qui change dans la liste, c'est l'adresse ou le port d'une racine : un
/// geste d'exploitant, rare, et annoncé. Relire à chaque commande coûterait
/// un aller-retour de plus à chacune et une écriture sur disque, pour une
/// réponse qui ne bouge pas d'un mois sur l'autre ; relire une fois par jour
/// suit un déménagement le jour même. **Et un cache en retard ne casse rien** :
/// les locateurs embarqués restent en secours derrière, et au moins une
/// racine écoute sur 6630 (décision 76). Un cache absent ou illisible, lui,
/// se relit tout de suite.
pub const RELIRE_APRES_S: u64 = 24 * 60 * 60;

/// Le nombre de locateurs gardés par racine — la borne du renvoi.
pub const LOCATEURS_MAX: usize = asl_client::renvoi::ADRESSES_MAX;

/// La taille au-delà de laquelle un cache n'est pas lu, en octets.
///
/// Deux racines de huit locateurs tiennent dans moins d'un kibioctet ; un
/// fichier seize fois plus gros n'est pas le nôtre.
pub const CACHE_MAX: usize = 16 * 1024;

/// D'où vient un locateur de racine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Appris de `GET /v1/racines`, et absent de la liste embarquée : la
    /// racine a déménagé, ou écoute ailleurs.
    Appris,
    /// De la liste embarquée seulement : le secours.
    Embarque,
    /// Les deux : la racine le sert encore, tel que ce binaire l'embarque.
    ApprisEtEmbarque,
}

impl core::fmt::Display for Provenance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Appris => "appris",
            Self::Embarque => "embarqué",
            Self::ApprisEtEmbarque => "appris et embarqué",
        })
    }
}

/// Ce qui empêche de lire un cache. **Jamais une panne** : l'appelant
/// l'ignore, le dit dans un diagnostic, et joint les racines embarquées.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FauteDeCache {
    /// Plus de [`CACHE_MAX`] octets.
    TropGros,
    /// Une ligne ne se lit pas ; son numéro, à partir de un, et ce qui cloche.
    Ligne(usize, &'static str),
    /// Il manque la date d'apprentissage.
    SansDate,
}

impl core::fmt::Display for FauteDeCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TropGros => write!(f, "plus de {CACHE_MAX} octets"),
            Self::Ligne(numero, quoi) => write!(f, "ligne {numero} : {quoi}"),
            Self::SansDate => write!(f, "la date d'apprentissage manque"),
        }
    }
}

/// Les locateurs appris des racines embarquées, et quand.
///
/// # CE QUI Y ENTRE
///
/// Seulement des **adresses littérales** (`[IPv6]:port`, `IPv4:port`, port
/// non nul), sous le `n-…` d'une **racine embarquée**. Un nom de la liste
/// n'y entre pas : le chemin par défaut ne résout rien (C20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocateursAppris {
    /// Quand la liste a été lue, en secondes depuis l'époque.
    appris_a: u64,
    /// Par racine embarquée, dans l'ordre de la liste lue.
    racines: Vec<(Identifiant, Vec<SocketAddr>)>,
}

/// Le locateur, s'il est une adresse littérale au port non nul.
fn litteral(texte: &str) -> Option<SocketAddr> {
    texte
        .parse::<SocketAddr>()
        .ok()
        .filter(|adresse| adresse.port() != 0)
}

impl LocateursAppris {
    /// Garde, d'une liste **vérifiée**, ce qu'un cache a le droit de garder
    /// (décision 85) ; rend aussi les racines ignorées, pour qu'on le dise.
    ///
    /// Une racine inconnue de ce binaire est ignorée — **une racine nouvelle
    /// exige une nouvelle version du client**. D'une racine connue, on garde
    /// ses locateurs littéraux, sans doublon, au plus [`LOCATEURS_MAX`] ; une
    /// racine qui n'en donne aucun n'est pas rangée, et ses locateurs embarqués
    /// restent seuls.
    #[must_use]
    pub fn depuis_la_liste(apprises: &[RacineApprise], appris_a: u64) -> (Self, Vec<Identifiant>) {
        let mut racines: Vec<(Identifiant, Vec<SocketAddr>)> = Vec::new();
        let mut ignorees = Vec::new();
        for apprise in apprises {
            if !est_une_racine_embarquee(apprise.identifiant) {
                ignorees.push(apprise.identifiant);
                continue;
            }
            if racines.iter().any(|(deja, _)| *deja == apprise.identifiant) {
                continue;
            }
            let mut adresses: Vec<SocketAddr> = Vec::new();
            for adresse in apprise.locateurs.iter().filter_map(|texte| litteral(texte)) {
                if adresses.len() < LOCATEURS_MAX && !adresses.contains(&adresse) {
                    adresses.push(adresse);
                }
            }
            if !adresses.is_empty() {
                racines.push((apprise.identifiant, adresses));
            }
        }
        (Self { appris_a, racines }, ignorees)
    }

    /// Lit un cache écrit par [`LocateursAppris::ecrire`].
    ///
    /// # STRICT, PARCE QUE L'IGNORER NE COÛTE RIEN
    ///
    /// Une ligne qu'on ne comprend pas rend le cache entier illisible : on
    /// l'ignore, les racines embarquées répondent, et la prochaine relecture
    /// le réécrit. **Une racine qu'on ne connaît plus**, elle, n'est pas une
    /// faute — un autre binaire a pu l'écrire — : elle est sautée.
    ///
    /// # Errors
    ///
    /// [`FauteDeCache`].
    pub fn lire(texte: &str) -> Result<Self, FauteDeCache> {
        if texte.len() > CACHE_MAX {
            return Err(FauteDeCache::TropGros);
        }
        let mut appris_a = None;
        let mut racines: Vec<(Identifiant, Vec<SocketAddr>)> = Vec::new();
        for (rang, ligne) in texte.lines().enumerate() {
            let numero = rang.saturating_add(1);
            let faute = |quoi| FauteDeCache::Ligne(numero, quoi);
            let ligne = ligne.trim();
            if ligne.is_empty() || ligne.starts_with('#') {
                continue;
            }
            let (cle, valeur) = ligne.split_once('=').ok_or_else(|| faute("pas de `=`"))?;
            match cle.trim() {
                "appris_a" if appris_a.is_none() => {
                    appris_a = Some(
                        valeur
                            .trim()
                            .parse::<u64>()
                            .map_err(|_| faute("une date en secondes"))?,
                    );
                }
                "appris_a" => return Err(faute("une seconde date")),
                "racine" => {
                    let mut mots = valeur.split_whitespace();
                    let identite = mots
                        .next()
                        .and_then(|mot| Identifiant::analyser_genre(Genre::Annuaire, mot).ok())
                        .ok_or_else(|| faute("un `n-…` d'abord"))?;
                    let mut adresses = Vec::new();
                    for mot in mots {
                        adresses.push(litteral(mot).ok_or_else(|| faute("une adresse littérale"))?);
                    }
                    if adresses.is_empty() || adresses.len() > LOCATEURS_MAX {
                        return Err(faute("entre une et huit adresses"));
                    }
                    if racines.iter().any(|(deja, _)| *deja == identite) {
                        return Err(faute("une racine deux fois"));
                    }
                    if est_une_racine_embarquee(identite) {
                        racines.push((identite, adresses));
                    }
                }
                _ => return Err(faute("une clé inconnue")),
            }
        }
        Ok(Self {
            appris_a: appris_a.ok_or(FauteDeCache::SansDate)?,
            racines,
        })
    }

    /// Le cache, tel qu'il s'écrit sur disque.
    #[must_use]
    pub fn ecrire(&self) -> String {
        let mut texte = String::from(
            "# asl — les locateurs des racines, appris de GET /v1/racines.\n\
             #\n\
             # UN CACHE, PAS UNE ANCRE : il ne change que les adresses des racines\n\
             # embarquées dans ce binaire, par leur n-… ; la clé reste celle du binaire.\n\
             # L'effacer ne casse rien — les racines embarquées répondent, et il se\n\
             # réécrit à la prochaine connexion.\n",
        );
        texte.push_str(&format!("appris_a = {}\n", self.appris_a));
        for (identite, adresses) in &self.racines {
            texte.push_str("racine = ");
            texte.push_str(identite.texte().as_str());
            for adresse in adresses {
                texte.push(' ');
                texte.push_str(&adresse.to_string());
            }
            texte.push('\n');
        }
        texte
    }

    /// Quand la liste a été lue, en secondes depuis l'époque.
    #[must_use]
    pub const fn appris_a(&self) -> u64 {
        self.appris_a
    }

    /// Faut-il relire la liste ? Au-delà de [`RELIRE_APRES_S`] — ou si la
    /// date est dans le futur, qu'une horloge reculée a laissée là.
    #[must_use]
    pub const fn a_relire(&self, maintenant: u64) -> bool {
        match maintenant.checked_sub(self.appris_a) {
            Some(age) => age >= RELIRE_APRES_S,
            None => true,
        }
    }

    /// Les racines gardées et leurs locateurs.
    #[must_use]
    pub fn racines(&self) -> &[(Identifiant, Vec<SocketAddr>)] {
        &self.racines
    }
}

/// Les racines à essayer, chaque adresse avec sa provenance : **d'abord les
/// locateurs appris, puis ceux de la liste embarquée en secours**
/// (décision 85).
///
/// # IPv6 D'ABORD RESTE LA RÈGLE
///
/// La tournée essaie les adresses IPv6 avant les IPv4 (`modele.md` §1,
/// `asl_client::place_en_ordre`), quel que soit l'ordre qu'on lui donne ;
/// « appris d'abord » vaut donc **dans chaque famille** : IPv6 appris, IPv6
/// embarqués, IPv4 appris, IPv4 embarqués. Une adresse apprise qui est aussi
/// embarquée n'apparaît qu'une fois, au rang des apprises.
#[must_use]
pub fn racines_a_essayer(appris: Option<&LocateursAppris>) -> Vec<(Annuaire, Provenance)> {
    let annuaire = |adresse: SocketAddr, identite| Annuaire {
        adresse,
        nom: adresse.ip().to_string(),
        identite,
    };
    let mut toutes: Vec<(Annuaire, Provenance)> = Vec::new();
    for (racine, identite) in embarquees() {
        let apprises = appris
            .and_then(|appris| {
                appris
                    .racines
                    .iter()
                    .find(|(connue, _)| *connue == identite)
            })
            .map(|(_, adresses)| adresses.as_slice())
            .unwrap_or_default();
        for &adresse in apprises {
            let provenance = if adresses_embarquees(racine).any(|deja| deja == adresse) {
                Provenance::ApprisEtEmbarque
            } else {
                Provenance::Appris
            };
            toutes.push((annuaire(adresse, identite), provenance));
        }
    }
    for (racine, identite) in embarquees() {
        for adresse in adresses_embarquees(racine) {
            let deja = toutes
                .iter()
                .any(|(vu, _)| vu.adresse == adresse && vu.identite == identite);
            if !deja {
                toutes.push((annuaire(adresse, identite), Provenance::Embarque));
            }
        }
    }
    // Un tri stable garde l'ordre — appris d'abord — à l'intérieur d'une
    // famille.
    toutes.sort_by_key(|(annuaire, _)| annuaire.adresse.is_ipv4());
    toutes
}

/// Une racine apprise d'une liste, **vérifiée** : sa clé se déduit en son
/// identifiant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RacineApprise {
    /// Son identité.
    pub identifiant: Identifiant,
    /// Sa clé d'identité.
    pub cle: [u8; 32],
    /// Où la joindre — sans valeur de confiance.
    pub locateurs: Vec<String>,
}

/// Demande `GET /v1/racines` à la racine au bout de cette connexion, et rend
/// la liste **vérifiée** (décision 56).
///
/// La connexion a déjà été jugée — c'est elle, vérifiée par la clé de la
/// racine jointe, qui signe la liste ; ce qui reste à juger est la liste
/// elle-même : **une seule clé fausse la refuse entière**.
///
/// # Errors
///
/// Celles de la requête ; [`Faute::Statut`] pour autre chose que `200` ;
/// [`Faute::Illisible`] pour une liste qui ne se lit pas ou qui ment.
pub async fn apprendre_les_racines(connexion: &mut Connexion) -> Result<Vec<RacineApprise>, Faute> {
    let reponse = connexion.requete(b"GET", b"/v1/racines", &[], b"").await?;
    reponse.exige(200)?;
    lire_les_racines(&reponse.corps)
}

/// La liste lue et jugée, en racines apprises.
///
/// # Errors
///
/// [`Faute::Illisible`].
fn lire_les_racines(corps: &[u8]) -> Result<Vec<RacineApprise>, Faute> {
    let liste = verifier_la_liste(corps).map_err(|_| Faute::Illisible)?;
    Ok(liste
        .racines()
        .map(|racine| RacineApprise {
            identifiant: racine.annuaire,
            cle: racine.cle,
            locateurs: racine
                .locateurs()
                .iter()
                .map(|&texte| texte.to_owned())
                .collect(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{
        FauteDeCache, LocateursAppris, Provenance, RELIRE_APRES_S, RacineApprise,
        est_une_racine_embarquee, lire_les_racines, racines_a_essayer, racines_embarquees,
    };
    use asl_client::racines::RACINES;
    use asl_id::{Genre, Identifiant};
    use std::net::SocketAddr;

    fn nitrogen() -> Identifiant {
        RACINES[0].identite().expect("embarquée")
    }

    fn argon() -> Identifiant {
        RACINES[1].identite().expect("embarquée")
    }

    fn inconnue() -> Identifiant {
        Identifiant::depuis_entropie(Genre::Annuaire, [0x77; 16])
    }

    fn apprise(identifiant: Identifiant, locateurs: &[&str]) -> RacineApprise {
        RacineApprise {
            identifiant,
            cle: [0; 32],
            locateurs: locateurs.iter().map(|&texte| texte.to_owned()).collect(),
        }
    }

    fn a(texte: &str) -> SocketAddr {
        texte.parse().expect("une adresse d'essai")
    }

    #[test]
    fn la_fusion_ne_garde_que_les_adresses_litterales_des_racines_embarquees() {
        let liste = [
            apprise(
                nitrogen(),
                &[
                    "[2001:41d0:20a:900::1dd4]:7000",
                    "nitrogen.air-desktop.org:7000",
                    "178.32.16.250:7000",
                    "178.32.16.250:7000",
                    "192.0.2.1:0",
                ],
            ),
            // **UNE RACINE INCONNUE EST IGNORÉE** : une racine nouvelle exige
            // une nouvelle version du client (décision 85).
            apprise(inconnue(), &["[2001:db8::9]:6630"]),
            // Une racine sans adresse littérale n'est pas rangée : ses
            // locateurs embarqués restent seuls.
            apprise(argon(), &["argon.air-desktop.org:6630"]),
            // Une seconde fois la même : la première compte.
            apprise(nitrogen(), &["[2001:db8::1]:6630"]),
        ];
        let (appris, ignorees) = LocateursAppris::depuis_la_liste(&liste, 1_000);
        assert_eq!(ignorees, vec![inconnue()]);
        assert_eq!(appris.appris_a(), 1_000);
        assert_eq!(
            appris.racines(),
            &[(
                nitrogen(),
                vec![a("[2001:41d0:20a:900::1dd4]:7000"), a("178.32.16.250:7000")]
            )]
        );
        assert!(!est_une_racine_embarquee(inconnue()));
        assert!(est_une_racine_embarquee(argon()));
    }

    #[test]
    fn la_fusion_borne_les_locateurs_d_une_racine() {
        let beaucoup: Vec<String> = (1..=20).map(|n| format!("192.0.2.{n}:6630")).collect();
        let textes: Vec<&str> = beaucoup.iter().map(String::as_str).collect();
        let (appris, _) = LocateursAppris::depuis_la_liste(&[apprise(argon(), &textes)], 0);
        assert_eq!(appris.racines()[0].1.len(), super::LOCATEURS_MAX);
    }

    #[test]
    fn les_appris_passent_avant_les_embarques_dans_chaque_famille() {
        let (appris, _) = LocateursAppris::depuis_la_liste(
            &[apprise(
                argon(),
                &[
                    "178.32.16.249:6631",
                    "[2001:db8::32]:6631",
                    // Déjà embarquée : une seule fois, au rang des apprises.
                    "[2001:41d0:20a:900::1d32]:6630",
                ],
            )],
            0,
        );
        let ordre: Vec<(String, Identifiant, Provenance)> = racines_a_essayer(Some(&appris))
            .into_iter()
            .map(|(annuaire, provenance)| {
                (annuaire.adresse.to_string(), annuaire.identite, provenance)
            })
            .collect();
        assert_eq!(
            ordre,
            vec![
                (
                    "[2001:db8::32]:6631".to_owned(),
                    argon(),
                    Provenance::Appris
                ),
                (
                    "[2001:41d0:20a:900::1d32]:6630".to_owned(),
                    argon(),
                    Provenance::ApprisEtEmbarque
                ),
                (
                    "[2001:41d0:20a:900::1dd4]:6630".to_owned(),
                    nitrogen(),
                    Provenance::Embarque
                ),
                ("178.32.16.249:6631".to_owned(), argon(), Provenance::Appris),
                (
                    "178.32.16.250:6630".to_owned(),
                    nitrogen(),
                    Provenance::Embarque
                ),
                (
                    "178.32.16.249:6630".to_owned(),
                    argon(),
                    Provenance::Embarque
                ),
            ]
        );
        // **AUCUNE RACINE EMBARQUÉE N'EST RETIRÉE** : sans rien d'appris, ce
        // sont exactement les embarquées.
        let sans: Vec<SocketAddr> = racines_a_essayer(None)
            .iter()
            .map(|(annuaire, _)| annuaire.adresse)
            .collect();
        let embarquees: Vec<SocketAddr> = racines_embarquees()
            .iter()
            .map(|annuaire| annuaire.adresse)
            .collect();
        assert_eq!(sans, embarquees);
        assert_eq!(Provenance::Embarque.to_string(), "embarqué");
        assert_eq!(Provenance::Appris.to_string(), "appris");
        assert_eq!(
            Provenance::ApprisEtEmbarque.to_string(),
            "appris et embarqué"
        );
    }

    #[test]
    fn le_cache_se_relit_tel_qu_il_s_ecrit() {
        let (appris, _) = LocateursAppris::depuis_la_liste(
            &[
                apprise(nitrogen(), &["[2001:db8::1]:6631", "192.0.2.1:6631"]),
                apprise(argon(), &["192.0.2.2:6630"]),
            ],
            1_790_000_000,
        );
        let texte = appris.ecrire();
        assert_eq!(LocateursAppris::lire(&texte), Ok(appris));
    }

    #[test]
    fn un_cache_de_travers_est_refuse_sans_rien_casser() {
        let n = nitrogen().texte();
        let n = n.as_str();
        let cas = [
            (
                format!("appris_a = 1\nracine {n} 192.0.2.1:6630"),
                "pas de `=`",
            ),
            ("appris_a = hier".to_owned(), "une date en secondes"),
            ("appris_a = 1\nappris_a = 2".to_owned(), "une seconde date"),
            (
                "appris_a = 1\nracine = 192.0.2.1:6630".to_owned(),
                "un `n-…` d'abord",
            ),
            ("appris_a = 1\nracine =".to_owned(), "un `n-…` d'abord"),
            (
                format!("appris_a = 1\nracine = {n} nitrogen.example:6630"),
                "une adresse littérale",
            ),
            (
                format!("appris_a = 1\nracine = {n} 192.0.2.1:0"),
                "une adresse littérale",
            ),
            (
                format!("appris_a = 1\nracine = {n}"),
                "entre une et huit adresses",
            ),
            (
                format!(
                    "appris_a = 1\nracine = {n} {}",
                    ["192.0.2.1:6630"; 9].join(" ")
                ),
                "entre une et huit adresses",
            ),
            (
                format!("appris_a = 1\nracine = {n} 192.0.2.1:6630\nracine = {n} 192.0.2.2:6630"),
                "une racine deux fois",
            ),
            ("appris_a = 1\nautre = x".to_owned(), "une clé inconnue"),
        ];
        for (texte, attendu) in cas {
            match LocateursAppris::lire(&texte) {
                Err(FauteDeCache::Ligne(_, quoi)) => assert_eq!(quoi, attendu, "{texte}"),
                autre => panic!("{texte} : {autre:?}"),
            }
        }
        assert_eq!(
            LocateursAppris::lire("# rien\n\n"),
            Err(FauteDeCache::SansDate)
        );
        assert_eq!(
            LocateursAppris::lire(&"#".repeat(super::CACHE_MAX + 1)),
            Err(FauteDeCache::TropGros)
        );
        assert_eq!(
            FauteDeCache::Ligne(3, "une clé inconnue").to_string(),
            "ligne 3 : une clé inconnue"
        );
        assert!(FauteDeCache::SansDate.to_string().contains("date"));
        assert!(FauteDeCache::TropGros.to_string().contains("octets"));
    }

    #[test]
    fn une_racine_inconnue_du_cache_est_sautee_sans_le_refuser() {
        let texte = format!(
            "appris_a = 5\nracine = {} [2001:db8::9]:6630\n",
            inconnue().texte().as_str()
        );
        let lu = LocateursAppris::lire(&texte).expect("un autre binaire a pu l'écrire");
        assert!(lu.racines().is_empty());
        assert_eq!(
            racines_a_essayer(Some(&lu)).len(),
            racines_embarquees().len()
        );
    }

    #[test]
    fn le_cache_se_relit_apres_un_jour_ou_si_l_horloge_a_recule() {
        let (appris, _) = LocateursAppris::depuis_la_liste(&[], 10_000);
        assert!(!appris.a_relire(10_000));
        assert!(!appris.a_relire(10_000 + RELIRE_APRES_S - 1));
        assert!(appris.a_relire(10_000 + RELIRE_APRES_S));
        assert!(appris.a_relire(9_999), "une date dans le futur se relit");
    }

    #[test]
    fn les_racines_embarquees_sont_des_adresses_ipv6_d_abord_et_identifiees() {
        let toutes = racines_embarquees();
        assert_eq!(toutes.len(), 4);
        assert!(toutes[0].adresse.is_ipv6() && toutes[1].adresse.is_ipv6());
        assert!(toutes[2].adresse.is_ipv4() && toutes[3].adresse.is_ipv4());
        assert!(
            toutes
                .iter()
                .all(|annuaire| annuaire.identite.genre() == asl_id::Genre::Annuaire)
        );
        assert_ne!(toutes[0].identite, toutes[1].identite);
    }

    #[test]
    fn une_liste_de_travers_est_illisible() {
        assert!(matches!(
            lire_les_racines(b"pas une liste"),
            Err(crate::Faute::Illisible)
        ));
    }
}
