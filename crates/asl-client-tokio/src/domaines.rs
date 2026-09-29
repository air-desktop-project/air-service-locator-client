//! Les domaines, lus depuis une machine (`protocole.md` §3, serveur 0.39.0) :
//! ce qu'un compte y voit, ce qui y est rangé, et les services de ses machines.
//!
//! # POURQUOI ICI, ET NON DANS `asl-client`
//!
//! `asl-client` est `no_std`, sans allocateur : ce qu'il lit, il le lit dans
//! des tableaux bornés à l'avance (`renvoi` en porte huit adresses, pas une de
//! plus). **Une liste de domaines ou de machines n'a pas de borne de ce
//! genre** : un domaine de famille range trois machines, celui d'un atelier en
//! range soixante. Des objets possédés, des `Vec` et des `String`, sont donc
//! la forme honnête — et c'est cette crate-ci qui alloue.
//!
//! # CE QUE LA VOIE MACHINE SERT, ET CE QU'ELLE TAIT
//!
//! Depuis la 0.39.0 du serveur, une machine qui porte la capacité `lecture`
//! lit, au nom de son propriétaire :
//!
//! | Route | Ce qu'elle rend |
//! |---|---|
//! | `GET /v1/domaines` | les domaines visibles — [`Domaine`] ; `[]` sans `lecture` |
//! | `GET /v1/domaines?alias=…` | ceux qui portent cet alias — [`DomaineTrouve`] ; sans `lecture` aussi |
//! | `GET /v1/domaines/{d}` | le domaine, ses groupes, ses machines — [`DomaineDetaille`] ; `404` sinon (C10) |
//! | `GET /v1/machines/{m}/services` | les services d'une machine — [`ServiceDeMachine`] — **à son propriétaire seul** ; `[]` aux autres |
//!
//! **Les services d'une machine d'un AUTRE compte ne sont servis nulle part**,
//! même à qui tient `voir` sur le domaine où elle est rangée : c'est une
//! limite du serveur, dite dans son `protocole.md` §3 comme « à trancher ». Un
//! `[]` rendu pour une telle machine ne dit donc pas qu'elle n'a rien ; il dit
//! qu'on ne le saura pas par là.
//!
//! # UN LECTEUR QUI SAUTE CE QU'IL NE CONNAÎT PAS
//!
//! Ces objets grandissent : `sorte` est arrivée en 0.39.0, `sonde_par` en
//! 0.32.0. **Un champ inconnu se saute, quelle que soit sa valeur** — chaîne,
//! nombre, objet, tableau —, pour qu'un client d'aujourd'hui lise encore ce
//! qu'un annuaire de demain lui rend. Ce qui est connu, en revanche, est
//! vérifié : un identifiant du mauvais genre, un champ exigé absent ou en
//! double refusent l'objet entier, plutôt que d'en garder une moitié.
//!
//! Le lecteur est celui du serveur (`asl_proto::cadrage::Lecteur`), et non un
//! analyseur JSON de plus : les chaînes sans échappement, les textes libres
//! sans contrôles ni forceurs de sens, lus par le même code des deux côtés.

use asl_id::{Genre, Identifiant};
use asl_proto::cadrage::Lecteur;

use crate::{Connexion, Faute};

/// Ce que `heberge_par` et `autorite` disent d'un domaine que les racines
/// tiennent (`asl_api::domaine::HEBERGE_PAR_LES_RACINES`).
pub const HEBERGE_PAR_LES_RACINES: &str = "racines";

/// La `sorte` du domaine racine (`asl_api::domaine::SORTE_DU_DOMAINE_RACINE`,
/// 0.39.0) : **absente** pour tout autre domaine.
pub const SORTE_DU_DOMAINE_RACINE: &str = "racine";

/// Les droits qui laissent voir ce qui est rangé dans un domaine
/// (`modele.md` §2.13) : `voir`, et ce qui l'emporte.
const DROITS_QUI_VOIENT: [&str; 3] = ["voir", "localiser", "administrer"];

/// La profondeur au-delà de laquelle une valeur inconnue n'est plus sautée.
///
/// **UNE BORNE, ET NON UNE RÉCURSION LIBRE** : ce qu'on saute vient de qui
/// répond, et cent mille crochets ouvrants suffiraient à épuiser la pile d'un
/// lecteur qui les suivrait sans compter. Aucun objet de ce protocole n'en
/// imbrique plus de quatre.
const PROFONDEUR_MAX: usize = 16;

/// Ce qu'une réponse de l'annuaire avait d'illisible, en toutes lettres.
///
/// **UNE PHRASE, ET NON UNE ÉNUMÉRATION** : personne ne rattrape une réponse
/// mal formée — on la rapporte. [`Connexion`] la rend en [`Faute::Illisible`] ;
/// qui décode lui-même un corps peut la montrer telle quelle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Illisible(pub String);

impl core::fmt::Display for Illisible {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Illisible {}

/// Qui fait autorité pour un domaine : les racines, ou l'annuaire local qui
/// l'héberge (`heberge_par`, `autorite` — 0.27.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Autorite {
    /// Les racines.
    Racines,
    /// Un annuaire local, par le `n-…` de son titulaire.
    Annuaire(Identifiant),
}

impl core::fmt::Display for Autorite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Racines => f.write_str(HEBERGE_PAR_LES_RACINES),
            Self::Annuaire(annuaire) => f.write_str(annuaire.texte().as_str()),
        }
    }
}

/// Un domaine trouvé par son alias — `GET /v1/domaines?alias=…`.
///
/// **Ni propriétaire, ni machine** : savoir qu'un domaine « Maison » existe
/// n'ouvre rien (`protocole.md` §2.2). C'est `GET /v1/domaines/{d}` qui dit
/// ce qu'on y voit, et `404` si l'on n'y voit rien.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomaineTrouve {
    /// Le domaine.
    pub domaine: Identifiant,
    /// Qui fait autorité pour lui.
    pub autorite: Autorite,
}

/// Un domaine tel que `GET /v1/domaines` le rend — et tel que
/// `GET /v1/domaines/{d}` le commence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domaine {
    /// Son identifiant.
    pub domaine: Identifiant,
    /// Le compte qui le possède.
    pub proprietaire: Identifiant,
    /// Son alias, s'il en a un — **sensible à la casse**, en NFC.
    pub alias: Option<String>,
    /// Qui l'héberge.
    pub heberge_par: Autorite,
    /// Ce que le compte qui lit peut sur lui — la réunion de ses droits
    /// (`modele.md` §2.13), dans l'ordre où l'annuaire les écrit.
    pub droits: Vec<String>,
    /// Sa sorte : [`SORTE_DU_DOMAINE_RACINE`] pour le domaine racine, `None`
    /// pour tout autre. **Un mot inconnu est gardé tel quel** — un annuaire de
    /// demain peut en dire un autre.
    pub sorte: Option<String>,
}

impl Domaine {
    /// Est-ce le domaine racine ?
    #[must_use]
    pub fn est_racine(&self) -> bool {
        self.sorte.as_deref() == Some(SORTE_DU_DOMAINE_RACINE)
    }

    /// Le compte qui lit tient-il ce droit sur ce domaine ?
    #[must_use]
    pub fn peut(&self, droit: &str) -> bool {
        self.droits.iter().any(|tenu| tenu == droit)
    }

    /// Voit-il ce qui y est rangé — `voir`, ou ce qui l'emporte ?
    ///
    /// C'est la condition pour que `machines` ne soit pas vide par défaut
    /// (`protocole.md` §2.2) : **une liste vide sans ce droit ne dit rien** du
    /// domaine, elle dit qu'on ne le voit pas.
    #[must_use]
    pub fn voit_ses_machines(&self) -> bool {
        DROITS_QUI_VOIENT.iter().any(|droit| self.peut(droit))
    }
}

/// Une machine rangée dans un domaine, telle que `GET /v1/domaines/{d}` la
/// rend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineDeDomaine {
    /// La machine.
    pub machine: Identifiant,
    /// Son propriétaire — qui peut n'être pas celui du domaine.
    pub proprietaire: Identifiant,
    /// Son nom d'hôte, quand l'annuaire le rend.
    pub nom: Option<String>,
    /// Son alias, texte libre, quand elle en a un.
    pub alias: Option<String>,
}

/// Un groupe d'un domaine, tel que `GET /v1/domaines/{d}` le rend — **à ses
/// administrateurs seulement** ; la liste est vide pour les autres.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupeDeDomaine {
    /// Le groupe.
    pub groupe: Identifiant,
    /// Son étiquette, quand il en porte une.
    pub etiquette: Option<String>,
    /// Sa sorte : `administrateurs`, `domaine`, `personnel` — rendue telle
    /// quelle.
    pub sorte: String,
}

/// Un domaine, ses groupes et ses machines — `GET /v1/domaines/{d}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomaineDetaille {
    /// Ce que la liste en dit.
    pub domaine: Domaine,
    /// Ses groupes, pour qui l'administre ; vide sinon.
    pub groupes: Vec<GroupeDeDomaine>,
    /// Les machines qui y sont rangées, pour qui a `voir` ; vide sinon.
    pub machines: Vec<MachineDeDomaine>,
}

/// L'état d'un service déclaré — `GET /v1/machines/{m}/services`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtatDeService {
    /// Vivant : sa connexion est tenue. Le corps est l'objet d'annonce
    /// (`asl_proto::Reponse`) **tel que l'annuaire l'a réémis**, que
    /// `asl_proto::Reponse::decoder` lit — bail, adresse observée,
    /// joignabilité de chaque point.
    Annonce(Vec<u8>),
    /// Déclaré, mais sa connexion n'est plus tenue. `volontaire` dit si le
    /// daemon s'est retiré lui-même ; `None` quand l'annuaire ne le sait plus
    /// (`modele.md` §4.2).
    Parti {
        /// Le départ était-il volontaire ?
        volontaire: Option<bool>,
    },
    /// Un état qu'un annuaire plus récent dit, et que ce client ne connaît
    /// pas : le mot, tel quel.
    Autre(String),
}

/// Un service d'une machine — `GET /v1/machines/{m}/services`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceDeMachine {
    /// Son identifiant.
    pub service: Identifiant,
    /// Le nom sous lequel la machine l'annonce — celui que
    /// `GET /v1/ou/{m}/{nom}` résout.
    pub nom: String,
    /// Son état.
    pub etat: EtatDeService,
    /// L'annuaire local qui l'a rapporté, pour une machine d'un domaine
    /// confié (décision 60) ; `None` pour un service tenu par la racine.
    pub sonde_par: Option<Identifiant>,
    /// Cet annuaire local s'est-il sondé de l'intérieur ? Alors son
    /// « joignable » ne dit rien de ce qu'un client du dehors verra.
    pub sonde_locale: Option<bool>,
}

// ── Les décodeurs ───────────────────────────────────────────────────────────

/// Lit `GET /v1/domaines?alias=…` : `[{"domaine","autorite"}]`.
///
/// # Errors
///
/// [`Illisible`], avec ce qui ne se lit pas.
pub fn lire_domaines_trouves(corps: &[u8]) -> Result<Vec<DomaineTrouve>, Illisible> {
    lire_une_liste(corps, |lecteur| {
        let mut domaine = None;
        let mut autorite = None;
        lire_un_objet(lecteur, "un domaine trouvé", |champ, lecteur| {
            match champ {
                "domaine" => poser(
                    &mut domaine,
                    lire_un_identifiant(lecteur, Genre::Domaine)?,
                    champ,
                )?,
                "autorite" => poser(&mut autorite, lire_une_autorite(lecteur)?, champ)?,
                _ => sauter_une_valeur(lecteur, 0)?,
            }
            Ok(())
        })?;
        Ok(DomaineTrouve {
            domaine: exiger(domaine, "domaine")?,
            autorite: exiger(autorite, "autorite")?,
        })
    })
}

/// Lit `GET /v1/domaines` : `[{"domaine","proprietaire","alias"?,
/// "heberge_par","droits":[…],"sorte"?}]`.
///
/// # Errors
///
/// [`Illisible`], avec ce qui ne se lit pas.
pub fn lire_domaines(corps: &[u8]) -> Result<Vec<Domaine>, Illisible> {
    lire_une_liste(corps, |lecteur| {
        let mut lu = DomaineEnLecture::default();
        lire_un_objet(lecteur, "un domaine", |champ, lecteur| {
            if !lu.lire_le_champ(champ, lecteur)? {
                sauter_une_valeur(lecteur, 0)?;
            }
            Ok(())
        })?;
        lu.achever()
    })
}

/// Lit `GET /v1/domaines/{d}` : les champs de [`lire_domaines`], puis
/// `"groupes":[…]` et `"machines":[…]`.
///
/// # Errors
///
/// [`Illisible`], avec ce qui ne se lit pas.
pub fn lire_domaine_detaille(corps: &[u8]) -> Result<DomaineDetaille, Illisible> {
    let mut lecteur = Lecteur::nouveau(corps);
    let mut lu = DomaineEnLecture::default();
    let mut groupes = None;
    let mut machines = None;
    lire_un_objet(&mut lecteur, "le domaine", |champ, lecteur| {
        if lu.lire_le_champ(champ, lecteur)? {
            return Ok(());
        }
        match champ {
            "groupes" => poser(
                &mut groupes,
                lire_un_tableau(lecteur, lire_un_groupe)?,
                champ,
            )?,
            "machines" => poser(
                &mut machines,
                lire_un_tableau(lecteur, lire_une_machine)?,
                champ,
            )?,
            _ => sauter_une_valeur(lecteur, 0)?,
        }
        Ok(())
    })?;
    lecteur.fin().map_err(faute("le domaine"))?;
    Ok(DomaineDetaille {
        domaine: lu.achever()?,
        // **ABSENTS, ILS VALENT VIDES** : ce sont des listes que l'annuaire
        // vide pour qui n'a pas le droit — les lire absentes comme vides ne
        // fait croire à personne qu'il y a quelque chose.
        groupes: groupes.unwrap_or_default(),
        machines: machines.unwrap_or_default(),
    })
}

/// Lit `GET /v1/machines/{m}/services` :
/// `[{"service","nom","etat":"annonce","annonce":{…}}]` ou
/// `[{"service","nom","etat":"parti","volontaire":true|false|null}]`, et
/// `sonde_par`/`sonde_locale` pour un service rapporté par un annuaire local.
///
/// # Errors
///
/// [`Illisible`], avec ce qui ne se lit pas — en particulier un `annonce`
/// sans état `annonce`, ou l'inverse.
pub fn lire_services(corps: &[u8]) -> Result<Vec<ServiceDeMachine>, Illisible> {
    lire_une_liste(corps, |lecteur| {
        let mut service = None;
        let mut nom = None;
        let mut etat: Option<String> = None;
        let mut annonce = None;
        let mut volontaire = None;
        let mut sonde_par = None;
        let mut sonde_locale = None;
        lire_un_objet(lecteur, "un service", |champ, lecteur| {
            match champ {
                "service" => poser(
                    &mut service,
                    lire_un_identifiant(lecteur, Genre::Service)?,
                    champ,
                )?,
                "nom" => poser(&mut nom, lire_un_texte(lecteur)?, champ)?,
                "etat" => poser(&mut etat, lire_un_texte(lecteur)?, champ)?,
                "annonce" => {
                    lecteur.sauter_blancs();
                    let debut = lecteur.position();
                    if lecteur.regarder() != Some(b'{') {
                        return Err(Illisible("`annonce` n'est pas un objet".to_owned()));
                    }
                    sauter_une_valeur(lecteur, 0)?;
                    let objet = corps
                        .get(debut..lecteur.position())
                        .unwrap_or_default()
                        .to_vec();
                    poser(&mut annonce, objet, champ)?;
                }
                "volontaire" => poser(&mut volontaire, lire_un_booleen_ou_nul(lecteur)?, champ)?,
                "sonde_par" => poser(
                    &mut sonde_par,
                    lire_un_identifiant(lecteur, Genre::Annuaire)?,
                    champ,
                )?,
                "sonde_locale" => {
                    let valeur = lire_un_booleen_ou_nul(lecteur)?
                        .ok_or_else(|| Illisible("`sonde_locale` est nul".to_owned()))?;
                    poser(&mut sonde_locale, valeur, champ)?;
                }
                _ => sauter_une_valeur(lecteur, 0)?,
            }
            Ok(())
        })?;
        let etat = match (exiger(etat, "etat")?.as_str(), annonce) {
            ("annonce", Some(objet)) => EtatDeService::Annonce(objet),
            ("annonce", None) => {
                return Err(Illisible(
                    "un service `annonce` sans son `annonce`".to_owned(),
                ));
            }
            (_, Some(_)) => {
                return Err(Illisible(
                    "un `annonce` sur un service qui n'est pas annoncé".to_owned(),
                ));
            }
            ("parti", None) => EtatDeService::Parti {
                volontaire: volontaire.flatten(),
            },
            (autre, None) => EtatDeService::Autre(autre.to_owned()),
        };
        Ok(ServiceDeMachine {
            service: exiger(service, "service")?,
            nom: exiger(nom, "nom")?,
            etat,
            sonde_par,
            sonde_locale,
        })
    })
}

/// Écrit un alias comme `GET /v1/domaines?alias=…` l'attend : chaque octet
/// hors de `A–Z a–z 0–9 - . _ ~` en `%HH`.
///
/// **L'ESPACE EST `%20`, JAMAIS `+`** : l'annuaire ne lit pas un formulaire,
/// et `+` y est refusé plutôt que pris pour une espace — deux écritures de la
/// même chose en ouvriraient deux lectures (`asl_api::domaine::AliasCherche`).
/// Rien n'est normalisé ici : l'annuaire range l'alias en NFC et compare
/// **en respectant la casse** ; « maison » ne trouve pas « Maison ».
#[must_use]
pub fn alias_en_requete(alias: &str) -> String {
    const HEXA: &[u8; 16] = b"0123456789ABCDEF";
    let mut sortie = String::with_capacity(alias.len());
    for octet in alias.bytes() {
        if octet.is_ascii_alphanumeric() || b"-._~".contains(&octet) {
            sortie.push(char::from(octet));
        } else {
            sortie.push('%');
            sortie.push(char::from(HEXA[usize::from(octet >> 4)]));
            sortie.push(char::from(HEXA[usize::from(octet & 0x0F)]));
        }
    }
    sortie
}

// ── Les verbes ──────────────────────────────────────────────────────────────

impl Connexion {
    /// Les domaines que le propriétaire de cette machine voit —
    /// `GET /v1/domaines`.
    ///
    /// # UNE LISTE VIDE VEUT PRESQUE TOUJOURS DIRE « SANS `lecture` »
    ///
    /// Un compte a toujours au moins un domaine (`modele.md` §2.11) : l'annuaire
    /// rend `[]` à une machine qui ne porte pas la capacité `lecture`, sans
    /// refuser — c'est la seule façon de le savoir sur ce verbe.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] — `401` sans
    /// preuve — et [`Faute::Illisible`].
    pub async fn domaines(&mut self) -> Result<Vec<Domaine>, Faute> {
        let reponse = self.requete(b"GET", b"/v1/domaines", &[], b"").await?;
        reponse.exige(200)?;
        lire_domaines(&reponse.corps).map_err(|_| Faute::Illisible)
    }

    /// Les domaines qui portent cet alias — `GET /v1/domaines?alias=…`.
    ///
    /// **Une liste, toujours** : l'alias de domaine n'est pas unique, et deux
    /// comptes peuvent avoir chacun leur « Maison ». Elle ne demande pas
    /// `lecture` — toute machine qui a prouvé sa clé —, et ne dit rien de ce
    /// qu'on voit dans chacun.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] — `400` pour
    /// un alias qu'on n'aurait pas pu poser — et [`Faute::Illisible`].
    pub async fn domaines_par_alias(&mut self, alias: &str) -> Result<Vec<DomaineTrouve>, Faute> {
        let cible = format!("/v1/domaines?alias={}", alias_en_requete(alias));
        let reponse = self.requete(b"GET", cible.as_bytes(), &[], b"").await?;
        reponse.exige(200)?;
        lire_domaines_trouves(&reponse.corps).map_err(|_| Faute::Illisible)
    }

    /// Un domaine, ses groupes et ses machines — `GET /v1/domaines/{d}`.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] — **`404` pour
    /// un domaine absent, supprimé, où l'on ne tient rien, ou lu par une
    /// machine sans `lecture`** : l'annuaire ne les distingue pas (C10) — et
    /// [`Faute::Illisible`].
    pub async fn domaine(&mut self, domaine: Identifiant) -> Result<DomaineDetaille, Faute> {
        let cible = format!("/v1/domaines/{}", domaine.texte());
        let reponse = self.requete(b"GET", cible.as_bytes(), &[], b"").await?;
        reponse.exige(200)?;
        lire_domaine_detaille(&reponse.corps).map_err(|_| Faute::Illisible)
    }

    /// Les services d'une machine — `GET /v1/machines/{m}/services`.
    ///
    /// **À SON PROPRIÉTAIRE SEUL** : pour la machine d'un autre compte,
    /// l'annuaire rend `[]` — même à qui voit le domaine où elle est rangée.
    /// Une liste vide ne dit donc quelque chose que pour une machine à soi.
    ///
    /// # Errors
    ///
    /// Celles de [`Connexion::requete`], plus [`Faute::Statut`] et
    /// [`Faute::Illisible`].
    pub async fn services_de_machine(
        &mut self,
        machine: Identifiant,
    ) -> Result<Vec<ServiceDeMachine>, Faute> {
        let cible = format!("/v1/machines/{}/services", machine.texte());
        let reponse = self.requete(b"GET", cible.as_bytes(), &[], b"").await?;
        reponse.exige(200)?;
        lire_services(&reponse.corps).map_err(|_| Faute::Illisible)
    }
}

// ── La mécanique ────────────────────────────────────────────────────────────

/// Les champs d'un domaine, au fil de la lecture.
#[derive(Default)]
struct DomaineEnLecture {
    domaine: Option<Identifiant>,
    proprietaire: Option<Identifiant>,
    alias: Option<String>,
    heberge_par: Option<Autorite>,
    droits: Option<Vec<String>>,
    sorte: Option<String>,
}

impl DomaineEnLecture {
    /// Lit ce champ s'il est à un domaine ; rend `false` sinon, sans rien
    /// avoir consommé.
    fn lire_le_champ(&mut self, champ: &str, lecteur: &mut Lecteur<'_>) -> Result<bool, Illisible> {
        match champ {
            "domaine" => poser(
                &mut self.domaine,
                lire_un_identifiant(lecteur, Genre::Domaine)?,
                champ,
            )?,
            "proprietaire" => poser(
                &mut self.proprietaire,
                lire_un_identifiant(lecteur, Genre::Utilisateur)?,
                champ,
            )?,
            "alias" => poser(&mut self.alias, lire_un_texte(lecteur)?, champ)?,
            "heberge_par" => poser(&mut self.heberge_par, lire_une_autorite(lecteur)?, champ)?,
            "droits" => poser(
                &mut self.droits,
                lire_un_tableau(lecteur, lire_un_texte)?,
                champ,
            )?,
            "sorte" => poser(&mut self.sorte, lire_un_texte(lecteur)?, champ)?,
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn achever(self) -> Result<Domaine, Illisible> {
        Ok(Domaine {
            domaine: exiger(self.domaine, "domaine")?,
            proprietaire: exiger(self.proprietaire, "proprietaire")?,
            alias: self.alias,
            heberge_par: exiger(self.heberge_par, "heberge_par")?,
            droits: exiger(self.droits, "droits")?,
            sorte: self.sorte,
        })
    }
}

/// Lit `{"groupe":"e-…","domaine":"d-…"|null,"etiquette"?,"sorte"}`.
fn lire_un_groupe(lecteur: &mut Lecteur<'_>) -> Result<GroupeDeDomaine, Illisible> {
    let mut groupe = None;
    let mut etiquette = None;
    let mut sorte = None;
    lire_un_objet(lecteur, "un groupe", |champ, lecteur| {
        match champ {
            "groupe" => poser(
                &mut groupe,
                lire_un_identifiant(lecteur, Genre::Ensemble)?,
                champ,
            )?,
            "etiquette" => poser(&mut etiquette, lire_un_texte(lecteur)?, champ)?,
            "sorte" => poser(&mut sorte, lire_un_texte(lecteur)?, champ)?,
            _ => sauter_une_valeur(lecteur, 0)?,
        }
        Ok(())
    })?;
    Ok(GroupeDeDomaine {
        groupe: exiger(groupe, "groupe")?,
        etiquette,
        sorte: exiger(sorte, "sorte")?,
    })
}

/// Lit `{"machine":"m-…","proprietaire":"u-…","nom"?,"alias"?}`.
fn lire_une_machine(lecteur: &mut Lecteur<'_>) -> Result<MachineDeDomaine, Illisible> {
    let mut machine = None;
    let mut proprietaire = None;
    let mut nom = None;
    let mut alias = None;
    lire_un_objet(lecteur, "une machine", |champ, lecteur| {
        match champ {
            "machine" => poser(
                &mut machine,
                lire_un_identifiant(lecteur, Genre::Machine)?,
                champ,
            )?,
            "proprietaire" => poser(
                &mut proprietaire,
                lire_un_identifiant(lecteur, Genre::Utilisateur)?,
                champ,
            )?,
            "nom" => poser(&mut nom, lire_un_texte(lecteur)?, champ)?,
            "alias" => poser(&mut alias, lire_un_texte(lecteur)?, champ)?,
            _ => sauter_une_valeur(lecteur, 0)?,
        }
        Ok(())
    })?;
    Ok(MachineDeDomaine {
        machine: exiger(machine, "machine")?,
        proprietaire: exiger(proprietaire, "proprietaire")?,
        nom,
        alias,
    })
}

/// Transforme une faute du cadrage en phrase, en disant où l'on lisait.
fn faute(ou: &'static str) -> impl Fn(asl_proto::Erreur) -> Illisible {
    move |quoi| Illisible(format!("{ou} ne se lit pas : {quoi:?}"))
}

/// Pose une valeur lue, ou refuse le champ en double.
///
/// **UN CHAMP EN DOUBLE EST UN REFUS, ET NON UN DERNIER-GAGNE** — la règle de
/// l'annuaire (`asl_api::corps`) : deux lecteurs qui choisiraient
/// différemment liraient deux objets dans un seul.
fn poser<T>(place: &mut Option<T>, valeur: T, champ: &str) -> Result<(), Illisible> {
    if place.is_some() {
        return Err(Illisible(format!("`{champ}` apparaît deux fois")));
    }
    *place = Some(valeur);
    Ok(())
}

/// Exige un champ.
fn exiger<T>(valeur: Option<T>, champ: &str) -> Result<T, Illisible> {
    valeur.ok_or_else(|| Illisible(format!("il manque `{champ}`")))
}

/// Lit un identifiant de ce genre.
fn lire_un_identifiant(lecteur: &mut Lecteur<'_>, genre: Genre) -> Result<Identifiant, Illisible> {
    let texte = lecteur.chaine().map_err(faute("un identifiant"))?;
    Identifiant::analyser_genre(genre, texte).map_err(|_| {
        Illisible(format!(
            "`{texte}` n'est pas un identifiant du genre attendu"
        ))
    })
}

/// Lit `racines` ou un `n-…`.
fn lire_une_autorite(lecteur: &mut Lecteur<'_>) -> Result<Autorite, Illisible> {
    let texte = lecteur.chaine().map_err(faute("un hébergeur"))?;
    if texte == HEBERGE_PAR_LES_RACINES {
        return Ok(Autorite::Racines);
    }
    Identifiant::analyser_genre(Genre::Annuaire, texte)
        .map(Autorite::Annuaire)
        .map_err(|_| Illisible(format!("`{texte}` n'est ni `racines` ni un annuaire")))
}

/// Lit un texte libre — un alias, un nom, une étiquette.
fn lire_un_texte(lecteur: &mut Lecteur<'_>) -> Result<String, Illisible> {
    lecteur
        .texte_libre()
        .map(str::to_owned)
        .map_err(faute("un texte"))
}

/// Lit `true`, `false` ou `null`.
fn lire_un_booleen_ou_nul(lecteur: &mut Lecteur<'_>) -> Result<Option<bool>, Illisible> {
    lecteur.sauter_blancs();
    if lecteur.mot("true") {
        Ok(Some(true))
    } else if lecteur.mot("false") {
        Ok(Some(false))
    } else if lecteur.mot("null") {
        Ok(None)
    } else {
        Err(Illisible("un booléen attendu".to_owned()))
    }
}

/// Lit un objet : `{`, puis chaque `"champ":` confié à `champ_lu`, puis `}`.
fn lire_un_objet<'a, F>(
    lecteur: &mut Lecteur<'a>,
    ou: &'static str,
    mut champ_lu: F,
) -> Result<(), Illisible>
where
    F: FnMut(&str, &mut Lecteur<'a>) -> Result<(), Illisible>,
{
    lecteur.attendre(b'{', "un objet").map_err(faute(ou))?;
    lecteur.sauter_blancs();
    if lecteur.regarder() == Some(b'}') {
        lecteur.avancer();
        return Ok(());
    }
    loop {
        let champ = lecteur.chaine().map_err(faute(ou))?;
        lecteur.attendre(b':', "deux-points").map_err(faute(ou))?;
        champ_lu(champ, lecteur)?;
        lecteur.sauter_blancs();
        match lecteur.regarder() {
            Some(b',') => lecteur.avancer(),
            _ => break,
        }
    }
    lecteur
        .attendre(b'}', "la fin de l'objet")
        .map_err(faute(ou))
}

/// Lit un tableau dont chaque élément se lit par `element`.
fn lire_un_tableau<'a, T, F>(lecteur: &mut Lecteur<'a>, mut element: F) -> Result<Vec<T>, Illisible>
where
    F: FnMut(&mut Lecteur<'a>) -> Result<T, Illisible>,
{
    lecteur
        .attendre(b'[', "un tableau")
        .map_err(faute("un tableau"))?;
    let mut lus = Vec::new();
    lecteur.sauter_blancs();
    if lecteur.regarder() == Some(b']') {
        lecteur.avancer();
        return Ok(lus);
    }
    loop {
        lus.push(element(lecteur)?);
        lecteur.sauter_blancs();
        match lecteur.regarder() {
            Some(b',') => lecteur.avancer(),
            _ => break,
        }
    }
    lecteur
        .attendre(b']', "la fin du tableau")
        .map_err(faute("un tableau"))?;
    Ok(lus)
}

/// Lit un corps qui est un tableau, et rien après.
fn lire_une_liste<T, F>(corps: &[u8], element: F) -> Result<Vec<T>, Illisible>
where
    F: FnMut(&mut Lecteur<'_>) -> Result<T, Illisible>,
{
    let mut lecteur = Lecteur::nouveau(corps);
    let lus = lire_un_tableau(&mut lecteur, element)?;
    lecteur.fin().map_err(faute("la liste"))?;
    Ok(lus)
}

/// Saute une valeur JSON sans l'interpréter — ce que porte un champ inconnu.
///
/// Une chaîne (échappements compris : on ne l'interprète pas), un nombre, un
/// mot (`true`, `false`, `null`), un objet ou un tableau, **à moins de
/// [`PROFONDEUR_MAX`] niveaux**.
fn sauter_une_valeur(lecteur: &mut Lecteur<'_>, profondeur: usize) -> Result<(), Illisible> {
    if profondeur >= PROFONDEUR_MAX {
        return Err(Illisible(
            "une valeur imbriquée trop profondément".to_owned(),
        ));
    }
    let plus_bas = profondeur.saturating_add(1);
    lecteur.sauter_blancs();
    match lecteur.regarder() {
        Some(b'"') => {
            lecteur.avancer();
            loop {
                match lecteur.regarder() {
                    None => return Err(Illisible("une chaîne sans sa fin".to_owned())),
                    Some(b'"') => {
                        lecteur.avancer();
                        return Ok(());
                    }
                    Some(b'\\') => {
                        lecteur.avancer();
                        lecteur.avancer();
                    }
                    Some(_) => lecteur.avancer(),
                }
            }
        }
        Some(b'{') => lire_un_objet(lecteur, "une valeur inconnue", |_, lecteur| {
            sauter_une_valeur(lecteur, plus_bas)
        }),
        Some(b'[') => {
            lire_un_tableau(lecteur, |lecteur| sauter_une_valeur(lecteur, plus_bas)).map(|_| ())
        }
        _ => {
            let debut = lecteur.position();
            while matches!(
                lecteur.regarder(),
                Some(b'-' | b'+' | b'.' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
            ) {
                lecteur.avancer();
            }
            if lecteur.position() == debut {
                return Err(Illisible("une valeur attendue".to_owned()));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod essais {
    use super::*;

    fn id(genre: Genre, octet: u8) -> Identifiant {
        Identifiant::depuis_entropie(genre, [octet; 16])
    }

    fn texte(identifiant: Identifiant) -> String {
        identifiant.texte().as_str().to_owned()
    }

    #[test]
    fn la_liste_des_domaines_se_lit_telle_que_l_annuaire_l_ecrit() {
        // **OCTET POUR OCTET CE QU'`asl_api::domaine::DomaineRendu` ÉCRIT** :
        // l'alias absent quand il n'y en a pas, `sorte` en dernier et sur le
        // seul domaine racine.
        let d1 = id(Genre::Domaine, 1);
        let d2 = id(Genre::Domaine, 2);
        let u = id(Genre::Utilisateur, 3);
        let n = id(Genre::Annuaire, 4);
        let corps = format!(
            concat!(
                r#"[{{"domaine":"{}","proprietaire":"{}","alias":"Maison été","heberge_par":"racines","#,
                r#""droits":["administrer","rattacher","voir","localiser"],"sorte":"racine"}},"#,
                r#"{{"domaine":"{}","proprietaire":"{}","heberge_par":"{}","droits":["voir"]}}]"#
            ),
            texte(d1),
            texte(u),
            texte(d2),
            texte(u),
            texte(n)
        );
        let lus = lire_domaines(corps.as_bytes()).expect("la forme de l'annuaire");
        assert_eq!(lus.len(), 2);
        assert_eq!(lus[0].domaine, d1);
        assert_eq!(lus[0].alias.as_deref(), Some("Maison été"));
        assert_eq!(lus[0].heberge_par, Autorite::Racines);
        assert!(lus[0].est_racine());
        assert!(lus[0].peut("localiser"));
        assert!(lus[0].voit_ses_machines());
        assert_eq!(lus[1].alias, None);
        assert_eq!(lus[1].heberge_par, Autorite::Annuaire(n));
        assert!(!lus[1].est_racine());
        assert!(!lus[1].peut("localiser"));
        assert!(lus[1].voit_ses_machines());
        assert_eq!(lire_domaines(b"[]").expect("vide"), Vec::new());
        assert_eq!(lire_domaines(b" [ ] ").expect("des blancs"), Vec::new());
    }

    #[test]
    fn rattacher_seul_ne_voit_pas_les_machines() {
        let corps = format!(
            r#"[{{"domaine":"{}","proprietaire":"{}","heberge_par":"racines","droits":["rattacher"]}}]"#,
            texte(id(Genre::Domaine, 1)),
            texte(id(Genre::Utilisateur, 2))
        );
        let lus = lire_domaines(corps.as_bytes()).expect("elle se lit");
        assert!(!lus[0].voit_ses_machines());
    }

    #[test]
    fn un_champ_inconnu_se_saute_quelle_que_soit_sa_valeur() {
        // **UN ANNUAIRE DE DEMAIN AJOUTE DES CHAMPS** : un nombre, un objet,
        // un tableau d'objets, une chaîne échappée, un mot — tout se saute.
        let corps = format!(
            concat!(
                r#"[{{"futur":{{"a":[1,-2.5e3,{{"b":null}}],"c":"x\"y"}},"domaine":"{}","n":42,"#,
                r#""proprietaire":"{}","vrai":true,"heberge_par":"racines","droits":[],"sorte":"autre"}}]"#
            ),
            texte(id(Genre::Domaine, 1)),
            texte(id(Genre::Utilisateur, 2))
        );
        let lus = lire_domaines(corps.as_bytes()).expect("les inconnus se sautent");
        assert_eq!(lus[0].sorte.as_deref(), Some("autre"));
        assert!(
            !lus[0].est_racine(),
            "une sorte inconnue n'est pas « racine »"
        );
    }

    #[test]
    fn ce_qui_est_connu_est_verifie() {
        let d = texte(id(Genre::Domaine, 1));
        let u = texte(id(Genre::Utilisateur, 2));
        let refus = |corps: String| lire_domaines(corps.as_bytes()).unwrap_err().0;
        // Un champ exigé absent.
        assert!(
            refus(format!(
                r#"[{{"domaine":"{d}","heberge_par":"racines","droits":[]}}]"#
            ))
            .contains("proprietaire")
        );
        // Un identifiant du mauvais genre.
        assert!(
            refus(format!(
                r#"[{{"domaine":"{u}","proprietaire":"{u}","heberge_par":"racines","droits":[]}}]"#
            ))
            .contains("genre")
        );
        // Un hébergeur qui n'est ni `racines` ni un annuaire.
        assert!(
            refus(format!(
                r#"[{{"domaine":"{d}","proprietaire":"{u}","heberge_par":"{u}","droits":[]}}]"#
            ))
            .contains("racines")
        );
        // Un champ en double.
        assert!(refus(format!(
            r#"[{{"domaine":"{d}","domaine":"{d}","proprietaire":"{u}","heberge_par":"racines","droits":[]}}]"#
        ))
        .contains("deux fois"));
        // Des octets après la liste, un objet qui n'en est pas un.
        assert!(lire_domaines(b"[] []").is_err());
        assert!(lire_domaines(b"[1]").is_err());
        assert!(lire_domaines(b"{}").is_err());
        assert!(lire_domaines(b"[").is_err());
        // Un inconnu mal formé, ou trop profond.
        assert!(lire_domaines(br#"[{"x":"sans fin"#).is_err());
        assert!(lire_domaines(br#"[{"x":}]"#).is_err());
        let profond = format!(r#"[{{"x":{}{}}}]"#, "[".repeat(40), "]".repeat(40));
        assert!(
            lire_domaines(profond.as_bytes())
                .unwrap_err()
                .0
                .contains("profondément")
        );
    }

    #[test]
    fn la_recherche_par_alias_rend_l_autorite() {
        let d1 = id(Genre::Domaine, 1);
        let d2 = id(Genre::Domaine, 2);
        let n = id(Genre::Annuaire, 3);
        let corps = format!(
            r#"[{{"domaine":"{}","autorite":"racines"}},{{"domaine":"{}","autorite":"{}"}}]"#,
            texte(d1),
            texte(d2),
            texte(n)
        );
        let lus = lire_domaines_trouves(corps.as_bytes()).expect("elle se lit");
        assert_eq!(
            lus,
            vec![
                DomaineTrouve {
                    domaine: d1,
                    autorite: Autorite::Racines
                },
                DomaineTrouve {
                    domaine: d2,
                    autorite: Autorite::Annuaire(n)
                },
            ]
        );
        assert_eq!(Autorite::Racines.to_string(), "racines");
        assert_eq!(Autorite::Annuaire(n).to_string(), texte(n));
        assert!(lire_domaines_trouves(br#"[{"autorite":"racines"}]"#).is_err());
        assert!(
            lire_domaines_trouves(br#"[{"domaine":"d-x","autorite":"racines","x":1}]"#).is_err()
        );
    }

    #[test]
    fn le_detail_d_un_domaine_porte_ses_groupes_et_ses_machines() {
        let d = id(Genre::Domaine, 1);
        let u = id(Genre::Utilisateur, 2);
        let autre = id(Genre::Utilisateur, 3);
        let m1 = id(Genre::Machine, 4);
        let m2 = id(Genre::Machine, 5);
        let e = id(Genre::Ensemble, 6);
        let corps = format!(
            concat!(
                r#"{{"domaine":"{d}","proprietaire":"{u}","alias":"Maison","heberge_par":"racines","#,
                r#""droits":["administrer","rattacher","voir","localiser"],"#,
                r#""groupes":[{{"groupe":"{e}","domaine":"{d}","sorte":"administrateurs"}},"#,
                r#"{{"groupe":"{e}","domaine":null,"etiquette":"Famille","sorte":"domaine"}}],"#,
                r#""machines":[{{"machine":"{m1}","proprietaire":"{u}","nom":"grenier","alias":"Le Grenier — NAS"}},"#,
                r#"{{"machine":"{m2}","proprietaire":"{autre}"}}]}}"#
            ),
            d = texte(d),
            u = texte(u),
            e = texte(e),
            m1 = texte(m1),
            m2 = texte(m2),
            autre = texte(autre)
        );
        let lu = lire_domaine_detaille(corps.as_bytes()).expect("elle se lit");
        assert_eq!(lu.domaine.alias.as_deref(), Some("Maison"));
        assert_eq!(lu.groupes.len(), 2);
        assert_eq!(lu.groupes[0].sorte, "administrateurs");
        assert_eq!(lu.groupes[1].etiquette.as_deref(), Some("Famille"));
        assert_eq!(
            lu.machines,
            vec![
                MachineDeDomaine {
                    machine: m1,
                    proprietaire: u,
                    nom: Some("grenier".to_owned()),
                    alias: Some("Le Grenier — NAS".to_owned()),
                },
                MachineDeDomaine {
                    machine: m2,
                    proprietaire: autre,
                    nom: None,
                    alias: None,
                },
            ]
        );
    }

    #[test]
    fn un_detail_sans_listes_les_lit_vides_et_refuse_ce_qui_manque() {
        let d = texte(id(Genre::Domaine, 1));
        let u = texte(id(Genre::Utilisateur, 2));
        let corps = format!(
            r#"{{"domaine":"{d}","proprietaire":"{u}","heberge_par":"racines","droits":["voir"],"groupes":[],"machines":[]}}"#
        );
        let lu = lire_domaine_detaille(corps.as_bytes()).expect("elle se lit");
        assert!(lu.groupes.is_empty() && lu.machines.is_empty());
        let sans = format!(
            r#"{{"domaine":"{d}","proprietaire":"{u}","heberge_par":"racines","droits":[],"inconnu":{{}}}}"#
        );
        assert!(lire_domaine_detaille(sans.as_bytes()).is_ok());
        assert!(lire_domaine_detaille(format!("{sans} x").as_bytes()).is_err());
        let machine_sans_proprietaire = format!(
            r#"{{"domaine":"{d}","proprietaire":"{u}","heberge_par":"racines","droits":[],"machines":[{{"machine":"{}","x":0}}]}}"#,
            texte(id(Genre::Machine, 3))
        );
        assert!(
            lire_domaine_detaille(machine_sans_proprietaire.as_bytes())
                .unwrap_err()
                .0
                .contains("proprietaire")
        );
        let groupe_sans_sorte = format!(
            r#"{{"domaine":"{d}","proprietaire":"{u}","heberge_par":"racines","droits":[],"groupes":[{{"groupe":"{}","x":0}}]}}"#,
            texte(id(Genre::Ensemble, 3))
        );
        assert!(lire_domaine_detaille(groupe_sans_sorte.as_bytes()).is_err());
        assert!(lire_domaine_detaille(b"{}").is_err());
    }

    #[test]
    fn les_services_d_une_machine_gardent_leur_annonce_intacte() {
        let s1 = id(Genre::Service, 1);
        let s2 = id(Genre::Service, 2);
        let s3 = id(Genre::Service, 3);
        let n = id(Genre::Annuaire, 4);
        let annonce = r#"{"service":"s-x","bail":{"a":[1,2]},"t":"}"}"#;
        let corps = format!(
            concat!(
                r#"[{{"service":"{s1}","nom":"depot","etat":"annonce","annonce":{annonce}}},"#,
                r#"{{"service":"{s2}","nom":"nas","etat":"parti","volontaire":null}},"#,
                r#"{{"service":"{s3}","nom":"web","etat":"parti","volontaire":true,"sonde_par":"{n}","sonde_locale":false}},"#,
                r#"{{"service":"{s3}","nom":"autre","etat":"suspendu"}}]"#
            ),
            s1 = texte(s1),
            s2 = texte(s2),
            s3 = texte(s3),
            n = texte(n),
            annonce = annonce
        );
        let lus = lire_services(corps.as_bytes()).expect("elle se lit");
        assert_eq!(lus.len(), 4);
        assert_eq!(lus[0].nom, "depot");
        assert_eq!(
            lus[0].etat,
            EtatDeService::Annonce(annonce.as_bytes().to_vec())
        );
        assert_eq!(lus[1].etat, EtatDeService::Parti { volontaire: None });
        assert_eq!(
            lus[2].etat,
            EtatDeService::Parti {
                volontaire: Some(true)
            }
        );
        assert_eq!(lus[2].sonde_par, Some(n));
        assert_eq!(lus[2].sonde_locale, Some(false));
        assert_eq!(lus[3].etat, EtatDeService::Autre("suspendu".to_owned()));
    }

    #[test]
    fn un_service_incoherent_est_refuse() {
        let s = texte(id(Genre::Service, 1));
        let refus = |corps: String| lire_services(corps.as_bytes()).unwrap_err().0;
        assert!(
            refus(format!(
                r#"[{{"service":"{s}","nom":"a","etat":"annonce"}}]"#
            ))
            .contains("sans")
        );
        assert!(
            refus(format!(
                r#"[{{"service":"{s}","nom":"a","etat":"parti","annonce":{{}}}}]"#
            ))
            .contains("pas annoncé")
        );
        assert!(
            refus(format!(
                r#"[{{"service":"{s}","nom":"a","etat":"annonce","annonce":[]}}]"#
            ))
            .contains("objet")
        );
        assert!(
            refus(format!(
                r#"[{{"service":"{s}","nom":"a","etat":"parti","sonde_par":"n-x","sonde_locale":null}}]"#
            ))
            .contains("genre")
        );
        assert!(
            refus(format!(
                r#"[{{"service":"{s}","nom":"a","etat":"parti","sonde_locale":null}}]"#
            ))
            .contains("nul")
        );
        assert!(
            refus(format!(
                r#"[{{"service":"{s}","nom":"a","etat":"parti","volontaire":2}}]"#
            ))
            .contains("booléen")
        );
        assert!(refus(format!(r#"[{{"service":"{s}","etat":"parti"}}]"#)).contains("nom"));
    }

    #[test]
    fn un_alias_s_ecrit_en_pourcent_et_l_espace_n_est_jamais_un_plus() {
        assert_eq!(alias_en_requete("Maison"), "Maison");
        assert_eq!(alias_en_requete("a-b.c_d~e"), "a-b.c_d~e");
        assert_eq!(alias_en_requete("Maison été"), "Maison%20%C3%A9t%C3%A9");
        assert_eq!(
            alias_en_requete("a+b&c=d#e%f/g?"),
            "a%2Bb%26c%3Dd%23e%25f%2Fg%3F"
        );
        // La casse est gardée : l'annuaire la compare.
        assert_ne!(alias_en_requete("maison"), alias_en_requete("Maison"));
    }

    #[test]
    fn une_faute_de_lecture_se_dit_en_toutes_lettres() {
        let faute = Illisible("il manque `domaine`".to_owned());
        assert_eq!(faute.to_string(), "il manque `domaine`");
    }
}
