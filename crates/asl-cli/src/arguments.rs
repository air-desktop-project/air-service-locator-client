//! Ce que l'utilisateur a tapé, et ce que cela veut dire.
//!
//! # POURQUOI CETTE GRAMMAIRE EST ÉCRITE À LA MAIN
//!
//! Pas par principe : par mesure. Elle tient en deux cents lignes, elle n'a ni
//! sous-commandes imbriquées, ni complétion, ni valeurs par défaut calculées.
//! Un analyseur d'arguments tiers apporterait tout cela — et sa centaine de
//! crates — dans le verrou d'un dépôt dont `check-sans-c.sh` doit inspecter le
//! graphe construit à chaque passage.
//!
//! **La contrepartie est réelle** : pas de `--annuaire=x` collé, pas
//! d'abréviations, pas de messages d'erreur qui suggèrent la bonne orthographe.
//! Le jour où l'utilitaire aura des options qui se composent, la balance
//! changera, et ce fichier devra céder.
//!
//! # CE QUI EST ÉPROUVÉ ICI, ET NULLE PART AILLEURS
//!
//! C'est la seule partie de `asl` qui soit une pure fonction : du texte entre,
//! une décision sort. Le reste ouvre des sockets et lit des fichiers. Les essais
//! de ce module sont donc les seuls qui puissent être exhaustifs, et ils le sont.

use asl_client::renvoi::ASL_DIRECTORY;
use asl_id::{Genre, Identifiant};
use asl_proto::{PointEcoute, Port, Protocole};

/// Ce que `asl` doit faire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Commande {
    /// Lier une clé neuve à cette machine, avec un code à usage unique.
    Enrole {
        /// Le code affiché par l'application.
        code: String,
    },
    /// Annoncer un service, et TENIR l'annonce.
    Annonce {
        /// Le nom du service.
        service: String,
        /// Ses points d'écoute.
        points: Vec<PointEcoute>,
    },
    /// Demander où joindre un service.
    Ou {
        /// La machine qui le porte — ou aucune : toutes les instances du nom
        /// que ce compte a le droit de voir (`GET /v1/ou?service=`).
        machine: Option<Identifiant>,
        /// Le nom du service.
        service: String,
    },
    /// Demander où joindre un annuaire local — son `asl-directory`, résolu
    /// sous le `n-…` de son titulaire (`annuaires.md` §2 quinquies).
    OuAnnuaire {
        /// L'annuaire : le `n-…` de son titulaire.
        annuaire: Identifiant,
    },
    /// Les machines d'un utilisateur que ce compte a le droit de voir.
    Machines {
        /// L'utilisateur — ou aucun : le compte de cette machine, celui
        /// qu'`asl identity` rend.
        compte: Option<Identifiant>,
    },
    /// Les appareils enrôlés sur le compte de cette machine, révoqués compris.
    Enroles {
        /// Un compte, quand il est nommé : **ce ne peut être que le
        /// propriétaire de cette machine** — les appareils d'un compte ne se
        /// voient que depuis ce compte (`modele.md` §2.2, C13). Le nommer
        /// n'est admis que pour le confirmer ; un autre est refusé avant
        /// toute requête.
        compte: Option<Identifiant>,
    },
    /// Les domaines que ce compte voit (`GET /v1/domaines`, serveur 0.39.0).
    Domaines,
    /// Un domaine, ses machines et leurs services.
    Domaine {
        /// Le domaine, par son `d-…` ou par son alias.
        cible: CibleDeDomaine,
        /// `--where` : résoudre aussi l'adresse de chaque service listé.
        ou: bool,
    },
    /// L'état de la voie entre les deux racines, vu de celle qu'on a jointe.
    Replication,
    /// L'écho de cette machine : annoncer `asl-echo`, tenir le bail sur la
    /// socket où il écoute, et répondre aux sondes autorisées
    /// (`protocole.md` §3 quater).
    Echo {
        /// La passerelle UPnP : active par défaut, `--no-upnp` la coupe
        /// (décision 95 ; E15).
        upnp: bool,
        /// `--verbose` : dire aussi ce que la passerelle tait d'habitude.
        bavard: bool,
    },
    /// Sonder l'écho d'une machine, d'ici, et vérifier que c'est bien elle.
    Ping {
        /// La machine : son `m-…`, ou un nom ou un alias que ce compte voit.
        cible: CibleDeMachine,
    },
    /// La liste des racines, demandée à une racine et VÉRIFIÉE : chaque clé
    /// se déduit en son identifiant (décision 56).
    Racines,
    /// Dire qui est cette machine et pour qui elle agit, **hors ligne**.
    Identite,
    /// Dire ce qu'on sait de l'annuaire, et ce qu'on ne sait pas.
    Diagnostic,
    /// Afficher l'aide.
    Aide,
    /// Afficher la version et le commit, puis s'arrêter.
    Version,
}

/// Un domaine tel qu'il a été écrit : son identifiant, ou son alias.
///
/// **UN `d-…` VALIDE EST UN IDENTIFIANT, TOUT LE RESTE UN ALIAS.** Un alias
/// est du texte libre, et rien n'empêche d'en poser un qui ressemble à un
/// identifiant ; celui-là se désigne par le `d-…` de son domaine, que
/// `asl domains` donne.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CibleDeDomaine {
    /// Le domaine, nommé par son identifiant.
    Identifiant(Identifiant),
    /// Un alias — **sensible à la casse**, comme partout.
    Alias(String),
}

/// Une machine telle qu'elle a été écrite : son identifiant, ou ce qui la
/// nomme.
///
/// **UN `m-…` VALIDE EST UN IDENTIFIANT, TOUT LE RESTE UN NOM OU UN ALIAS**
/// (décision 93 ; E12), cherché parmi les machines que ce compte voit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CibleDeMachine {
    /// La machine, nommée par son identifiant.
    Identifiant(Identifiant),
    /// Un nom ou un alias — **sensible à la casse**, comme partout.
    Nom(String),
}

/// L'option propre à `asl domain` : résoudre chaque service listé.
///
/// **LE NOM DE LA COMMANDE QUI FAIT CELA**, et non une lettre : `asl where`
/// est le verbe qui résout, `--where` dit « et faites-le pour chacun ».
pub const OPTION_WHERE: &str = "--where";

/// L'option d'`asl echo` qui coupe la passerelle UPnP (décision 95 ; E15).
pub const OPTION_NO_UPNP: &str = "--no-upnp";

/// L'option d'`asl echo` qui dit aussi ce que la passerelle tait d'habitude
/// — le trou IPv6 absent, une réponse SSDP écartée (décision 97 ; E20).
pub const OPTION_VERBOSE: &str = "--verbose";

/// Un annuaire tel qu'il a été écrit sur la ligne de commande.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cible {
    /// L'hôte, tel qu'écrit : un nom ou une adresse littérale.
    pub hote: String,
    /// Le port.
    pub port: u16,
    /// L'identité `n-…` qu'on doit trouver au bout (`--directory
    /// <locateur>=<n-…>`, décision 58).
    ///
    /// **ELLE N'EST PLUS FACULTATIVE** (décision 58, étape 5) : sans elle,
    /// rien ne dit qui croire au bout, depuis que l'autorité d'hier est
    /// retirée.
    pub identite: Identifiant,
}

/// L'invocation entière.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// Les annuaires à essayer.
    pub annuaires: Vec<Cible>,
    /// Le répertoire où vit l'identité de cette machine.
    pub etat: Option<String>,
    /// Le nom à mettre dans `:authority`, quand il n'est pas celui de
    /// l'hôte. Il ne prouve rien (C20).
    pub nom: Option<String>,
    /// Ce qu'il faut faire.
    pub commande: Commande,
}

/// Ce qui peut clocher dans ce qui a été tapé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Faute {
    /// Aucune commande.
    RienADire,
    /// Une option qu'on ne connaît pas.
    OptionInconnue(String),
    /// Une option sans sa valeur.
    ValeurManquante(String),
    /// Une option qui a existé, et qui n'existe plus : on dit quoi faire.
    OptionRetiree(&'static str),
    /// Une commande qu'on ne connaît pas.
    CommandeInconnue(String),
    /// Il manque un argument à la commande.
    ArgumentManquant {
        /// La commande.
        commande: &'static str,
        /// Ce qui manque.
        quoi: &'static str,
    },
    /// Un argument de trop.
    ArgumentEnTrop(String),
    /// Cet annuaire ne se lit pas.
    AnnuaireIllisible(String),
    /// Cet annuaire ne dit pas qui l'on doit trouver au bout.
    IdentiteManquante(String),
    /// Ce point d'écoute ne se lit pas.
    PointIllisible(String),
    /// Cet identifiant de machine ne se lit pas.
    MachineIllisible(String),
    /// Cet identifiant d'utilisateur ne se lit pas.
    UtilisateurIllisible(String),
    /// Un annuaire (`n-…`) suivi d'un autre nom qu'`asl-directory`.
    AutreNomSousUnAnnuaire(String),
    /// `asl-directory` sous autre chose que le `n-…` d'un annuaire.
    AslDirectorySansAnnuaire,
}

impl core::fmt::Display for Faute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RienADire => write!(f, "il n'y a pas de commande — essayez `asl help`"),
            Self::OptionInconnue(quoi) => write!(f, "l'option `{quoi}` n'existe pas"),
            Self::ValeurManquante(quoi) => write!(f, "l'option `{quoi}` attend une valeur"),
            // **LA SEULE OPTION RETIRÉE, ET CE QU'ON FAIT À LA PLACE** : la
            // décision 58 est allée au bout, un annuaire se croit par sa clé.
            Self::OptionRetiree(quoi) => write!(
                f,
                "`{quoi}` n'existe plus : un annuaire se croit par sa clé, plus par une \
                 autorité — `--directory <hôte:port>=<n-…>`, ou rien pour les racines \
                 embarquées (`asl roots` les liste)"
            ),
            Self::CommandeInconnue(quoi) => write!(f, "la commande `{quoi}` n'existe pas"),
            Self::ArgumentManquant { commande, quoi } => {
                write!(f, "`asl {commande}` attend {quoi}")
            }
            Self::ArgumentEnTrop(quoi) => write!(f, "`{quoi}` est en trop"),
            Self::AnnuaireIllisible(quoi) => {
                write!(f, "`{quoi}` ne se lit pas comme un `hôte:port`")
            }
            Self::IdentiteManquante(quoi) => write!(
                f,
                "`{quoi}` ne dit pas qui l'on doit trouver au bout : écrivez `{quoi}=n-…`, \
                 l'identité de l'annuaire (`asl roots` donne celle des racines)"
            ),
            Self::PointIllisible(quoi) => {
                write!(f, "`{quoi}` ne se lit pas comme un `protocole:port`")
            }
            Self::MachineIllisible(quoi) => write!(f, "`{quoi}` n'est pas une machine"),
            Self::UtilisateurIllisible(quoi) => {
                write!(f, "`{quoi}` n'est pas un utilisateur (u-…)")
            }
            // **SOUS UN `n-…`, UN SEUL NOM SE RÉSOUT** (décision 73) : un
            // annuaire n'annonce pas de services, il en est un.
            Self::AutreNomSousUnAnnuaire(nom) => write!(
                f,
                "sous un annuaire (n-…), seul `asl-directory` se résout, pas `{nom}` : \
                 `asl where <n-…> asl-directory` ; un service se résout sous sa machine (m-…)"
            ),
            Self::AslDirectorySansAnnuaire => write!(
                f,
                "`asl-directory` se résout sous le n-… d'un annuaire local — celui de son \
                 titulaire : `asl where <n-…> asl-directory`"
            ),
        }
    }
}

/// Lit `hôte:port`, en acceptant la forme `[::1]:6630` d'IPv6.
///
/// **LES CROCHETS NE SONT PAS UNE COMMODITÉ** : sans eux, `::1:6630` est
/// ambigu — le dernier `:` sépare-t-il un port, ou un groupe d'adresse ? RFC
/// 3986 §3.2.2 tranche par les crochets, et les refuser rendrait tout annuaire
/// IPv6 littéral inatteignable.
fn cible(texte: &str) -> Result<Cible, Faute> {
    let illisible = || Faute::AnnuaireIllisible(texte.to_owned());
    // **`=n-…` DIT QUI L'ON DOIT TROUVER AU BOUT**, comme `--federation` côté
    // serveur. Aucune adresse ne contient de `=`. Sans lui, rien ne dit qui
    // croire : l'autorité d'hier, qui le disait à sa place, est retirée.
    let Some((locateur, n)) = texte.split_once('=') else {
        return Err(Faute::IdentiteManquante(texte.to_owned()));
    };
    let identite = Identifiant::analyser_genre(Genre::Annuaire, n).map_err(|_| illisible())?;
    let (hote, port) = match locateur.strip_prefix('[') {
        Some(reste) => {
            let (adresse, apres) = reste.split_once(']').ok_or_else(illisible)?;
            (adresse, apres.strip_prefix(':').ok_or_else(illisible)?)
        }
        None => locateur.rsplit_once(':').ok_or_else(illisible)?,
    };
    if hote.is_empty() {
        return Err(illisible());
    }
    let port = port.parse::<u16>().map_err(|_| illisible())?;
    if port == 0 {
        return Err(illisible());
    }
    Ok(Cible {
        hote: hote.to_owned(),
        port,
        identite,
    })
}

/// Lit `protocole:port`.
fn point(texte: &str) -> Result<PointEcoute, Faute> {
    let illisible = || Faute::PointIllisible(texte.to_owned());
    let (protocole, port) = texte.split_once(':').ok_or_else(illisible)?;
    let protocole = Protocole::analyser(protocole).map_err(|_| illisible())?;
    let port = Port::analyser(port).map_err(|_| illisible())?;
    Ok(PointEcoute::nouveau(protocole, port))
}

/// Lit un `u-…` s'il y en a un.
///
/// Un mot présent qui n'est pas un utilisateur est refusé comme tel — et non
/// pris pour « aucun », ce qui ferait répondre sur le mauvais compte à une
/// faute de frappe.
fn utilisateur_facultatif(mot: Option<String>) -> Result<Option<Identifiant>, Faute> {
    mot.map(|texte| {
        Identifiant::analyser_genre(Genre::Utilisateur, &texte)
            .map_err(|_| Faute::UtilisateurIllisible(texte.clone()))
    })
    .transpose()
}

/// Lit la ligne de commande.
///
/// **LES OPTIONS VIENNENT AVANT LA COMMANDE**, et cette rigidité est voulue :
/// `asl announce depot --directory x` et `asl --directory x announce depot` se
/// liraient pareil dans un analyseur permissif, et l'un des deux mentirait le
/// jour où une commande prendra une option qui lui est propre.
///
/// # Erreurs
///
/// Tout ce que [`Faute`] énumère.
pub fn analyser<I>(arguments: I) -> Result<Invocation, Faute>
where
    I: IntoIterator<Item = String>,
{
    let mut restants = arguments.into_iter().peekable();
    let mut annuaires = Vec::new();
    let mut etat = None;
    let mut nom = None;

    let commande = loop {
        let Some(mot) = restants.next() else {
            return Err(Faute::RienADire);
        };
        if !mot.starts_with("--") {
            break mot;
        }
        let mut valeur = || restants.next().ok_or(Faute::ValeurManquante(mot.clone()));
        match mot.as_str() {
            "--directory" => annuaires.push(cible(&valeur()?)?),
            // Refusée tout de suite, valeur ou non : ce n'est pas la valeur
            // qui manque, c'est l'option qui n'est plus.
            "--roots" => return Err(Faute::OptionRetiree("--roots")),
            "--state" => etat = Some(valeur()?),
            "--name" => nom = Some(valeur()?),
            "--help" | "--version" => {
                return Ok(Invocation {
                    annuaires,
                    etat,
                    nom,
                    commande: if mot == "--help" {
                        Commande::Aide
                    } else {
                        Commande::Version
                    },
                });
            }
            _ => return Err(Faute::OptionInconnue(mot)),
        }
    };

    let mut suite = restants.collect::<Vec<_>>().into_iter();
    let commande = match commande.as_str() {
        "help" => Commande::Aide,
        "version" => Commande::Version,
        "diagnose" => Commande::Diagnostic,
        "enroll" => Commande::Enrole {
            code: suite.next().ok_or(Faute::ArgumentManquant {
                commande: "enroll",
                quoi: "le code affiché par l'application",
            })?,
        },
        "announce" => {
            let service = suite.next().ok_or(Faute::ArgumentManquant {
                commande: "announce",
                quoi: "un nom de service",
            })?;
            let points = suite
                .by_ref()
                .map(|mot| point(&mot))
                .collect::<Result<Vec<_>, _>>()?;
            if points.is_empty() {
                return Err(Faute::ArgumentManquant {
                    commande: "announce",
                    quoi: "au moins un `protocole:port`",
                });
            }
            Commande::Annonce { service, points }
        }
        // **UN ARGUMENT, OU DEUX.** `asl where <machine> <service>` vise une
        // machine ; `asl where <service>` demande toutes les instances du nom
        // qu'on a le droit de voir. Un `m-…` seul serait une machine sans
        // service, et c'est dit comme tel.
        "where" => {
            let premier = suite.next().ok_or(Faute::ArgumentManquant {
                commande: "where",
                quoi: "un nom de service, ou une machine et un nom de service",
            })?;
            // **UN `n-…` N'EST ADMIS QUE DEVANT `asl-directory`** (décision
            // 73) : c'est le seul nom qui se résout sous un annuaire, et le
            // seul qui ne se résout sous rien d'autre.
            let annuaire = Identifiant::analyser_genre(Genre::Annuaire, &premier).ok();
            match (suite.next(), annuaire) {
                (Some(service), Some(annuaire)) if service == ASL_DIRECTORY => {
                    Commande::OuAnnuaire { annuaire }
                }
                (Some(service), Some(_)) => return Err(Faute::AutreNomSousUnAnnuaire(service)),
                (Some(service), None) => {
                    let machine = Identifiant::analyser_genre(Genre::Machine, &premier)
                        .map_err(|_| Faute::MachineIllisible(premier.clone()))?;
                    if service == ASL_DIRECTORY {
                        return Err(Faute::AslDirectorySansAnnuaire);
                    }
                    Commande::Ou {
                        machine: Some(machine),
                        service,
                    }
                }
                (None, Some(_)) => {
                    return Err(Faute::ArgumentManquant {
                        commande: "where",
                        quoi: "`asl-directory` après l'annuaire",
                    });
                }
                (None, None) => {
                    if Identifiant::analyser_genre(Genre::Machine, &premier).is_ok() {
                        return Err(Faute::ArgumentManquant {
                            commande: "where",
                            quoi: "un nom de service après la machine",
                        });
                    }
                    // Aucune recherche générale ne rend un annuaire (décision
                    // 84) : on le résout par son `n-…`.
                    if premier == ASL_DIRECTORY {
                        return Err(Faute::AslDirectorySansAnnuaire);
                    }
                    Commande::Ou {
                        machine: None,
                        service: premier,
                    }
                }
            }
        }
        // **UN COMPTE, OU AUCUN.** Sans argument, c'est le compte de cette
        // machine — ce qu'on veut neuf fois sur dix, et qu'il fallait jusqu'ici
        // aller recopier dans `asl identity`.
        "machines" => Commande::Machines {
            compte: utilisateur_facultatif(suite.next())?,
        },
        "enrolled" => Commande::Enroles {
            compte: utilisateur_facultatif(suite.next())?,
        },
        "domains" => Commande::Domaines,
        // **LA SEULE OPTION QUI SUIT UNE COMMANDE**, parce qu'elle n'a de
        // sens que pour celle-ci : `--where` avant ou après le domaine. Tout
        // autre mot qui commence par `--` y est refusé plutôt que pris pour
        // un alias — un alias qui commencerait ainsi se désigne par son `d-…`.
        "domain" => {
            let mut ou = false;
            let mut cible = None;
            for mot in suite.by_ref() {
                if mot == OPTION_WHERE {
                    ou = true;
                } else if mot.starts_with("--") {
                    return Err(Faute::OptionInconnue(mot));
                } else if cible.is_none() {
                    cible = Some(mot);
                } else {
                    return Err(Faute::ArgumentEnTrop(mot));
                }
            }
            let cible = cible.ok_or(Faute::ArgumentManquant {
                commande: "domain",
                quoi: "un domaine : son `d-…` ou son alias",
            })?;
            let cible = match Identifiant::analyser_genre(Genre::Domaine, &cible) {
                Ok(domaine) => CibleDeDomaine::Identifiant(domaine),
                Err(_) => CibleDeDomaine::Alias(cible),
            };
            Commande::Domaine { cible, ou }
        }
        // Sans argument : l'annuaire joint dit lui-même de quelle voie il
        // parle, et le client n'a pas à nommer un pair qu'il ne connaît pas.
        "replication" => Commande::Replication,
        // **DEUX OPTIONS, APRÈS LA COMMANDE**, parce qu'elles n'ont de sens
        // que pour elle : `--no-upnp` coupe la passerelle (E15), `--verbose`
        // dit ce qu'elle tait d'habitude (E20). Tout autre mot est refusé.
        "echo" => {
            let mut upnp = true;
            let mut bavard = false;
            for mot in suite.by_ref() {
                match mot.as_str() {
                    OPTION_NO_UPNP => upnp = false,
                    OPTION_VERBOSE => bavard = true,
                    _ if mot.starts_with("--") => return Err(Faute::OptionInconnue(mot)),
                    _ => return Err(Faute::ArgumentEnTrop(mot)),
                }
            }
            Commande::Echo { upnp, bavard }
        }
        "ping" => {
            let cible = suite.next().ok_or(Faute::ArgumentManquant {
                commande: "ping",
                quoi: "une machine : son `m-…`, son nom ou son alias",
            })?;
            // Un mot en `--` n'est pas un nom : c'est une option que `ping`
            // n'a pas. Une machine dont le nom commencerait ainsi se sonde
            // par son `m-…`.
            if cible.starts_with("--") {
                return Err(Faute::OptionInconnue(cible));
            }
            let cible = match Identifiant::analyser_genre(Genre::Machine, &cible) {
                Ok(machine) => CibleDeMachine::Identifiant(machine),
                Err(_) => CibleDeMachine::Nom(cible),
            };
            Commande::Ping { cible }
        }
        "roots" => Commande::Racines,
        "identity" => Commande::Identite,
        _ => return Err(Faute::CommandeInconnue(commande)),
    };

    if let Some(trop) = suite.next() {
        return Err(Faute::ArgumentEnTrop(trop));
    }

    Ok(Invocation {
        annuaires,
        etat,
        nom,
        commande,
    })
}

#[cfg(test)]
mod essais {
    use super::*;

    /// Ce que le shell nous passe.
    fn ligne(mots: &[&str]) -> Vec<String> {
        mots.iter().map(|mot| (*mot).to_owned()).collect()
    }

    fn lire(mots: &[&str]) -> Result<Invocation, Faute> {
        analyser(ligne(mots))
    }

    #[test]
    fn une_ligne_vide_ne_dit_rien() {
        assert_eq!(lire(&[]), Err(Faute::RienADire));
    }

    #[test]
    fn les_quatre_commandes_se_lisent() {
        assert_eq!(lire(&["help"]).unwrap().commande, Commande::Aide);
        assert_eq!(lire(&["diagnose"]).unwrap().commande, Commande::Diagnostic);
        assert_eq!(
            lire(&["enroll", "4K9M2-P7R1T"]).unwrap().commande,
            Commande::Enrole {
                code: "4K9M2-P7R1T".to_owned()
            }
        );
        let annonce = lire(&["announce", "depot", "tcp:8080"]).unwrap().commande;
        assert_eq!(
            annonce,
            Commande::Annonce {
                service: "depot".to_owned(),
                points: vec![PointEcoute::nouveau(
                    Protocole::Tcp,
                    Port::depuis_u16(8080).unwrap()
                )],
            }
        );
    }

    #[test]
    fn un_annuaire_ipv6_litteral_se_lit_entre_crochets() {
        // **SANS LES CROCHETS, `::1:6630` EST AMBIGU** — et les refuser rendrait
        // tout annuaire IPv6 littéral inatteignable.
        let lu = lire(&[
            "--directory",
            "[2001:db8::1]:6630=n-0PWT8HZD80QMSPPDZ5CQXXYHQC",
            "diagnose",
        ])
        .unwrap();
        assert_eq!(
            lu.annuaires,
            vec![Cible {
                hote: "2001:db8::1".to_owned(),
                port: 6630,
                identite: Identifiant::analyser_genre(
                    Genre::Annuaire,
                    "n-0PWT8HZD80QMSPPDZ5CQXXYHQC"
                )
                .unwrap()
            }]
        );
    }

    #[test]
    fn un_annuaire_se_lit_par_son_nom_ou_par_une_adresse_v4() {
        let lu = lire(&[
            "--directory",
            "nitrogen.example:6630=n-0PWT8HZD80QMSPPDZ5CQXXYHQC",
            "--directory",
            "203.0.113.7:6630=n-0PWT8HZD80QMSPPDZ5CQXXYHQC",
            "diagnose",
        ])
        .unwrap();
        assert_eq!(lu.annuaires.len(), 2, "l'option est répétable");
        assert_eq!(lu.annuaires[0].hote, "nitrogen.example");
        assert_eq!(lu.annuaires[1].port, 6630);
    }

    #[test]
    fn ce_qui_ne_se_lit_pas_comme_un_annuaire_est_refuse() {
        for quoi in [
            "nitrogen.example",       // pas de port
            "nitrogen.example:",      // port vide
            "nitrogen.example:0",     // le port zéro n'écoute nulle part
            "nitrogen.example:99999", // hors d'un `u16`
            ":6630",                  // pas d'hôte
            "[2001:db8::1:6630",      // crochet non refermé
            "[2001:db8::1]6630",      // pas de `:` après le crochet
        ] {
            let complet = format!("{quoi}=n-0PWT8HZD80QMSPPDZ5CQXXYHQC");
            assert_eq!(
                lire(&["--directory", &complet, "diagnose"]),
                Err(Faute::AnnuaireIllisible(complet.clone())),
                "{quoi}"
            );
        }
    }

    #[test]
    fn un_annuaire_sans_identite_est_refuse_et_l_on_dit_quoi_ecrire() {
        // **LA FORME D'HIER EST RETIRÉE** (décision 58, étape 5) : un
        // `hôte:port` seul ne dit pas qui croire au bout.
        let refus = lire(&["--directory", "nitrogen.example:6630", "diagnose"]);
        assert_eq!(
            refus,
            Err(Faute::IdentiteManquante("nitrogen.example:6630".to_owned()))
        );
        let texte = refus.unwrap_err().to_string();
        assert!(texte.contains("nitrogen.example:6630=n-…"), "{texte}");
    }

    #[test]
    fn roots_n_existe_plus_et_dit_quoi_faire() {
        // **UNE OPTION RETIRÉE SE DIT RETIRÉE**, et non inconnue : qui l'a
        // dans un script doit apprendre ce qui la remplace.
        for ligne in [
            &["--roots", "/etc/asl/ca.pem", "diagnose"][..],
            &["--roots"][..],
        ] {
            let refus = lire(ligne);
            assert_eq!(refus, Err(Faute::OptionRetiree("--roots")));
            let texte = refus.unwrap_err().to_string();
            assert!(texte.contains("n'existe plus"), "{texte}");
            assert!(texte.contains("--directory <hôte:port>=<n-…>"), "{texte}");
        }
    }

    #[test]
    fn une_annonce_prend_autant_de_points_qu_on_lui_en_donne() {
        let lu = lire(&["announce", "depot", "tcp:8080", "udp:9000"]).unwrap();
        let Commande::Annonce { points, .. } = lu.commande else {
            panic!("une annonce");
        };
        assert_eq!(points.len(), 2);
        assert_eq!(points[1].protocole, Protocole::Udp);
    }

    #[test]
    fn une_annonce_sans_point_est_refusee_avant_toute_connexion() {
        // Le daemon l'apprend ici, et non après un aller-retour réseau.
        assert_eq!(
            lire(&["announce", "depot"]),
            Err(Faute::ArgumentManquant {
                commande: "announce",
                quoi: "au moins un `protocole:port`"
            })
        );
    }

    #[test]
    fn un_point_mal_ecrit_est_refuse() {
        for quoi in ["8080", "sctp:8080", "tcp:", "tcp:0", "tcp:70000"] {
            assert_eq!(
                lire(&["announce", "depot", quoi]),
                Err(Faute::PointIllisible(quoi.to_owned())),
                "{quoi}"
            );
        }
    }

    #[test]
    fn ou_exige_une_machine_et_non_n_importe_quel_identifiant() {
        // **UN SERVICE N'EST PAS UNE MACHINE**, et confondre les deux ferait
        // demander à l'annuaire une chose qui n'a pas de sens.
        let service = Identifiant::depuis_entropie(Genre::Service, [7; 16]);
        let texte = service.texte();
        assert_eq!(
            lire(&["where", texte.as_str(), "depot"]),
            Err(Faute::MachineIllisible(texte.as_str().to_owned()))
        );

        let machine = Identifiant::depuis_entropie(Genre::Machine, [7; 16]);
        let texte = machine.texte();
        let lu = lire(&["where", texte.as_str(), "depot"]).unwrap();
        assert_eq!(
            lu.commande,
            Commande::Ou {
                machine: Some(machine),
                service: "depot".to_owned()
            }
        );
    }

    #[test]
    fn un_annuaire_ne_se_resout_que_par_asl_directory() {
        let annuaire = "n-7MSV5RPCXBZH25PQM4ZPE5X87P";
        assert_eq!(
            lire(&["where", annuaire, "asl-directory"])
                .unwrap()
                .commande,
            Commande::OuAnnuaire {
                annuaire: Identifiant::analyser_genre(Genre::Annuaire, annuaire).unwrap()
            }
        );
        // **UN AUTRE NOM SOUS UN `n-…` EST REFUSÉ CLAIREMENT**, et le refus
        // dit la forme qui se tape.
        let refus = lire(&["where", annuaire, "depot"]);
        assert_eq!(
            refus,
            Err(Faute::AutreNomSousUnAnnuaire("depot".to_owned()))
        );
        let texte = refus.unwrap_err().to_string();
        assert!(texte.contains("asl where <n-…> asl-directory"), "{texte}");
        // Un annuaire seul : c'est `asl-directory` qui manque.
        assert_eq!(
            lire(&["where", annuaire]),
            Err(Faute::ArgumentManquant {
                commande: "where",
                quoi: "`asl-directory` après l'annuaire"
            })
        );
        // `asl-directory` sous une machine, ou sans rien : pas un annuaire.
        let machine = Identifiant::depuis_entropie(Genre::Machine, [7; 16]);
        for ligne in [
            &["where", machine.texte().as_str(), "asl-directory"][..],
            &["where", "asl-directory"][..],
        ] {
            let refus = lire(ligne);
            assert_eq!(refus, Err(Faute::AslDirectorySansAnnuaire), "{ligne:?}");
            assert!(refus.unwrap_err().to_string().contains("n-…"));
        }
        assert_eq!(
            lire(&["where", annuaire, "asl-directory", "encore"]),
            Err(Faute::ArgumentEnTrop("encore".to_owned()))
        );
    }

    #[test]
    fn replication_ne_prend_rien() {
        // Pas de pair à nommer : c'est l'annuaire joint qui dit de quelle voie
        // il parle. Un mot de plus est donc un mot de trop.
        assert_eq!(
            lire(&["replication"]).unwrap().commande,
            Commande::Replication
        );
        assert_eq!(
            lire(&["replication", "n-0PWT8HZDQ7V4XK2M9RJ3TB6ANE"]),
            Err(Faute::ArgumentEnTrop(
                "n-0PWT8HZDQ7V4XK2M9RJ3TB6ANE".to_owned()
            ))
        );
    }

    #[test]
    fn roots_ne_prend_rien_et_une_identite_se_dit_par_egal() {
        assert_eq!(lire(&["roots"]).unwrap().commande, Commande::Racines);
        assert_eq!(
            lire(&["roots", "x"]),
            Err(Faute::ArgumentEnTrop("x".to_owned()))
        );
        let lu = lire(&[
            "--directory",
            "[2001:db8::1]:6630=n-0PWT8HZD80QMSPPDZ5CQXXYHQC",
            "roots",
        ])
        .unwrap();
        assert_eq!(lu.annuaires[0].hote, "2001:db8::1");
        assert_eq!(
            lu.annuaires[0].identite.texte().as_str(),
            "n-0PWT8HZD80QMSPPDZ5CQXXYHQC"
        );
        // Une identité qui n'est pas celle d'un annuaire est refusée.
        assert!(matches!(
            lire(&[
                "--directory",
                "[::1]:6630=u-0PWT8HZD80QMSPPDZ5CQXXYHQC",
                "roots"
            ]),
            Err(Faute::AnnuaireIllisible(_))
        ));
    }

    #[test]
    fn les_arguments_en_trop_sont_refuses() {
        assert_eq!(
            lire(&["diagnose", "et", "puis"]),
            Err(Faute::ArgumentEnTrop("et".to_owned()))
        );
        assert_eq!(
            lire(&["enroll", "4K9M2P7R1T", "encore"]),
            Err(Faute::ArgumentEnTrop("encore".to_owned()))
        );
    }

    #[test]
    fn une_option_sans_valeur_est_refusee() {
        for quoi in ["--directory", "--state", "--name"] {
            assert_eq!(lire(&[quoi]), Err(Faute::ValeurManquante(quoi.to_owned())));
        }
    }

    #[test]
    fn ce_qu_on_ne_connait_pas_est_dit_et_non_ignore() {
        // **UNE OPTION IGNORÉE EST PIRE QU'UNE OPTION REFUSÉE** : l'utilisateur
        // croit avoir demandé quelque chose, et rien ne le détrompe.
        assert_eq!(
            lire(&["--verbose", "diagnose"]),
            Err(Faute::OptionInconnue("--verbose".to_owned()))
        );
        assert_eq!(
            lire(&["annoncer"]),
            Err(Faute::CommandeInconnue("annoncer".to_owned()))
        );
    }

    #[test]
    fn les_options_viennent_avant_la_commande() {
        // Après la commande, un `--` est un argument comme un autre — et c'est
        // ce qui rend la lecture non ambiguë.
        let lu = lire(&[
            "--state",
            "/var/lib/asl",
            "--name",
            "nitrogen.example",
            "diagnose",
        ])
        .unwrap();
        assert_eq!(lu.etat.as_deref(), Some("/var/lib/asl"));
        assert_eq!(lu.nom.as_deref(), Some("nitrogen.example"));

        assert_eq!(
            lire(&["diagnose", "--state", "/var/lib/asl"]),
            Err(Faute::ArgumentEnTrop("--state".to_owned()))
        );
    }

    #[test]
    fn ou_avec_un_seul_mot_demande_toutes_les_instances_du_nom() {
        let lu = lire(&["where", "depot"]).unwrap();
        assert_eq!(
            lu.commande,
            Commande::Ou {
                machine: None,
                service: "depot".to_owned()
            }
        );
        // **UNE MACHINE SEULE N'EST PAS UN SERVICE** : c'est un argument qui
        // manque, dit comme tel, et non un nom de service bizarre.
        let machine = Identifiant::depuis_entropie(Genre::Machine, [7; 16]);
        assert!(matches!(
            lire(&["where", machine.texte().as_str()]),
            Err(Faute::ArgumentManquant {
                commande: "where",
                ..
            })
        ));
        assert!(matches!(
            lire(&["where"]),
            Err(Faute::ArgumentManquant {
                commande: "where",
                ..
            })
        ));
    }

    #[test]
    fn machines_prend_un_utilisateur_ou_aucun() {
        let compte = Identifiant::depuis_entropie(Genre::Utilisateur, [7; 16]);
        assert_eq!(
            lire(&["machines", compte.texte().as_str()])
                .unwrap()
                .commande,
            Commande::Machines {
                compte: Some(compte)
            }
        );
        // **SANS ARGUMENT, LE COMPTE DE CETTE MACHINE** — et non une faute.
        assert_eq!(
            lire(&["machines"]).unwrap().commande,
            Commande::Machines { compte: None }
        );
        // Un mot qui n'est pas un utilisateur est refusé, pas pris pour « aucun ».
        let machine = Identifiant::depuis_entropie(Genre::Machine, [7; 16]);
        assert_eq!(
            lire(&["machines", machine.texte().as_str()]),
            Err(Faute::UtilisateurIllisible(
                machine.texte().as_str().to_owned()
            ))
        );
        assert_eq!(
            lire(&["machines", compte.texte().as_str(), "encore"]),
            Err(Faute::ArgumentEnTrop("encore".to_owned()))
        );
    }

    #[test]
    fn enrolled_prend_un_utilisateur_ou_aucun() {
        // La même grammaire que `machines` : le compte est facultatif, et ce
        // qu'on en fait — le refuser s'il n'est pas le nôtre — n'est pas
        // l'affaire de l'analyseur, qui ne connaît pas l'identité.
        let compte = Identifiant::depuis_entropie(Genre::Utilisateur, [7; 16]);
        assert_eq!(
            lire(&["enrolled"]).unwrap().commande,
            Commande::Enroles { compte: None }
        );
        assert_eq!(
            lire(&["enrolled", compte.texte().as_str()])
                .unwrap()
                .commande,
            Commande::Enroles {
                compte: Some(compte)
            }
        );
        let appareil = Identifiant::depuis_entropie(Genre::Appareil, [7; 16]);
        assert_eq!(
            lire(&["enrolled", appareil.texte().as_str()]),
            Err(Faute::UtilisateurIllisible(
                appareil.texte().as_str().to_owned()
            ))
        );
        assert_eq!(
            lire(&["enrolled", compte.texte().as_str(), "encore"]),
            Err(Faute::ArgumentEnTrop("encore".to_owned()))
        );
    }

    #[test]
    fn domains_ne_prend_rien() {
        assert_eq!(lire(&["domains"]).unwrap().commande, Commande::Domaines);
        assert_eq!(
            lire(&["domains", "Maison"]),
            Err(Faute::ArgumentEnTrop("Maison".to_owned()))
        );
    }

    #[test]
    fn domain_prend_un_identifiant_ou_un_alias_et_where_de_part_ou_d_autre() {
        let domaine = Identifiant::depuis_entropie(Genre::Domaine, [7; 16]);
        assert_eq!(
            lire(&["domain", domaine.texte().as_str()])
                .unwrap()
                .commande,
            Commande::Domaine {
                cible: CibleDeDomaine::Identifiant(domaine),
                ou: false
            }
        );
        // **L'ALIAS EST GARDÉ TEL QU'ÉCRIT** : la casse compte, les espaces
        // et les accents aussi — le shell l'a déjà découpé.
        for ligne in [
            &["domain", "Maison été", "--where"][..],
            &["domain", "--where", "Maison été"][..],
        ] {
            assert_eq!(
                lire(ligne).unwrap().commande,
                Commande::Domaine {
                    cible: CibleDeDomaine::Alias("Maison été".to_owned()),
                    ou: true
                },
                "{ligne:?}"
            );
        }
        // Un identifiant d'un autre genre n'est pas un domaine : c'est un
        // alias, que l'annuaire ne trouvera pas — et le dira.
        let machine = Identifiant::depuis_entropie(Genre::Machine, [7; 16]);
        assert_eq!(
            lire(&["domain", machine.texte().as_str()])
                .unwrap()
                .commande,
            Commande::Domaine {
                cible: CibleDeDomaine::Alias(machine.texte().as_str().to_owned()),
                ou: false
            }
        );
        assert_eq!(
            lire(&["domain"]),
            Err(Faute::ArgumentManquant {
                commande: "domain",
                quoi: "un domaine : son `d-…` ou son alias"
            })
        );
        assert_eq!(
            lire(&["domain", "--where"]),
            Err(Faute::ArgumentManquant {
                commande: "domain",
                quoi: "un domaine : son `d-…` ou son alias"
            })
        );
        assert_eq!(
            lire(&["domain", "Maison", "Grenier"]),
            Err(Faute::ArgumentEnTrop("Grenier".to_owned()))
        );
        assert_eq!(
            lire(&["domain", "Maison", "--verbose"]),
            Err(Faute::OptionInconnue("--verbose".to_owned()))
        );
    }

    #[test]
    fn echo_prend_no_upnp_et_verbose_et_rien_d_autre() {
        assert_eq!(
            lire(&["echo"]).unwrap().commande,
            Commande::Echo {
                upnp: true,
                bavard: false
            }
        );
        assert_eq!(
            lire(&["echo", "--no-upnp"]).unwrap().commande,
            Commande::Echo {
                upnp: false,
                bavard: false
            }
        );
        assert_eq!(
            lire(&["echo", "--verbose", "--no-upnp"]).unwrap().commande,
            Commande::Echo {
                upnp: false,
                bavard: true
            }
        );
        assert_eq!(
            lire(&["echo", "--upnp"]),
            Err(Faute::OptionInconnue("--upnp".to_owned()))
        );
        assert_eq!(
            lire(&["echo", "grenier"]),
            Err(Faute::ArgumentEnTrop("grenier".to_owned()))
        );
    }

    #[test]
    fn ping_prend_une_machine_un_nom_ou_un_alias() {
        let machine = Identifiant::depuis_entropie(Genre::Machine, [7; 16]);
        assert_eq!(
            lire(&["ping", machine.texte().as_str()]).unwrap().commande,
            Commande::Ping {
                cible: CibleDeMachine::Identifiant(machine)
            }
        );
        // **UN AUTRE IDENTIFIANT N'EST PAS UNE MACHINE** : c'est un nom, que
        // l'annuaire ne connaîtra pas — et asl ping le dira.
        for mot in ["grenier", "La cave", "u-0PWT8HZD80QMSPPDZ5CQXXYHQC"] {
            assert_eq!(
                lire(&["ping", mot]).unwrap().commande,
                Commande::Ping {
                    cible: CibleDeMachine::Nom(mot.to_owned())
                }
            );
        }
        assert_eq!(
            lire(&["ping"]),
            Err(Faute::ArgumentManquant {
                commande: "ping",
                quoi: "une machine : son `m-…`, son nom ou son alias"
            })
        );
        assert_eq!(
            lire(&["ping", "--count", "3"]),
            Err(Faute::OptionInconnue("--count".to_owned()))
        );
        assert_eq!(
            lire(&["ping", "grenier", "cave"]),
            Err(Faute::ArgumentEnTrop("cave".to_owned()))
        );
    }

    #[test]
    fn identite_se_demande_sans_rien() {
        assert_eq!(lire(&["identity"]).unwrap().commande, Commande::Identite);
    }

    #[test]
    fn la_version_se_demande_comme_l_aide() {
        // `asl --version` et `asl version` : sans configuration, comme l'aide —
        // c'est ce qu'on tape pour savoir ce qu'on a installé.
        assert_eq!(lire(&["--version"]).unwrap().commande, Commande::Version);
        assert_eq!(lire(&["version"]).unwrap().commande, Commande::Version);
        assert_eq!(
            lire(&[
                "--directory",
                "[::1]:6630=n-0PWT8HZD80QMSPPDZ5CQXXYHQC",
                "--version"
            ])
            .unwrap()
            .commande,
            Commande::Version
        );
    }

    #[test]
    fn l_aide_se_demande_avant_toute_configuration() {
        // `asl --aide` doit répondre même quand rien n'est configuré : c'est la
        // commande qu'on tape justement parce qu'on ne sait pas quoi configurer.
        assert_eq!(lire(&["--help"]).unwrap().commande, Commande::Aide);
        assert_eq!(
            lire(&[
                "--directory",
                "[::1]:6630=n-0PWT8HZD80QMSPPDZ5CQXXYHQC",
                "--help"
            ])
            .unwrap()
            .commande,
            Commande::Aide
        );
    }
}
