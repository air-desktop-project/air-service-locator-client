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
        /// La machine qui le porte.
        machine: Identifiant,
        /// Le nom du service.
        service: String,
    },
    /// Dire ce qu'on sait de l'annuaire, et ce qu'on ne sait pas.
    Diagnostic,
    /// Afficher l'aide.
    Aide,
}

/// Un annuaire tel qu'il a été écrit sur la ligne de commande.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cible {
    /// L'hôte, tel qu'écrit : un nom ou une adresse littérale.
    pub hote: String,
    /// Le port.
    pub port: u16,
}

/// L'invocation entière.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// Les annuaires à essayer.
    pub annuaires: Vec<Cible>,
    /// Le fichier de certificats d'autorité, en PEM.
    pub racines: Option<String>,
    /// Le répertoire où vit l'identité de cette machine.
    pub etat: Option<String>,
    /// Le nom exigé du certificat, quand il n'est pas celui de l'hôte.
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
    /// Ce point d'écoute ne se lit pas.
    PointIllisible(String),
    /// Cet identifiant de machine ne se lit pas.
    MachineIllisible(String),
}

impl core::fmt::Display for Faute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RienADire => write!(f, "il n'y a pas de commande — essayez `asl aide`"),
            Self::OptionInconnue(quoi) => write!(f, "l'option `{quoi}` n'existe pas"),
            Self::ValeurManquante(quoi) => write!(f, "l'option `{quoi}` attend une valeur"),
            Self::CommandeInconnue(quoi) => write!(f, "la commande `{quoi}` n'existe pas"),
            Self::ArgumentManquant { commande, quoi } => {
                write!(f, "`asl {commande}` attend {quoi}")
            }
            Self::ArgumentEnTrop(quoi) => write!(f, "`{quoi}` est en trop"),
            Self::AnnuaireIllisible(quoi) => {
                write!(f, "`{quoi}` ne se lit pas comme un `hôte:port`")
            }
            Self::PointIllisible(quoi) => {
                write!(f, "`{quoi}` ne se lit pas comme un `protocole:port`")
            }
            Self::MachineIllisible(quoi) => write!(f, "`{quoi}` n'est pas une machine"),
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
    let (hote, port) = match texte.strip_prefix('[') {
        Some(reste) => {
            let (adresse, apres) = reste.split_once(']').ok_or_else(illisible)?;
            (adresse, apres.strip_prefix(':').ok_or_else(illisible)?)
        }
        None => texte.rsplit_once(':').ok_or_else(illisible)?,
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

/// Lit la ligne de commande.
///
/// **LES OPTIONS VIENNENT AVANT LA COMMANDE**, et cette rigidité est voulue :
/// `asl annonce depot --annuaire x` et `asl --annuaire x annonce depot` se
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
    let mut racines = None;
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
            "--annuaire" => annuaires.push(cible(&valeur()?)?),
            "--racines" => racines = Some(valeur()?),
            "--etat" => etat = Some(valeur()?),
            "--nom" => nom = Some(valeur()?),
            "--aide" => {
                return Ok(Invocation {
                    annuaires,
                    racines,
                    etat,
                    nom,
                    commande: Commande::Aide,
                });
            }
            _ => return Err(Faute::OptionInconnue(mot)),
        }
    };

    let mut suite = restants.collect::<Vec<_>>().into_iter();
    let commande = match commande.as_str() {
        "aide" => Commande::Aide,
        "diagnostic" => Commande::Diagnostic,
        "enrole" => Commande::Enrole {
            code: suite.next().ok_or(Faute::ArgumentManquant {
                commande: "enrole",
                quoi: "le code affiché par l'application",
            })?,
        },
        "annonce" => {
            let service = suite.next().ok_or(Faute::ArgumentManquant {
                commande: "annonce",
                quoi: "un nom de service",
            })?;
            let points = suite
                .by_ref()
                .map(|mot| point(&mot))
                .collect::<Result<Vec<_>, _>>()?;
            if points.is_empty() {
                return Err(Faute::ArgumentManquant {
                    commande: "annonce",
                    quoi: "au moins un `protocole:port`",
                });
            }
            Commande::Annonce { service, points }
        }
        "ou" => {
            let machine = suite.next().ok_or(Faute::ArgumentManquant {
                commande: "ou",
                quoi: "une machine",
            })?;
            let machine = Identifiant::analyser_genre(Genre::Machine, &machine)
                .map_err(|_| Faute::MachineIllisible(machine.clone()))?;
            Commande::Ou {
                machine,
                service: suite.next().ok_or(Faute::ArgumentManquant {
                    commande: "ou",
                    quoi: "un nom de service",
                })?,
            }
        }
        _ => return Err(Faute::CommandeInconnue(commande)),
    };

    if let Some(trop) = suite.next() {
        return Err(Faute::ArgumentEnTrop(trop));
    }

    Ok(Invocation {
        annuaires,
        racines,
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
        assert_eq!(lire(&["aide"]).unwrap().commande, Commande::Aide);
        assert_eq!(
            lire(&["diagnostic"]).unwrap().commande,
            Commande::Diagnostic
        );
        assert_eq!(
            lire(&["enrole", "4K9M2-P7R1T"]).unwrap().commande,
            Commande::Enrole {
                code: "4K9M2-P7R1T".to_owned()
            }
        );
        let annonce = lire(&["annonce", "depot", "tcp:8080"]).unwrap().commande;
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
        let lu = lire(&["--annuaire", "[2001:db8::1]:6630", "diagnostic"]).unwrap();
        assert_eq!(
            lu.annuaires,
            vec![Cible {
                hote: "2001:db8::1".to_owned(),
                port: 6630
            }]
        );
    }

    #[test]
    fn un_annuaire_se_lit_par_son_nom_ou_par_une_adresse_v4() {
        let lu = lire(&[
            "--annuaire",
            "nitrogen.example:6630",
            "--annuaire",
            "203.0.113.7:6630",
            "diagnostic",
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
            assert_eq!(
                lire(&["--annuaire", quoi, "diagnostic"]),
                Err(Faute::AnnuaireIllisible(quoi.to_owned())),
                "{quoi}"
            );
        }
    }

    #[test]
    fn une_annonce_prend_autant_de_points_qu_on_lui_en_donne() {
        let lu = lire(&["annonce", "depot", "tcp:8080", "udp:9000"]).unwrap();
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
            lire(&["annonce", "depot"]),
            Err(Faute::ArgumentManquant {
                commande: "annonce",
                quoi: "au moins un `protocole:port`"
            })
        );
    }

    #[test]
    fn un_point_mal_ecrit_est_refuse() {
        for quoi in ["8080", "sctp:8080", "tcp:", "tcp:0", "tcp:70000"] {
            assert_eq!(
                lire(&["annonce", "depot", quoi]),
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
            lire(&["ou", texte.as_str(), "depot"]),
            Err(Faute::MachineIllisible(texte.as_str().to_owned()))
        );

        let machine = Identifiant::depuis_entropie(Genre::Machine, [7; 16]);
        let texte = machine.texte();
        let lu = lire(&["ou", texte.as_str(), "depot"]).unwrap();
        assert_eq!(
            lu.commande,
            Commande::Ou {
                machine,
                service: "depot".to_owned()
            }
        );
    }

    #[test]
    fn les_arguments_en_trop_sont_refuses() {
        assert_eq!(
            lire(&["diagnostic", "et", "puis"]),
            Err(Faute::ArgumentEnTrop("et".to_owned()))
        );
        assert_eq!(
            lire(&["enrole", "4K9M2P7R1T", "encore"]),
            Err(Faute::ArgumentEnTrop("encore".to_owned()))
        );
    }

    #[test]
    fn une_option_sans_valeur_est_refusee() {
        for quoi in ["--annuaire", "--racines", "--etat", "--nom"] {
            assert_eq!(lire(&[quoi]), Err(Faute::ValeurManquante(quoi.to_owned())));
        }
    }

    #[test]
    fn ce_qu_on_ne_connait_pas_est_dit_et_non_ignore() {
        // **UNE OPTION IGNORÉE EST PIRE QU'UNE OPTION REFUSÉE** : l'utilisateur
        // croit avoir demandé quelque chose, et rien ne le détrompe.
        assert_eq!(
            lire(&["--verbeux", "diagnostic"]),
            Err(Faute::OptionInconnue("--verbeux".to_owned()))
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
            "--racines",
            "/etc/asl/ca.pem",
            "--etat",
            "/var/lib/asl",
            "--nom",
            "nitrogen.example",
            "diagnostic",
        ])
        .unwrap();
        assert_eq!(lu.racines.as_deref(), Some("/etc/asl/ca.pem"));
        assert_eq!(lu.etat.as_deref(), Some("/var/lib/asl"));
        assert_eq!(lu.nom.as_deref(), Some("nitrogen.example"));

        assert_eq!(
            lire(&["diagnostic", "--racines", "/etc/asl/ca.pem"]),
            Err(Faute::ArgumentEnTrop("--racines".to_owned()))
        );
    }

    #[test]
    fn l_aide_se_demande_avant_toute_configuration() {
        // `asl --aide` doit répondre même quand rien n'est configuré : c'est la
        // commande qu'on tape justement parce qu'on ne sait pas quoi configurer.
        assert_eq!(lire(&["--aide"]).unwrap().commande, Commande::Aide);
        assert_eq!(
            lire(&["--annuaire", "[::1]:6630", "--aide"])
                .unwrap()
                .commande,
            Commande::Aide
        );
    }
}
