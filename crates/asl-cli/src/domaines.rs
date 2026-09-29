//! `asl domains` et `asl domain` — ce qu'un compte voit de ses domaines, mis
//! en français sur un terminal.
//!
//! # CE QUE CE MODULE REND, ET CE QU'IL NE FAIT PAS
//!
//! Des chaînes, comme `rendu` : aucune entrée-sortie, pour que chaque phrase
//! s'éprouve en lisant ce qu'elle rend. Les requêtes sont dans `commandes` ;
//! elles remplissent une [`VueDeDomaine`], et c'est elle qu'on met en forme.
//!
//! # TROIS SILENCES QUI NE VEULENT PAS DIRE LA MÊME CHOSE
//!
//! L'annuaire rend des listes VIDES là où un autre dirait « interdit », et
//! chacune se lit autrement — les afficher pareil enverrait chercher au
//! mauvais endroit :
//!
//! - **`GET /v1/domaines` vide** : un compte a toujours au moins un domaine
//!   (`modele.md` §2.11) ; une liste vide dit donc que cette machine ne porte
//!   pas la capacité `lecture`, pas que le compte n'a rien.
//! - **`machines` vide sans `voir`** : on ne voit pas ce qui est rangé — ce
//!   n'est pas qu'il n'y a rien.
//! - **les services d'une machine d'un autre compte, sans `voir`** : l'annuaire
//!   rend `[]` à qui ne voit pas le domaine où elle est rangée. On ne demande
//!   donc rien, et on le dit.
//!
//! # UN SERVICE ANNONCÉ, SANS ADRESSE
//!
//! Depuis le serveur 0.40.0 (décisions 103–104), qui a `voir` sur le domaine
//! lit les services des machines d'autrui qui y sont rangées, **sans leurs
//! adresses** : un service vivant y porte `"annonce":{}`. Il se dit
//! « annoncé », sans candidat ; avec `--where`, il se résout si le domaine
//! donne `localiser`, et la ligne « adresse : hors de vos droits » le dit
//! sinon.

use asl_client_tokio::domaines::{
    Autorite, Domaine, DomaineDetaille, DomaineTrouve, EtatDeService, ServiceDeMachine,
};
use asl_id::Identifiant;
use asl_proto::{Origine, Reponse, cadrage::TamponsReponse, ordonner};

/// Ce qu'on dit d'une machine dont la capacité `lecture` manque.
///
/// **UNE HYPOTHÈSE, ET ELLE EST DITE COMME TELLE** : l'annuaire ne refuse
/// pas, il rend vide ; mais un compte sans aucun domaine n'existe pas.
pub const SANS_LECTURE: &str = "aucun domaine visible. Un compte a toujours au moins le sien : cette\n\
     machine ne porte donc pas la capacité `lecture`, sans laquelle l'annuaire\n\
     ne lui montre aucun domaine. Elle se donne à la machine depuis\n\
     l'application.";

/// Ce qu'on dit d'un `404` sur `GET /v1/domaines/{d}` quand la machine lit.
pub const HORS_DE_VOS_DROITS: &str = "domaine introuvable ou hors de vos droits.\n\
     L'annuaire ne fait pas la différence (C10) : la faire révélerait\n\
     l'existence de ce qu'on ne vous laisse pas voir. `asl domains` liste\n\
     ceux que vous voyez.";

/// Ce qu'on sait des services d'une machine rangée dans le domaine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServicesVus {
    /// La machine est à un autre compte, et le domaine ne nous donne pas
    /// `voir` : l'annuaire rendrait `[]`, et l'on n'a rien demandé.
    Autrui,
    /// La demande n'a pas abouti — ce qu'on en sait, en toutes lettres.
    Echec(String),
    /// Les services, chacun avec son adresse quand on l'a demandée.
    Liste(Vec<ServiceVu>),
}

/// Un service, et ce que sa résolution a donné.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceVu {
    /// Ce que `GET /v1/machines/{m}/services` en dit.
    pub service: ServiceDeMachine,
    /// Son adresse, avec `--where` ; `None` sans.
    pub adresse: Option<AdresseVue>,
}

/// Ce que `GET /v1/ou/{m}/{s}` a donné pour un service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdresseVue {
    /// Le corps de la résolution, tel qu'`asl_proto::Reponse` le lit.
    Resolue(Vec<u8>),
    /// On ne tient pas `localiser` : rien n'a été demandé.
    HorsDeVosDroits,
    /// `404` : introuvable, parti depuis la liste, ou hors de vos droits.
    Introuvable,
    /// Le service est parti : il n'y a rien à résoudre.
    Parti,
    /// Autre chose, en toutes lettres.
    Echec(String),
}

/// Tout ce que `asl domain` a appris, prêt à être mis en forme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VueDeDomaine {
    /// Le domaine, ses groupes, ses machines.
    pub detail: DomaineDetaille,
    /// Le compte de cette machine — ce qui fait dire « à vous ».
    pub moi: Identifiant,
    /// Pour chaque machine de `detail.machines`, dans le même ordre.
    pub services: Vec<ServicesVus>,
}

/// La largeur d'une colonne : le plus long de ses textes, en caractères.
///
/// **MESURÉE SUR LA LISTE**, comme dans `asl enrolled` : un alias est du texte
/// libre, et une largeur devinée décale tout ce qui suit dès qu'un seul la
/// dépasse.
fn largeur<'a>(textes: impl Iterator<Item = &'a str>) -> usize {
    textes.map(|texte| texte.chars().count()).max().unwrap_or(0)
}

/// L'alias entre guillemets, ou un tiret.
fn alias_ecrit(alias: Option<&str>) -> String {
    alias.map_or_else(|| "—".to_owned(), |alias| format!("« {alias} »"))
}

/// Les droits, séparés d'une virgule — ou « aucun ».
fn droits_ecrits(domaine: &Domaine) -> String {
    if domaine.droits.is_empty() {
        return "aucun".to_owned();
    }
    domaine.droits.join(", ")
}

/// `asl domains` : un domaine par ligne — identifiant, alias, hébergeur, vos
/// droits, et « domaine racine » pour lui seul.
///
/// Une liste vide ne se rend pas ici : elle est l'issue [`SANS_LECTURE`].
#[must_use]
pub fn liste(domaines: &[Domaine]) -> String {
    let alias: Vec<String> = domaines
        .iter()
        .map(|domaine| alias_ecrit(domaine.alias.as_deref()))
        .collect();
    let hotes: Vec<String> = domaines
        .iter()
        .map(|domaine| domaine.heberge_par.to_string())
        .collect();
    let droits: Vec<String> = domaines.iter().map(droits_ecrits).collect();
    let (l_alias, l_hote, l_droits) = (
        largeur(alias.iter().map(String::as_str)),
        largeur(hotes.iter().map(String::as_str)),
        largeur(droits.iter().map(String::as_str)),
    );
    let mut texte = String::new();
    for (rang, domaine) in domaines.iter().enumerate() {
        let ligne = format!(
            "{}   {:<l_alias$}   {:<l_hote$}   {:<l_droits$}{}",
            domaine.domaine.texte().as_str(),
            alias.get(rang).map_or("", String::as_str),
            hotes.get(rang).map_or("", String::as_str),
            droits.get(rang).map_or("", String::as_str),
            if domaine.est_racine() {
                "   domaine racine"
            } else {
                ""
            }
        );
        texte.push_str(ligne.trim_end());
        texte.push('\n');
    }
    texte
}

/// Un alias que plusieurs domaines portent : on le dit, et l'on liste les
/// candidats — **avec ce qu'on en voit**, pour qu'on sache lequel taper.
///
/// La recherche ne rend que l'identifiant et l'autorité ; ce qui est visible
/// d'autre (propriétaire, droits) vient de `GET /v1/domaines`. Un candidat
/// qu'on ne voit pas le dit, sans rien inventer.
#[must_use]
pub fn alias_ambigu(alias: &str, candidats: &[DomaineTrouve], visibles: &[Domaine]) -> String {
    let mut texte = format!(
        "l'alias « {alias} » est porté par {} domaines — l'alias d'un domaine\n\
         n'est pas unique. Nommez-le par son identifiant : asl domain <d-…>\n",
        candidats.len()
    );
    for candidat in candidats {
        let vu = visibles
            .iter()
            .find(|domaine| domaine.domaine == candidat.domaine);
        let dit = match vu {
            Some(domaine) => format!(
                "propriétaire {}   vos droits : {}",
                domaine.proprietaire.texte().as_str(),
                droits_ecrits(domaine)
            ),
            None => "hors de vos droits".to_owned(),
        };
        texte.push_str(&format!(
            "  {}   {:<30}   {dit}\n",
            candidat.domaine.texte().as_str(),
            format!("autorité : {}", candidat.autorite)
        ));
    }
    texte
}

/// Aucun domaine ne porte cet alias.
#[must_use]
pub fn alias_inconnu(alias: &str) -> String {
    format!(
        "aucun domaine ne porte l'alias « {alias} ».\n\
         La casse compte : « maison » ne trouve pas « Maison ». `asl domains`\n\
         liste ceux que vous voyez, avec leur alias."
    )
}

/// `asl domain` : le domaine, puis ses machines et, pour chacune, ses
/// services — et leur adresse avec `--where`.
#[must_use]
pub fn detail(vue: &VueDeDomaine) -> String {
    let domaine = &vue.detail.domaine;
    let mut texte = String::new();
    let mut dire = |ligne: String| {
        texte.push_str(ligne.trim_end());
        texte.push('\n');
    };
    dire(format!(
        "domaine        {}",
        domaine.domaine.texte().as_str()
    ));
    dire(format!(
        "alias          {}",
        domaine
            .alias
            .as_deref()
            .map_or_else(|| "aucun".to_owned(), |alias| format!("« {alias} »"))
    ));
    dire(format!(
        "propriétaire   {}{}",
        domaine.proprietaire.texte().as_str(),
        if domaine.proprietaire == vue.moi {
            " (vous)"
        } else {
            ""
        }
    ));
    dire(format!(
        "hébergé par    {}",
        match domaine.heberge_par {
            Autorite::Racines => "les racines".to_owned(),
            Autorite::Annuaire(annuaire) =>
                format!("l'annuaire local {}", annuaire.texte().as_str()),
        }
    ));
    dire(format!("vos droits     {}", droits_ecrits(domaine)));
    if domaine.est_racine() {
        dire(
            "sorte          domaine racine — il ne se confie pas et ne se supprime pas".to_owned(),
        );
    } else if let Some(sorte) = &domaine.sorte {
        dire(format!("sorte          {sorte}"));
    }
    dire(String::new());

    let machines = &vue.detail.machines;
    if !domaine.voit_ses_machines() {
        dire(
            "machines       non visibles — il faut `voir` (ou `localiser`, ou\n\
             \x20              `administrer`) sur ce domaine pour voir ce qui y est rangé."
                .to_owned(),
        );
        return texte;
    }
    if machines.is_empty() {
        dire("machines       aucune — rien n'est rangé dans ce domaine.".to_owned());
        return texte;
    }
    dire(format!("machines       {}", machines.len()));

    let noms: Vec<&str> = machines
        .iter()
        .map(|machine| machine.nom.as_deref().unwrap_or("?"))
        .collect();
    let alias: Vec<String> = machines
        .iter()
        .map(|machine| alias_ecrit(machine.alias.as_deref()))
        .collect();
    let l_nom = largeur(noms.iter().copied());
    let l_alias = largeur(alias.iter().map(String::as_str));
    for (rang, machine) in machines.iter().enumerate() {
        let a_moi = machine.proprietaire == vue.moi;
        dire(format!(
            "  {}   {:<l_nom$}   {:<l_alias$}   {}",
            machine.machine.texte().as_str(),
            noms.get(rang).copied().unwrap_or("?"),
            alias.get(rang).map_or("", String::as_str),
            if a_moi {
                "à vous".to_owned()
            } else {
                format!("à {}", machine.proprietaire.texte().as_str())
            }
        ));
        match vue.services.get(rang) {
            None | Some(ServicesVus::Autrui) => {
                dire(
                    "      services : non visibles (machine d'un autre compte, sans `voir`)"
                        .to_owned(),
                );
            }
            Some(ServicesVus::Echec(quoi)) => {
                dire(format!("      services : NON LUS — {quoi}"));
            }
            Some(ServicesVus::Liste(services)) if services.is_empty() => {
                dire("      aucun service déclaré".to_owned());
            }
            Some(ServicesVus::Liste(services)) => {
                let l_service = largeur(services.iter().map(|vu| vu.service.nom.as_str()));
                for vu in services {
                    dire(format!(
                        "      {:<l_service$}   {}   {}",
                        vu.service.nom,
                        vu.service.service.texte().as_str(),
                        etat(&vu.service)
                    ));
                    if let Some(adresse) = &vu.adresse {
                        for ligne in adresse_ecrite(adresse) {
                            dire(format!("          {ligne}"));
                        }
                    }
                }
            }
        }
    }
    texte
}

/// L'état d'un service, en clair — et d'où vient ce qu'on en dit, quand un
/// annuaire local l'a rapporté en se sondant de l'intérieur.
fn etat(service: &ServiceDeMachine) -> String {
    let mot = match &service.etat {
        EtatDeService::Annonce(_) => "annoncé".to_owned(),
        EtatDeService::Parti {
            volontaire: Some(true),
        } => "parti — retiré par le daemon".to_owned(),
        EtatDeService::Parti {
            volontaire: Some(false),
        } => "parti — connexion perdue".to_owned(),
        EtatDeService::Parti { volontaire: None } => "parti".to_owned(),
        EtatDeService::Autre(mot) => mot.clone(),
    };
    match (service.sonde_par, service.sonde_locale) {
        (Some(annuaire), Some(true)) => format!(
            "{mot}   (rapporté par {}, qui se sonde de l'intérieur)",
            annuaire.texte().as_str()
        ),
        (Some(annuaire), _) => format!("{mot}   (rapporté par {})", annuaire.texte().as_str()),
        (None, _) => mot,
    }
}

/// Les lignes de l'adresse d'un service : ses candidats, dans l'ordre où un
/// client les essaierait — ou pourquoi il n'y en a pas.
fn adresse_ecrite(adresse: &AdresseVue) -> Vec<String> {
    match adresse {
        AdresseVue::HorsDeVosDroits => {
            vec!["adresse : hors de vos droits (`localiser`)".to_owned()]
        }
        AdresseVue::Introuvable => {
            vec!["adresse : introuvable, partie depuis, ou hors de vos droits".to_owned()]
        }
        AdresseVue::Parti => vec!["adresse : aucune — le service est parti".to_owned()],
        AdresseVue::Echec(quoi) => vec![format!("adresse : NON RÉSOLUE — {quoi}")],
        AdresseVue::Resolue(corps) => {
            let mut tampons = TamponsReponse::nouveaux();
            let Ok(lue) = Reponse::decoder(corps, &mut tampons) else {
                return vec!["adresse : la réponse ne se lit pas".to_owned()];
            };
            let mut candidats = crate::rendu::candidats(&lue);
            ordonner(&mut candidats);
            if candidats.is_empty() {
                return vec!["adresse : aucun candidat".to_owned()];
            }
            candidats
                .iter()
                .enumerate()
                .map(|(rang, candidat)| {
                    format!(
                        "{}. {:<4} {:<40} {}",
                        rang.saturating_add(1),
                        candidat.protocole.texte(),
                        crate::rendu::point_ecrit(candidat),
                        match candidat.origine {
                            Origine::Reflexif => "réflexif",
                            Origine::Annonce => "annoncé",
                        }
                    )
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod essais {
    use super::*;
    use asl_client_tokio::domaines::MachineDeDomaine;
    use asl_id::Genre;

    fn id(genre: Genre, octet: u8) -> Identifiant {
        Identifiant::depuis_entropie(genre, [octet; 16])
    }

    fn domaine(octet: u8, alias: Option<&str>, droits: &[&str], racine: bool) -> Domaine {
        Domaine {
            domaine: id(Genre::Domaine, octet),
            proprietaire: id(Genre::Utilisateur, 1),
            alias: alias.map(str::to_owned),
            heberge_par: Autorite::Racines,
            droits: droits.iter().map(|droit| (*droit).to_owned()).collect(),
            sorte: racine.then(|| "racine".to_owned()),
        }
    }

    const QUATRE: [&str; 4] = ["administrer", "rattacher", "voir", "localiser"];

    /// Une réponse de résolution, telle qu'`asl_proto` l'encode.
    fn resolution() -> Vec<u8> {
        use asl_proto::{
            Bail, Candidat, Horodatage, Joignabilite, PointEcoute, Port, Protocole, Verdict,
            VerdictNat, VuDepuis,
        };
        use core::net::{IpAddr, Ipv6Addr};
        let adresse = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let port = Port::depuis_u16(8080).expect("un port");
        let joignabilite = [Joignabilite {
            point: PointEcoute::nouveau(Protocole::Tcp, port),
            verdict: Verdict::Joignable {
                candidat: Candidat {
                    protocole: Protocole::Tcp,
                    adresse,
                    port,
                    origine: Origine::Reflexif,
                },
                a: Horodatage::depuis_millisecondes(1_700_000_000),
            },
        }];
        let reponse = Reponse::nouvelle(
            id(Genre::Service, 9),
            Bail::nouveau(15, 45).expect("un bail"),
            VuDepuis {
                adresse,
                port: Port::depuis_u16(41_000).expect("un port"),
            },
            VerdictNat::Non,
            &joignabilite,
        )
        .expect("une réponse");
        let mut sortie = vec![0_u8; asl_proto::cadrage::MESSAGE_MAX];
        let combien = reponse.encoder(&mut sortie).expect("elle s'encode");
        sortie.truncate(combien);
        sortie
    }

    #[test]
    fn la_liste_aligne_ses_colonnes_et_nomme_le_domaine_racine() {
        let texte = liste(&[
            domaine(1, Some("Maison été"), &QUATRE, false),
            domaine(2, None, &["voir"], false),
            domaine(3, Some("Racine"), &QUATRE, true),
        ]);
        let lignes: Vec<&str> = texte.lines().collect();
        assert_eq!(lignes.len(), 3, "{texte}");
        assert!(lignes[0].contains("« Maison été »"), "{texte}");
        assert!(
            lignes[1].contains("   —   "),
            "sans alias, un tiret : {texte}"
        );
        assert!(lignes[2].ends_with("domaine racine"), "{texte}");
        assert!(!lignes[0].contains("domaine racine"), "{texte}");
        // Les colonnes tiennent : l'hébergeur commence au même caractère.
        let colonne = |ligne: &str| {
            ligne
                .find("racines")
                .map(|octet| ligne[..octet].chars().count())
        };
        assert_eq!(colonne(lignes[0]), colonne(lignes[1]), "{texte}");
        assert_eq!(colonne(lignes[1]), colonne(lignes[2]), "{texte}");
        assert!(
            lignes[1].ends_with("voir"),
            "pas d'espaces en fin : {texte:?}"
        );
    }

    #[test]
    fn un_domaine_sans_droit_le_dit() {
        let texte = liste(&[domaine(1, None, &[], false)]);
        assert!(texte.contains("aucun"), "{texte}");
    }

    #[test]
    fn un_alias_ambigu_liste_ses_candidats_et_ce_qu_on_en_voit() {
        let vu = domaine(1, Some("Maison"), &QUATRE, false);
        let annuaire = id(Genre::Annuaire, 7);
        let candidats = [
            DomaineTrouve {
                domaine: vu.domaine,
                autorite: Autorite::Racines,
            },
            DomaineTrouve {
                domaine: id(Genre::Domaine, 2),
                autorite: Autorite::Annuaire(annuaire),
            },
        ];
        let texte = alias_ambigu("Maison", &candidats, core::slice::from_ref(&vu));
        assert!(texte.contains("porté par 2 domaines"), "{texte}");
        assert!(texte.contains("asl domain <d-…>"), "{texte}");
        assert!(texte.contains(vu.domaine.texte().as_str()), "{texte}");
        assert!(texte.contains("vos droits : administrer"), "{texte}");
        assert!(texte.contains("hors de vos droits"), "{texte}");
        assert!(
            texte.contains(&format!("autorité : {}", annuaire.texte().as_str())),
            "{texte}"
        );
        assert!(alias_inconnu("maison").contains("La casse compte"));
    }

    fn service(nom: &str, octet: u8, etat: EtatDeService) -> ServiceDeMachine {
        ServiceDeMachine {
            service: id(Genre::Service, octet),
            nom: nom.to_owned(),
            etat,
            sonde_par: None,
            sonde_locale: None,
        }
    }

    fn vue_complete() -> VueDeDomaine {
        let moi = id(Genre::Utilisateur, 1);
        let autre = id(Genre::Utilisateur, 2);
        let local = id(Genre::Annuaire, 8);
        let mut detail = DomaineDetaille {
            domaine: domaine(1, Some("Maison"), &QUATRE, false),
            groupes: Vec::new(),
            machines: vec![
                MachineDeDomaine {
                    machine: id(Genre::Machine, 1),
                    proprietaire: moi,
                    nom: Some("grenier".to_owned()),
                    alias: Some("Le Grenier".to_owned()),
                },
                MachineDeDomaine {
                    machine: id(Genre::Machine, 2),
                    proprietaire: autre,
                    nom: Some("cave".to_owned()),
                    alias: None,
                },
                MachineDeDomaine {
                    machine: id(Genre::Machine, 3),
                    proprietaire: moi,
                    nom: None,
                    alias: None,
                },
                MachineDeDomaine {
                    machine: id(Genre::Machine, 4),
                    proprietaire: moi,
                    nom: Some("atelier".to_owned()),
                    alias: None,
                },
            ],
        };
        detail.domaine.heberge_par = Autorite::Annuaire(local);
        let mut rapporte = service(
            "web",
            5,
            EtatDeService::Parti {
                volontaire: Some(false),
            },
        );
        rapporte.sonde_par = Some(local);
        rapporte.sonde_locale = Some(true);
        let mut rapporte_du_dehors =
            service("imap", 6, EtatDeService::Autre("suspendu".to_owned()));
        rapporte_du_dehors.sonde_par = Some(local);
        VueDeDomaine {
            detail,
            moi,
            services: vec![
                ServicesVus::Liste(vec![
                    ServiceVu {
                        service: service("depot", 1, EtatDeService::Annonce(Vec::new())),
                        adresse: Some(AdresseVue::Resolue(resolution())),
                    },
                    ServiceVu {
                        service: service(
                            "nas-de-la-maison",
                            2,
                            EtatDeService::Parti {
                                volontaire: Some(true),
                            },
                        ),
                        adresse: Some(AdresseVue::Parti),
                    },
                    ServiceVu {
                        service: service(
                            "sauvegarde",
                            3,
                            EtatDeService::Parti { volontaire: None },
                        ),
                        adresse: Some(AdresseVue::Introuvable),
                    },
                    ServiceVu {
                        service: rapporte,
                        adresse: Some(AdresseVue::HorsDeVosDroits),
                    },
                    ServiceVu {
                        service: rapporte_du_dehors,
                        adresse: Some(AdresseVue::Echec("l'annuaire a répondu 421".to_owned())),
                    },
                    ServiceVu {
                        service: service("vide", 7, EtatDeService::Annonce(Vec::new())),
                        adresse: Some(AdresseVue::Resolue(b"{}".to_vec())),
                    },
                ]),
                ServicesVus::Autrui,
                ServicesVus::Liste(Vec::new()),
                ServicesVus::Echec("l'annuaire a répondu 401".to_owned()),
            ],
        }
    }

    #[test]
    fn le_detail_dit_chaque_machine_et_chaque_service() {
        let texte = detail(&vue_complete());
        assert!(texte.contains("alias          « Maison »"), "{texte}");
        assert!(texte.contains(" (vous)"), "{texte}");
        assert!(
            texte.contains("hébergé par    l'annuaire local n-"),
            "{texte}"
        );
        assert!(
            texte.contains("vos droits     administrer, rattacher, voir, localiser"),
            "{texte}"
        );
        assert!(texte.contains("machines       4"), "{texte}");
        assert!(texte.contains("« Le Grenier »"), "{texte}");
        assert!(texte.contains("à vous"), "{texte}");
        assert!(
            texte.contains("services : non visibles (machine d'un autre compte, sans `voir`)"),
            "{texte}"
        );
        assert!(texte.contains("aucun service déclaré"), "{texte}");
        assert!(
            texte.contains("services : NON LUS — l'annuaire a répondu 401"),
            "{texte}"
        );
        // Les états, et leur provenance.
        assert!(texte.contains("annoncé"), "{texte}");
        assert!(texte.contains("parti — retiré par le daemon"), "{texte}");
        assert!(texte.contains("parti — connexion perdue"), "{texte}");
        assert!(texte.contains("qui se sonde de l'intérieur"), "{texte}");
        assert!(texte.contains("suspendu   (rapporté par n-"), "{texte}");
        // Les adresses.
        assert!(texte.contains("1. tcp  [2001:db8::1]:8080"), "{texte}");
        assert!(texte.contains("réflexif"), "{texte}");
        assert!(
            texte.contains("adresse : aucune — le service est parti"),
            "{texte}"
        );
        assert!(
            texte.contains("adresse : introuvable, partie depuis"),
            "{texte}"
        );
        assert!(texte.contains("adresse : hors de vos droits"), "{texte}");
        assert!(
            texte.contains("adresse : NON RÉSOLUE — l'annuaire a répondu 421"),
            "{texte}"
        );
        assert!(
            texte.contains("adresse : la réponse ne se lit pas"),
            "{texte}"
        );
        // Une machine sans nom rendu : un point d'interrogation, pas un trou.
        assert!(texte.contains("   ?   "), "{texte}");
        assert!(
            !texte.lines().any(|ligne| ligne.ends_with(' ')),
            "{texte:?}"
        );
    }

    #[test]
    fn les_services_s_alignent_sur_le_plus_long_nom() {
        let texte = detail(&vue_complete());
        let colonne = |nom: &str| {
            let ligne = texte
                .lines()
                .find(|ligne| ligne.trim_start().starts_with(nom))
                .expect("la ligne du service");
            ligne.find(" s-").expect("l'identifiant")
        };
        assert_eq!(colonne("depot"), colonne("nas-de-la-maison"), "{texte}");
    }

    /// Ce que le serveur 0.40.0 rend à qui a `voir` seul sur le domaine d'une
    /// machine d'autrui : un service vivant, `"annonce":{}`, et un parti.
    fn vue_d_autrui_avec_voir(ou: bool) -> VueDeDomaine {
        let mut vue = vue_complete();
        vue.detail.domaine.droits = vec!["voir".to_owned()];
        vue.detail.machines.truncate(2);
        let adresse = |a: AdresseVue| ou.then_some(a);
        vue.services = vec![
            ServicesVus::Liste(Vec::new()),
            ServicesVus::Liste(vec![
                ServiceVu {
                    service: service("imprimante", 11, EtatDeService::Annonce(b"{}".to_vec())),
                    adresse: adresse(AdresseVue::HorsDeVosDroits),
                },
                ServiceVu {
                    service: service("scanner", 12, EtatDeService::Parti { volontaire: None }),
                    adresse: adresse(AdresseVue::HorsDeVosDroits),
                },
            ]),
        ];
        vue
    }

    #[test]
    fn avec_voir_les_services_d_autrui_se_disent_annonces_sans_adresse() {
        let texte = detail(&vue_d_autrui_avec_voir(false));
        let ligne = texte
            .lines()
            .find(|ligne| ligne.trim_start().starts_with("imprimante"))
            .expect("le service d'autrui est listé");
        assert!(ligne.ends_with("   annoncé"), "{texte}");
        assert!(texte.contains("scanner"), "{texte}");
        assert!(!texte.contains("non visibles"), "{texte}");
        // Sans `--where`, ni candidat ni ligne d'adresse.
        assert!(!texte.contains("adresse"), "{texte}");
        assert!(!texte.contains("1. "), "{texte}");

        // Avec `--where` et sans `localiser` : la ligne le dit.
        let texte = detail(&vue_d_autrui_avec_voir(true));
        assert_eq!(
            texte
                .matches("adresse : hors de vos droits (`localiser`)")
                .count(),
            2,
            "{texte}"
        );
        assert!(!texte.contains("ne se lit pas"), "{texte}");
    }

    #[test]
    fn sans_voir_les_machines_ne_sont_pas_dites_absentes() {
        let mut vue = vue_complete();
        vue.detail.domaine.droits = vec!["rattacher".to_owned()];
        vue.detail.machines.clear();
        let texte = detail(&vue);
        assert!(
            texte.contains("machines       non visibles — il faut `voir`"),
            "{texte}"
        );
        assert!(!texte.contains("aucune"), "{texte}");
    }

    #[test]
    fn un_domaine_vide_le_dit_et_le_domaine_racine_se_nomme() {
        let mut vue = vue_complete();
        vue.detail.machines.clear();
        vue.detail.domaine.sorte = Some("racine".to_owned());
        vue.detail.domaine.alias = None;
        vue.detail.domaine.heberge_par = Autorite::Racines;
        vue.moi = id(Genre::Utilisateur, 9);
        let texte = detail(&vue);
        assert!(
            texte.contains("machines       aucune — rien n'est rangé"),
            "{texte}"
        );
        assert!(texte.contains("sorte          domaine racine"), "{texte}");
        assert!(texte.contains("alias          aucun"), "{texte}");
        assert!(texte.contains("hébergé par    les racines"), "{texte}");
        assert!(!texte.contains("(vous)"), "{texte}");

        vue.detail.domaine.sorte = Some("autre".to_owned());
        assert!(detail(&vue).contains("sorte          autre"));
    }

    #[test]
    fn une_resolution_sans_candidat_le_dit() {
        use asl_proto::{Bail, Port, VerdictNat, VuDepuis};
        let reponse = Reponse::nouvelle(
            id(Genre::Service, 9),
            Bail::nouveau(15, 45).expect("un bail"),
            VuDepuis {
                adresse: core::net::IpAddr::V4(core::net::Ipv4Addr::LOCALHOST),
                port: Port::depuis_u16(41_000).expect("un port"),
            },
            VerdictNat::Indetermine,
            &[],
        );
        // Une réponse sans point d'écoute peut être refusée à la
        // composition ; si elle se compose, elle se dit sans candidat.
        if let Ok(reponse) = reponse {
            let mut sortie = vec![0_u8; asl_proto::cadrage::MESSAGE_MAX];
            let combien = reponse.encoder(&mut sortie).expect("elle s'encode");
            sortie.truncate(combien);
            assert_eq!(
                adresse_ecrite(&AdresseVue::Resolue(sortie)),
                vec!["adresse : aucun candidat".to_owned()]
            );
        }
    }
}
