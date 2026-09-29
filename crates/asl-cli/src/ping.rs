//! `asl ping <m-…|nom|alias>` — « est-ce que je la joins, d'ici, maintenant,
//! et est-ce bien elle ? » (`protocole.md` §3 quater, décisions 91 et 93).
//!
//! # DANS L'ORDRE
//!
//! 1. **La cible** : un `m-…` tel quel ; sinon un nom ou un alias, cherché
//!    parmi les machines que ce compte voit — les siennes, et celles des
//!    domaines où il a `voir`. Plusieurs : on les liste, et l'on ne choisit
//!    pas (E12).
//! 2. **`GET /v1/ou/{m}/asl-echo`** : les candidats, IPv6 d'abord.
//! 3. **`POST /v1/echo/jetons`**, sur la même connexion : un jeton lié à la
//!    clé de cette machine et à celle de la cible, que la racine signe.
//! 4. **Chaque candidat est sondé** depuis une socket éphémère, un quart de
//!    seconde d'écart entre deux, trois envois d'une seconde chacun — l'UDP
//!    perd, et un envoi seul confondrait perte et silence. **Chaque envoi a
//!    son défi** : l'écho retient ceux qu'il a vus, et un défi renvoyé
//!    tomberait dans son anti-rejeu.
//! 5. **La réponse est vérifiée contre la clé que le jeton porte**, signée
//!    par la racine — et non contre ce que la réponse dit d'elle-même.
//!
//! # CE QU'IL DIT, ET CE QU'IL NE CHANGE PAS
//!
//! D'où la sonde est partie, et sous quelle adresse l'écho l'a vue — signée.
//! **Rien n'est remonté à l'annuaire** : le verdict est celui d'ici, et un
//! sondeur autorisé n'écrit pas l'état d'une machine qui n'est pas la sienne.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use asl_client::Identite;
use asl_client::echo::{Constat, Jeton, NOM_SERVICE, constater};
use asl_client_tokio::{Connexion, Faute as FauteReseau};
use asl_echo::{DefiEcho, REQUETE_OCTETS};
use asl_id::Identifiant;
use asl_proto::{Candidat, Origine, Protocole};
use tokio::net::UdpSocket;

use crate::arguments::{CibleDeMachine, Invocation};
use crate::commandes::{ouvrir_et_relire, refus_de_l_annuaire, reglages};
use crate::{Issue, Sortie, etat, rendu};

/// Combien d'envois par candidat.
pub const ENVOIS: u32 = 3;

/// Combien de temps on attend chaque envoi.
const ATTENTE: Duration = Duration::from_secs(1);

/// L'écart entre deux candidats, à la façon de *Happy Eyeballs*.
const ECART: Duration = Duration::from_millis(250);

/// Ce que `404` veut dire ici, et qu'on ne peut pas dire mieux (C9).
const INTROUVABLE: &str = "introuvable : pas d'écho annoncé, ou pas le droit de la localiser —\n\
     l'annuaire ne distingue pas les deux, et c'est voulu : la différence\n\
     révélerait ce qu'on ne vous laisse pas voir.";

/// Une machine que ce compte voit : son identifiant, et ce qui la nomme.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Nommee {
    machine: Identifiant,
    nom: Option<String>,
    alias: Option<String>,
}

impl Nommee {
    fn dite(&self) -> String {
        match (&self.nom, &self.alias) {
            (Some(nom), Some(alias)) => format!("{nom} « {alias} »"),
            (Some(nom), None) => nom.clone(),
            (None, Some(alias)) => format!("« {alias} »"),
            (None, None) => "?".to_owned(),
        }
    }
}

/// Ce qu'il faut pour sonder : la cible, ses candidats, le jeton.
struct Preparee {
    cible: Identifiant,
    nom: Option<String>,
    moi_nom: Option<String>,
    candidats: Vec<Candidat>,
    jeton: Jeton,
}

/// Ce qu'un candidat a donné.
#[derive(Debug, Clone)]
enum Resultat {
    /// Joignable d'ici, et c'est elle.
    Prouvee {
        rtt: Duration,
        vu_comme: SocketAddr,
        locale: Option<SocketAddr>,
    },
    /// Quelqu'un d'autre répond à cette adresse.
    AutreCle,
    /// Une réponse est venue, et ne se lit pas.
    Illisible(String),
    /// Rien, après trois envois.
    Muet,
    /// On n'a même pas pu envoyer.
    Envoi(String),
}

/// `asl ping`.
pub async fn ping(invocation: &Invocation, identite: &Identite, cible: &CibleDeMachine) -> Sortie {
    let reglages = reglages(invocation)?;
    let mut connexion = ouvrir_et_relire(invocation, &reglages).await?;
    connexion
        .authentifier(identite)
        .await
        .map_err(refus_de_l_annuaire)?;
    let preparee = preparer(&mut connexion, identite, cible).await;
    let _ = connexion.fermer().await;
    let preparee = preparee?;

    let issues = sonder_tout(identite, &preparee).await;
    conclure(identite, &preparee, &issues)
}

/// Résout la cible, ses candidats, et le jeton — sur la connexion prouvée.
async fn preparer(
    connexion: &mut Connexion,
    identite: &Identite,
    cible: &CibleDeMachine,
) -> Result<Preparee, Issue> {
    let moi = connexion.moi().await.map_err(refus_de_l_annuaire)?;
    let miennes = mes_machines(connexion, moi.proprietaire).await?;
    let nom_de = |machine: Identifiant, parmi: &[Nommee]| {
        parmi
            .iter()
            .find(|quoi| quoi.machine == machine)
            .map(Nommee::dite)
    };
    let moi_nom = nom_de(identite.machine(), &miennes);

    let (machine, nom) = match cible {
        CibleDeMachine::Identifiant(machine) => (*machine, nom_de(*machine, &miennes)),
        CibleDeMachine::Nom(texte) => {
            let visibles = machines_visibles(connexion, miennes).await;
            let trouvees: Vec<&Nommee> = visibles
                .iter()
                .filter(|quoi| {
                    quoi.nom.as_deref() == Some(texte.as_str())
                        || quoi.alias.as_deref() == Some(texte.as_str())
                })
                .collect();
            match trouvees.as_slice() {
                [] => {
                    return Err(Issue::RefusDit(format!(
                        "aucune machine que ce compte voit ne s'appelle « {texte} » — ni par son\n\
                         nom, ni par son alias. `asl machines` et `asl domain <d-…>` les listent ;\n\
                         un m-… se sonde tel quel."
                    )));
                }
                [une] => (une.machine, Some(une.dite())),
                plusieurs => {
                    let liste: String = plusieurs
                        .iter()
                        .map(|quoi| {
                            format!("\n  {}   {}", quoi.machine.texte().as_str(), quoi.dite())
                        })
                        .collect();
                    return Err(Issue::Usage(format!(
                        "« {texte} » désigne plusieurs machines, et asl ping ne choisit pas à\n\
                         votre place — sondez-en une par son m-… :{liste}"
                    )));
                }
            }
        }
    };

    let corps = match connexion.ou(machine, NOM_SERVICE).await {
        Ok(corps) => corps,
        Err(FauteReseau::Statut(404)) => return Err(Issue::RefusDit(INTROUVABLE.to_owned())),
        Err(autre) => return Err(refus_de_l_annuaire(autre)),
    };
    let candidats = candidats_udp(&corps).map_err(Issue::Injoignable)?;
    let jeton = match connexion.jeton_d_echo(machine).await {
        Ok(jeton) => jeton,
        Err(FauteReseau::Statut(404)) => return Err(Issue::RefusDit(INTROUVABLE.to_owned())),
        Err(FauteReseau::Illisible) => {
            return Err(Issue::Injoignable(
                "le jeton rendu par l'annuaire ne se lit pas".to_owned(),
            ));
        }
        Err(autre) => return Err(refus_de_l_annuaire(autre)),
    };
    // **UN JETON QUI NE NOMME PAS CETTE SONDE NE SERT À RIEN** : l'écho le
    // refuserait. Le dire ici vaut mieux que trois secondes de silence.
    if jeton.cible() != machine
        || jeton.sondeur() != identite.machine()
        || jeton.cle_sondeur() != identite.publique()
    {
        return Err(Issue::RefusDit(
            "le jeton rendu ne nomme pas cette sonde — ni cette cible, ni la clé de cette\n\
             machine : l'écho le refuserait."
                .to_owned(),
        ));
    }
    Ok(Preparee {
        cible: machine,
        nom,
        moi_nom,
        candidats,
        jeton,
    })
}

/// Les machines du compte de cette machine.
async fn mes_machines(
    connexion: &mut Connexion,
    compte: Identifiant,
) -> Result<Vec<Nommee>, Issue> {
    let corps = connexion
        .machines_de(compte)
        .await
        .map_err(refus_de_l_annuaire)?;
    let elements = asl_proto::cadrage::elements(&corps).map_err(|quoi| {
        Issue::Injoignable(format!("la liste des machines ne se lit pas : {quoi:?}"))
    })?;
    let mut lues = Vec::new();
    for element in elements {
        let (machine, nom, alias) = rendu::machine_vue(element).map_err(Issue::Injoignable)?;
        lues.push(Nommee {
            machine,
            nom: Some(nom),
            alias,
        });
    }
    Ok(lues)
}

/// Les machines que ce compte voit : les siennes, puis celles des domaines
/// où il a `voir` — **sans doublon**. Un domaine qui ne se lit pas est
/// sauté : on cherche un nom, on ne dresse pas un inventaire.
async fn machines_visibles(connexion: &mut Connexion, miennes: Vec<Nommee>) -> Vec<Nommee> {
    let mut visibles = miennes;
    let domaines = connexion.domaines().await.unwrap_or_default();
    for domaine in domaines
        .iter()
        .filter(|domaine| domaine.voit_ses_machines())
    {
        let Ok(detail) = connexion.domaine(domaine.domaine).await else {
            continue;
        };
        for machine in detail.machines {
            if visibles.iter().any(|deja| deja.machine == machine.machine) {
                continue;
            }
            visibles.push(Nommee {
                machine: machine.machine,
                nom: machine.nom,
                alias: machine.alias,
            });
        }
    }
    visibles
}

/// Les candidats UDP d'une résolution d'`asl-echo`, dans l'ordre où un
/// client les essaie — IPv6 d'abord.
fn candidats_udp(corps: &[u8]) -> Result<Vec<Candidat>, String> {
    let mut tampons = asl_proto::cadrage::TamponsReponse::nouveaux();
    let lue = asl_proto::Reponse::decoder(corps, &mut tampons)
        .map_err(|quoi| format!("la résolution d'asl-echo ne se lit pas : {quoi:?}"))?;
    let mut candidats: Vec<Candidat> = rendu::candidats(&lue)
        .into_iter()
        .filter(|candidat| candidat.protocole == Protocole::Udp)
        .collect();
    asl_proto::ordonner(&mut candidats);
    Ok(candidats)
}

/// Où envoyer, pour ce candidat.
fn adresse(candidat: &Candidat) -> SocketAddr {
    SocketAddr::new(candidat.adresse, candidat.port.valeur())
}

/// Sonde tous les candidats, un quart de seconde d'écart entre deux, et rend
/// ce que chacun a donné, dans l'ordre.
async fn sonder_tout(identite: &Identite, preparee: &Preparee) -> Vec<Resultat> {
    let mut taches = Vec::new();
    for (rang, candidat) in preparee.candidats.iter().enumerate() {
        // **LES SONDES SONT SIGNÉES ICI**, avant de partir : la clé ne quitte
        // pas la tâche principale, et chaque envoi a son défi.
        let mut sondes = Vec::new();
        for _ in 0..ENVOIS {
            let defi = DefiEcho::depuis_octets(etat::hasard::<16>().unwrap_or([0; 16]));
            sondes.push((defi, identite.sonder(defi, preparee.jeton).octets()));
        }
        let retard = ECART.saturating_mul(u32::try_from(rang).unwrap_or(u32::MAX));
        let vers = adresse(candidat);
        let (cible, moi, cle) = (
            preparee.cible,
            identite.machine(),
            preparee.jeton.cle_cible(),
        );
        taches.push(tokio::spawn(async move {
            tokio::time::sleep(retard).await;
            sonder(vers, &sondes, cible, moi, &cle).await
        }));
    }
    let mut issues = Vec::with_capacity(taches.len());
    for tache in taches {
        issues.push(
            tache
                .await
                .unwrap_or_else(|quoi| Resultat::Envoi(quoi.to_string())),
        );
    }
    issues
}

/// Sonde un candidat, depuis sa socket éphémère.
///
/// **UNE SOCKET CONNECTÉE PAR CANDIDAT** : le noyau dit alors l'adresse
/// locale d'où la sonde part — ce qu'on affiche —, et jette ce qui ne vient
/// pas de ce candidat.
async fn sonder(
    vers: SocketAddr,
    sondes: &[(DefiEcho, [u8; REQUETE_OCTETS])],
    cible: Identifiant,
    moi: Identifiant,
    cle_cible: &asl_cle::ClePublique,
) -> Resultat {
    let lien = if vers.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = match UdpSocket::bind(lien).await {
        Ok(socket) => socket,
        Err(quoi) => return Resultat::Envoi(quoi.to_string()),
    };
    if let Err(quoi) = socket.connect(vers).await {
        return Resultat::Envoi(quoi.to_string());
    }
    let locale = socket.local_addr().ok();
    let mut defis: Vec<DefiEcho> = Vec::new();
    let mut partis: Vec<Instant> = Vec::new();
    let mut illisible: Option<String> = None;
    let mut recu = [0_u8; 1_500];
    for (defi, octets) in sondes {
        if let Err(quoi) = socket.send(octets).await {
            // Un refus du noyau — pas de route, par exemple — se dit tel quel.
            if defis.is_empty() {
                return Resultat::Envoi(quoi.to_string());
            }
        }
        defis.push(*defi);
        partis.push(Instant::now());
        let parti = tokio::time::Instant::now();
        let echeance = parti.checked_add(ATTENTE).unwrap_or(parti);
        loop {
            let Ok(lu) = tokio::time::timeout_at(echeance, socket.recv(&mut recu)).await else {
                break;
            };
            // Une erreur de lecture — un ICMP « port injoignable » qu'une
            // socket connectée remonte — n'est pas une réponse : on attend.
            let Ok(lus) = lu else {
                continue;
            };
            match constater(
                recu.get(..lus).unwrap_or_default(),
                &defis,
                cible,
                moi,
                cle_cible,
            ) {
                Constat::Prouvee { rang, vu_comme } => {
                    let rtt = partis.get(rang).map_or(Duration::ZERO, Instant::elapsed);
                    return Resultat::Prouvee {
                        rtt,
                        vu_comme,
                        locale,
                    };
                }
                Constat::AutreCle => return Resultat::AutreCle,
                Constat::Illisible(quoi) => illisible = Some(format!("{quoi:?}")),
                Constat::PasPourMoi => {}
            }
        }
    }
    illisible.map_or(Resultat::Muet, Resultat::Illisible)
}

/// Une adresse, telle qu'on la lit : une IPv4 enfouie redevient une IPv4.
fn vue(adresse: SocketAddr) -> String {
    SocketAddr::new(adresse.ip().to_canonical(), adresse.port()).to_string()
}

/// L'heure UTC, `hh:mm:ss`, d'un instant en secondes depuis l'époque.
fn heure_utc(secondes: u64) -> String {
    let jour = secondes % 86_400;
    format!(
        "{:02}:{:02}:{:02} UTC",
        jour / 3_600,
        (jour % 3_600) / 60,
        jour % 60
    )
}

/// Dit ce que chaque candidat a donné, et rend l'issue.
fn conclure(identite: &Identite, preparee: &Preparee, issues: &[Resultat]) -> Sortie {
    let moi = identite.machine();
    let moi_dit = preparee
        .moi_nom
        .as_ref()
        .map_or_else(String::new, |nom| format!(" ({nom})"));
    let premiere = issues.iter().find_map(|issue| match issue {
        Resultat::Prouvee {
            rtt,
            vu_comme,
            locale,
        } => Some((*rtt, *vu_comme, *locale)),
        _ => None,
    });
    match premiere {
        Some((_, vu_comme, locale)) => {
            let depuis = locale.map_or_else(String::new, |ici| format!(" depuis {}", vue(ici)));
            println!(
                "sonde partie de {}{moi_dit}{depuis}, vue par l'écho comme {}",
                moi.texte().as_str(),
                vue(vu_comme)
            );
        }
        None => println!("sonde partie de {}{moi_dit}", moi.texte().as_str()),
    }

    let largeur = preparee
        .candidats
        .iter()
        .map(|candidat| vue(adresse(candidat)).len())
        .max()
        .unwrap_or(0);
    for (candidat, issue) in preparee.candidats.iter().zip(issues) {
        let origine = match candidat.origine {
            Origine::Reflexif => "réflexif",
            Origine::Annonce => "annoncé ",
        };
        let dit = match issue {
            Resultat::Prouvee { rtt, locale, .. } => format!(
                "joignable d'ici — {} ms, preuve vérifiée{}",
                rtt.as_millis(),
                locale.map_or_else(String::new, |ici| format!(" (depuis {})", vue(ici)))
            ),
            Resultat::AutreCle => {
                "QUELQU'UN D'AUTRE RÉPOND à cette adresse — une autre clé".to_owned()
            }
            Resultat::Illisible(quoi) => format!("réponse illisible ({quoi})"),
            Resultat::Muet => format!(
                "pas de réponse ({ENVOIS} envois, {} s)",
                ATTENTE.as_secs().saturating_mul(u64::from(ENVOIS))
            ),
            Resultat::Envoi(quoi) => format!("non envoyée — {quoi}"),
        };
        println!(
            "  {:<largeur$}  udp  {origine}  {dit}",
            vue(adresse(candidat))
        );
    }

    let qui = match &preparee.nom {
        Some(nom) => format!("{nom} ({})", preparee.cible.texte().as_str()),
        None => preparee.cible.texte().as_str().to_owned(),
    };
    if let Some((rtt, ..)) = premiere {
        println!(
            "{qui} : joignable d'ici, {} ms, preuve vérifiée",
            rtt.as_millis()
        );
        println!(
            "  — clé de {} selon la racine {} ; constaté à {}",
            preparee.cible.texte().as_str(),
            preparee.jeton.racine().texte().as_str(),
            heure_utc(etat::maintenant())
        );
        return Ok(());
    }
    if preparee.candidats.is_empty() {
        return Err(Issue::PasDeReponse(format!(
            "{qui} : aucun candidat UDP — l'annuaire n'a rien à sonder pour cet écho"
        )));
    }
    if issues
        .iter()
        .any(|issue| matches!(issue, Resultat::AutreCle))
    {
        return Err(Issue::AutreCle(format!(
            "{qui} : quelqu'un d'autre répond à cette adresse — une réponse bien formée,\n\
             à notre défi, signée d'une autre clé que celle que la racine connaît pour\n\
             cette machine : une adresse réattribuée, un NAT partagé, un port repris."
        )));
    }
    if issues
        .iter()
        .any(|issue| matches!(issue, Resultat::Illisible(_)))
    {
        return Err(Issue::ReponseIllisible(format!(
            "{qui} : réponse illisible — quelque chose répond à cette adresse, et ce n'est\n\
             pas un écho de cette version."
        )));
    }
    Err(Issue::PasDeReponse(format!(
        "{qui} : pas de réponse d'ici — filtré en chemin, écho arrêté depuis, ou sonde\n\
         refusée : l'écho se tait dans les trois cas, et asl ping ne prétend pas savoir\n\
         lequel."
    )))
}

#[cfg(test)]
mod tests {
    #[test]
    fn l_heure_se_dit_en_utc_sur_vingt_quatre_heures() {
        assert_eq!(super::heure_utc(0), "00:00:00 UTC");
        assert_eq!(super::heure_utc(1_789_217_751), "12:55:51 UTC");
        assert_eq!(super::heure_utc(86_399), "23:59:59 UTC");
    }
}
