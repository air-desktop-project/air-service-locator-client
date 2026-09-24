//! Les verbes, et ce qu'ils demandent au réseau.

use std::net::ToSocketAddrs as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use asl_client::Identite;
use asl_client_tokio::{Annuaire, Connexion, Faute as FauteReseau, Reglages, joindre};
use asl_proto::{NomService, PointEcoute};

use crate::arguments::{Cible, Invocation};
use crate::etat;
use crate::rendu;
use crate::{Issue, Sortie};

/// Le plafond de recul, en millisecondes.
///
/// **QUINZE SECONDES, ET C'EST UN PLACEHOLDER ASSUMÉ.** La vraie cadence vient
/// du bail que l'annuaire accorde (`modele.md` §4.1), mais il faut bien une
/// valeur avant d'avoir parlé à qui que ce soit. Le bon delta se mesure derrière
/// des NAT réels, et il ne l'est pas encore.
const PLAFOND_MS: u64 = 15_000;

/// Ce que l'annuaire répond à un code d'enrôlement qu'il ne veut pas.
///
/// `403` — et le même pour un code faux, périmé ou déjà servi : il les supprime
/// au lieu de les marquer, et ne les distingue donc pas (`protocole.md` §2.0).
const CODE_REFUSE: u16 = 403;

/// Combien de temps `asl` attend une connexion avant de rendre la main.
///
/// # POURQUOI L'UTILITAIRE SE DONNE UNE BORNE QUE LA BIBLIOTHÈQUE REFUSE
///
/// `announce` n'abandonne jamais, et c'est juste : un daemon qui tourne depuis un
/// mois doit se réannoncer tout seul le jour où l'annuaire revient.
///
/// **Une personne devant un terminal n'a pas cette patience**, et surtout elle a
/// besoin d'un verdict : « je n'y arrive pas » est une réponse, une invite qui
/// ne revient jamais n'en est pas une. La borne est donc posée ici, par
/// l'appelant, exactement là où la bibliothèque dit qu'elle doit l'être.
const PATIENCE_S: u64 = 20;

/// La patience, telle que l'environnement peut la raccourcir.
///
/// **`ASL_TIMEOUT` EXISTE POUR LES SCRIPTS**, qui ont souvent une borne à eux
/// et ne peuvent pas se permettre vingt secondes par sonde. Une valeur illisible
/// ou nulle est ignorée plutôt que refusée : un diagnostic qui refuserait de
/// démarrer à cause de sa propre horloge serait le comble.
fn patience() -> u64 {
    std::env::var("ASL_TIMEOUT")
        .ok()
        .and_then(|texte| texte.parse::<u64>().ok())
        .filter(|secondes| *secondes > 0)
        .unwrap_or(PATIENCE_S)
}

/// Résout les annuaires et monte la configuration.
///
/// # LA RÉSOLUTION DE NOMS SE FAIT ICI, ET NON DANS LA BIBLIOTHÈQUE
///
/// `asl-client-tokio` prend des adresses toutes faites, délibérément : un daemon
/// chargé dans un interpréteur Python ne doit pas se voir imposer un résolveur.
/// **`asl` est un processus à lui**, et il emploie donc celui du système —
/// `getaddrinfo`, qui honore `/etc/hosts`, `nsswitch` et le résolveur configuré.
/// C'est ce qu'un administrateur qui diagnostique attend, et c'est ce qui rend
/// `asl` comparable à ce que fera son daemon.
///
/// **UN NOM QUI REND PLUSIEURS ADRESSES LES REND TOUTES**, et elles entrent
/// toutes dans la tournée : c'est ainsi qu'un annuaire à double pile est essayé
/// en IPv6 d'abord sans que personne ait à l'écrire.
fn reglages(invocation: &Invocation) -> Result<Reglages, Issue> {
    let cibles = if invocation.annuaires.is_empty() {
        depuis_l_environnement()?
    } else {
        invocation.annuaires.clone()
    };

    let mut annuaires = Vec::new();
    for cible in &cibles {
        let nom = invocation.nom.clone().unwrap_or_else(|| cible.hote.clone());
        let adresses = (cible.hote.as_str(), cible.port)
            .to_socket_addrs()
            .map_err(|quoi| {
                Issue::Configuration(format!("`{}` ne se résout pas : {quoi}", cible.hote))
            })?;
        for adresse in tourner(adresses.collect()) {
            annuaires.push(Annuaire {
                adresse,
                nom: nom.clone(),
            });
        }
    }
    if annuaires.is_empty() {
        return Err(Issue::Configuration(
            "aucun annuaire ne se résout en une adresse".to_owned(),
        ));
    }

    let racines = racines(invocation)?;
    Reglages::nouveaux(annuaires, racines, PLAFOND_MS)
        .map_err(|quoi| Issue::Configuration(quoi.to_string()))
}

/// Fait tourner, au hasard, les adresses qu'un même nom a rendues.
///
/// # POURQUOI LE DNS NE SUFFIT PAS
///
/// Un alias comme celui des racines rend plusieurs adresses, et le DNS les
/// sert en tournant — mais **`getaddrinfo` les retrie** (RFC 6724, sur macOS
/// comme avec la glibc), et met la même en tête à chaque fois : deux racines
/// dont une seule reçoit tout. Le tirage se fait donc ici, par un décalage
/// aléatoire de la liste, de sorte qu'un `asl` lancé cent fois se répartisse
/// entre elles. **L'ordre des familles ne change pas** — IPv6 d'abord reste
/// une décision de produit, et la tournée est faite APRÈS, par famille.
/// Un nom à une seule adresse, ou une adresse littérale, ne tourne pas.
fn tourner(adresses: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    let (mut v6, mut v4): (Vec<_>, Vec<_>) = adresses.into_iter().partition(|a| a.is_ipv6());
    // Un octet du noyau suffit à choisir le point de départ ; si le noyau
    // ne répond pas, on ne tourne pas — ce n'est pas une raison d'échouer.
    let depart = crate::etat::hasard::<1>().map_or(0, |[octet]| usize::from(octet));
    if v6.len() > 1 {
        let n = v6.len();
        v6.rotate_left(depart.checked_rem(n).unwrap_or(0));
    }
    if v4.len() > 1 {
        let n = v4.len();
        v4.rotate_left(depart.checked_rem(n).unwrap_or(0));
    }
    v6.extend(v4);
    v6
}

/// L'alias des annuaires racines d'`air-desktop-project` : un nom qui rend
/// les adresses des deux serveurs racines, et que le DNS sert en tournant.
///
/// **C'est ce qu'on joint quand on ne dit rien.** Un utilisateur qui tape
/// `asl machines u-…` n'a pas à savoir où sont les racines : elles sont là où
/// le produit les met, sous ce nom, et c'est ce nom que leur certificat
/// porte. Le certificat de chaque racine le porte aussi, ce qui fait que le
/// nom exigé (`--name`, l'hôte par défaut) vaut pour l'une comme pour
/// l'autre.
pub const ANNUAIRES_RACINES: &str = "asl-root.air-desktop.org:6630";

/// Les annuaires que `ASL_DIRECTORY` désigne, séparés par des virgules — et,
/// sans elle, les racines.
fn depuis_l_environnement() -> Result<Vec<Cible>, Issue> {
    let brut = std::env::var("ASL_DIRECTORY").unwrap_or_else(|_| ANNUAIRES_RACINES.to_owned());
    brut.split(',')
        .map(str::trim)
        .filter(|mot| !mot.is_empty())
        .map(|mot| {
            crate::arguments::analyser(
                ["--directory", mot, "diagnose"]
                    .into_iter()
                    .map(str::to_owned),
            )
            .map_err(|quoi| Issue::Configuration(format!("`ASL_DIRECTORY` : {quoi}")))
            .and_then(|lue| {
                lue.annuaires
                    .into_iter()
                    .next()
                    .ok_or_else(|| Issue::Configuration("`ASL_DIRECTORY` est vide".to_owned()))
            })
        })
        .collect()
}

/// Les certificats d'autorité, en PEM.
///
/// **IL N'Y A PAS DE REPLI SUR LE MAGASIN DU SYSTÈME**, et c'est voulu : les
/// annuaires racines de ce produit sont signés par SA propre autorité, et se
/// rabattre silencieusement sur les centaines de racines d'un système ferait
/// accepter un certificat qu'aucune d'elles n'aurait dû émettre.
///
/// **LA RACINE D'`air-desktop-project` EST ÉPINGLÉE DANS CE BINAIRE**, et
/// c'est ce qui rend `asl` utilisable sans un fichier à aller chercher : sans
/// `--roots` ni `ASL_ROOTS`, c'est elle qui vaut — la même que celle des
/// annuaires racines. Un fichier donné la remplace entièrement (un banc, une
/// autre autorité) : on n'ajoute pas, on choisit.
fn racines(invocation: &Invocation) -> Result<Vec<u8>, Issue> {
    let Some(ou) = invocation
        .racines
        .clone()
        .or_else(|| std::env::var("ASL_ROOTS").ok())
    else {
        return Ok(RACINE_EPINGLEE.to_vec());
    };
    std::fs::read(&ou).map_err(|quoi| Issue::Configuration(format!("{ou} : {quoi}")))
}

/// La racine d'`air-desktop-project`, en PEM — celle qui a signé les
/// certificats des annuaires racines. Publique par nature : c'est une clé
/// publique, et l'épingler est ce que `ca.sh` du serveur annonce.
const RACINE_EPINGLEE: &[u8] = include_bytes!("../racines/air-desktop-project.pem");

/// Ouvre une connexion, avec la patience d'une personne et non d'un daemon.
async fn ouvrir(reglages: &Reglages) -> Result<Connexion, Issue> {
    let secondes = patience();
    let patience = tokio::time::Duration::from_secs(secondes);
    match tokio::time::timeout(
        patience,
        joindre(reglages, &|| etat::hasard::<16>().unwrap_or([0; 16])),
    )
    .await
    {
        Ok(Ok(connexion)) => Ok(connexion),
        Ok(Err(FauteReseau::Tls(quoi))) => Err(Issue::Configuration(quoi)),
        Ok(Err(quoi)) => Err(Issue::Configuration(quoi.to_string())),
        Err(_) => Err(Issue::Injoignable(format!(
            "aucun annuaire n'a répondu en {secondes} seconde{}",
            if secondes > 1 { "s" } else { "" }
        ))),
    }
}

// ── `asl enroll` ────────────────────────────────────────────────────────────

/// Les réglages privés de l'adresse qu'on vient d'essayer.
///
/// Rend `None` quand il n'y en avait qu'une : il n'y a alors pas de seconde
/// tentative à faire, et c'est le cas d'un banc unique.
///
/// # CE QUE LE CLIENT SAIT, ET CE QU'IL NE SAIT PAS
///
/// Il connaît des ADRESSES, pas des racines. L'alias en rend quatre — l'A et
/// l'AAAA de chacun des deux bancs —, et rien dans une réponse ne dit de
/// laquelle elle vient (`replication.md` §6, dernier paragraphe). Retirer
/// celle qu'on vient d'essayer est donc ce qu'on peut faire de mieux ; avec la
/// liste de l'alias, la tournée qui suit prend l'autre adresse de la même
/// famille, c'est-à-dire l'autre banc.
fn restants_sans(reglages: &Reglages, deja: Option<std::net::SocketAddr>) -> Option<Vec<Annuaire>> {
    let restants: Vec<Annuaire> = reglages
        .annuaires()
        .iter()
        .filter(|annuaire| Some(annuaire.adresse) != deja)
        .cloned()
        .collect();
    (!restants.is_empty()).then_some(restants)
}

fn ailleurs_que(
    invocation: &Invocation,
    reglages: &Reglages,
    deja: Option<std::net::SocketAddr>,
) -> Result<Option<Reglages>, Issue> {
    let Some(restants) = restants_sans(reglages, deja) else {
        return Ok(None);
    };
    let racines = racines(invocation)?;
    Reglages::nouveaux(restants, racines, PLAFOND_MS)
        .map(Some)
        .map_err(|quoi| Issue::Configuration(quoi.to_string()))
}

/// Lie une clé neuve à cette machine.
///
/// # UN CODE REFUSÉ S'ESSAIE UNE FOIS SUR L'AUTRE RACINE
///
/// `replication.md` §6. Un code émis chez une racine met une fraction de
/// seconde à arriver chez l'autre — la coupure entière si la voie est coupée —,
/// et **le refus est le même pour un code inconnu et pour un code pas encore
/// arrivé** : l'annuaire supprime les codes au lieu de les marquer
/// (`protocole.md` §2.0), et ne peut donc pas les distinguer. Seul le client
/// sait qu'il y a une autre racine ; c'est donc à lui d'essayer.
///
/// **DEUX TENTATIVES, ET PAS UNE DE PLUS.** La borne n'est pas une prudence
/// vague : elle est ce qui rend cette règle gratuite. Un secret de cinquante
/// bits que l'on présente deux fois au lieu d'une reste un secret de cinquante
/// bits ; une boucle sur toutes les adresses de l'alias en ferait un oracle
/// qu'on interroge quatre fois par code deviné, et le jour où l'alias en
/// rendrait vingt, vingt fois.
///
/// La clé, elle, ne change pas entre les deux : elle n'a été liée nulle part,
/// puisque le code a été refusé. En générer une seconde laisserait la première
/// derrière soi.
pub async fn enrole(invocation: &Invocation, dossier: &Path, code: &str) -> Sortie {
    let reglages = reglages(invocation)?;
    let mut connexion = ouvrir(&reglages).await?;

    // **LA GRAINE EST GARDÉE DE CÔTÉ, ET N'EST ÉCRITE QU'APRÈS L'ACCORD.** Une
    // machine refusée ne doit pas laisser derrière elle une identité que
    // personne ne reconnaît.
    let (enrolement, graine) =
        etat::preparer_un_enrolement().map_err(|quoi| Issue::Configuration(quoi.to_string()))?;

    let enrolee = match connexion.enroler(&enrolement, code).await {
        Ok(enrolee) => enrolee,
        Err(FauteReseau::Statut(CODE_REFUSE)) => {
            let deja = connexion.distante().ok();
            let _ = connexion.fermer().await;
            let Some(ailleurs) = ailleurs_que(invocation, &reglages, deja)? else {
                return Err(Issue::CodeInconnu);
            };
            connexion = ouvrir(&ailleurs).await?;
            connexion
                .enroler(&enrolement, code)
                .await
                .map_err(|quoi| match quoi {
                    // La seconde a dit non elle aussi : le refus est acquis.
                    FauteReseau::Statut(CODE_REFUSE) => Issue::CodeInconnu,
                    autre => refus_de_l_annuaire(autre),
                })?
        }
        Err(autre) => return Err(refus_de_l_annuaire(autre)),
    };

    etat::ecrire(dossier, enrolee.machine, enrolee.proprietaire, &graine)
        .map_err(|quoi| Issue::Configuration(quoi.to_string()))?;

    println!("machine        {}", enrolee.machine.texte().as_str());
    match enrolee.proprietaire {
        Some(compte) => println!("compte         {}", compte.texte().as_str()),
        // Un annuaire d'avant 0.3.0 : `asl diagnose` l'apprendra.
        None => {
            println!("compte         non rendu par cet annuaire — `asl diagnose` le demandera")
        }
    }
    println!("identité       {}", dossier.join("identite").display());
    println!();
    println!(
        "La clé a été générée ICI, et sa moitié privée n'a pas quitté ce disque.\n\
         Le code est dépensé : il ne servira plus."
    );
    let _ = connexion.fermer().await;
    Ok(())
}

// ── `asl announce` ───────────────────────────────────────────────────────────

/// Annonce un service, et TIENT l'annonce.
///
/// # ELLE NE REND PAS LA MAIN, ET C'EST LE POINT LE PLUS FACILE À MANQUER
///
/// La connexion EST le bail (`protocole.md` §1.2) : `asl announce` qui se
/// terminerait retirerait l'annonce en se terminant. Un utilitaire qui afficherait
/// « annoncé » puis rendrait l'invite mentirait sur ce qu'il a fait — l'annonce
/// aurait déjà disparu quand l'invite s'affiche.
///
/// Elle reste donc au premier plan, et **Ctrl-C retire proprement** : une trame
/// `CONNECTION_CLOSE` au lieu d'une minute pendant laquelle l'annuaire donne une
/// adresse morte.
pub async fn annonce(
    invocation: &Invocation,
    identite: &Identite,
    service: &str,
    points: &[PointEcoute],
) -> Sortie {
    let nom = NomService::analyser(service).map_err(|quoi| {
        Issue::Usage(format!(
            "`{service}` n'est pas un nom de service : {quoi:?}"
        ))
    })?;
    let reglages = reglages(invocation)?;
    let arret = ecouter_ctrl_c();

    loop {
        let mut connexion = ouvrir(&reglages).await?;

        // **L'ADRESSE LOCALE EST CELLE QUI A SERVI À JOINDRE L'ANNUAIRE.** C'est
        // la seule qui ait un sens à comparer : sans elle, le verdict de NAT
        // serait `indetermine`, ce qui est vrai mais inutile.
        let locales = [connexion
            .locale()
            .map_err(|quoi| Issue::Injoignable(quoi.to_string()))?
            .ip()];
        let annonce = identite
            .annoncer(nom, points, &locales)
            .map_err(|quoi| Issue::Usage(format!("l'annonce est refusée : {quoi:?}")))?;

        connexion
            .authentifier(identite)
            .await
            .map_err(refus_de_l_annuaire)?;
        let corps = connexion
            .annoncer(&annonce)
            .await
            .map_err(refus_de_l_annuaire)?;

        println!("{}", rendu::reponse(&corps).map_err(Issue::Injoignable)?);
        println!();
        println!(
            "L'annonce est TENUE par cette connexion. Ctrl-C pour la retirer\n\
             proprement ; tuer le processus la laisserait vivre une minute de plus."
        );

        // On tient.
        while connexion.vivante() && !arret.load(Ordering::Acquire) {
            if connexion.entretenir(500).await.is_err() {
                break;
            }
        }

        if arret.load(Ordering::Acquire) {
            let _ = connexion.fermer().await;
            println!();
            println!("annonce retirée.");
            return Ok(());
        }

        println!();
        println!("attache perdue — on recommence, et l'on réannonce.");
    }
}

// ── `asl where` ────────────────────────────────────────────────────────────────

/// Demande où joindre un service — sur une machine, ou partout où ce compte a
/// le droit de le voir.
pub async fn ou(
    invocation: &Invocation,
    identite: &Identite,
    machine: Option<asl_id::Identifiant>,
    service: &str,
) -> Sortie {
    let reglages = reglages(invocation)?;
    let mut connexion = ouvrir(&reglages).await?;
    connexion
        .authentifier(identite)
        .await
        .map_err(refus_de_l_annuaire)?;

    let dit = match machine {
        Some(machine) => {
            let corps = connexion
                .ou(machine, service)
                .await
                .map_err(refus_de_l_annuaire)?;
            rendu::reponse(&corps)
        }
        None => {
            let corps = connexion
                .ou_par_nom(service)
                .await
                .map_err(refus_de_l_annuaire)?;
            rendu::reponses(&corps)
        }
    };
    println!("{}", dit.map_err(Issue::Injoignable)?);
    let _ = connexion.fermer().await;
    Ok(())
}

// ── `asl machines` ──────────────────────────────────────────────────────────

/// Les machines d'un utilisateur que ce compte a le droit de voir.
///
/// **UNE LISTE VIDE N'EST PAS UNE PANNE** : c'est ce que l'annuaire répond à
/// qui n'a rien reçu de cet utilisateur — et il ne dit pas s'il a des machines
/// (C9). Le rendu le dit à la place d'un `[]` muet.
///
/// **SANS COMPTE, LES MIENNES** : celles du propriétaire de cette machine, que
/// l'annuaire nomme lui-même (`GET /v1/moi`) — et non ce qu'un fichier local
/// croit, qui peut dater d'avant un ré-enrôlement.
pub async fn machines(
    invocation: &Invocation,
    identite: &Identite,
    compte: Option<asl_id::Identifiant>,
) -> Sortie {
    let reglages = reglages(invocation)?;
    let mut connexion = ouvrir(&reglages).await?;
    connexion
        .authentifier(identite)
        .await
        .map_err(refus_de_l_annuaire)?;
    let corps = match compte {
        Some(compte) => connexion.machines_de(compte).await,
        None => connexion.machines_du_proprietaire().await,
    }
    .map_err(refus_de_l_annuaire)?;
    print!("{}", rendu::machines(&corps).map_err(Issue::Injoignable)?);
    let _ = connexion.fermer().await;
    Ok(())
}

// ── `asl enrolled` ──────────────────────────────────────────────────────────

/// Les appareils enrôlés sur le compte de cette machine, révoqués compris.
///
/// # UN COMPTE NOMMÉ NE PEUT ÊTRE QUE LE NÔTRE, ET C'EST DIT AVANT DE JOINDRE
///
/// `GET /v1/moi/appareils` est **pour soi seulement** (`protocole.md` §3) : il
/// n'existe aucune forme qui nomme un compte, parce que les appareils d'un
/// compte ne se voient que depuis ce compte (`modele.md` §2.2, C13). Nommer le
/// propriétaire de cette machine est admis — c'est le confirmer — ; en nommer
/// un autre est refusé **ici, avant toute requête**, et non par un `401` de
/// l'annuaire qui enverrait chercher une clé là où c'est la demande qui n'a
/// pas de sens. Quand le fichier d'identité ne connaît pas encore le compte,
/// c'est `GET /v1/moi` qui le dit, sur la connexion prouvée — toujours avant
/// de demander la liste.
pub async fn enroles(
    invocation: &Invocation,
    dossier: &Path,
    compte: Option<asl_id::Identifiant>,
) -> Sortie {
    let fiche =
        etat::lire_la_fiche(dossier).map_err(|quoi| Issue::Configuration(quoi.to_string()))?;
    if let (Some(demande), Some(connu)) = (compte, fiche.compte)
        && demande != connu
    {
        return Err(compte_etranger(demande, connu));
    }

    let reglages = reglages(invocation)?;
    let mut connexion = ouvrir(&reglages).await?;
    connexion
        .authentifier(&fiche.identite)
        .await
        .map_err(refus_de_l_annuaire)?;
    if let (Some(demande), None) = (compte, fiche.compte) {
        let moi = connexion.moi().await.map_err(refus_de_l_annuaire)?;
        if demande != moi.proprietaire {
            let _ = connexion.fermer().await;
            return Err(compte_etranger(demande, moi.proprietaire));
        }
    }
    let corps = connexion
        .appareils_du_proprietaire()
        .await
        .map_err(refus_de_l_annuaire)?;
    print!("{}", rendu::appareils(&corps).map_err(Issue::Injoignable)?);
    let _ = connexion.fermer().await;
    Ok(())
}

/// Le refus d'`asl enrolled u-…` pour un compte qui n'est pas celui de cette
/// machine — une issue d'usage : ce qui a été demandé ne se demande pas.
fn compte_etranger(demande: asl_id::Identifiant, notre: asl_id::Identifiant) -> Issue {
    Issue::Usage(format!(
        "les appareils d'un compte ne se voient que depuis ce compte : cette\n\
         machine appartient à {}, et `{}` n'est pas lui. `asl enrolled` sans\n\
         argument rend les appareils de son compte.",
        notre.texte().as_str(),
        demande.texte().as_str()
    ))
}

// ── `asl replication` ───────────────────────────────────────────────────────

/// L'état de la voie entre les deux racines, vu de celle qu'on a jointe.
///
/// # ELLE DIT D'ABORD QUI A RÉPONDU, PARCE QUE L'ALIAS NE LE DIT PAS
///
/// `asl-root.air-desktop.org` rend les deux racines, et la tournée en joint
/// une — sans dire laquelle, et la réponse ne le dit pas non plus
/// (`replication.md` §6). Or ce que `GET /v1/replication` rend est **l'état vu
/// de cette racine-là** : son horloge, son curseur sur l'autre. Une ligne qui
/// dirait « ouverte, à jour » sans dire de qui ne prouverait rien sur l'autre
/// ; `asl replication` lancé deux fois joint, en général, les deux.
///
/// C'est un verbe de CLI, sans ABI (C12 n'est pas touchée) : comme
/// `asl machines`, il vit sur la voie machine, une connexion prouvée, une
/// requête, et la main rendue.
pub async fn replication(invocation: &Invocation, identite: &Identite) -> Sortie {
    let reglages = reglages(invocation)?;
    let mut connexion = ouvrir(&reglages).await?;
    connexion
        .authentifier(identite)
        .await
        .map_err(refus_de_l_annuaire)?;
    let corps = connexion
        .etat_de_la_replication()
        .await
        .map_err(refus_de_l_annuaire)?;
    let dit = rendu::replication(&corps).map_err(Issue::Injoignable)?;
    match connexion.distante() {
        Ok(ou) => println!("annuaire       {ou}"),
        Err(quoi) => println!("annuaire       inconnu — {quoi}"),
    }
    print!("{dit}");
    let _ = connexion.fermer().await;
    Ok(())
}

// ── `asl identity` ──────────────────────────────────────────────────────────

/// Dit qui est cette machine et pour qui elle agit, **sans rien joindre**.
///
/// C'est ce qu'un script ou un exploitant lit sur une machine dont le réseau est
/// en panne : le fichier d'identité suffit, et l'annuaire n'a rien à y ajouter.
pub fn identite(dossier: &Path) -> Sortie {
    let fiche =
        etat::lire_la_fiche(dossier).map_err(|quoi| Issue::Configuration(quoi.to_string()))?;
    println!(
        "machine        {}",
        fiche.identite.machine().texte().as_str()
    );
    match fiche.compte {
        Some(compte) => println!("compte         {}", compte.texte().as_str()),
        None => println!(
            "compte         inconnu de ce fichier — `asl diagnose` le demande à l'annuaire"
        ),
    }
    println!("identité       {}", dossier.join("identite").display());
    Ok(())
}

// ── `asl diagnose` ────────────────────────────────────────────────────────

/// Dit ce qu'on sait de l'annuaire, et **ce qu'on ne sait pas**.
///
/// # CE QU'IL NE PEUT PAS RÉPONDRE AUJOURD'HUI, ET POURQUOI IL LE DIT
///
/// « Sous quelle adresse l'annuaire me voit-il ? » et « suis-je derrière un
/// NAT ? » sont les deux questions pour lesquelles cet utilitaire existe. Or
/// **aucune route ne les rend sans annoncer** : `vu_depuis` et `derriere_nat`
/// n'arrivent que dans la réponse à `POST /v1/annonce`, qui crée un service.
///
/// Un diagnostic qui annoncerait en douce laisserait derrière lui un service que
/// personne n'a demandé. Il dit donc ce qu'il sait, nomme ce qui manque, et
/// renvoie à `asl announce` — plutôt que d'affirmer ce qu'il n'a pas mesuré, ce
/// que C6 interdit à l'annuaire et que l'utilitaire n'a pas plus le droit de
/// faire.
pub async fn diagnostic(invocation: &Invocation, dossier: &Path) -> Sortie {
    let reglages = reglages(invocation)?;

    println!("annuaires, dans l'ordre où ils seront essayés");
    let adresses: Vec<std::net::SocketAddr> = reglages
        .annuaires()
        .iter()
        .map(|quoi| quoi.adresse)
        .collect();
    for rang in 0..adresses.len() {
        let Some(place) = asl_client::place_en_ordre(&adresses, rang) else {
            break;
        };
        let quoi = &reglages.annuaires()[place];
        println!(
            "  {}. {:<45} nom exigé : {}   ({})",
            rang.saturating_add(1),
            quoi.adresse.to_string(),
            quoi.nom,
            if quoi.adresse.is_ipv6() {
                "IPv6"
            } else {
                "IPv4"
            }
        );
    }

    println!();
    let mut connexion = ouvrir(&reglages).await?;
    println!("connexion      établie");
    match connexion.locale() {
        Ok(ou) => println!("locale         {ou}"),
        Err(quoi) => println!("locale         inconnue — {quoi}"),
    }
    println!(
        "liaison        exportée de la poignée de main ({} octets)",
        connexion.liaison().octets().len()
    );

    // **CE QUE L'ANNUAIRE VOIT DE NOUS**, et c'est la première chose qu'on
    // regarde quand personne n'arrive à joindre un port. `GET /v1/vu` n'exige
    // aucune preuve et n'annonce rien ; un annuaire plus ancien ne la sert pas,
    // et le dire vaut mieux que de faire échouer le diagnostic entier.
    match connexion.vu().await {
        Ok(corps) => match rendu::vu(&corps) {
            Ok(dit) => println!("vu             {dit}"),
            Err(quoi) => println!("vu             ILLISIBLE — {quoi}"),
        },
        Err(quoi) => println!("vu             INDISPONIBLE — {quoi}"),
    }

    // L'identité, si elle existe.
    println!();
    match etat::lire_la_fiche(dossier) {
        Err(quoi) => {
            println!("identité       ABSENTE OU ILLISIBLE");
            println!("               {quoi}");
        }
        Ok(fiche) => {
            let identite = fiche.identite;
            println!("machine        {}", identite.machine().texte().as_str());
            match connexion.authentifier(&identite).await {
                Ok(()) => {
                    println!("clé            acceptée par l'annuaire");
                    // **POUR QUI CETTE MACHINE AGIT**, demandé à l'annuaire
                    // sur la connexion qu'elle vient de prouver ; et le fichier
                    // d'identité est complété s'il ne le disait pas encore
                    // (`protocole.md` §3, `GET /v1/moi`).
                    match connexion.moi().await {
                        Ok(moi) => {
                            println!("compte         {}", moi.proprietaire.texte().as_str());
                            if fiche.compte != Some(moi.proprietaire) {
                                match etat::completer(dossier, moi.proprietaire) {
                                    Ok(()) => {
                                        println!("               (posé dans le fichier d'identité)")
                                    }
                                    Err(quoi) => println!(
                                        "               (non posé dans le fichier : {quoi})"
                                    ),
                                }
                            }
                        }
                        Err(quoi) => match fiche.compte {
                            Some(compte) => println!(
                                "compte         {} (d'après le fichier ; l'annuaire ne répond pas à /v1/moi — {quoi})",
                                compte.texte().as_str()
                            ),
                            None => println!(
                                "compte         INCONNU — l'annuaire ne sert pas /v1/moi ({quoi})"
                            ),
                        },
                    }
                }
                Err(quoi) => {
                    println!("clé            REFUSÉE — {quoi}");
                    println!(
                        "               la clé de cette machine n'est pas (ou plus) liée.\n\
                         \x20              Demandez un code, puis : asl enroll <code>"
                    );
                }
            }
        }
    }

    println!();
    println!(
        "Ce que ce diagnostic NE dit pas : si vous êtes derrière un NAT. Ce\n\
         verdict se tranche en comparant l'adresse ci-dessus à celles que votre\n\
         daemon ANNONCE, et qui n'a rien annoncé n'a rien à comparer. Pour\n\
         l'obtenir : asl announce <service> <protocole>:<port>"
    );
    let _ = connexion.fermer().await;
    Ok(())
}

/// Traduit un refus du réseau en une issue, en gardant la distinction qui compte.
///
/// **UN REFUS N'EST PAS UNE PANNE.** `403` veut dire « l'annuaire a compris et
/// a dit non » ; un délai veut dire « on n'a rien obtenu ». Les confondre ferait
/// chercher une panne de réseau là où il y a un droit manquant.
fn refus_de_l_annuaire(quoi: FauteReseau) -> Issue {
    match quoi {
        FauteReseau::Statut(code) => Issue::Refuse(code),
        autre => Issue::Injoignable(autre.to_string()),
    }
}

/// Un drapeau que Ctrl-C lève.
///
/// **PAS DE `select!`, DONC PAS DE MACROS `tokio`** : une tâche pose un drapeau,
/// la boucle d'entretien le lit à chaque réveil. C'est exactement ce que fait
/// `asl_client_tokio::Attache`, et cela coûte une demi-seconde de latence au
/// pire — sur un retrait manuel, personne ne la mesure.
fn ecouter_ctrl_c() -> Arc<AtomicBool> {
    let arret = Arc::new(AtomicBool::new(false));
    let sien = Arc::clone(&arret);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            sien.store(true, Ordering::Release);
        }
    });
    arret
}

#[cfg(test)]
mod tests {
    /// La tournée ne change ni les familles ni leur ordre : IPv6 d'abord,
    /// toujours ; elle ne fait que décaler chaque famille — et un ensemble
    /// à une adresse par famille reste tel quel.
    #[test]
    fn la_tournee_garde_ipv6_devant_et_ne_perd_rien() {
        use std::net::SocketAddr;
        let six_a: SocketAddr = "[2001:db8::1]:6630".parse().unwrap();
        let six_b: SocketAddr = "[2001:db8::2]:6630".parse().unwrap();
        let quatre: SocketAddr = "192.0.2.1:6630".parse().unwrap();
        for _ in 0..16 {
            let tournee = super::tourner(vec![quatre, six_a, six_b]);
            assert_eq!(tournee.len(), 3);
            assert!(tournee[0].is_ipv6() && tournee[1].is_ipv6(), "{tournee:?}");
            assert_eq!(tournee[2], quatre);
            assert!(tournee.contains(&six_a) && tournee.contains(&six_b));
        }
        assert_eq!(super::tourner(vec![quatre]), vec![quatre]);
        assert!(super::tourner(vec![]).is_empty());
    }

    /// La seconde tentative de `asl enroll` vise AILLEURS, et n'existe pas
    /// quand il n'y a qu'une adresse.
    ///
    /// **C'est la borne de `replication.md` §6 qu'on éprouve ici** : deux
    /// tentatives, pas une de plus. Retirer l'adresse déjà essayée est ce qui
    /// la garantit — une liste qui la garderait permettrait à la tournée d'y
    /// revenir, et le « une fois » deviendrait « jusqu'à ce que ça marche ».
    #[test]
    fn la_seconde_tentative_exclut_l_adresse_deja_essayee() {
        use asl_client_tokio::{Annuaire, Reglages};
        use std::net::SocketAddr;

        let une: SocketAddr = "192.0.2.1:6630".parse().unwrap();
        let autre: SocketAddr = "192.0.2.2:6630".parse().unwrap();
        let nomme = |adresse| Annuaire {
            adresse,
            nom: "annuaire.example".to_owned(),
        };
        let racines = super::RACINE_EPINGLEE.to_vec();
        let deux = Reglages::nouveaux(
            vec![nomme(une), nomme(autre)],
            racines.clone(),
            super::PLAFOND_MS,
        )
        .expect("deux adresses, une configuration valable");

        let restants = super::restants_sans(&deux, Some(une)).expect("il en reste une");
        let adresses: Vec<SocketAddr> = restants.iter().map(|a| a.adresse).collect();
        assert_eq!(adresses, vec![autre], "l'adresse essayée doit disparaître");

        // Une seule adresse : il n'y a pas d'ailleurs, et c'est le cas d'un banc.
        let seule = Reglages::nouveaux(vec![nomme(une)], racines, super::PLAFOND_MS)
            .expect("une adresse suffit à une configuration");
        assert!(
            super::restants_sans(&seule, Some(une)).is_none(),
            "sans autre adresse, il n'y a pas de seconde tentative"
        );
    }
}
