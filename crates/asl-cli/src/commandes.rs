//! Les verbes, et ce qu'ils demandent au réseau.

use std::net::ToSocketAddrs as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use asl_client::Identite;
use asl_client_tokio::{
    Annuaire, Connexion, Faute as FauteReseau, LocateursAppris, Provenance, Reglages, confiance_de,
    est_une_racine_embarquee, joindre, racines_a_essayer,
};
use asl_proto::{NomService, PointEcoute};

use crate::arguments::{Cible, CibleDeDomaine, Invocation};
use crate::domaines::{AdresseVue, ServiceVu, ServicesVus, VueDeDomaine};
use crate::etat;
use crate::rendu;
use crate::{Issue, Sortie};

/// Le plafond de recul, en millisecondes.
///
/// **QUINZE SECONDES, ET C'EST UN PLACEHOLDER ASSUMÉ.** La vraie cadence vient
/// du bail que l'annuaire accorde (`modele.md` §4.1), mais il faut bien une
/// valeur avant d'avoir parlé à qui que ce soit. Le bon delta se mesure derrière
/// des NAT réels, et il ne l'est pas encore.
pub(crate) const PLAFOND_MS: u64 = 15_000;

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
pub(crate) fn patience() -> u64 {
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
pub(crate) fn reglages(invocation: &Invocation) -> Result<Reglages, Issue> {
    avertir_d_asl_roots();
    let cibles = if invocation.annuaires.is_empty() {
        depuis_l_environnement()?
    } else {
        Some(invocation.annuaires.clone())
    };
    // **SANS RIEN DIRE, LES RACINES EMBARQUÉES** — leurs adresses, leurs
    // identités : aucun résolveur (C20) —, **précédées des locateurs appris**
    // que le cache garde pour elles (décision 85).
    let Some(cibles) = cibles else {
        let racines = racines_par_defaut(invocation)
            .into_iter()
            .map(|(annuaire, _)| annuaire)
            .collect();
        return Reglages::nouveaux(racines, PLAFOND_MS)
            .map_err(|quoi| Issue::Configuration(quoi.to_string()));
    };

    let mut annuaires = Vec::new();
    for cible in &cibles {
        let nom = invocation.nom.clone().unwrap_or_else(|| cible.hote.clone());
        // **UNE ADRESSE LITTÉRALE NE SE RÉSOUT PAS.** Un nom, si : c'est une
        // commodité qu'on a écrite, jamais une preuve — l'identité reste ce
        // qu'on juge.
        let adresses: Vec<std::net::SocketAddr> = match cible.hote.parse::<std::net::IpAddr>() {
            Ok(ip) => vec![std::net::SocketAddr::new(ip, cible.port)],
            Err(_) => (cible.hote.as_str(), cible.port)
                .to_socket_addrs()
                .map_err(|quoi| {
                    Issue::Configuration(format!("`{}` ne se résout pas : {quoi}", cible.hote))
                })?
                .collect(),
        };
        for adresse in tourner(adresses) {
            annuaires.push(Annuaire {
                adresse,
                nom: nom.clone(),
                identite: cible.identite,
            });
        }
    }
    if annuaires.is_empty() {
        return Err(Issue::Configuration(
            "aucun annuaire ne se résout en une adresse".to_owned(),
        ));
    }

    Reglages::nouveaux(annuaires, PLAFOND_MS).map_err(|quoi| Issue::Configuration(quoi.to_string()))
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

/// Les annuaires que `ASL_DIRECTORY` désigne, séparés par des virgules ;
/// `None` sans elle — on joindra alors les racines embarquées.
fn depuis_l_environnement() -> Result<Option<Vec<Cible>>, Issue> {
    let Ok(brut) = std::env::var("ASL_DIRECTORY") else {
        return Ok(None);
    };
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
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// `ASL_ROOTS` n'est plus lue : on le dit, sans échouer.
///
/// **UN AVERTISSEMENT, ET NON UN REFUS** — à la différence de `--roots`, qu'on
/// tape : une variable d'environnement traîne dans une unité systemd écrite
/// il y a des mois, à côté d'un daemon qui joint très bien les racines
/// embarquées par leur identité. Le faire tomber pour une variable devenue
/// sans effet serait casser ce qui marche ; se taire laisserait croire
/// qu'elle compte encore.
fn avertir_d_asl_roots() {
    if std::env::var_os("ASL_ROOTS").is_some() {
        eprintln!(
            "asl : `ASL_ROOTS` est ignorée — un annuaire se croit par sa clé, plus par une \
             autorité ; `ASL_DIRECTORY=<hôte:port>=<n-…>`, ou rien pour les racines embarquées"
        );
    }
}

/// Les racines qu'on joint sans rien dire, chaque adresse avec sa provenance :
/// les locateurs appris d'abord, les embarqués en secours.
///
/// **UN CACHE ILLISIBLE EST UN CACHE ABSENT** : on joint les racines
/// embarquées, et `asl diagnose` dit pourquoi. Jamais une panne.
fn racines_par_defaut(invocation: &Invocation) -> Vec<(Annuaire, Provenance)> {
    let dossier = etat::repertoire(invocation.etat.as_deref());
    match etat::lire_le_cache(&dossier) {
        etat::Cache::Lu(appris) => racines_a_essayer(Some(&appris)),
        etat::Cache::Absent | etat::Cache::Illisible(_) => racines_a_essayer(None),
    }
}

/// Ce que la relecture de `GET /v1/racines` a donné.
enum Relecture {
    /// Le cache a moins d'un jour : rien à relire.
    Inutile,
    /// L'annuaire joint n'est pas une racine embarquée : sa liste ne se garde
    /// pas.
    PasUneRacine,
    /// La liste a été relue, vérifiée et gardée.
    Relue {
        /// Les racines embarquées dont on garde des locateurs.
        gardees: usize,
        /// Les racines de la liste que ce binaire ne connaît pas.
        ignorees: Vec<asl_id::Identifiant>,
    },
    /// La relecture n'a pas abouti — ce n'est pas l'échec de la commande.
    Ratee(String),
}

/// Relit la liste des racines sur une connexion qu'on vient d'ouvrir, si le
/// cache est absent, illisible, ou plus vieux que
/// [`asl_client_tokio::RELIRE_APRES_S`] — ou toujours, avec `toujours`.
///
/// # SEULEMENT SUR UNE RACINE EMBARQUÉE
///
/// La liste n'a pas d'autre signature que la connexion (décision 56) : on ne
/// la garde que si l'annuaire joint a été jugé sous la clé d'une racine que
/// ce binaire embarque. Un annuaire local, ou un banc nommé par
/// `--directory`, ne réécrit rien.
///
/// **SANS BRUIT** : une relecture ratée laisse le cache tel qu'il était, et
/// la commande continue — ce n'est pas ce qu'on lui a demandé.
async fn relire_les_racines(
    invocation: &Invocation,
    reglages: &Reglages,
    connexion: &mut Connexion,
    toujours: bool,
) -> Relecture {
    let jointe = connexion.distante().ok().and_then(|ou| {
        reglages
            .annuaires()
            .iter()
            .find(|quoi| quoi.adresse == ou)
            .map(|quoi| quoi.identite)
    });
    if !jointe.is_some_and(est_une_racine_embarquee) {
        return Relecture::PasUneRacine;
    }
    let dossier = etat::repertoire(invocation.etat.as_deref());
    let maintenant = etat::maintenant();
    if !toujours
        && let etat::Cache::Lu(appris) = etat::lire_le_cache(&dossier)
        && !appris.a_relire(maintenant)
    {
        return Relecture::Inutile;
    }
    let racines = match asl_client_tokio::apprendre_les_racines(connexion).await {
        Ok(racines) => racines,
        Err(quoi) => return Relecture::Ratee(quoi.to_string()),
    };
    let (appris, ignorees) = LocateursAppris::depuis_la_liste(&racines, maintenant);
    if let Err(quoi) = etat::ecrire_le_cache(&dossier, &appris) {
        return Relecture::Ratee(format!("le cache ne s'écrit pas : {quoi}"));
    }
    Relecture::Relue {
        gardees: appris.racines().len(),
        ignorees,
    }
}

/// Ouvre une connexion, puis relit la liste des racines s'il est temps.
pub(crate) async fn ouvrir_et_relire(
    invocation: &Invocation,
    reglages: &Reglages,
) -> Result<Connexion, Issue> {
    let mut connexion = ouvrir(reglages).await?;
    let _ = relire_les_racines(invocation, reglages, &mut connexion, false).await;
    Ok(connexion)
}

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
    reglages: &Reglages,
    deja: Option<std::net::SocketAddr>,
) -> Result<Option<Reglages>, Issue> {
    let Some(restants) = restants_sans(reglages, deja) else {
        return Ok(None);
    };
    Reglages::nouveaux(restants, PLAFOND_MS)
        .map(Some)
        .map_err(|quoi| Issue::Configuration(quoi.to_string()))
}

/// Ce qu'`asl enroll` suggère une fois la machine enrôlée : activer l'écho,
/// que le paquet a posé sans l'activer (`protocole.md` §3 quater, décision
/// 93).
#[cfg(target_os = "linux")]
const SUGGESTION_ECHO: &str = "Pour que l'annuaire puisse prouver qu'elle est joignable : systemctl --user enable --now asl-echo";

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
    let mut connexion = ouvrir_et_relire(invocation, &reglages).await?;

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
            let Some(ailleurs) = ailleurs_que(&reglages, deja)? else {
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
    // **UNE LIGNE, ET RIEN D'ACTIVÉ** (décision 93 ; E14) : le paquet pose
    // l'unité de l'écho désactivée, et c'est ici, au moment où la clé existe,
    // qu'on dit qu'elle est là. Sous Linux seulement : c'est là que le paquet
    // la pose.
    #[cfg(target_os = "linux")]
    println!("{SUGGESTION_ECHO}");
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
    // **L'ANNUAIRE LOCAL VERS LEQUEL UNE RACINE NOUS A RENVOYÉS** (`421`,
    // décision 59), s'il y en a un : on y retourne tant qu'il répond, et l'on
    // revient aux racines quand il se tait — pour réapprendre si le domaine a
    // changé d'hébergeur. **UN SEUL SAUT** : un `421` reçu de l'annuaire
    // local n'est pas suivi, il est une faute (la même règle que l'attache).
    let mut local: Option<Reglages> = None;

    loop {
        let mut connexion = match &local {
            Some(chez_lui) => match ouvrir(chez_lui).await {
                Ok(connexion) => connexion,
                Err(quoi) => {
                    println!("l'annuaire local ne répond pas ({quoi:?}) — retour aux racines.");
                    local = None;
                    continue;
                }
            },
            None => ouvrir_et_relire(invocation, &reglages).await?,
        };

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
        let corps = match connexion.annoncer(&annonce).await {
            Ok(corps) => corps,
            Err(FauteReseau::Renvoye(corps)) if local.is_none() => {
                let _ = connexion.fermer().await;
                local = Some(reglages_du_renvoi(&corps).await?);
                continue;
            }
            Err(quoi) => return Err(refus_de_l_annuaire(quoi)),
        };

        // **LE KEEPALIVE À LA CADENCE DU BAIL** (`modele.md` §4.1) — ce que
        // l'attache du daemon fait, et que cette commande oubliait : sa
        // connexion restait silencieuse, mourait au délai d'inactivité (30 s)
        // et se refaisait, le service passant « parti » à chaque fois. Vu le
        // 27/09 sur speedy : 41 « attache perdue » en vingt minutes, et les
        // racines qui le disaient tour à tour vivant et introuvable.
        if let Ok(bail) = asl_client_tokio::cadence_du_bail(&corps) {
            connexion.maintenir(bail);
        }
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
    let mut connexion = ouvrir_et_relire(invocation, &reglages).await?;
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

/// Demande où joindre un annuaire local — `asl where n-… asl-directory`
/// (`annuaires.md` §2 quinquies ; serveur 0.38.0).
///
/// # TROIS ISSUES, ET LA TROISIÈME NE SE DÉTAILLE PAS
///
/// Avec `localiser`, chaque adresse et l'identité qu'on doit y trouver ;
/// avec `voir` seul, qu'il existe et qu'il est vivant, **sans adresses** ;
/// sinon `404` — introuvable, parti ou hors de vos droits, que la racine ne
/// distingue pas (C9), et que ce verbe ne cherche pas à distinguer.
pub async fn ou_annuaire(
    invocation: &Invocation,
    identite: &Identite,
    annuaire: asl_id::Identifiant,
) -> Sortie {
    let reglages = reglages(invocation)?;
    let mut connexion = ouvrir_et_relire(invocation, &reglages).await?;
    connexion
        .authentifier(identite)
        .await
        .map_err(refus_de_l_annuaire)?;
    let corps = connexion
        .ou_annuaire(annuaire)
        .await
        .map_err(refus_de_l_annuaire)?;
    let _ = connexion.fermer().await;
    print!(
        "{}",
        rendu::annuaire_local(annuaire, &corps).map_err(Issue::Injoignable)?
    );
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
    let mut connexion = ouvrir_et_relire(invocation, &reglages).await?;
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
    let mut connexion = ouvrir_et_relire(invocation, &reglages).await?;
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

// ── `asl domains` et `asl domain` ───────────────────────────────────────────

/// Les domaines que ce compte voit — `GET /v1/domaines` (serveur 0.39.0).
///
/// **UNE LISTE VIDE EST UNE ISSUE, PAS UNE SORTIE** : un compte a toujours au
/// moins un domaine, et l'annuaire rend `[]` à une machine sans `lecture`
/// plutôt que de refuser. On le dit sur la sortie d'erreur, code 3 — un
/// script qui liste des domaines ne doit pas prendre ce silence pour « rien
/// à faire ».
pub async fn domaines(invocation: &Invocation, identite: &Identite) -> Sortie {
    let reglages = reglages(invocation)?;
    let mut connexion = ouvrir_et_relire(invocation, &reglages).await?;
    connexion
        .authentifier(identite)
        .await
        .map_err(refus_de_l_annuaire)?;
    let visibles = connexion.domaines().await.map_err(refus_de_l_annuaire)?;
    let _ = connexion.fermer().await;
    if visibles.is_empty() {
        return Err(Issue::RefusDit(crate::domaines::SANS_LECTURE.to_owned()));
    }
    print!("{}", crate::domaines::liste(&visibles));
    Ok(())
}

/// Un domaine, ses machines, et les services de celles qu'on a le droit de
/// voir.
///
/// # DANS L'ORDRE, ET POURQUOI
///
/// 1. **L'alias se résout d'abord** (`GET /v1/domaines?alias=…`), s'il en est
///    un : aucun domaine, on le dit ; plusieurs, on refuse et on les liste —
///    choisir à la place de l'utilisateur serait lui montrer peut-être le
///    domaine d'un autre sous le nom du sien.
/// 2. **Le détail** (`GET /v1/domaines/{d}`). Un `404` ne se distingue pas
///    (C10) ; mais un second `GET /v1/domaines` vide dit que c'est la
///    capacité `lecture` qui manque, et cela vaut d'être dit à part.
/// 3. **Qui je suis** (`GET /v1/moi`) : c'est ce qui sépare une machine à
///    moi d'une machine d'autrui.
/// 4. **Les services de chaque machine qu'on voit** : les nôtres, et —
///    depuis le serveur 0.40.0 (décisions 103–104) — celles d'autrui dès
///    que le domaine nous donne `voir`. L'annuaire les rend alors **sans
///    adresses** (un service vivant y porte `"annonce":{}`), et complètes
///    avec `localiser`. Sans `voir`, on ne demande rien : la réponse serait
///    un `[]` qu'on prendrait pour « rien ».
/// 5. Avec `--where`, **chaque service annoncé se résout** comme `asl where`
///    le ferait (`GET /v1/ou/{m}/{nom}`), si l'on tient `localiser` — sur la
///    machine, parce qu'elle est à nous, ou sur le domaine, qui atteint
///    toutes ses machines. Sinon, la ligne le dit, sans rien demander.
///
/// Un échec à l'étape 4 ou 5 n'arrête pas le verbe : il se dit sur la ligne
/// de la machine ou du service, et le reste s'affiche.
pub async fn domaine(
    invocation: &Invocation,
    identite: &Identite,
    cible: &CibleDeDomaine,
    ou: bool,
) -> Sortie {
    let reglages = reglages(invocation)?;
    let mut connexion = ouvrir_et_relire(invocation, &reglages).await?;
    connexion
        .authentifier(identite)
        .await
        .map_err(refus_de_l_annuaire)?;

    let issue = lire_un_domaine(&mut connexion, cible, ou).await;
    let _ = connexion.fermer().await;
    print!("{}", crate::domaines::detail(&issue?));
    Ok(())
}

/// Le corps d'[`domaine`], sur une connexion prouvée — séparé pour que la
/// connexion se ferme quelle que soit l'issue.
async fn lire_un_domaine(
    connexion: &mut Connexion,
    cible: &CibleDeDomaine,
    ou: bool,
) -> Result<VueDeDomaine, Issue> {
    let domaine = match cible {
        CibleDeDomaine::Identifiant(domaine) => *domaine,
        CibleDeDomaine::Alias(alias) => {
            let trouves = connexion
                .domaines_par_alias(alias)
                .await
                .map_err(refus_de_l_annuaire)?;
            match trouves.as_slice() {
                [] => return Err(Issue::RefusDit(crate::domaines::alias_inconnu(alias))),
                [seul] => seul.domaine,
                plusieurs => {
                    // Ce qu'on voit de chacun, pour qu'on sache lequel taper ;
                    // sans `lecture`, rien — et chacun se dit hors de vos droits.
                    let visibles = connexion.domaines().await.unwrap_or_default();
                    return Err(Issue::Usage(crate::domaines::alias_ambigu(
                        alias, plusieurs, &visibles,
                    )));
                }
            }
        }
    };

    let detail = match connexion.domaine(domaine).await {
        Ok(detail) => detail,
        Err(FauteReseau::Statut(404)) => {
            let visibles = connexion.domaines().await.map_err(refus_de_l_annuaire)?;
            return Err(Issue::RefusDit(
                if visibles.is_empty() {
                    crate::domaines::SANS_LECTURE
                } else {
                    crate::domaines::HORS_DE_VOS_DROITS
                }
                .to_owned(),
            ));
        }
        Err(autre) => return Err(refus_de_l_annuaire(autre)),
    };
    let moi = connexion
        .moi()
        .await
        .map_err(refus_de_l_annuaire)?
        .proprietaire;
    let voit_le_domaine = detail.domaine.voit_ses_machines();
    let localise_le_domaine = detail.domaine.peut("localiser");

    let mut services = Vec::with_capacity(detail.machines.len());
    for machine in &detail.machines {
        let a_moi = machine.proprietaire == moi;
        // **SANS `voir`, ON NE DEMANDE PAS** : l'annuaire rendrait `[]` pour
        // la machine d'autrui, qu'on ne distinguerait pas d'une machine sans
        // service. (Il ne liste d'ailleurs pas les machines sans `voir` ;
        // cette branche garde le verbe honnête si cela change.)
        if !a_moi && !voit_le_domaine {
            services.push(ServicesVus::Autrui);
            continue;
        }
        let lus = match connexion.services_de_machine(machine.machine).await {
            Ok(lus) => lus,
            Err(quoi) => {
                services.push(ServicesVus::Echec(quoi.to_string()));
                continue;
            }
        };
        let mut vus = Vec::with_capacity(lus.len());
        for service in lus {
            let adresse = if ou {
                // **À MOI, JE LA LOCALISE** : le propriétaire tient tous les
                // droits sur sa machine ; `localiser` sur le domaine atteint
                // toutes celles qui y sont rangées, d'autrui comprises
                // (décision 104). Avec `voir` seul, le service reste
                // « annoncé », sans adresse, et `resoudre` le dit sans rien
                // demander.
                let localise = localise_le_domaine || a_moi;
                Some(resoudre(connexion, machine.machine, &service, localise).await)
            } else {
                None
            };
            vus.push(ServiceVu { service, adresse });
        }
        services.push(ServicesVus::Liste(vus));
    }
    Ok(VueDeDomaine {
        detail,
        moi,
        services,
    })
}

/// Résout un service listé, comme `asl where <m-…> <nom>`.
async fn resoudre(
    connexion: &mut Connexion,
    machine: asl_id::Identifiant,
    service: &asl_client_tokio::domaines::ServiceDeMachine,
    localise: bool,
) -> AdresseVue {
    use asl_client_tokio::domaines::EtatDeService;
    if !localise {
        return AdresseVue::HorsDeVosDroits;
    }
    if !matches!(service.etat, EtatDeService::Annonce(_)) {
        return AdresseVue::Parti;
    }
    match connexion.ou(machine, &service.nom).await {
        Ok(corps) => AdresseVue::Resolue(corps),
        Err(FauteReseau::Statut(404)) => AdresseVue::Introuvable,
        Err(quoi) => AdresseVue::Echec(quoi.to_string()),
    }
}

// ── `asl roots` ─────────────────────────────────────────────────────────────

/// La liste des racines, demandée à une racine et **vérifiée** (décision 56).
///
/// La connexion est jugée par la clé de la racine jointe — c'est elle qui
/// signe la liste ; la liste l'est ensuite entrée par entrée : **une seule clé
/// qui ne donne pas son `n-…` la refuse entière**. `GET /v1/racines` n'exige
/// aucune preuve : cette commande marche sur une machine non enrôlée.
///
/// # ELLE REMET LE CACHE À JOUR, ET MONTRE CE QU'ELLE EN GARDE
///
/// Quelle que soit l'âge du cache : c'est ce qu'on tape pour voir la liste
/// d'aujourd'hui. Chaque locateur dit s'il est gardé, et pourquoi pas sinon
/// (un nom, une racine inconnue de ce binaire) ; puis l'ordre dans lequel
/// les racines seront essayées, chaque adresse avec sa provenance.
pub async fn racines_apprises(invocation: &Invocation) -> Sortie {
    let reglages = reglages(invocation)?;
    let mut connexion = ouvrir(&reglages).await?;
    let racines = asl_client_tokio::apprendre_les_racines(&mut connexion)
        .await
        .map_err(|quoi| Issue::Injoignable(format!("la liste des racines : {quoi}")))?;
    match connexion.forme() {
        Some(forme) => println!("confiance      {forme}"),
        None => println!("confiance      inconnue"),
    }
    let jointe = connexion.distante().ok().and_then(|ou| {
        reglages
            .annuaires()
            .iter()
            .find(|quoi| quoi.adresse == ou)
            .map(|quoi| quoi.identite)
    });
    let _ = connexion.fermer().await;

    let maintenant = etat::maintenant();
    let (appris, _) = LocateursAppris::depuis_la_liste(&racines, maintenant);
    println!("racines        {} — liste vérifiée", racines.len());
    for racine in &racines {
        let cle: String = racine
            .cle
            .iter()
            .map(|octet| format!("{octet:02x}"))
            .collect();
        let gardes = appris
            .racines()
            .iter()
            .find(|(identite, _)| *identite == racine.identifiant)
            .map(|(_, adresses)| adresses.as_slice())
            .unwrap_or_default();
        if est_une_racine_embarquee(racine.identifiant) {
            println!("  {}   embarquée", racine.identifiant.texte().as_str());
        } else {
            println!(
                "  {}   INCONNUE de ce binaire — ignorée : une racine nouvelle exige une\n\
                 \x20                                  nouvelle version du client",
                racine.identifiant.texte().as_str()
            );
        }
        println!("    clé        {cle}");
        for locateur in &racine.locateurs {
            let garde = locateur
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|adresse| gardes.contains(&adresse));
            let note = if garde {
                "gardé"
            } else if !est_une_racine_embarquee(racine.identifiant) {
                "ignoré"
            } else if locateur.parse::<std::net::SocketAddr>().is_err() {
                "non gardé — un nom : on ne résout rien sans le dire (C20)"
            } else {
                "non gardé"
            };
            println!("    locateur   {locateur:<45} {note}");
        }
    }

    // **LE CACHE N'APPREND QUE D'UNE RACINE EMBARQUÉE** : la liste n'a pas
    // d'autre signature que la connexion qui l'a portée.
    let dossier = etat::repertoire(invocation.etat.as_deref());
    let fichier = dossier.join(etat::CACHE_DES_RACINES);
    println!();
    if jointe.is_some_and(est_une_racine_embarquee) {
        match etat::ecrire_le_cache(&dossier, &appris) {
            Ok(()) => println!("cache          {} — écrit", fichier.display()),
            Err(quoi) => println!("cache          NON ÉCRIT — {quoi}"),
        }
    } else {
        println!(
            "cache          non écrit — l'annuaire joint n'est pas une racine embarquée,\n\
             \x20              et sa liste n'a pas d'autre signature que la connexion"
        );
    }
    println!();
    println!("racines, dans l'ordre où elles seront essayées sans --directory");
    let adresses: Vec<(Annuaire, Option<Provenance>)> = racines_par_defaut(invocation)
        .into_iter()
        .map(|(annuaire, provenance)| (annuaire, Some(provenance)))
        .collect();
    afficher_l_ordre(&adresses);
    Ok(())
}

/// Les annuaires, dans l'ordre où la tournée les essaiera — IPv6 d'abord —,
/// chacun avec l'identité qu'on doit trouver au bout et, pour une racine,
/// **d'où vient son locateur** : appris, embarqué, ou les deux.
fn afficher_l_ordre(annuaires: &[(Annuaire, Option<Provenance>)]) {
    let adresses: Vec<std::net::SocketAddr> =
        annuaires.iter().map(|(quoi, _)| quoi.adresse).collect();
    for rang in 0..adresses.len() {
        let Some(place) = asl_client::place_en_ordre(&adresses, rang) else {
            break;
        };
        let Some((quoi, provenance)) = annuaires.get(place) else {
            break;
        };
        // **CE QU'ON CROIT AU BOUT** : l'identité, et rien d'autre.
        let attendu = format!("identité : {}", quoi.identite.texte().as_str());
        let famille = if quoi.adresse.is_ipv6() {
            "IPv6"
        } else {
            "IPv4"
        };
        let origine = provenance.map_or_else(String::new, |provenance| format!(", {provenance}"));
        println!(
            "  {}. {:<45} {attendu}   ({famille}{origine})",
            rang.saturating_add(1),
            quoi.adresse.to_string(),
        );
    }
}

/// Dit l'état du cache des racines, pour un diagnostic.
fn dire_le_cache(invocation: &Invocation) {
    let dossier = etat::repertoire(invocation.etat.as_deref());
    let fichier = dossier.join(etat::CACHE_DES_RACINES);
    match etat::lire_le_cache(&dossier) {
        etat::Cache::Absent => println!(
            "cache          {} — absent : rien d'appris encore",
            fichier.display()
        ),
        etat::Cache::Illisible(quoi) => {
            println!("cache          {} — ILLISIBLE, ignoré", fichier.display());
            println!("               {quoi}");
            println!(
                "               les racines embarquées répondent ; il se réécrit à la connexion."
            );
        }
        etat::Cache::Lu(appris) => {
            let heures = etat::maintenant().saturating_sub(appris.appris_a()) / 3_600;
            println!(
                "cache          {} — appris il y a {heures} h{}",
                fichier.display(),
                if appris.a_relire(etat::maintenant()) {
                    ", à relire"
                } else {
                    ""
                }
            );
        }
    }
}

// ── `asl replication` ───────────────────────────────────────────────────────

/// L'état de la voie entre les deux racines — les DEUX, puis la conclusion.
///
/// # ELLE DIT D'ABORD QUI A RÉPONDU, PARCE QUE L'ALIAS NE LE DIT PAS
///
/// `asl-root.air-desktop.org` rend les deux racines, et la tournée en joint
/// une — sans dire laquelle, et la réponse ne le dit pas non plus
/// (`replication.md` §6). Or ce que `GET /v1/replication` rend est **l'état vu
/// de cette racine-là** : son horloge, son curseur sur l'autre, et depuis
/// 0.17.0 la dernière estampille qu'elle a écrite.
///
/// # POURQUOI ELLE EN JOINT DEUX, ET NON UNE
///
/// Parce qu'une seule ne conclut rien. L'`applique` d'une racine se compare à
/// l'`ecrit` de l'AUTRE (`rendu::conclusion`), et une ligne qui dirait
/// « ouverte, à jour » sans avoir vu l'autre ne prouverait rien. Le champ
/// `ecrit` n'a été ajouté que pour cela ; le lire d'un seul côté serait le
/// laisser inutile.
///
/// **UNE SECONDE TENTATIVE, ET PAS UNE DE PLUS**, sur le modèle d'`asl enroll`
/// et par le même `ailleurs_que` : l'adresse déjà jointe est retirée, et la
/// tournée prend ce qui reste. Si rien ne reste, si la seconde ne répond pas,
/// ou si elle nomme le même pair que la première — l'alias rend quatre
/// adresses, deux par banc —, on rend ce qu'on a et l'on dit ce qui manque
/// pour conclure. **On ne conclut jamais avec une moitié** : ce serait
/// l'erreur du 21/09 sous une autre forme.
///
/// C'est un verbe de CLI, sans ABI (C12 n'est pas touchée) : comme
/// `asl machines`, il vit sur la voie machine, une connexion prouvée, une
/// requête, et la main rendue.
pub async fn replication(invocation: &Invocation, identite: &Identite) -> Sortie {
    let reglages = reglages(invocation)?;
    let mut connexion = ouvrir_et_relire(invocation, &reglages).await?;
    connexion
        .authentifier(identite)
        .await
        .map_err(refus_de_l_annuaire)?;
    let premier = connexion
        .etat_de_la_replication()
        .await
        .map_err(refus_de_l_annuaire)?;
    let deja = connexion.distante().ok();
    match connexion.distante() {
        Ok(ou) => println!("annuaire       {ou}"),
        Err(quoi) => println!("annuaire       inconnu — {quoi}"),
    }
    print!(
        "{}",
        rendu::replication(&premier).map_err(Issue::Injoignable)?
    );
    let _ = connexion.fermer().await;

    // La seconde racine, pour conclure. Son échec n'est pas l'échec du verbe :
    // ce qu'on a lu de la première reste vrai, et vaut d'être montré.
    let second = match ailleurs_que(&reglages, deja)? {
        None => None,
        Some(ailleurs) => match joindre_et_lire(&ailleurs, identite).await {
            Ok(corps) => Some(corps),
            Err(quoi) => {
                println!();
                println!("la seconde racine n'a pas répondu — {quoi}");
                None
            }
        },
    };

    println!();
    match second {
        Some(second) => {
            print!(
                "{}",
                rendu::conclusion(&premier, &second).map_err(Issue::Injoignable)?
            );
        }
        None => println!(
            "sans conclusion   une seule racine a répondu, et l'état de la voie se\n             juge des deux côtés."
        ),
    }
    Ok(())
}

/// Joint une racine, prouve, lit son état, et referme — le second tour de
/// [`replication`].
///
/// Elle rend la faute en toutes lettres plutôt qu'une [`Issue`] : ici, une
/// racine qui ne répond pas n'est pas une panne du verbe, c'est une ligne de
/// plus à afficher.
async fn joindre_et_lire(reglages: &Reglages, identite: &Identite) -> Result<Vec<u8>, String> {
    let mut connexion = ouvrir(reglages).await.map_err(|quoi| quoi.dire())?;
    let issue = async {
        connexion
            .authentifier(identite)
            .await
            .map_err(|quoi| quoi.to_string())?;
        let corps = connexion
            .etat_de_la_replication()
            .await
            .map_err(|quoi| quoi.to_string())?;
        match connexion.distante() {
            Ok(ou) => println!("annuaire       {ou}"),
            Err(quoi) => println!("annuaire       inconnu — {quoi}"),
        }
        print!("{}", rendu::replication(&corps)?);
        Ok(corps)
    }
    .await;
    let _ = connexion.fermer().await;
    issue
}

// ── `asl identity` ──────────────────────────────────────────────────────────

/// Dit qui est cette machine et pour qui elle agit, **sans rien joindre**.
///
/// C'est ce qu'un script ou un exploitant lit sur une machine dont le réseau est
/// en panne : le fichier d'identité suffit, et l'annuaire n'a rien à y ajouter.
pub fn identite(etat: &etat::Etat) -> Sortie {
    let dossier = etat.dossier.as_path();
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
    println!("               lue depuis {}", etat.origine.dire());
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
pub async fn diagnostic(invocation: &Invocation, etat: &etat::Etat) -> Sortie {
    let dossier = etat.dossier.as_path();
    let reglages = reglages(invocation)?;

    println!("annuaires, dans l'ordre où ils seront essayés");
    // **D'OÙ VIENT CHAQUE LOCATEUR** (décision 85) : pour les racines qu'on
    // joint sans rien dire, appris ou embarqué ; ce qu'on a nommé soi-même
    // n'a pas d'autre provenance que la ligne de commande.
    let par_defaut = invocation.annuaires.is_empty() && std::env::var("ASL_DIRECTORY").is_err();
    let annuaires: Vec<(Annuaire, Option<Provenance>)> = if par_defaut {
        racines_par_defaut(invocation)
            .into_iter()
            .map(|(annuaire, provenance)| (annuaire, Some(provenance)))
            .collect()
    } else {
        reglages
            .annuaires()
            .iter()
            .map(|annuaire| (annuaire.clone(), None))
            .collect()
    };
    afficher_l_ordre(&annuaires);
    if par_defaut {
        dire_le_cache(invocation);
    }
    println!();
    let mut connexion = ouvrir(&reglages).await?;
    println!("connexion      établie");
    match relire_les_racines(invocation, &reglages, &mut connexion, false).await {
        Relecture::Inutile => println!("liste racines  le cache a moins d'un jour : pas relue"),
        Relecture::PasUneRacine => {}
        Relecture::Relue { gardees, ignorees } => {
            println!("liste racines  relue, vérifiée : {gardees} racine(s) embarquée(s) gardée(s)");
            for inconnue in ignorees {
                println!(
                    "               {} ignorée — inconnue de ce binaire",
                    inconnue.texte().as_str()
                );
            }
        }
        Relecture::Ratee(quoi) => println!("liste racines  NON RELUE — {quoi}"),
    }
    // **LA FORME QUI A SERVI** (décision 58) : il n'en reste qu'une, et on la
    // dit quand même — c'est ce qu'on a cru, et un diagnostic le montre.
    match connexion.forme() {
        Some(forme) => println!("confiance      {forme}"),
        None => println!("confiance      inconnue"),
    }
    if let Some(identite) = connexion.distante().ok().and_then(|ou| {
        reglages
            .annuaires()
            .iter()
            .find(|quoi| quoi.adresse == ou)
            .map(|quoi| quoi.identite)
    }) {
        println!("identité jointe {}", identite.texte().as_str());
    }

    // **À QUOI PARLE-T-ON, ET QU'EXIGE-T-IL ?** `GET /v1/version` n'exige
    // aucune preuve : c'est la ressource que peut lire qui n'a pas encore de
    // clé, et cette ligne sort donc aussi sur une machine non enrôlée — là où
    // le diagnostic sert le plus. Un annuaire qui ne la sert pas, ou qui
    // répond de travers, ne fait pas échouer le reste : on le dit et on
    // continue, comme pour `GET /v1/vu` juste en dessous.
    match connexion.version().await {
        Ok(corps) => match rendu::version(&corps) {
            Ok((version, posture)) => {
                println!("version        {version}");
                println!("posture        {posture}");
            }
            Err(quoi) => println!("version        ILLISIBLE — {quoi}"),
        },
        Err(quoi) => println!("version        INDISPONIBLE — {quoi}"),
    }

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

    // L'identité, si elle existe — et d'où on la lit (décision 93).
    println!();
    println!(
        "état           {} — {}",
        dossier.display(),
        etat.origine.dire()
    );
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
                    // **OÙ CETTE MACHINE S'ANNONCE** (0.28.0) : une racine
                    // renvoie en `421` l'annonce d'une machine dont le
                    // domaine est confié à un annuaire local.
                    renvoi_de_l_annonce(&mut connexion).await;
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

/// Dit si les annonces de cette machine sont renvoyées vers un annuaire local,
/// lequel, et si on l'atteint.
///
/// # UNE SONDE QUI N'ANNONCE RIEN
///
/// Le diagnostic n'annonce jamais en douce (voir [`diagnostic`]). Il pose
/// donc `POST /v1/annonce` avec un corps VIDE : une racine qui renvoie répond
/// `421` avant de lire le corps ; sinon le corps vide est refusé, et rien n'a
/// été créé. Un refus veut alors dire « pas de renvoi » — et non « pas le
/// droit d'annoncer », que ce diagnostic ne sait pas trancher et ne prétend
/// pas trancher.
async fn renvoi_de_l_annonce(connexion: &mut Connexion) {
    let json: (&[u8], &[u8]) = (b"content-type", b"application/json");
    let reponse = match connexion
        .requete(b"POST", b"/v1/annonce", &[json], b"")
        .await
    {
        Ok(reponse) => reponse,
        Err(quoi) => {
            println!("annonce        INCONNU — la sonde n'a pas abouti ({quoi})");
            return;
        }
    };
    if reponse.statut != 421 {
        println!("annonce        ici — aucun renvoi : le domaine de cette machine est aux racines");
        return;
    }
    let renvoi = match asl_client::renvoi::Renvoi::lire(&reponse.corps) {
        Ok(renvoi) => renvoi,
        Err(quoi) => {
            println!("annonce        renvoyée, mais le renvoi ne se lit pas ({quoi:?})");
            return;
        }
    };
    println!(
        "annonce        renvoyée vers l'annuaire local {}",
        renvoi.annuaire().texte().as_str()
    );
    let membres = asl_client_tokio::membres_du_renvoi(&renvoi).await;
    if membres.is_empty() {
        println!(
            "               aucune de ses adresses ne se résout : {:?}",
            renvoi.adresses()
        );
        return;
    }
    let patience = tokio::time::Duration::from_secs(patience());
    for membre in &membres {
        let essai = tokio::time::timeout(
            patience,
            Connexion::ouvrir_confiance(
                membre.adresse,
                &membre.nom,
                &confiance_de(membre),
                &|| etat::hasard::<16>().unwrap_or([0; 16]),
            ),
        )
        .await;
        match essai {
            Ok(Ok(mut ouverte)) => {
                let forme = ouverte.forme().map_or_else(
                    || "confiance inconnue".to_owned(),
                    |forme| forme.to_string(),
                );
                let qui = format!(", sous {}", membre.identite.texte().as_str());
                println!(
                    "  {:<45} joignable ({forme}{qui})",
                    membre.adresse.to_string()
                );
                let _ = ouverte.fermer().await;
            }
            Ok(Err(quoi)) => println!("  {:<45} INJOIGNABLE — {quoi}", membre.adresse.to_string()),
            Err(_) => println!(
                "  {:<45} INJOIGNABLE — aucune réponse",
                membre.adresse.to_string()
            ),
        }
    }
    if renvoi.nomme_chaque_membre() {
        println!(
            "               chaque membre doit présenter SA clé — l'identité que le 421 met à côté de son adresse."
        );
    } else {
        println!(
            "               il doit présenter la clé de {} — son identité, que le 421 nomme.",
            renvoi.annuaire().texte().as_str()
        );
    }
}

/// Traduit un refus du réseau en une issue, en gardant la distinction qui compte.
///
/// **UN REFUS N'EST PAS UNE PANNE.** `403` veut dire « l'annuaire a compris et
/// a dit non » ; un délai veut dire « on n'a rien obtenu ». Les confondre ferait
/// chercher une panne de réseau là où il y a un droit manquant.
/// Les réglages qui visent l'annuaire local qu'un `421` désigne : chacun de
/// ses membres, sous SA propre identité (décision 59).
pub(crate) async fn reglages_du_renvoi(corps: &[u8]) -> Result<Reglages, Issue> {
    let renvoi = asl_client::renvoi::Renvoi::lire(corps).map_err(|quoi| {
        Issue::Injoignable(format!(
            "l'annuaire renvoie ailleurs, mais le renvoi ne se lit pas ({quoi:?})"
        ))
    })?;
    let membres = asl_client_tokio::membres_du_renvoi(&renvoi).await;
    if membres.is_empty() {
        return Err(Issue::Injoignable(format!(
            "renvoyé vers l'annuaire local {}, dont aucune adresse ne se joint : {:?}",
            renvoi.annuaire().texte().as_str(),
            renvoi.adresses()
        )));
    }
    println!(
        "renvoyé vers l'annuaire local {} ({} adresse(s)).",
        renvoi.annuaire().texte().as_str(),
        membres.len()
    );
    Reglages::nouveaux(membres, PLAFOND_MS).map_err(|quoi| Issue::Configuration(quoi.to_string()))
}

pub(crate) fn refus_de_l_annuaire(quoi: FauteReseau) -> Issue {
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
pub(crate) fn ecouter_ctrl_c() -> Arc<AtomicBool> {
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
        let identite = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Annuaire, [0x6E; 16]);
        let nomme = |adresse| Annuaire {
            adresse,
            nom: "annuaire.example".to_owned(),
            identite,
        };
        let deux = Reglages::nouveaux(vec![nomme(une), nomme(autre)], super::PLAFOND_MS)
            .expect("deux adresses, une configuration valable");

        let restants = super::restants_sans(&deux, Some(une)).expect("il en reste une");
        let adresses: Vec<SocketAddr> = restants.iter().map(|a| a.adresse).collect();
        assert_eq!(adresses, vec![autre], "l'adresse essayée doit disparaître");

        // Une seule adresse : il n'y a pas d'ailleurs, et c'est le cas d'un banc.
        let seule = Reglages::nouveaux(vec![nomme(une)], super::PLAFOND_MS)
            .expect("une adresse suffit à une configuration");
        assert!(
            super::restants_sans(&seule, Some(une)).is_none(),
            "sans autre adresse, il n'y a pas de seconde tentative"
        );
    }

    /// **CE QU'`asl enroll` SUGGÈRE EXISTE, ET LANCE L'ÉCHO** : le nom de
    /// l'unité que la suggestion donne est celui du fichier que le paquet
    /// pose, et ce fichier lance `/usr/bin/asl echo`. Deux textes qui disent
    /// la même chose divergent ; celui-ci les confronte.
    #[cfg(target_os = "linux")]
    #[test]
    fn la_suggestion_d_enroll_nomme_l_unite_que_le_paquet_pose() {
        let unite = include_str!("../../../paquet/asl-echo.service");
        assert!(
            super::SUGGESTION_ECHO.ends_with("systemctl --user enable --now asl-echo"),
            "{}",
            super::SUGGESTION_ECHO
        );
        assert!(
            unite
                .lines()
                .any(|ligne| ligne == "ExecStart=/usr/bin/asl echo"),
            "l'unité lance l'écho"
        );
        assert!(
            unite
                .lines()
                .any(|ligne| ligne == "WantedBy=default.target"),
            "et s'active dans la cible de l'utilisateur"
        );
    }
}
