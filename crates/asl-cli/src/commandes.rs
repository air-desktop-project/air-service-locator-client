//! Les quatre verbes, et ce qu'ils demandent au réseau.

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

/// Combien de temps `asl` attend une connexion avant de rendre la main.
///
/// # POURQUOI L'UTILITAIRE SE DONNE UNE BORNE QUE LA BIBLIOTHÈQUE REFUSE
///
/// `joindre` n'abandonne jamais, et c'est juste : un daemon qui tourne depuis un
/// mois doit se réannoncer tout seul le jour où l'annuaire revient.
///
/// **Une personne devant un terminal n'a pas cette patience**, et surtout elle a
/// besoin d'un verdict : « je n'y arrive pas » est une réponse, une invite qui
/// ne revient jamais n'en est pas une. La borne est donc posée ici, par
/// l'appelant, exactement là où la bibliothèque dit qu'elle doit l'être.
const PATIENCE_S: u64 = 20;

/// La patience, telle que l'environnement peut la raccourcir.
///
/// **`ASL_PATIENCE` EXISTE POUR LES SCRIPTS**, qui ont souvent une borne à eux
/// et ne peuvent pas se permettre vingt secondes par sonde. Une valeur illisible
/// ou nulle est ignorée plutôt que refusée : un diagnostic qui refuserait de
/// démarrer à cause de sa propre horloge serait le comble.
fn patience() -> u64 {
    std::env::var("ASL_PATIENCE")
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
        for adresse in adresses {
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

/// Les annuaires que `ASL_ANNUAIRE` désigne, séparés par des virgules.
fn depuis_l_environnement() -> Result<Vec<Cible>, Issue> {
    let brut = std::env::var("ASL_ANNUAIRE").map_err(|_| {
        Issue::Configuration(
            "aucun annuaire : passez `--annuaire <hôte:port>` ou posez `ASL_ANNUAIRE`".to_owned(),
        )
    })?;
    brut.split(',')
        .map(str::trim)
        .filter(|mot| !mot.is_empty())
        .map(|mot| {
            crate::arguments::analyser(
                ["--annuaire", mot, "diagnostic"]
                    .into_iter()
                    .map(str::to_owned),
            )
            .map_err(|quoi| Issue::Configuration(format!("`ASL_ANNUAIRE` : {quoi}")))
            .and_then(|lue| {
                lue.annuaires
                    .into_iter()
                    .next()
                    .ok_or_else(|| Issue::Configuration("`ASL_ANNUAIRE` est vide".to_owned()))
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
fn racines(invocation: &Invocation) -> Result<Vec<u8>, Issue> {
    let ou = invocation
        .racines
        .clone()
        .or_else(|| std::env::var("ASL_RACINES").ok())
        .ok_or_else(|| {
            Issue::Configuration(
                "aucune racine : passez `--racines <fichier.pem>` ou posez `ASL_RACINES`"
                    .to_owned(),
            )
        })?;
    std::fs::read(&ou).map_err(|quoi| Issue::Configuration(format!("{ou} : {quoi}")))
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

// ── `asl enrole` ────────────────────────────────────────────────────────────

/// Lie une clé neuve à cette machine.
pub async fn enrole(invocation: &Invocation, dossier: &Path, code: &str) -> Sortie {
    let reglages = reglages(invocation)?;
    let mut connexion = ouvrir(&reglages).await?;

    // **LA GRAINE EST GARDÉE DE CÔTÉ, ET N'EST ÉCRITE QU'APRÈS L'ACCORD.** Une
    // machine refusée ne doit pas laisser derrière elle une identité que
    // personne ne reconnaît.
    let (enrolement, graine) =
        etat::preparer_un_enrolement().map_err(|quoi| Issue::Configuration(quoi.to_string()))?;

    let machine = connexion
        .enroler(&enrolement, code)
        .await
        .map_err(refus_de_l_annuaire)?;

    etat::ecrire(dossier, machine, &graine)
        .map_err(|quoi| Issue::Configuration(quoi.to_string()))?;

    println!("machine        {}", machine.texte().as_str());
    println!("identité       {}", dossier.join("identite").display());
    println!();
    println!(
        "La clé a été générée ICI, et sa moitié privée n'a pas quitté ce disque.\n\
         Le code est dépensé : il ne servira plus."
    );
    let _ = connexion.fermer().await;
    Ok(())
}

// ── `asl annonce` ───────────────────────────────────────────────────────────

/// Annonce un service, et TIENT l'annonce.
///
/// # ELLE NE REND PAS LA MAIN, ET C'EST LE POINT LE PLUS FACILE À MANQUER
///
/// La connexion EST le bail (`protocole.md` §1.2) : `asl annonce` qui se
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

// ── `asl ou` ────────────────────────────────────────────────────────────────

/// Demande où joindre un service.
pub async fn ou(
    invocation: &Invocation,
    identite: &Identite,
    machine: asl_id::Identifiant,
    service: &str,
) -> Sortie {
    let reglages = reglages(invocation)?;
    let mut connexion = ouvrir(&reglages).await?;
    connexion
        .authentifier(identite)
        .await
        .map_err(refus_de_l_annuaire)?;

    let corps = connexion
        .ou(machine, service)
        .await
        .map_err(refus_de_l_annuaire)?;
    println!("{}", rendu::reponse(&corps).map_err(Issue::Injoignable)?);
    let _ = connexion.fermer().await;
    Ok(())
}

// ── `asl diagnostic` ────────────────────────────────────────────────────────

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
/// renvoie à `asl annonce` — plutôt que d'affirmer ce qu'il n'a pas mesuré, ce
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
    match etat::lire(dossier) {
        Err(quoi) => {
            println!("identité       ABSENTE OU ILLISIBLE");
            println!("               {quoi}");
        }
        Ok(identite) => {
            println!("machine        {}", identite.machine().texte().as_str());
            match connexion.authentifier(&identite).await {
                Ok(()) => println!("clé            acceptée par l'annuaire"),
                Err(quoi) => {
                    println!("clé            REFUSÉE — {quoi}");
                    println!(
                        "               la clé de cette machine n'est pas (ou plus) liée.\n\
                         \x20              Demandez un code, puis : asl enrole <code>"
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
         l'obtenir : asl annonce <service> <protocole>:<port>"
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
