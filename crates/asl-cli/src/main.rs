//! `asl` — faire à la main ce que la bibliothèque fait dans un programme.
//!
//! # À QUOI IL SERT VRAIMENT
//!
//! Pas à remplacer la bibliothèque : à **diagnostiquer**. Quand un daemon ne
//! s'annonce pas, la question est de savoir si le tort est au daemon, au réseau
//! ou à l'annuaire — et un utilitaire qui refait le même chemin, seul, tranche
//! en une commande.
//!
//! Il emprunte exactement le même chemin qu'un daemon : la même `asl-client`,
//! le même transport, la même tournée d'annuaires. **C'est ce qui rend sa
//! réponse comparable** ; un outil qui parlerait autrement ne prouverait rien de
//! ce que le daemon vit.
//!
//! # LE BINAIRE S'APPELLE `asl`, ET LA CRATE `asl-cli`
//!
//! Ce que l'on tape est `asl`. Le nom de la crate porte le suffixe parce qu'il
//! doit être unique dans un registre, ce dont la ligne de commande n'a que
//! faire. `[[bin]] name = "asl"` sépare les deux.
//!
//! # LES CODES DE SORTIE SONT UNE INTERFACE
//!
//! Un outil de diagnostic finit dans un script, et un script ne lit pas du
//! français. Chaque issue a donc son code, et il est stable :
//!
//! | Code | Ce qu'il dit |
//! |---|---|
//! | `0` | Ce qui a été demandé a abouti. |
//! | `1` | Ce qui a été tapé ne se lit pas. |
//! | `2` | La configuration ne tient pas : pas d'annuaire, pas de racine, une identité illisible. |
//! | `3` | **L'annuaire a compris, et il a dit non.** |
//! | `4` | Personne n'a répondu. |
//!
//! **`3` et `4` sont la distinction qui compte** : un droit manquant et un câble
//! débranché se corrigent à des endroits opposés, et un outil qui les rendrait
//! sous le même code enverrait chercher au mauvais.

#![forbid(unsafe_code)]

use std::process::ExitCode;

mod arguments;
mod commandes;
mod etat;
mod rendu;

use arguments::{Commande, Invocation};

/// Ce qui a empêché la commande d'aboutir.
#[derive(Debug)]
pub enum Issue {
    /// Ce qui a été tapé ne se lit pas.
    Usage(String),
    /// La configuration ne tient pas.
    Configuration(String),
    /// L'annuaire a compris, et il a dit non.
    Refuse(u16),
    /// Personne n'a répondu.
    Injoignable(String),
}

/// Ce que rend une commande.
pub type Sortie = Result<(), Issue>;

impl Issue {
    /// Le code de sortie qui lui correspond.
    const fn code(&self) -> u8 {
        match self {
            Self::Usage(_) => 1,
            Self::Configuration(_) => 2,
            Self::Refuse(_) => 3,
            Self::Injoignable(_) => 4,
        }
    }

    /// Ce qu'on en dit sur `stderr`.
    fn dire(&self) -> String {
        match self {
            Self::Usage(quoi) | Self::Configuration(quoi) | Self::Injoignable(quoi) => quoi.clone(),
            // **CHAQUE CODE EST TRADUIT**, parce qu'un nombre nu envoie chercher
            // dans une spécification que personne n'a sous la main.
            Self::Refuse(401) => "401 — la clé de cette machine n'a pas été acceptée.\n\
                 Elle n'est pas liée, ou elle a été révoquée : asl enrole <code>"
                .to_owned(),
            Self::Refuse(403) => "403 — cette machine n'a pas le droit de faire cela.".to_owned(),
            // **`404` VEUT DIRE DEUX CHOSES, ET L'ANNUAIRE REFUSE DE LES
            // DISTINGUER** (C10) : « ce service n'existe pas » et « il existe et
            // vous n'y avez pas droit » rendent le même code, exprès — un `403`
            // dirait à qui essaie que la cible existe.
            Self::Refuse(404) => "404 — introuvable, ou hors de ce à quoi vous avez droit.\n\
                 L'annuaire ne fait pas la différence : la faire révélerait\n\
                 l'existence de ce qu'on ne vous laisse pas voir."
                .to_owned(),
            Self::Refuse(501) => {
                "501 — cette route existe dans les spécifications, et pas encore\n\
                 dans le serveur."
                    .to_owned()
            }
            Self::Refuse(code) => format!("l'annuaire a répondu {code}."),
        }
    }
}

/// L'aide, telle qu'elle s'affiche.
fn aide() {
    println!(
        "asl — annoncer, résoudre et diagnostiquer un service, à la main.

USAGE
    asl [options] <commande> [arguments]

COMMANDES
    enrole <code>                     Lie une clé neuve à cette machine.
                                      La clé est générée ICI ; le code ne sert
                                      qu'une fois et n'ouvre que cette opération.

    annonce <service> <proto:port>... Annonce un service et TIENT l'annonce.
                                      Elle ne rend pas la main : la connexion EST
                                      le bail. Ctrl-C retire proprement.

    ou <machine> <service>            Demande où joindre ce service, et montre
                                      les candidats dans l'ordre où un client les
                                      essaierait.

    diagnostic                        Dit ce qu'on sait de l'annuaire, et ce
                                      qu'on ne sait pas.

OPTIONS
    --annuaire <hôte:port>   Répétable. Un nom qui rend plusieurs adresses les
                             fournit toutes, et IPv6 est essayé d'abord.
                             À défaut : ASL_ANNUAIRE, séparé par des virgules.
    --racines <fichier.pem>  Les certificats d'autorité. Il n'y a PAS de repli
                             sur le magasin du système. À défaut : ASL_RACINES.
    --etat <répertoire>      Où vit l'identité de cette machine.
                             À défaut : ASL_ETAT, puis $XDG_CONFIG_HOME/asl,
                             puis ~/.config/asl.
    --nom <nom>              Le nom exigé du certificat, s'il diffère de l'hôte.
    --aide                   Ceci.

    ASL_PATIENCE             Secondes à attendre une connexion (20 par défaut).
                             `joindre` n'abandonne jamais ; la borne est à vous.

    Les options viennent AVANT la commande.

CODES DE SORTIE
    0 abouti   1 usage   2 configuration   3 refusé par l'annuaire   4 injoignable

EXEMPLES
    asl --annuaire nitrogen.example:6630 --racines /etc/asl/ca.pem enrole 4K9M2-P7R1T
    asl annonce depot tcp:8080 udp:9000
    asl ou m_7f3a9c2e5b1d4068 depot"
    );
}

fn main() -> ExitCode {
    let invocation = match arguments::analyser(std::env::args().skip(1)) {
        Ok(lue) => lue,
        Err(quoi) => {
            eprintln!("asl : {quoi}");
            eprintln!("      `asl aide` montre ce qui se tape.");
            return ExitCode::from(1);
        }
    };

    if matches!(invocation.commande, Commande::Aide) {
        aide();
        return ExitCode::SUCCESS;
    }

    // **UN ORDONNANCEUR À UN SEUL FIL SUFFIT.** Cet utilitaire tient UNE
    // connexion ; un ordonnanceur multi-fils lui ferait porter des fils de
    // travail qu'il n'emploierait jamais.
    let moteur = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(moteur) => moteur,
        Err(quoi) => {
            eprintln!("asl : l'ordonnanceur ne se monte pas : {quoi}");
            return ExitCode::from(2);
        }
    };

    match moteur.block_on(conduire(&invocation)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(quoi) => {
            eprintln!();
            eprintln!("asl : {}", quoi.dire());
            ExitCode::from(quoi.code())
        }
    }
}

/// Mène la commande, une fois l'ordonnanceur monté.
async fn conduire(invocation: &Invocation) -> Sortie {
    let dossier = etat::repertoire(invocation.etat.as_deref());

    match &invocation.commande {
        // Déjà traitée avant l'ordonnanceur : `asl --aide` doit répondre même
        // quand rien ne se monte.
        Commande::Aide => Ok(()),
        Commande::Diagnostic => commandes::diagnostic(invocation, &dossier).await,
        Commande::Enrole { code } => commandes::enrole(invocation, &dossier, code).await,
        Commande::Annonce { service, points } => {
            let identite = identite(&dossier)?;
            commandes::annonce(invocation, &identite, service, points).await
        }
        Commande::Ou { machine, service } => {
            let identite = identite(&dossier)?;
            commandes::ou(invocation, &identite, *machine, service).await
        }
    }
}

/// L'identité de cette machine, ou ce qui manque pour l'avoir.
///
/// **ELLE EST LUE AVANT D'OUVRIR QUOI QUE CE SOIT.** Une machine non enrôlée
/// doit l'apprendre tout de suite, et non après vingt secondes passées à joindre
/// un annuaire qui l'aurait de toute façon renvoyée.
fn identite(dossier: &std::path::Path) -> Result<asl_client::Identite, Issue> {
    etat::lire(dossier).map_err(|quoi| Issue::Configuration(quoi.to_string()))
}
