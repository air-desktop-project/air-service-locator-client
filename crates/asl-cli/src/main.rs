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
    /// Le code d'enrôlement a été refusé par les DEUX racines.
    ///
    /// **Il a sa variante à lui**, et non un `Refuse(403)`, parce que c'est la
    /// seule issue que `replication.md` §6 nomme : après la seconde tentative,
    /// le refus n'est plus « peut-être pas encore arrivé », il est définitif.
    CodeInconnu,
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
            Self::Refuse(_) | Self::CodeInconnu => 3,
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
                 Elle n'est pas liée, ou elle a été révoquée : asl enroll <code>"
                .to_owned(),
            Self::Refuse(403) => "403 — cette machine n'a pas le droit de faire cela.".to_owned(),
            // **LES DEUX RACINES ONT DIT NON**, et l'annuaire ne distingue pas
            // un code inconnu d'un code périmé (`protocole.md` §2.0) : un code
            // consommé est SUPPRIMÉ, pas marqué. On ne peut donc pas en dire
            // plus que les trois causes possibles.
            Self::CodeInconnu => "code inconnu — les deux racines l'ont refusé.\n\
                 Il est faux, il a expiré, ou il a déjà servi : l'annuaire ne les\n\
                 distingue pas. Demandez-en un autre à l'application."
                .to_owned(),
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

/// Ce que `asl --version` imprime : `asl 0.2.0 (4726464)`.
///
/// La version est celle du workspace, en lockstep (`Cargo.toml`) ; le commit
/// vient de `build.rs`, et manque quand le binaire n'a pas été construit dans
/// un dépôt — on l'omet alors plutôt que d'écrire « inconnu », qui aurait
/// l'air d'une valeur. Un `+` derrière le commit dit que l'arbre était modifié.
fn version() -> String {
    let commit = env!("ASL_COMMIT");
    if commit.is_empty() {
        format!("asl {}", env!("CARGO_PKG_VERSION"))
    } else {
        format!("asl {} ({commit})", env!("CARGO_PKG_VERSION"))
    }
}

/// L'aide, telle qu'elle s'affiche.
fn aide() {
    println!(
        "asl — announce, resolve and diagnose a service, by hand.

USAGE
    asl [options] <command> [arguments]

COMMANDS
    enroll <code>                     Bind a fresh key to this machine.
                                      The key is generated HERE; the code is
                                      single-use and opens this operation only.

    announce <service> <proto:port>...
                                      Announce a service and HOLD the announcement.
                                      It does not return: the connection IS the
                                      lease. Ctrl-C withdraws it cleanly.

    where <machine> <service>         Ask where to reach this service, and list
                                      the candidates in the order a client would
                                      try them.

    where <service>                   Every instance of this name your account
                                      may see — yours, and those granted to you.

    machines [u-…]                    The machines of this user your account may
                                      see: yours if it is you, else what they
                                      granted you. Without argument: yours.

    enrolled [u-…]                    The devices enrolled on this machine's
                                      account, revoked ones marked. A user may
                                      be named only to confirm it is this one:
                                      a device never leaves its account.

    replication                       The state of the link between the two
                                      root directories, as seen by the one
                                      reached: peer, open or cut, its clock,
                                      and how far it has applied the peer.

    identity                          Who this machine is and whom it acts for,
                                      without connecting.

    diagnose                          What is known about the directory, and
                                      what is not.

OPTIONS
    --directory <host:port>  Repeatable. A name resolving to several addresses
                             yields them all; IPv6 is tried first.
                             Default: ASL_DIRECTORY, comma-separated; else the
                             root directories, asl-root.air-desktop.org:6630.
    --roots <file.pem>       The certificate authorities. There is NO fallback
                             to the system store. Default: ASL_ROOTS; else the
                             air-desktop-project root CA, pinned in this binary.
    --state <dir>            Where this machine's identity lives.
                             Default: ASL_STATE, then $XDG_CONFIG_HOME/asl,
                             then ~/.config/asl (on macOS, the Service Locator
                             app's identity when that one is empty).
    --name <name>            The name required of the certificate, when it
                             differs from the host.
    --help                   This.
    --version                Version and commit, then exit.

    ASL_TIMEOUT              Seconds to wait for a connection (default 20).
                             `announce` never gives up; the bound is yours.

    Options come BEFORE the command.

EXIT CODES
    0 done   1 usage   2 configuration   3 refused by the directory   4 unreachable

EXAMPLES
    asl --directory nitrogen.example:6630 --roots /etc/asl/ca.pem enroll 4K9M2-P7R1T
    asl announce depot tcp:8080 udp:9000
    asl where m-7F3A9C2E5B1D4068ABCDEFGHJK depot
    asl where depot
    asl machines u-5884A5EE7THEKHBQ3BT0VPGJKN
    asl machines
    asl enrolled
    asl replication"
    );
}

fn main() -> ExitCode {
    let invocation = match arguments::analyser(std::env::args().skip(1)) {
        Ok(lue) => lue,
        Err(quoi) => {
            eprintln!("asl : {quoi}");
            eprintln!("      `asl help` montre ce qui se tape.");
            return ExitCode::from(1);
        }
    };

    if matches!(invocation.commande, Commande::Aide) {
        aide();
        return ExitCode::SUCCESS;
    }
    if matches!(invocation.commande, Commande::Version) {
        println!("{}", version());
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
        Commande::Aide | Commande::Version => Ok(()),
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
        Commande::Machines { compte } => {
            let identite = identite(&dossier)?;
            commandes::machines(invocation, &identite, *compte).await
        }
        // Elle lit la fiche entière elle-même : le compte qu'elle porte est
        // ce qui permet de refuser un compte étranger avant de rien joindre.
        Commande::Enroles { compte } => commandes::enroles(invocation, &dossier, *compte).await,
        Commande::Replication => {
            let identite = identite(&dossier)?;
            commandes::replication(invocation, &identite).await
        }
        // Hors ligne : rien à joindre.
        Commande::Identite => commandes::identite(&dossier),
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
