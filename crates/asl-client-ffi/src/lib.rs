//! L'ABI C d'`asl-client` — le seul passage par lequel les liaisons entrent.
//!
//! # POURQUOI UNE ABI C, ET PAS CINQ LIAISONS NATIVES
//!
//! Python, Ruby, C++, Kotlin et Swift savent tous appeler du C. Aucun ne sait
//! appeler du Rust. Écrire cinq passages natifs, ce serait maintenir cinq fois
//! la même logique de conversion — et c'est la copie qu'on oublie qui finit par
//! diverger.
//!
//! # LES DEUX RÈGLES, ET CE QU'ELLES INTERDISENT (contrainte C12)
//!
//! **AUCUN TYPE RUST NE TRAVERSE LA FRONTIÈRE.** Ni `String`, ni `Result`, ni
//! générique, ni trait. Des entiers, des pointeurs opaques, des tampons fournis
//! par l'appelant, et des codes d'erreur. Un `String` rendu à Python serait un
//! bloc alloué par l'allocateur de Rust que l'appelant tenterait de libérer avec
//! le sien.
//!
//! **LE RETRAIT D'UNE SIGNATURE EST UNE RUPTURE MAJEURE**, pour les cinq
//! liaisons à la fois — qui ne se mettent pas à jour au même rythme. Un ajout est
//! libre ; c'est le retrait qui casse. `scripts/check-abi.sh` compare les
//! symboles réellement exportés, l'en-tête committé et le registre `abi.txt`.
//!
//! # « PAS UNE LIGNE DE C » N'EST PAS « PAS D'`unsafe` » (contrainte C4)
//!
//! C4 interdit de **compiler du C** — parce que cette bibliothèque est chargée
//! dans des interpréteurs Python et Ruby, où une pile qui lierait sa propre
//! libcrypto entrerait en conflit avec celle du processus hôte.
//!
//! Une frontière FFI, elle, se passe forcément d'`unsafe` : déréférencer un
//! pointeur venu de l'extérieur ne se prouve pas. **Tout l'`unsafe` du produit
//! est ici**, et nulle part ailleurs — `asl-client` et `asl-client-tokio`
//! portent `forbid(unsafe_code)`. C'est le but de la frontière : concentrer en
//! un fichier ce que le reste ne veut pas connaître.
//!
//! # AUCUNE PANIQUE NE SORT D'ICI
//!
//! Chaque point d'entrée enveloppe son corps dans [`std::panic::catch_unwind`].
//! Depuis Rust 1.81, une panique qui traverse un `extern "C"` avorte le
//! processus au lieu d'être un comportement indéfini — **et avorter le processus
//! d'un tiers reste inacceptable** : notre bibliothèque tuerait son application.
//! Une panique rattrapée rend [`ASL_INTERNE`], et l'appelant décide.
//!
//! # LE FIL D'EXÉCUTION, ET POURQUOI IL EST À NOUS
//!
//! L'annonce est TENUE par une connexion (`protocole.md` §1.2) : elle doit
//! progresser pendant que l'hôte fait autre chose. Un ordonnanceur à un seul fil
//! ne progresse que lorsque quelqu'un l'attend — l'utilitaire `asl` peut s'en
//! contenter, une bibliothèque chargée dans le processus d'un autre, non.
//!
//! Ce client monte donc son propre ordonnanceur, avec **un** fil de travail : il
//! ne tient qu'une connexion, et prendre plus de fils dans le processus d'un
//! tiers serait décider à sa place.

// L'`unsafe` est la raison d'être de cette crate ; il n'est pas caché, il est
// concentré. Chaque bloc porte l'invariant que l'appelant doit tenir.
#![allow(clippy::missing_safety_doc)]

use core::ffi::{CStr, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

use asl_client::Identite;
use asl_client_tokio::{Annuaire, Attache, Reglages};
use asl_id::{Genre, Identifiant};
use asl_proto::{NomService, PointEcoute, Port, Protocole};

// ── LES CODES ───────────────────────────────────────────────────────────────
//
// **ZÉRO OU NÉGATIF, JAMAIS UNE VALEUR UTILE.** Une fonction qui rendrait tantôt
// un compte, tantôt un code d'erreur obligerait chaque liaison à connaître la
// frontière entre les deux — et l'une des cinq la placerait ailleurs.

/// Ce qui a été demandé a abouti.
pub const ASL_OK: i32 = 0;
/// Un pointeur nul, une chaîne qui n'est pas de l'UTF-8, une valeur hors bornes.
pub const ASL_ARGUMENT: i32 = -1;
/// La configuration ne tient pas : pas d'annuaire, pas de racine, un plafond nul.
pub const ASL_CONFIGURATION: i32 = -2;
/// Personne n'a répondu.
pub const ASL_INJOIGNABLE: i32 = -3;
/// L'annuaire a compris, et il a dit non.
pub const ASL_REFUSE: i32 = -4;
/// Le tampon fourni est trop petit ; sa taille nécessaire a été écrite.
pub const ASL_TAMPON_TROP_PETIT: i32 = -5;
/// Une panique a été rattrapée, ou l'impossible est arrivé.
pub const ASL_INTERNE: i32 = -6;
/// Cette machine n'a pas d'identité : appelez `asl_client_identite`.
pub const ASL_PAS_D_IDENTITE: i32 = -7;
/// Ce client annonce déjà.
pub const ASL_DEJA: i32 = -8;
/// L'annuaire n'a encore rien poussé.
///
/// **CE N'EST PAS UNE PANNE, C'EST LE CAS ORDINAIRE** : il ne pousse que ce qui
/// a CHANGÉ, et un service dont les sondes confirment ce qu'il disait déjà n'en
/// produit aucune. Le distinguer d'une liste vide évite de faire croire à un
/// porteur que ses points sont devenus injoignables.
pub const ASL_PAS_DE_POUSSEE: i32 = -9;
/// Cet appareil n'est pas connecté : appelez `asl_appareil_connecter`.
pub const ASL_NON_CONNECTE: i32 = -10;
/// Le signataire de l'application n'a pas rendu de signature.
///
/// **CE N'EST PAS UNE PANNE, C'EST LE PORTEUR** : il n'a pas confirmé son
/// identité, ou a annulé. Rien n'est parti, et rien n'est à réessayer sans lui.
pub const ASL_SIGNATURE_REFUSEE: i32 = -11;

pub mod appareil;

/// Combien d'octets écrit `asl_enroler` dans son tampon de machine, NUL compris.
pub const ASL_IDENTIFIANT_OCTETS: usize = asl_id::LONGUEUR + 1;
/// Combien d'octets fait une graine.
pub const ASL_GRAINE_OCTETS: usize = 32;

/// `tcp`, dans un [`AslPoint`] ou un [`AslCandidat`].
pub const ASL_TCP: u8 = 1;
/// `udp`.
pub const ASL_UDP: u8 = 2;

/// L'adresse observée par l'annuaire — celle sous laquelle il nous voit.
pub const ASL_REFLEXIF: u8 = 1;
/// L'adresse que le daemon a annoncée lui-même.
pub const ASL_ANNONCE: u8 = 2;

/// L'annuaire a ouvert une connexion vers ce candidat et l'a vue aboutir.
pub const ASL_JOIGNABLE: u8 = 1;
/// Il a essayé, et cela n'a pas abouti.
pub const ASL_INJOIGNABLE_POINT: u8 = 2;
/// Il ne mesurera pas : UDP n'a pas de poignée de main.
pub const ASL_NON_SONDE: u8 = 3;
/// La sonde n'a pas encore rendu son verdict.
pub const ASL_EN_COURS: u8 = 4;

/// L'adresse observée figure parmi celles que le daemon a annoncées.
pub const ASL_NAT_NON: u8 = 1;
/// Elle ne figure dans aucune.
pub const ASL_NAT_OUI: u8 = 2;
/// **Rien à comparer**, et l'affirmer serait mentir.
///
/// Le daemon n'a annoncé aucune adresse locale. Un booléen forcerait à répondre
/// « non », c'est-à-dire à affirmer une chose qu'on n'a pas mesurée — et un
/// daemon derrière un NAT qui lirait « non » chercherait la panne partout sauf
/// là où elle est.
pub const ASL_NAT_INDETERMINE: u8 = 3;

// ── LES STRUCTURES QUI TRAVERSENT ───────────────────────────────────────────
//
// **AUCUN TROU IMPLICITE.** Cinq langages calculent la disposition chacun de son
// côté ; un octet de bourrage que le compilateur choisit est exactement l'endroit
// où deux d'entre eux choisiront différemment. Les champs sont donc ordonnés du
// plus large au plus étroit, et le reste est un `reserve` NOMMÉ.

/// Un point d'écoute à annoncer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AslPoint {
    /// Le port, jamais zéro.
    pub port: u16,
    /// [`ASL_TCP`] ou [`ASL_UDP`].
    pub protocole: u8,
    /// À zéro. Réservé.
    pub reserve: u8,
}

/// Où joindre un service, et ce que l'annuaire en sait.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AslCandidat {
    /// L'adresse, en ordre réseau. **Les quatre premiers octets en IPv4.**
    pub adresse: [u8; 16],
    /// Le port.
    pub port: u16,
    /// [`ASL_TCP`] ou [`ASL_UDP`].
    pub protocole: u8,
    /// `4` ou `6`.
    pub famille: u8,
    /// [`ASL_REFLEXIF`] ou [`ASL_ANNONCE`].
    pub origine: u8,
    /// [`ASL_JOIGNABLE`], [`ASL_INJOIGNABLE_POINT`], [`ASL_NON_SONDE`] ou
    /// [`ASL_EN_COURS`].
    ///
    /// # LES TROIS DERNIERS NE VEULENT PAS DIRE « ÇA NE MARCHE PAS » (C6)
    ///
    /// `en_cours` n'affirme rien — l'annuaire n'a pas fini de mesurer.
    /// `non_sonde` dit qu'il ne mesurera pas. Les aplatir en un booléen ferait
    /// écarter un candidat parfaitement bon.
    pub verdict: u8,
    /// À zéro. Réservé.
    pub reserve: [u8; 2],
}

/// Ce que l'attache a fait jusqu'ici.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AslEtat {
    /// Combien de fois on s'est attaché depuis le départ.
    pub attaches: u64,
    /// Combien de fois une attache établie s'est rompue.
    pub ruptures: u64,
    /// `1` si l'annuaire nous connaît en ce moment : authentifiés ET annoncés.
    pub attachee: u8,
    /// `1` si la tâche a renoncé — **et elle ne renonce que sur une faute de
    /// configuration**, jamais sur une panne de réseau.
    pub abandonnee: u8,
    /// À zéro. Réservé.
    pub reserve: [u8; 6],
}

// Les tailles font partie du contrat autant que les noms.
const _: () = assert!(core::mem::size_of::<AslPoint>() == 4);
const _: () = assert!(core::mem::size_of::<AslCandidat>() == 24);
const _: () = assert!(core::mem::size_of::<AslEtat>() == 24);

// ── LE CLIENT ───────────────────────────────────────────────────────────────

/// Un client, vu de C : un pointeur opaque et rien d'autre.
///
/// **IL N'EST PAS SÛR DE LE PARTAGER ENTRE FILS.** L'authentification est portée
/// par la connexion (`protocole.md` §3) : ce qu'une requête a le droit de faire
/// dépend de la clé prouvée sur celle-là. Deux fils qui partageraient un client
/// partageraient donc leurs droits — et se marcheraient dessus.
pub struct AslClient {
    moteur: tokio::runtime::Runtime,
    annuaires: Vec<Annuaire>,
    racines: Vec<u8>,
    plafond_ms: u64,
    /// **LA MACHINE ET SA GRAINE, ET NON UNE [`Identite`] TOUTE FAITE.**
    ///
    /// Une identité ne se duplique pas — elle porte une clé —, et l'annonce en
    /// CONSOMME une : `Attache` la garde pour se réauthentifier à chaque
    /// reconnexion. Ranger l'identité elle-même la ferait donc disparaître du
    /// client au premier [`asl_annoncer`], et le [`asl_ou`] suivant répondrait
    /// « aucune identité » à un daemon qui vient précisément de s'annoncer.
    ///
    /// La graine, elle, se recopie : on en dérive autant d'identités qu'il en
    /// faut, et ce sont toujours les mêmes.
    machine: Option<Identifiant>,
    graine: Option<[u8; ASL_GRAINE_OCTETS]>,
    attache: Option<Attache>,
}

impl AslClient {
    /// Monte les réglages, ou dit ce qui manque.
    fn reglages(&self) -> Result<Reglages, i32> {
        Reglages::nouveaux(
            self.annuaires.clone(),
            self.racines.clone(),
            self.plafond_ms,
        )
        .map_err(|_| ASL_CONFIGURATION)
    }

    /// Dérive l'identité de cette machine, autant de fois qu'on la demande.
    fn identite(&self) -> Result<Identite, i32> {
        let (Some(machine), Some(graine)) = (self.machine, self.graine) else {
            return Err(ASL_PAS_D_IDENTITE);
        };
        Identite::nouvelle(machine, graine).map_err(|_| ASL_INTERNE)
    }
}

/// Le plafond de recul par défaut, en millisecondes.
pub(crate) const PLAFOND_MS: u64 = 15_000;

/// Combien de temps un appel bloquant attend une connexion, en secondes.
///
/// **UNE BIBLIOTHÈQUE NE PEUT PAS NE JAMAIS RENDRE LA MAIN.** `joindre`
/// n'abandonne jamais, et c'est juste pour une annonce tenue en tâche de fond ;
/// un appel synchrone venu de Python, lui, doit rendre un verdict. Il est posé
/// ici, à l'endroit exact où `asl-client-tokio` dit qu'il doit l'être.
const PATIENCE_S: u64 = 20;

// ── CE QUI NE TOUCHE À RIEN ─────────────────────────────────────────────────

/// La version de cette bibliothèque.
///
/// # Safety
///
/// Les trois pointeurs, s'ils ne sont pas nuls, doivent viser un `uint32_t`
/// inscriptible.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_version(majeur: *mut u32, mineur: *mut u32, correctif: *mut u32) {
    let (ma, mi, co) = (0_u32, 1_u32, 0_u32);
    // SAFETY : l'appelant garantit que chaque pointeur non nul vise un
    // `uint32_t` qu'il possède.
    unsafe {
        if !majeur.is_null() {
            majeur.write(ma);
        }
        if !mineur.is_null() {
            mineur.write(mi);
        }
        if !correctif.is_null() {
            correctif.write(co);
        }
    }
}

/// Ce que veut dire un code.
///
/// # RIEN À LIBÉRER
///
/// La chaîne rendue est **statique** : elle vit aussi longtemps que la
/// bibliothèque est chargée. Rendre une chaîne allouée obligerait à une fonction
/// de libération, donc à ce que cinq liaisons pensent à l'appeler — sur le
/// chemin d'erreur, celui qu'on éprouve le moins.
#[unsafe(no_mangle)]
pub extern "C" fn asl_faute_texte(code: i32) -> *const c_char {
    let texte: &'static CStr = match code {
        ASL_OK => c"abouti",
        ASL_ARGUMENT => c"argument invalide",
        ASL_CONFIGURATION => c"configuration incomplete ou refusee",
        ASL_INJOIGNABLE => c"aucun annuaire n'a repondu",
        ASL_REFUSE => c"l'annuaire a refuse",
        ASL_TAMPON_TROP_PETIT => c"tampon trop petit",
        ASL_INTERNE => c"faute interne",
        ASL_PAS_D_IDENTITE => c"aucune identite: appelez asl_client_identite",
        ASL_DEJA => c"ce client annonce deja",
        ASL_PAS_DE_POUSSEE => c"rien n'a ete pousse",
        ASL_NON_CONNECTE => c"pas connecte: appelez asl_appareil_connecter",
        ASL_SIGNATURE_REFUSEE => c"le porteur n'a pas signe",
        _ => c"code inconnu",
    };
    texte.as_ptr()
}

// ── LA CONSTRUCTION ─────────────────────────────────────────────────────────

/// Crée un client. **Il n'ouvre aucune connexion.**
///
/// `protocole.md` §1.4 : un annuaire injoignable ne doit pas empêcher un daemon
/// de démarrer.
///
/// # Safety
///
/// `sortie` doit viser un pointeur inscriptible. Le client rendu se libère par
/// [`asl_client_libere`], et par rien d'autre.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_client_neuf(sortie: *mut *mut AslClient) -> i32 {
    protege(|| {
        if sortie.is_null() {
            return ASL_ARGUMENT;
        }
        let Ok(moteur) = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
        else {
            return ASL_INTERNE;
        };
        let client = Box::new(AslClient {
            moteur,
            annuaires: Vec::new(),
            racines: Vec::new(),
            plafond_ms: PLAFOND_MS,
            machine: None,
            graine: None,
            attache: None,
        });
        // SAFETY : `sortie` est non nul, et l'appelant garantit qu'il vise un
        // pointeur qu'il possède.
        unsafe { sortie.write(Box::into_raw(client)) };
        ASL_OK
    })
}

/// Ajoute un annuaire. **Répétable, et l'ordre compte.**
///
/// L'IPv6 est essayé d'abord quelle que soit la place à laquelle il est ajouté ;
/// à l'intérieur d'une famille, c'est l'ordre des appels qui décide.
///
/// **L'ADRESSE EST LITTÉRALE**, et non un nom : la résolution appartient à
/// l'appelant. Un daemon chargé dans un interpréteur a déjà son résolveur, et
/// lui en imposer un autre — avec sa politique de cache et ses fils — serait
/// décider à sa place. L'utilitaire `asl` fait le sien avec `getaddrinfo`.
///
/// # Safety
///
/// `client` vient de [`asl_client_neuf`]. `adresse` et `nom` sont des chaînes C
/// valides, terminées par NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_client_annuaire(
    client: *mut AslClient,
    adresse: *const c_char,
    nom: *const c_char,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(client) = (unsafe { client.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        let (Some(adresse), Some(nom)) =
            // SAFETY : contrat de la fonction.
            (unsafe { chaine(adresse) }, unsafe { chaine(nom) })
        else {
            return ASL_ARGUMENT;
        };
        let Ok(adresse) = adresse.parse::<std::net::SocketAddr>() else {
            return ASL_ARGUMENT;
        };
        if nom.is_empty() {
            return ASL_ARGUMENT;
        }
        client.annuaires.push(Annuaire {
            adresse,
            nom: nom.to_owned(),
        });
        ASL_OK
    })
}

/// Pose les certificats d'autorité, en PEM.
///
/// **IL N'Y A PAS DE REPLI SUR LE MAGASIN DU SYSTÈME**, et l'absence de repli
/// est une décision : les annuaires racines sont signés par LEUR autorité, et se
/// rabattre en silence sur les centaines de racines d'un système ferait accepter
/// un certificat qu'aucune d'elles n'aurait dû émettre.
///
/// # Safety
///
/// `pem` vise `taille` octets lisibles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_client_racines(
    client: *mut AslClient,
    pem: *const u8,
    taille: usize,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(client) = (unsafe { client.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        if pem.is_null() || taille == 0 {
            return ASL_ARGUMENT;
        }
        // SAFETY : l'appelant garantit `taille` octets lisibles depuis `pem`.
        client.racines = unsafe { core::slice::from_raw_parts(pem, taille) }.to_vec();
        ASL_OK
    })
}

/// Installe l'identité de cette machine.
///
/// `machine` est son identifiant en texte ; `graine` les trente-deux octets dont
/// la clé se dérive — ceux que [`asl_enroler`] a rendus.
///
/// # LA CLÉ EST DÉRIVÉE, ET NON TRANSPORTÉE
///
/// Ce qui traverse est la graine, et l'appelant est responsable de sa qualité et
/// de sa conservation : une graine tirée d'un compteur serait devinable, et toute
/// l'authentification du produit repose là-dessus.
///
/// # Safety
///
/// `machine` est une chaîne C valide ; `graine` vise [`ASL_GRAINE_OCTETS`]
/// octets lisibles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_client_identite(
    client: *mut AslClient,
    machine: *const c_char,
    graine: *const u8,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(client) = (unsafe { client.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        // SAFETY : contrat de la fonction.
        let Some(machine) = (unsafe { chaine(machine) }) else {
            return ASL_ARGUMENT;
        };
        if graine.is_null() {
            return ASL_ARGUMENT;
        }
        let Ok(machine) = Identifiant::analyser_genre(Genre::Machine, machine) else {
            return ASL_ARGUMENT;
        };
        let mut octets = [0_u8; ASL_GRAINE_OCTETS];
        // SAFETY : l'appelant garantit `ASL_GRAINE_OCTETS` octets lisibles.
        octets.copy_from_slice(unsafe { core::slice::from_raw_parts(graine, ASL_GRAINE_OCTETS) });
        // On la dérive tout de suite pour REFUSER ici ce qui ne se dérive pas,
        // plutôt qu'au premier verbe.
        if Identite::nouvelle(machine, octets).is_err() {
            return ASL_ARGUMENT;
        }
        client.machine = Some(machine);
        client.graine = Some(octets);
        ASL_OK
    })
}

/// Libère le client — **et retire l'annonce en le faisant**.
///
/// La connexion EST le bail : rendre le client rend l'annonce. Elle est fermée
/// PROPREMENT, ce qui épargne à l'annuaire la minute d'inactivité pendant
/// laquelle il donnerait une adresse morte.
///
/// Un pointeur nul est accepté et ne fait rien, comme `free`.
///
/// # Safety
///
/// `client` vient de [`asl_client_neuf`] et n'a pas déjà été libéré.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_client_libere(client: *mut AslClient) {
    if client.is_null() {
        return;
    }
    let _ = protege(|| {
        // SAFETY : l'appelant garantit que ce pointeur vient de
        // `asl_client_neuf` et n'a pas déjà été rendu.
        let mut client = unsafe { Box::from_raw(client) };
        if let Some(attache) = client.attache.take() {
            client.moteur.block_on(attache.retirer());
        }
        ASL_OK
    });
}

// ── LES VERBES ──────────────────────────────────────────────────────────────

/// Présente un code d'enrôlement, et rend l'identité obtenue.
///
/// L'identité est **installée dans le client** au passage : le code a été
/// dépensé, et obliger l'appelant à la réinstaller lui ferait perdre la clé que
/// l'annuaire vient d'accepter s'il oubliait.
///
/// # Safety
///
/// `code` est une chaîne C valide. `machine_sortie` vise
/// [`ASL_IDENTIFIANT_OCTETS`] octets inscriptibles, `graine_sortie`
/// [`ASL_GRAINE_OCTETS`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_enroler(
    client: *mut AslClient,
    code: *const c_char,
    machine_sortie: *mut c_char,
    graine_sortie: *mut u8,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(client) = (unsafe { client.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        // SAFETY : contrat de la fonction.
        let Some(code) = (unsafe { chaine(code) }) else {
            return ASL_ARGUMENT;
        };
        if machine_sortie.is_null() || graine_sortie.is_null() {
            return ASL_ARGUMENT;
        }
        let reglages = match client.reglages() {
            Ok(reglages) => reglages,
            Err(quoi) => return quoi,
        };

        let graine = match graine_du_noyau() {
            Some(graine) => graine,
            None => return ASL_INTERNE,
        };
        let enrolement = asl_client::Enrolement::nouveau(graine);

        let issue = client.moteur.block_on(async {
            let mut connexion = ouvrir(&reglages).await?;
            let machine = connexion
                .enroler(&enrolement, code)
                .await
                .map_err(traduire)?;
            let _ = connexion.fermer().await;
            Ok(machine)
        });
        let machine = match issue {
            Ok(machine) => machine,
            Err(quoi) => return quoi,
        };

        if Identite::nouvelle(machine, graine).is_err() {
            return ASL_INTERNE;
        }
        client.machine = Some(machine);
        client.graine = Some(graine);

        // SAFETY : l'appelant garantit les deux tampons et leurs tailles.
        unsafe {
            ecrire_chaine(machine.texte().as_str(), machine_sortie);
            core::ptr::copy_nonoverlapping(graine.as_ptr(), graine_sortie, ASL_GRAINE_OCTETS);
        }
        ASL_OK
    })
}

/// Annonce ce service, et **rend la main tout de suite**.
///
/// L'annonce est tenue en tâche de fond aussi longtemps que le client vit : elle
/// se réauthentifie et se réannonce toute seule à chaque reconnexion, et bascule
/// sur l'autre annuaire racine quand le premier tombe. [`asl_etat`] dit où elle
/// en est.
///
/// **UN CLIENT N'ANNONCE QU'UNE FOIS.** Un second appel rend [`ASL_DEJA`] plutôt
/// que de remplacer la première annonce en silence — ce qui la retirerait.
///
/// # Safety
///
/// `service` est une chaîne C valide ; `points` vise `combien` [`AslPoint`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_annoncer(
    client: *mut AslClient,
    service: *const c_char,
    points: *const AslPoint,
    combien: usize,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(client) = (unsafe { client.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        if client.attache.is_some() {
            return ASL_DEJA;
        }
        // SAFETY : contrat de la fonction.
        let Some(service) = (unsafe { chaine(service) }) else {
            return ASL_ARGUMENT;
        };
        if points.is_null() || combien == 0 {
            return ASL_ARGUMENT;
        }
        let Ok(nom) = NomService::analyser(service) else {
            return ASL_ARGUMENT;
        };
        // SAFETY : l'appelant garantit `combien` structures lisibles.
        let bruts = unsafe { core::slice::from_raw_parts(points, combien) };
        let mut ecoutes = Vec::with_capacity(bruts.len());
        for brut in bruts {
            let protocole = match brut.protocole {
                ASL_TCP => Protocole::Tcp,
                ASL_UDP => Protocole::Udp,
                _ => return ASL_ARGUMENT,
            };
            let Ok(port) = Port::depuis_u16(brut.port) else {
                return ASL_ARGUMENT;
            };
            ecoutes.push(PointEcoute::nouveau(protocole, port));
        }

        let identite = match client.identite() {
            Ok(identite) => identite,
            Err(quoi) => return quoi,
        };
        let reglages = match client.reglages() {
            Ok(reglages) => reglages,
            Err(quoi) => return quoi,
        };

        // **L'ANNONCE EST ENCODÉE ICI**, dans la main de l'appelant : une annonce
        // invalide devient un code de retour, et non une tâche qui échoue en
        // silence dans un fil que personne ne regarde.
        let Ok(annonce) = identite.annoncer(nom, &ecoutes, &[]) else {
            return ASL_ARGUMENT;
        };
        let Ok(encodee) = asl_client_tokio::encoder(&annonce) else {
            return ASL_ARGUMENT;
        };

        let garde = client.moteur.enter();
        client.attache = Some(Attache::annoncer(
            reglages,
            identite,
            vec![encodee],
            std::sync::Arc::new(graine16),
        ));
        drop(garde);
        ASL_OK
    })
}

/// Où l'attache en est.
///
/// # Safety
///
/// `sortie` vise un [`AslEtat`] inscriptible.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_etat(client: *const AslClient, sortie: *mut AslEtat) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(client) = (unsafe { client.as_ref() }) else {
            return ASL_ARGUMENT;
        };
        if sortie.is_null() {
            return ASL_ARGUMENT;
        }
        let etat = client.attache.as_ref().map(asl_client_tokio::Attache::etat);
        let rendu = AslEtat {
            attaches: etat.map_or(0, |quoi| quoi.attaches),
            ruptures: etat.map_or(0, |quoi| quoi.ruptures),
            attachee: u8::from(etat.is_some_and(|quoi| quoi.attachee)),
            abandonnee: u8::from(etat.is_some_and(|quoi| quoi.abandonnee)),
            reserve: [0; 6],
        };
        // SAFETY : `sortie` est non nul et vise un `AslEtat` de l'appelant.
        unsafe { sortie.write(rendu) };
        ASL_OK
    })
}

/// Demande où joindre un service, et rend les candidats **dans l'ordre**.
///
/// # LE TAMPON SE DIMENSIONNE EN DEUX TEMPS
///
/// Avec `candidats` nul, ou `combien` trop petit, la fonction écrit dans `ecrit`
/// le nombre qu'il faudrait et rend [`ASL_TAMPON_TROP_PETIT`]. C'est l'usage du
/// C, et il évite d'allouer pour le compte de l'appelant — donc de lui faire
/// libérer avec un allocateur qui n'est pas le nôtre.
///
/// # Safety
///
/// `machine` et `service` sont des chaînes C valides ; `candidats`, s'il n'est
/// pas nul, vise `combien` [`AslCandidat`] inscriptibles ; `ecrit` vise un
/// `size_t` inscriptible.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_ou(
    client: *mut AslClient,
    machine: *const c_char,
    service: *const c_char,
    candidats: *mut AslCandidat,
    combien: usize,
    ecrit: *mut usize,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(client) = (unsafe { client.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        // SAFETY : contrat de la fonction.
        let (Some(machine), Some(service)) =
            (unsafe { chaine(machine) }, unsafe { chaine(service) })
        else {
            return ASL_ARGUMENT;
        };
        if ecrit.is_null() {
            return ASL_ARGUMENT;
        }
        let Ok(machine) = Identifiant::analyser_genre(Genre::Machine, machine) else {
            return ASL_ARGUMENT;
        };
        let identite = match client.identite() {
            Ok(identite) => identite,
            Err(quoi) => return quoi,
        };
        let reglages = match client.reglages() {
            Ok(reglages) => reglages,
            Err(quoi) => return quoi,
        };

        let issue = client.moteur.block_on(async {
            let mut connexion = ouvrir(&reglages).await?;
            connexion.authentifier(&identite).await.map_err(traduire)?;
            let corps = connexion.ou(machine, service).await.map_err(traduire)?;
            let _ = connexion.fermer().await;
            Ok(corps)
        });
        let corps = match issue {
            Ok(corps) => corps,
            Err(quoi) => return quoi,
        };

        let Some(trouves) = candidats_de(&corps) else {
            return ASL_INTERNE;
        };
        // SAFETY : `ecrit` est non nul.
        unsafe { ecrit.write(trouves.len()) };
        if candidats.is_null() || combien < trouves.len() {
            return ASL_TAMPON_TROP_PETIT;
        }
        // SAFETY : l'appelant garantit `combien` places inscriptibles, et l'on
        // vient de vérifier qu'il y en a assez.
        unsafe {
            core::ptr::copy_nonoverlapping(trouves.as_ptr(), candidats, trouves.len());
        }
        ASL_OK
    })
}

/// Combien de poussées de verdict sont arrivées depuis le départ.
///
/// **ZÉRO N'EST PAS UNE ANOMALIE** : l'annuaire ne pousse que ce qui a CHANGÉ.
///
/// # Safety
///
/// `sortie` vise un `uint64_t` inscriptible.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_poussees_recues(client: *const AslClient, sortie: *mut u64) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(client) = (unsafe { client.as_ref() }) else {
            return ASL_ARGUMENT;
        };
        if sortie.is_null() {
            return ASL_ARGUMENT;
        }
        let combien = client
            .attache
            .as_ref()
            .map_or(0, |attache| attache.etat().poussees);
        // SAFETY : `sortie` est non nul.
        unsafe { sortie.write(combien) };
        ASL_OK
    })
}

/// Ce que l'annuaire a MESURÉ depuis, et poussé sur la connexion tenue.
///
/// # POURQUOI CETTE PORTE EXISTE, ALORS QUE `asl_ou` REND DÉJÀ DES CANDIDATS
///
/// `asl_ou` dit où joindre le service D'UN AUTRE. Celle-ci dit ce que l'annuaire
/// pense des NÔTRES — et surtout, elle dit ce qu'il a appris APRÈS avoir répondu.
///
/// L'annuaire répond `en_cours` à une annonce pour ne pas faire attendre un
/// démarrage le temps d'une sonde. **Sans cette porte, un daemon reste à croire
/// que sa joignabilité est en cours de mesure**, pour toujours.
///
/// # ELLE PORTE LA LISTE ENTIÈRE, ET NON UN DELTA
///
/// La dernière poussée remplace tout ce qui précède. L'appeler deux fois rend
/// deux fois la même chose tant qu'aucune autre n'est arrivée.
///
/// # Safety
///
/// `candidats`, s'il n'est pas nul, vise `combien` [`AslCandidat`] inscriptibles ;
/// `ecrit` vise un `size_t` inscriptible ; `derriere_nat`, s'il n'est pas nul, un
/// `uint8_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_derniere_poussee(
    client: *const AslClient,
    candidats: *mut AslCandidat,
    combien: usize,
    ecrit: *mut usize,
    derriere_nat: *mut u8,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(client) = (unsafe { client.as_ref() }) else {
            return ASL_ARGUMENT;
        };
        if ecrit.is_null() {
            return ASL_ARGUMENT;
        }
        let Some(octets) = client
            .attache
            .as_ref()
            .and_then(asl_client_tokio::Attache::derniere_poussee)
        else {
            return ASL_PAS_DE_POUSSEE;
        };
        let Some((trouves, nat)) = candidats_d_une_poussee(&octets) else {
            return ASL_INTERNE;
        };

        // SAFETY : `ecrit` est non nul.
        unsafe { ecrit.write(trouves.len()) };
        // SAFETY : l'appelant garantit que `derriere_nat`, s'il n'est pas nul,
        // vise un octet qu'il possède.
        unsafe {
            if !derriere_nat.is_null() {
                derriere_nat.write(nat);
            }
        }
        if candidats.is_null() || combien < trouves.len() {
            return ASL_TAMPON_TROP_PETIT;
        }
        // SAFETY : l'appelant garantit `combien` places, et l'on vient de
        // vérifier qu'il y en a assez.
        unsafe {
            core::ptr::copy_nonoverlapping(trouves.as_ptr(), candidats, trouves.len());
        }
        ASL_OK
    })
}

// ── CE QUI NE TRAVERSE PAS ──────────────────────────────────────────────────

/// Rattrape tout, y compris ce qui n'aurait pas dû arriver.
pub(crate) fn protege(corps: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(corps)).unwrap_or(ASL_INTERNE)
}

/// Une chaîne C, si elle en est une.
///
/// # Safety
///
/// `brut`, s'il n'est pas nul, vise une suite d'octets terminée par NUL.
pub(crate) unsafe fn chaine<'a>(brut: *const c_char) -> Option<&'a str> {
    if brut.is_null() {
        return None;
    }
    // SAFETY : contrat de la fonction.
    unsafe { CStr::from_ptr(brut) }.to_str().ok()
}

/// Écrit une chaîne et son NUL.
///
/// # Safety
///
/// `ou` vise au moins `texte.len() + 1` octets inscriptibles.
pub(crate) unsafe fn ecrire_chaine(texte: &str, ou: *mut c_char) {
    // SAFETY : contrat de la fonction.
    unsafe {
        core::ptr::copy_nonoverlapping(texte.as_ptr().cast::<c_char>(), ou, texte.len());
        ou.add(texte.len()).write(0);
    }
}

/// Ouvre une connexion, avec la patience d'une bibliothèque.
pub(crate) async fn ouvrir(reglages: &Reglages) -> Result<asl_client_tokio::Connexion, i32> {
    let patience = tokio::time::Duration::from_secs(PATIENCE_S);
    match tokio::time::timeout(patience, asl_client_tokio::joindre(reglages, &graine16_ref)).await {
        Ok(Ok(connexion)) => Ok(connexion),
        Ok(Err(_)) => Err(ASL_CONFIGURATION),
        Err(_) => Err(ASL_INJOIGNABLE),
    }
}

/// Traduit un refus du réseau. **`REFUSE` et `INJOIGNABLE` restent distincts** :
/// un droit manquant et un câble débranché se corrigent à des endroits opposés.
pub(crate) fn traduire(quoi: asl_client_tokio::Faute) -> i32 {
    match quoi {
        asl_client_tokio::Faute::Statut(_) => ASL_REFUSE,
        asl_client_tokio::Faute::Tls(_) => ASL_CONFIGURATION,
        _ => ASL_INJOIGNABLE,
    }
}

/// Seize octets d'entropie pour QUIC.
fn graine16() -> [u8; 16] {
    graine_du_noyau::<16>().unwrap_or([0; 16])
}

/// La même, en fonction nommée pour les emprunts.
fn graine16_ref() -> [u8; 16] {
    graine16()
}

/// De l'entropie, prise au noyau.
///
/// **AUCUN REPLI INVENTÉ** sur le chemin qui compte : [`asl_enroler`] rend
/// [`ASL_INTERNE`] plutôt qu'une clé tirée d'une horloge.
pub(crate) fn graine_du_noyau<const N: usize>() -> Option<[u8; N]> {
    use std::io::Read as _;
    let mut fichier = std::fs::File::open("/dev/urandom").ok()?;
    let mut octets = [0_u8; N];
    fichier.read_exact(&mut octets).ok()?;
    Some(octets)
}

/// Les candidats d'une POUSSÉE, ordonnés, et son verdict de NAT.
///
/// # POURQUOI CE N'EST PAS [`candidats_de`]
///
/// Une poussée n'a **ni service ni bail** (`protocole.md` §1.4) : la connexion
/// détermine déjà le premier, et le second est accordé une fois, à l'annonce.
/// Elle n'a donc pas la forme d'une `Reponse`, et un décodeur unique aurait dû
/// rendre facultatif ce qui est obligatoire dans l'autre.
///
/// Ce qu'elles ont en commun — `vu_depuis` et la liste de verdicts — est ce qui
/// produit les candidats, et cette partie-là est écrite une fois.
fn candidats_d_une_poussee(octets: &[u8]) -> Option<(Vec<AslCandidat>, u8)> {
    let mut tampons = asl_proto::cadrage::TamponsReponse::nouveaux();
    let lue = asl_proto::Poussee::decoder(octets, &mut tampons).ok()?;
    let nat = match lue.derriere_nat {
        asl_proto::VerdictNat::Non => ASL_NAT_NON,
        asl_proto::VerdictNat::Oui => ASL_NAT_OUI,
        asl_proto::VerdictNat::Indetermine => ASL_NAT_INDETERMINE,
    };
    Some((
        ordonner_les_candidats(lue.vu_depuis.adresse, lue.joignabilite),
        nat,
    ))
}

/// Les candidats d'une réponse d'annuaire, ordonnés.
///
/// # POURQUOI CETTE FONCTION EST À PART, ET NON DANS `asl_ou`
///
/// Parce que c'est la seule chose ici qui soit une pure fonction : des octets
/// entrent, des structures sortent. Elle s'éprouve sur une réponse composée à la
/// main, sans annuaire et sans socket — et c'est là que se cacherait une
/// confusion entre `en_cours` et `injoignable`.
fn candidats_de(corps: &[u8]) -> Option<Vec<AslCandidat>> {
    let mut tampons = asl_proto::cadrage::TamponsReponse::nouveaux();
    let lue = asl_proto::Reponse::decoder(corps, &mut tampons).ok()?;
    Some(ordonner_les_candidats(
        lue.vu_depuis.adresse,
        lue.joignabilite,
    ))
}

/// Les candidats que produit une liste de verdicts, ordonnés.
///
/// **ÉCRIT UNE FOIS, EMPLOYÉ DEUX** — par une réponse et par une poussée. Deux
/// copies de ce tri finiraient par diverger, et c'est celle qu'on oublie de
/// corriger qui rendrait un ordre faux.
fn ordonner_les_candidats(
    observee: core::net::IpAddr,
    verdicts: &[asl_proto::Joignabilite],
) -> Vec<AslCandidat> {
    let mut bruts: Vec<asl_proto::Candidat> = verdicts
        .iter()
        .map(|entree| match entree.verdict {
            // **CELUI QU'UNE SONDE A MESURÉ PASSE AVANT CELUI QU'ON DÉDUIT.**
            asl_proto::Verdict::Joignable { candidat, .. } => candidat,
            _ => asl_proto::Candidat {
                protocole: entree.point.protocole,
                adresse: observee,
                port: entree.point.port,
                origine: asl_proto::Origine::Reflexif,
            },
        })
        .collect();

    // Les verdicts suivent les candidats dans leur tri : on les apparie AVANT.
    let mut rendus: Vec<u8> = verdicts
        .iter()
        .map(|entree| match entree.verdict {
            asl_proto::Verdict::Joignable { .. } => ASL_JOIGNABLE,
            asl_proto::Verdict::Injoignable { .. } => ASL_INJOIGNABLE_POINT,
            asl_proto::Verdict::NonSonde { .. } => ASL_NON_SONDE,
            asl_proto::Verdict::EnCours => ASL_EN_COURS,
        })
        .collect();

    let mut ensemble: Vec<(asl_proto::Candidat, u8)> =
        bruts.drain(..).zip(rendus.drain(..)).collect();
    // `ordonner` trie des candidats seuls ; on trie ici la paire sur la même
    // clé, pour qu'aucun verdict ne se retrouve sur le candidat du voisin.
    ensemble.sort_by_key(|(candidat, _)| {
        let (famille, origine) = candidat.rang();
        (famille, origine, candidat.port.valeur())
    });

    ensemble
        .into_iter()
        .map(|(candidat, verdict)| {
            let (famille, adresse) = match candidat.adresse {
                core::net::IpAddr::V6(quoi) => (6_u8, quoi.octets()),
                core::net::IpAddr::V4(quoi) => {
                    let mut place = [0_u8; 16];
                    place
                        .get_mut(..4)
                        .unwrap_or_default()
                        .copy_from_slice(&quoi.octets());
                    (4_u8, place)
                }
            };
            AslCandidat {
                adresse,
                port: candidat.port.valeur(),
                protocole: match candidat.protocole {
                    asl_proto::Protocole::Tcp => ASL_TCP,
                    asl_proto::Protocole::Udp => ASL_UDP,
                },
                famille,
                origine: match candidat.origine {
                    asl_proto::Origine::Reflexif => ASL_REFLEXIF,
                    asl_proto::Origine::Annonce => ASL_ANNONCE,
                },
                verdict,
                reserve: [0; 2],
            }
        })
        .collect()
}

#[cfg(test)]
mod essais {
    use super::*;
    use asl_proto::{Bail, Horodatage, Joignabilite, Verdict, VerdictNat, VuDepuis};
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Compose une réponse d'annuaire, telle qu'elle arrive sur le fil.
    fn sur_le_fil(observee: IpAddr, verdicts: &[Joignabilite]) -> Vec<u8> {
        let service = Identifiant::depuis_entropie(Genre::Service, [0x11; 16]);
        let bail = Bail::nouveau(15, 45).expect("un bail juste");
        let vu = VuDepuis {
            adresse: observee,
            port: Port::depuis_u16(41_234).expect("un port"),
        };
        let reponse = asl_proto::Reponse::nouvelle(service, bail, vu, VerdictNat::Oui, verdicts)
            .expect("une réponse juste");
        let mut sortie = vec![0_u8; asl_proto::cadrage::MESSAGE_MAX];
        let combien = reponse.encoder(&mut sortie).expect("elle s'encode");
        sortie.truncate(combien);
        sortie
    }

    fn point(protocole: Protocole, port: u16) -> PointEcoute {
        PointEcoute::nouveau(protocole, Port::depuis_u16(port).expect("un port"))
    }

    #[test]
    fn les_quatre_verdicts_traversent_sans_etre_aplatis() {
        // **C6, DE L'AUTRE CÔTÉ DE LA FRONTIÈRE.** Trois de ces quatre états ne
        // veulent pas dire « ça ne marche pas » ; les rendre en un booléen ferait
        // écarter un candidat parfaitement bon.
        let observee = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let verdicts = [
            Joignabilite {
                point: point(Protocole::Tcp, 8080),
                verdict: Verdict::EnCours,
            },
            Joignabilite {
                point: point(Protocole::Tcp, 8081),
                verdict: Verdict::Injoignable {
                    a: Horodatage::depuis_millisecondes(1),
                },
            },
            Joignabilite {
                point: point(Protocole::Udp, 9000),
                verdict: Verdict::NonSonde {
                    raison: asl_proto::RaisonNonSonde::ProtocoleNonSondable,
                },
            },
            Joignabilite {
                point: point(Protocole::Tcp, 8082),
                verdict: Verdict::Joignable {
                    candidat: asl_proto::Candidat {
                        protocole: Protocole::Tcp,
                        adresse: observee,
                        port: Port::depuis_u16(8082).expect("un port"),
                        origine: asl_proto::Origine::Reflexif,
                    },
                    a: Horodatage::depuis_millisecondes(2),
                },
            },
        ];

        let rendus = candidats_de(&sur_le_fil(observee, &verdicts)).expect("elle se lit");
        assert_eq!(rendus.len(), 4);

        // Chaque verdict est resté sur SON candidat, malgré le tri.
        let par_port: std::collections::BTreeMap<u16, u8> = rendus
            .iter()
            .map(|quoi| (quoi.port, quoi.verdict))
            .collect();
        assert_eq!(par_port[&8080], ASL_EN_COURS);
        assert_eq!(par_port[&8081], ASL_INJOIGNABLE_POINT);
        assert_eq!(par_port[&9000], ASL_NON_SONDE);
        assert_eq!(par_port[&8082], ASL_JOIGNABLE);
    }

    #[test]
    fn l_ipv6_sort_en_premier_et_l_ipv4_tient_dans_ses_quatre_premiers_octets() {
        // Le tri est celui d'`asl_proto::ordonner` : IPv6 avant IPv4. Il n'est
        // pas réécrit ici, et il ne doit pas l'être.
        let observee = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let verdicts = [Joignabilite {
            point: point(Protocole::Tcp, 8080),
            verdict: Verdict::EnCours,
        }];
        let rendus = candidats_de(&sur_le_fil(observee, &verdicts)).expect("elle se lit");
        assert_eq!(rendus[0].famille, 6);
        assert_eq!(rendus[0].adresse[0], 0x20);
        assert_eq!(rendus[0].adresse[15], 0x01);
        assert_eq!(rendus[0].origine, ASL_REFLEXIF);

        let quatre = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let rendus = candidats_de(&sur_le_fil(quatre, &verdicts)).expect("elle se lit");
        assert_eq!(rendus[0].famille, 4);
        assert_eq!(&rendus[0].adresse[..4], &[203, 0, 113, 7]);
        assert_eq!(
            &rendus[0].adresse[4..],
            &[0; 12],
            "le reste doit être à zéro, et non laissé au hasard"
        );
    }

    #[test]
    fn un_corps_qui_n_est_pas_une_reponse_ne_se_devine_pas() {
        assert!(candidats_de(b"").is_none());
        assert!(candidats_de(b"{}").is_none());
    }
}
