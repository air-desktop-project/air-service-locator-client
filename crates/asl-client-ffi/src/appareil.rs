//! L'ABI C de la voie mobile — ce qu'un téléphone appelle.
//!
//! # POURQUOI ELLE EST À PART DU CLIENT DES DAEMONS
//!
//! `asl_client` sert un daemon : une identité Ed25519 dans un fichier, une
//! annonce tenue en tâche de fond, une résolution. Un téléphone ne fait rien de
//! cela. Il ADMINISTRE un compte, sa clé vit dans son matériel sous contrôle
//! biométrique, et ses requêtes sont celles d'un écran. Mêler les deux dans un
//! seul handle aurait donné un objet dont la moitié des fonctions rendent
//! toujours `ASL_ARGUMENT`.
//!
//! # LA SIGNATURE SE FAIT PAR RAPPEL
//!
//! Cette bibliothèque **ne détient jamais la clé d'un appareil**, et ne le
//! pourrait pas : la Secure Enclave et le Keystore ne rendent pas de clé
//! privée. L'application pose donc un [`AslSignataire`] — une fonction à elle,
//! et un contexte opaque — que la bibliothèque appelle avec les octets à
//! signer, au moment exact où le protocole les exige. C'est là que le porteur
//! pose son doigt, et pas avant.
//!
//! **Le rappel est fait sur le fil de l'appelant**, à l'intérieur de l'appel
//! qui l'a provoqué. Une application qui appelle depuis son fil d'interface
//! bloquerait donc ce fil pendant l'invite biométrique — elle appelle depuis un
//! fil de fond, comme pour toute entrée-sortie.
//!
//! # UN VERBE GÉNÉRIQUE POUR LES RESSOURCES
//!
//! Les vingt verbes de `protocole.md` §2 portent des corps JSON qu'un
//! téléphone lit nativement. La bibliothèque ne les interprète pas
//! ([`asl_appareil_requete`] rend les octets et le code d'état) : elle apporte
//! ce que l'application ne peut pas faire seule — QUIC, la liaison de canal, la
//! preuve sur la connexion, la connexion tenue.

use core::ffi::{c_char, c_void};

use asl_client::appareil::{
    self as regles, PREUVE_AUTHENTIFICATION_OCTETS, Plateforme, cle_publique,
};
use asl_client_tokio::{Annuaire, Reglages, Tenue};
use asl_id::{Genre, Identifiant};

use crate::{
    ASL_ARGUMENT, ASL_CONFIGURATION, ASL_IDENTIFIANT_OCTETS, ASL_INJOIGNABLE, ASL_INTERNE,
    ASL_NON_CONNECTE, ASL_OK, ASL_PAS_D_IDENTITE, ASL_SIGNATURE_REFUSEE, ASL_TAMPON_TROP_PETIT,
    PLAFOND_MS, chaine, ecrire_chaine, ouvrir, protege, traduire,
};

/// Combien d'octets fait une clé publique d'appareil : P-256, SEC1 compressé.
pub const ASL_CLE_APPAREIL_OCTETS: usize = asl_cle::CLE_APPAREIL_OCTETS;
/// Combien d'octets fait une signature d'appareil : `r ‖ s`.
pub const ASL_SIGNATURE_OCTETS: usize = asl_cle::SIGNATURE_APPAREIL_OCTETS;
/// Combien d'octets font un défi, et une liaison de canal.
pub const ASL_DEFI_OCTETS: usize = asl_cle::DEFI_OCTETS;
/// Le plus long message qu'un signataire recevra.
pub const ASL_MESSAGE_MAX: usize = asl_cle::MESSAGE_POSSESSION_APPAREIL_OCTETS;
/// L'attestation la plus longue que l'annuaire admette.
pub const ASL_ATTESTATION_MAX: usize = asl_api::corps::ATTESTATION_MAX;

/// Aucune attestation.
pub const ASL_PLATEFORME_AUCUNE: u8 = 0;
/// App Attest.
pub const ASL_PLATEFORME_APPLE: u8 = 1;
/// Play Integrity.
pub const ASL_PLATEFORME_GOOGLE: u8 = 2;

/// La cadence de maintien qu'on pose sur une connexion d'appareil, en secondes.
///
/// **DIX SECONDES, MESURÉES** (`modele.md` §4.1) : sur un lien résidentiel, le
/// chemin meurt à trente secondes de silence, en IPv4 comme en IPv6. Un
/// téléphone derrière la box de son propriétaire est sur ce lien-là.
const MAINTIEN_S: u16 = 10;

/// La fonction que l'application pose pour signer.
///
/// Elle reçoit `taille` octets à signer, et doit écrire soixante-quatre octets
/// `r ‖ s` dans `signature`, puis rendre zéro. **Toute autre valeur veut dire
/// que le porteur n'a pas signé** — annulé, non reconnu, clé absente —, et
/// l'appel en cours rend `ASL_SIGNATURE_REFUSEE`.
pub type AslSignataire = Option<
    unsafe extern "C" fn(
        contexte: *mut c_void,
        message: *const u8,
        taille: usize,
        signature: *mut u8,
    ) -> i32,
>;

/// Ce que l'application a posé pour signer, et le contexte qu'elle veut revoir.
struct Signataire {
    cle: [u8; ASL_CLE_APPAREIL_OCTETS],
    rappel: unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u8) -> i32,
    contexte: *mut c_void,
}

impl Signataire {
    /// Fait signer ces octets par l'application.
    fn signer(&self, message: &[u8]) -> Result<[u8; ASL_SIGNATURE_OCTETS], i32> {
        let mut signature = [0_u8; ASL_SIGNATURE_OCTETS];
        // SAFETY : le rappel est celui que l'application a posé, avec son
        // contexte ; `message` et `signature` sont valides pour la durée de
        // l'appel, et c'est tout ce que le contrat lui demande.
        let verdict = unsafe {
            (self.rappel)(
                self.contexte,
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
            )
        };
        if verdict == 0 {
            Ok(signature)
        } else {
            Err(ASL_SIGNATURE_REFUSEE)
        }
    }
}

/// Un appareil, vu de C : un pointeur opaque et rien d'autre.
///
/// **UN SEUL FIL À LA FOIS.** Les appels ne se chevauchent pas : le rappel de
/// signature est fait sur le fil de l'appel, et une requête attend la réponse
/// de la précédente. L'application sérialise — une file, un acteur, un fil
/// dédié —, et c'est elle qui sait comment.
pub struct AslAppareil {
    moteur: tokio::runtime::Runtime,
    annuaires: Vec<Annuaire>,
    racines: Vec<u8>,
    signataire: Option<Signataire>,
    /// L'identifiant de cet appareil, une fois enrôlé — ce qu'il signe à chaque
    /// connexion. Absent tant que le compte n'est pas créé.
    identite: Option<Identifiant>,
    /// La connexion tenue, si l'on est connecté.
    tenue: Option<Tenue>,
    /// Le dernier défi tiré sur la connexion, s'il n'a pas encore servi.
    defi: Option<asl_cle::Defi>,
}

impl AslAppareil {
    fn reglages(&self) -> Result<Reglages, i32> {
        Reglages::nouveaux(self.annuaires.clone(), self.racines.clone(), PLAFOND_MS)
            .map_err(|_| ASL_CONFIGURATION)
    }

    fn signataire(&self) -> Result<&Signataire, i32> {
        self.signataire.as_ref().ok_or(ASL_PAS_D_IDENTITE)
    }

    fn tenue(&self) -> Result<&Tenue, i32> {
        match &self.tenue {
            Some(tenue) if tenue.vivante() => Ok(tenue),
            _ => Err(ASL_NON_CONNECTE),
        }
    }
}

// ── LA CONSTRUCTION ─────────────────────────────────────────────────────────

/// Crée un appareil. **Il n'ouvre aucune connexion.**
///
/// # Safety
///
/// `sortie` vise un pointeur inscriptible. L'appareil rendu se libère par
/// [`asl_appareil_libere`], et par rien d'autre.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_appareil_neuf(sortie: *mut *mut AslAppareil) -> i32 {
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
        let appareil = Box::new(AslAppareil {
            moteur,
            annuaires: Vec::new(),
            racines: Vec::new(),
            signataire: None,
            identite: None,
            tenue: None,
            defi: None,
        });
        // SAFETY : `sortie` est non nul, et l'appelant garantit qu'il vise un
        // pointeur qu'il possède.
        unsafe { sortie.write(Box::into_raw(appareil)) };
        ASL_OK
    })
}

/// Ajoute un annuaire — mêmes règles que `asl_client_annuaire` : une adresse
/// littérale, un nom exigé du certificat, IPv6 d'abord.
///
/// # Safety
///
/// `appareil` vient de [`asl_appareil_neuf`]. `adresse` et `nom` sont des
/// chaînes C valides.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_appareil_annuaire(
    appareil: *mut AslAppareil,
    adresse: *const c_char,
    nom: *const c_char,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(appareil) = (unsafe { appareil.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        // SAFETY : contrat de la fonction.
        let (Some(adresse), Some(nom)) = (unsafe { chaine(adresse) }, unsafe { chaine(nom) })
        else {
            return ASL_ARGUMENT;
        };
        let Ok(adresse) = adresse.parse() else {
            return ASL_ARGUMENT;
        };
        if nom.is_empty() {
            return ASL_ARGUMENT;
        }
        appareil.annuaires.push(Annuaire {
            adresse,
            nom: nom.to_owned(),
        });
        ASL_OK
    })
}

/// Pose les certificats d'autorité, en PEM — mêmes règles que
/// `asl_client_racines` : aucun repli sur le magasin du système.
///
/// # Safety
///
/// `appareil` vient de [`asl_appareil_neuf`] ; `pem` vise `taille` octets
/// lisibles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_appareil_racines(
    appareil: *mut AslAppareil,
    pem: *const u8,
    taille: usize,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(appareil) = (unsafe { appareil.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        if pem.is_null() || taille == 0 {
            return ASL_ARGUMENT;
        }
        // SAFETY : contrat de la fonction.
        let octets = unsafe { core::slice::from_raw_parts(pem, taille) };
        appareil.racines.extend_from_slice(octets);
        ASL_OK
    })
}

/// Pose la clé publique de cet appareil, et la fonction qui signe avec.
///
/// `cle` fait trente-trois octets, P-256 SEC1 compressé, et **elle est
/// vérifiée** : des octets qui ne forment pas un point de la courbe sont
/// refusés ici, et non le jour où une preuve ne vérifie pas. `contexte` est
/// rendu tel quel au rappel, et n'est jamais lu.
///
/// # Safety
///
/// `appareil` vient de [`asl_appareil_neuf`] ; `cle` vise trente-trois octets
/// lisibles ; `signataire` reste valide tant que l'appareil vit.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_appareil_cle(
    appareil: *mut AslAppareil,
    cle: *const u8,
    signataire: AslSignataire,
    contexte: *mut c_void,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(appareil) = (unsafe { appareil.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        let (false, Some(rappel)) = (cle.is_null(), signataire) else {
            return ASL_ARGUMENT;
        };
        let mut octets = [0_u8; ASL_CLE_APPAREIL_OCTETS];
        // SAFETY : contrat de la fonction.
        unsafe { core::ptr::copy_nonoverlapping(cle, octets.as_mut_ptr(), octets.len()) };
        if cle_publique(&octets).is_err() {
            return ASL_ARGUMENT;
        }
        appareil.signataire = Some(Signataire {
            cle: octets,
            rappel,
            contexte,
        });
        ASL_OK
    })
}

/// Pose l'identifiant de cet appareil, `a-…`, quand il est déjà enrôlé — ce
/// que [`asl_appareil_creer_compte`] a rendu la première fois.
///
/// # Safety
///
/// `appareil` vient de [`asl_appareil_neuf`] ; `identifiant` est une chaîne C
/// valide.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_appareil_identite(
    appareil: *mut AslAppareil,
    identifiant: *const c_char,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(appareil) = (unsafe { appareil.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        // SAFETY : contrat de la fonction.
        let Some(texte) = (unsafe { chaine(identifiant) }) else {
            return ASL_ARGUMENT;
        };
        let Ok(identite) = Identifiant::analyser_genre(Genre::Appareil, texte) else {
            return ASL_ARGUMENT;
        };
        appareil.identite = Some(identite);
        ASL_OK
    })
}

/// Libère l'appareil, et ferme sa connexion proprement. Un pointeur nul ne
/// fait rien.
///
/// # Safety
///
/// `appareil` vient de [`asl_appareil_neuf`] et n'est plus employé après.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_appareil_libere(appareil: *mut AslAppareil) {
    if appareil.is_null() {
        return;
    }
    let _ = protege(|| {
        // SAFETY : contrat de la fonction.
        let appareil = unsafe { Box::from_raw(appareil) };
        if let Some(tenue) = appareil.tenue {
            appareil.moteur.block_on(tenue.fermer());
        }
        ASL_OK
    });
}

// ── LA CONNEXION ────────────────────────────────────────────────────────────

/// Ouvre la connexion, et prouve la clé de cet appareil s'il est enrôlé.
///
/// **C'EST ICI QUE LE PORTEUR EST SOLLICITÉ**, une fois : si une identité est
/// posée, le signataire est appelé sur le message d'authentification, et la
/// connexion en hérite pour toute sa durée. Sans identité, la connexion s'ouvre
/// nue — c'est l'état d'où l'on crée un compte.
///
/// Une connexion déjà ouverte est fermée d'abord. Rend `ASL_INJOIGNABLE` si
/// aucun annuaire ne répond, `ASL_REFUSE` si la preuve ne vérifie pas.
///
/// # Safety
///
/// `appareil` vient de [`asl_appareil_neuf`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_appareil_connecter(appareil: *mut AslAppareil) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(appareil) = (unsafe { appareil.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        let reglages = match appareil.reglages() {
            Ok(reglages) => reglages,
            Err(quoi) => return quoi,
        };
        if let Some(ancienne) = appareil.tenue.take() {
            appareil.moteur.block_on(ancienne.fermer());
        }
        appareil.defi = None;

        let identite = appareil.identite;
        let signataire = appareil.signataire.as_ref();
        let issue = appareil.moteur.block_on(async {
            let mut connexion = ouvrir(&reglages).await?;
            if let Some(identite) = identite {
                let signataire = signataire.ok_or(ASL_PAS_D_IDENTITE)?;
                let defi = connexion.defi().await.map_err(traduire)?;
                let message =
                    regles::message_d_authentification(identite, &defi, &connexion.liaison())
                        .map_err(|_| ASL_INTERNE)?;
                let signature = signataire.signer(&message)?;
                connexion
                    .prouver_appareil(identite, &signature)
                    .await
                    .map_err(traduire)?;
            }
            connexion.maintenir(MAINTIEN_S);
            Ok(Tenue::tenir(connexion))
        });
        match issue {
            Ok(tenue) => {
                appareil.tenue = Some(tenue);
                ASL_OK
            }
            Err(quoi) => quoi,
        }
    })
}

/// Ferme la connexion, proprement. Sans connexion, ne fait rien.
///
/// # Safety
///
/// `appareil` vient de [`asl_appareil_neuf`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_appareil_deconnecter(appareil: *mut AslAppareil) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(appareil) = (unsafe { appareil.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        if let Some(tenue) = appareil.tenue.take() {
            appareil.moteur.block_on(tenue.fermer());
        }
        appareil.defi = None;
        ASL_OK
    })
}

/// La liaison de canal de la connexion en cours — trente-deux octets.
///
/// Elle entre dans ce dont App Attest hache le condensat et dans le nonce Play
/// Integrity (`asl_appareil_message_pour_attestation`), et ne sert à rien
/// d'autre à l'application.
///
/// # Safety
///
/// `appareil` vient de [`asl_appareil_neuf`] ; `liaison` vise trente-deux
/// octets inscriptibles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_appareil_liaison(appareil: *mut AslAppareil, liaison: *mut u8) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(appareil) = (unsafe { appareil.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        if liaison.is_null() {
            return ASL_ARGUMENT;
        }
        let tenue = match appareil.tenue() {
            Ok(tenue) => tenue,
            Err(quoi) => return quoi,
        };
        let octets = tenue.liaison();
        // SAFETY : `liaison` est non nul, et l'appelant garantit trente-deux
        // octets inscriptibles.
        unsafe {
            core::ptr::copy_nonoverlapping(octets.octets().as_ptr(), liaison, ASL_DEFI_OCTETS);
        }
        ASL_OK
    })
}

/// Tire un défi sur la connexion en cours, et le rend — trente-deux octets.
///
/// **Il ne sert qu'une fois, et c'est le prochain appel qui le dépense** :
/// [`asl_appareil_creer_compte`]. Le tirer soi-même n'est utile que pour
/// composer une attestation par-dessus, avant de créer le compte ; sans
/// attestation, `asl_appareil_creer_compte` le tire lui-même.
///
/// # Safety
///
/// `appareil` vient de [`asl_appareil_neuf`] ; `defi` vise trente-deux octets
/// inscriptibles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_appareil_defi(appareil: *mut AslAppareil, defi: *mut u8) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(appareil) = (unsafe { appareil.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        if defi.is_null() {
            return ASL_ARGUMENT;
        }
        let tenue = match appareil.tenue() {
            Ok(tenue) => tenue.clone(),
            Err(quoi) => return quoi,
        };
        let issue = appareil.moteur.block_on(async {
            let reponse = tenue
                .requete("GET", "/v1/defi", &[])
                .await
                .map_err(traduire)?;
            reponse.exige(200).map_err(traduire)?;
            let mut octets = [0_u8; ASL_DEFI_OCTETS];
            if reponse.corps.len() != octets.len() {
                return Err(ASL_INTERNE);
            }
            octets.copy_from_slice(&reponse.corps);
            Ok(asl_cle::Defi::depuis_octets(octets))
        });
        match issue {
            Ok(tire) => {
                // SAFETY : `defi` est non nul, et l'appelant garantit trente-deux
                // octets inscriptibles.
                unsafe {
                    core::ptr::copy_nonoverlapping(tire.octets().as_ptr(), defi, ASL_DEFI_OCTETS);
                }
                appareil.defi = Some(tire);
                ASL_OK
            }
            Err(quoi) => quoi,
        }
    })
}

/// Compose ce dont une attestation doit couvrir le condensat : `domaine ‖
/// clé ‖ défi ‖ liaison`, avec le défi tiré par [`asl_appareil_defi`] et la
/// liaison de la connexion en cours.
///
/// Le tampon se dimensionne en deux temps, comme pour `asl_ou`.
///
/// # Safety
///
/// `appareil` vient de [`asl_appareil_neuf`] ; `sortie`, s'il n'est pas nul,
/// vise `combien` octets inscriptibles ; `ecrit` vise un `size_t`
/// inscriptible.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_appareil_message_pour_attestation(
    appareil: *mut AslAppareil,
    sortie: *mut u8,
    combien: usize,
    ecrit: *mut usize,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(appareil) = (unsafe { appareil.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        if ecrit.is_null() {
            return ASL_ARGUMENT;
        }
        let (tenue, signataire) = match (appareil.tenue(), appareil.signataire()) {
            (Ok(tenue), Ok(signataire)) => (tenue, signataire),
            (Err(quoi), _) | (_, Err(quoi)) => return quoi,
        };
        let Some(defi) = appareil.defi else {
            return ASL_ARGUMENT;
        };
        let Ok(message) =
            regles::message_pour_attestation(&signataire.cle, &defi, &tenue.liaison())
        else {
            return ASL_INTERNE;
        };
        // SAFETY : `ecrit` est non nul.
        unsafe { ecrit.write(message.len()) };
        if sortie.is_null() || combien < message.len() {
            return ASL_TAMPON_TROP_PETIT;
        }
        // SAFETY : l'appelant garantit `combien` octets inscriptibles, et l'on
        // vient de vérifier qu'il y en a assez.
        unsafe { core::ptr::copy_nonoverlapping(message.as_ptr(), sortie, message.len()) };
        ASL_OK
    })
}

/// Crée le compte, et enrôle cet appareil.
///
/// **LE PORTEUR EST SOLLICITÉ ICI** : le signataire est appelé sur la preuve de
/// possession de la clé. Le défi est celui d'[`asl_appareil_defi`] s'il en
/// reste un — c'est ce qui lie une attestation composée avant — et un défi
/// neuf sinon. `attestation` est vide pour `ASL_PLATEFORME_AUCUNE`, et exigée
/// pour les deux autres.
///
/// Rend le compte `u-…` et l'appareil `a-…` en texte, NUL compris ; **l'identité
/// est installée au passage**, et la connexion est désormais celle de cet
/// appareil.
///
/// # Safety
///
/// `appareil` vient de [`asl_appareil_neuf`] ; `attestation` vise `taille`
/// octets lisibles, ou est nul avec `taille` à zéro ; `compte_sortie` et
/// `appareil_sortie` visent chacun `ASL_IDENTIFIANT_OCTETS` octets
/// inscriptibles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_appareil_creer_compte(
    appareil: *mut AslAppareil,
    plateforme: u8,
    attestation: *const u8,
    taille: usize,
    compte_sortie: *mut c_char,
    appareil_sortie: *mut c_char,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(appareil) = (unsafe { appareil.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        let Some(plateforme) = Plateforme::depuis(plateforme) else {
            return ASL_ARGUMENT;
        };
        if compte_sortie.is_null() || appareil_sortie.is_null() {
            return ASL_ARGUMENT;
        }
        if attestation.is_null() != (taille == 0) || taille > ASL_ATTESTATION_MAX {
            return ASL_ARGUMENT;
        }
        let attestation: &[u8] = if taille == 0 {
            &[]
        } else {
            // SAFETY : contrat de la fonction.
            unsafe { core::slice::from_raw_parts(attestation, taille) }
        };
        let defi_tire = appareil.defi.take();
        let (tenue, signataire) = match (appareil.tenue(), appareil.signataire()) {
            (Ok(tenue), Ok(signataire)) => (tenue.clone(), signataire),
            (Err(quoi), _) | (_, Err(quoi)) => return quoi,
        };

        let issue = appareil.moteur.block_on(async {
            let defi = match defi_tire {
                Some(defi) => defi,
                None => {
                    let reponse = tenue
                        .requete("GET", "/v1/defi", &[])
                        .await
                        .map_err(traduire)?;
                    reponse.exige(200).map_err(traduire)?;
                    let mut octets = [0_u8; ASL_DEFI_OCTETS];
                    if reponse.corps.len() != octets.len() {
                        return Err(ASL_INTERNE);
                    }
                    octets.copy_from_slice(&reponse.corps);
                    asl_cle::Defi::depuis_octets(octets)
                }
            };
            let message = regles::message_de_possession(&signataire.cle, &defi, &tenue.liaison())
                .map_err(|_| ASL_INTERNE)?;
            let preuve = signataire.signer(&message)?;
            let mut corps = vec![0_u8; asl_api::corps::COMPTE_CORPS_MAX];
            let combien = regles::corps_de_compte(
                plateforme,
                &signataire.cle,
                &preuve,
                attestation,
                &mut corps,
            )
            .map_err(|_| ASL_ARGUMENT)?;
            corps.truncate(combien);
            let reponse = tenue
                .requete("POST", "/v1/comptes", &corps)
                .await
                .map_err(traduire)?;
            reponse.exige(201).map_err(traduire)?;
            Ok(asl_client_tokio::CompteCree {
                compte: reponse.identifiant("compte").map_err(|_| ASL_INTERNE)?,
                appareil: reponse.identifiant("appareil").map_err(|_| ASL_INTERNE)?,
            })
        });
        match issue {
            Ok(cree) => {
                appareil.identite = Some(cree.appareil);
                // SAFETY : l'appelant garantit `ASL_IDENTIFIANT_OCTETS` octets
                // inscriptibles derrière chaque pointeur, et un identifiant en
                // texte en fait exactement un de moins que NUL.
                unsafe {
                    ecrire_chaine(cree.compte.texte().as_str(), compte_sortie);
                    ecrire_chaine(cree.appareil.texte().as_str(), appareil_sortie);
                }
                ASL_OK
            }
            Err(quoi) => quoi,
        }
    })
}

/// Une requête de la voie mobile sur la connexion tenue : méthode, chemin,
/// corps JSON (ou vide), et en retour le code d'état et le corps.
///
/// **LE CODE D'ÉTAT EST RENDU, JAMAIS JUGÉ.** `ASL_OK` veut dire que
/// l'annuaire a répondu — `404`, `409` ou `204` compris — et c'est
/// l'application qui sait quoi en dire. `ASL_INJOIGNABLE` veut dire que la
/// connexion est tombée : il faut la rouvrir par [`asl_appareil_connecter`].
///
/// Le tampon se dimensionne en deux temps, comme pour `asl_ou` : avec `sortie`
/// nul, ou `combien` trop petit, `ecrit` reçoit la taille du corps et la
/// fonction rend `ASL_TAMPON_TROP_PETIT` — **et la requête a été faite** ;
/// l'appelant la refait avec un tampon assez grand, ou passe d'abord un tampon
/// de la taille du plus long corps qu'il attend.
///
/// # Safety
///
/// `appareil` vient de [`asl_appareil_neuf`] ; `methode` et `chemin` sont des
/// chaînes C valides ; `corps` vise `taille` octets lisibles, ou est nul avec
/// `taille` à zéro ; `sortie`, s'il n'est pas nul, vise `combien` octets
/// inscriptibles ; `ecrit` et `statut` visent respectivement un `size_t` et
/// un `uint16_t` inscriptibles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_appareil_requete(
    appareil: *mut AslAppareil,
    methode: *const c_char,
    chemin: *const c_char,
    corps: *const u8,
    taille: usize,
    sortie: *mut u8,
    combien: usize,
    ecrit: *mut usize,
    statut: *mut u16,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(appareil) = (unsafe { appareil.as_mut() }) else {
            return ASL_ARGUMENT;
        };
        // SAFETY : contrat de la fonction.
        let (Some(methode), Some(chemin)) = (unsafe { chaine(methode) }, unsafe { chaine(chemin) })
        else {
            return ASL_ARGUMENT;
        };
        if ecrit.is_null() || statut.is_null() || corps.is_null() != (taille == 0) {
            return ASL_ARGUMENT;
        }
        if !matches!(methode, "GET" | "POST" | "PUT" | "PATCH" | "DELETE")
            || !chemin.starts_with("/v1/")
        {
            return ASL_ARGUMENT;
        }
        let corps: &[u8] = if taille == 0 {
            &[]
        } else {
            // SAFETY : contrat de la fonction.
            unsafe { core::slice::from_raw_parts(corps, taille) }
        };
        let tenue = match appareil.tenue() {
            Ok(tenue) => tenue.clone(),
            Err(quoi) => return quoi,
        };
        let issue = appareil
            .moteur
            .block_on(tenue.requete(methode, chemin, corps))
            .map_err(|quoi| match quoi {
                // Une tenue qui ne répond plus est une connexion tombée.
                asl_client_tokio::Faute::Delai => ASL_INJOIGNABLE,
                autre => traduire(autre),
            });
        let reponse = match issue {
            Ok(reponse) => reponse,
            Err(quoi) => return quoi,
        };
        // SAFETY : les deux pointeurs sont non nuls.
        unsafe {
            statut.write(reponse.statut);
            ecrit.write(reponse.corps.len());
        }
        if sortie.is_null() || combien < reponse.corps.len() {
            return if reponse.corps.is_empty() {
                ASL_OK
            } else {
                ASL_TAMPON_TROP_PETIT
            };
        }
        // SAFETY : l'appelant garantit `combien` octets inscriptibles, et l'on
        // vient de vérifier qu'il y en a assez.
        unsafe {
            core::ptr::copy_nonoverlapping(reponse.corps.as_ptr(), sortie, reponse.corps.len());
        }
        ASL_OK
    })
}

/// L'identifiant de cet appareil, s'il est enrôlé — `a-…`, NUL compris.
///
/// # Safety
///
/// `appareil` vient de [`asl_appareil_neuf`] ; `sortie` vise
/// `ASL_IDENTIFIANT_OCTETS` octets inscriptibles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asl_appareil_identifiant(
    appareil: *const AslAppareil,
    sortie: *mut c_char,
) -> i32 {
    protege(|| {
        // SAFETY : contrat de la fonction.
        let Some(appareil) = (unsafe { appareil.as_ref() }) else {
            return ASL_ARGUMENT;
        };
        if sortie.is_null() {
            return ASL_ARGUMENT;
        }
        let Some(identite) = appareil.identite else {
            return ASL_PAS_D_IDENTITE;
        };
        // SAFETY : l'appelant garantit `ASL_IDENTIFIANT_OCTETS` octets.
        unsafe { ecrire_chaine(identite.texte().as_str(), sortie) };
        ASL_OK
    })
}

const _: () = assert!(ASL_IDENTIFIANT_OCTETS == asl_id::LONGUEUR + 1);
const _: () = assert!(PREUVE_AUTHENTIFICATION_OCTETS == 81);
