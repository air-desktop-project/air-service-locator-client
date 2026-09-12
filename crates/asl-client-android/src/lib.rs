//! La voie mobile, vue d'Android : des symboles JNI exportés depuis Rust.
//!
//! # POURQUOI JNI, ET POURQUOI CE N'EST PAS UNE ENTORSE À C4
//!
//! La liaison Kotlin de ce dépôt passe par `java.lang.foreign`, qui n'existe
//! pas sur Android. **JNI est une convention d'appel, pas un langage** : un
//! symbole `Java_<paquet>_<classe>_<methode>` exporté avec la bonne signature
//! suffit, et Rust sait l'exporter. Aucun C n'est compilé ; la glu vit ici, à
//! côté de ce qu'elle expose, et `check-sans-c` continue de le vérifier.
//!
//! # CE FICHIER NE DÉCIDE RIEN
//!
//! Il traduit : un `jlong` en handle, un `byte[]` en tranche, un `String` en
//! chaîne C, et rappelle [`asl_client_ffi::appareil`] pour tout le reste. Les
//! règles — quoi signer, quel corps, quelle connexion — sont là-bas, et le
//! côté iOS appelle exactement les mêmes.
//!
//! # LA SIGNATURE, PAR RAPPEL, JUSQU'À KOTLIN
//!
//! `cle` reçoit un objet Kotlin qui sait signer — `fun signer(message:
//! ByteArray): ByteArray?` — et le garde par référence globale. Quand la
//! bibliothèque a besoin d'une signature, elle rattache le fil courant à la
//! machine virtuelle et appelle cette méthode : **c'est là que le porteur pose
//! son doigt**, sur le fil qui a appelé `connecter` ou `creerCompte`. Un `null`
//! rendu veut dire qu'il ne l'a pas fait.

use core::ffi::{c_char, c_void};
use std::ffi::CString;

use asl_client_ffi::appareil::{
    ASL_CLE_APPAREIL_OCTETS, ASL_DEFI_OCTETS, ASL_MESSAGE_MAX, ASL_SIGNATURE_OCTETS, AslAppareil,
    asl_appareil_annuaire, asl_appareil_cle, asl_appareil_connecter, asl_appareil_creer_compte,
    asl_appareil_deconnecter, asl_appareil_defi, asl_appareil_identifiant, asl_appareil_identite,
    asl_appareil_liaison, asl_appareil_libere, asl_appareil_message_pour_attestation,
    asl_appareil_neuf, asl_appareil_racines, asl_appareil_requete,
};
use asl_client_ffi::{ASL_ARGUMENT, ASL_IDENTIFIANT_OCTETS, ASL_INTERNE, ASL_OK, asl_faute_texte};
use jni::JNIEnv;
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString};
use jni::sys::{jbyteArray, jint, jlong, jobjectArray, jstring};

/// Le plus long corps qu'une requête rend : soixante-quatre kibioctets,
/// au-delà de tout ce que l'annuaire compose (`asl_proto::cadrage::MESSAGE_MAX`
/// borne ses listes bien en deçà).
const CORPS_MAX: usize = 64 * 1024;

/// Ce que le rappel de signature garde : la machine virtuelle, et l'objet
/// Kotlin qui signe.
struct Signataire {
    vm: jni::JavaVM,
    objet: GlobalRef,
}

/// Le handle, tel que Kotlin le tient : un `Long`, et rien d'autre.
struct Handle {
    appareil: *mut AslAppareil,
    /// Gardé ici pour vivre aussi longtemps que le handle — l'ABI C ne
    /// possède pas son contexte.
    signataire: Option<Box<Signataire>>,
    /// Le dernier code rendu par un verbe qui rend autre chose qu'un code.
    dernier: i32,
}

/// Le pointeur que ce `Long` porte, ou rien s'il ne peut pas en être un.
fn pointeur(brut: jlong) -> *mut Handle {
    // Un `Long` à zéro — ou négatif, ce qu'aucune adresse n'est — est un handle
    // jamais créé, ou déjà libéré : on ne déréférence pas.
    usize::try_from(brut).map_or(core::ptr::null_mut(), |adresse| adresse as *mut Handle)
}

fn handle<'a>(brut: jlong) -> Option<&'a mut Handle> {
    // SAFETY : le seul `Long` non nul que Kotlin détient est celui que `neuf`
    // a rendu, et il n'est plus employé après `libere`.
    unsafe { pointeur(brut).as_mut() }
}

fn lire_chaine(env: &mut JNIEnv, texte: &JString) -> Option<CString> {
    let lu: String = env.get_string(texte).ok()?.into();
    CString::new(lu).ok()
}

fn lire_octets(env: &JNIEnv, tableau: &JByteArray) -> Option<Vec<u8>> {
    env.convert_byte_array(tableau).ok()
}

fn rendre_octets<'a>(env: &JNIEnv<'a>, octets: &[u8]) -> jbyteArray {
    env.byte_array_from_slice(octets)
        .map(|t| t.into_raw())
        .unwrap_or(core::ptr::null_mut())
}

fn rendre_chaine<'a>(env: &JNIEnv<'a>, texte: &str) -> jstring {
    env.new_string(texte)
        .map(|t| t.into_raw())
        .unwrap_or(core::ptr::null_mut())
}

/// Le rappel que l'ABI C appelle : il remonte jusqu'à `signer` de l'objet
/// Kotlin, sur le fil courant.
unsafe extern "C" fn rappel_de_signature(
    contexte: *mut c_void,
    message: *const u8,
    taille: usize,
    signature: *mut u8,
) -> i32 {
    // SAFETY : `contexte` est le `Signataire` boxé que `cle` a posé, et qui
    // vit aussi longtemps que le handle.
    let Some(signataire) = (unsafe { contexte.cast::<Signataire>().as_ref() }) else {
        return ASL_INTERNE;
    };
    if message.is_null() || signature.is_null() || taille > ASL_MESSAGE_MAX {
        return ASL_ARGUMENT;
    }
    // SAFETY : contrat du rappel — `taille` octets lisibles.
    let octets = unsafe { core::slice::from_raw_parts(message, taille) };
    // Le fil qui appelle est celui de Kotlin : le rattacher rend l'`env`
    // existant. Un fil qui n'aurait jamais vu la machine virtuelle serait
    // rattaché, et détaché au retour.
    let Ok(mut env) = signataire.vm.attach_current_thread() else {
        return ASL_INTERNE;
    };
    let Ok(tableau) = env.byte_array_from_slice(octets) else {
        return ASL_INTERNE;
    };
    let appel = env.call_method(
        signataire.objet.as_obj(),
        "signer",
        "([B)[B",
        &[(&tableau).into()],
    );
    let Ok(rendu) = appel.and_then(|v| v.l()) else {
        // Une exception Kotlin en cours rendrait tout appel JNI suivant
        // indéfini : on l'efface, et l'on dit non.
        let _ = env.exception_clear();
        return ASL_INTERNE;
    };
    if rendu.is_null() {
        // Le porteur n'a pas signé. Pas une panne.
        return 1;
    }
    let tableau: JByteArray = rendu.into();
    let Ok(lu) = env.convert_byte_array(&tableau) else {
        return ASL_INTERNE;
    };
    if lu.len() != ASL_SIGNATURE_OCTETS {
        return ASL_ARGUMENT;
    }
    // SAFETY : contrat du rappel — soixante-quatre octets inscriptibles.
    unsafe { core::ptr::copy_nonoverlapping(lu.as_ptr(), signature, ASL_SIGNATURE_OCTETS) };
    0
}

// ── `org.airdesktop.servicelocator.reseau.Natif` ────────────────────────────
//
// Chaque symbole est le nom JNI d'une méthode `external` de cet objet Kotlin.
// **Le nom du paquet est dans le symbole** : déplacer `Natif` casse la liaison,
// et c'est voulu — un objet natif n'a qu'un seul propriétaire.

/// `external fun neuf(): Long`
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_neuf(
    _env: JNIEnv,
    _classe: JClass,
) -> jlong {
    let mut appareil: *mut AslAppareil = core::ptr::null_mut();
    // SAFETY : `appareil` vise un pointeur que nous possédons.
    if unsafe { asl_appareil_neuf(&raw mut appareil) } != ASL_OK {
        return 0;
    }
    let handle = Box::new(Handle {
        appareil,
        signataire: None,
        dernier: ASL_OK,
    });
    // Un pointeur tient dans un `jlong` sur toutes les cibles d'Android.
    jlong::try_from(Box::into_raw(handle) as usize).unwrap_or(0)
}

/// `external fun libere(h: Long)`
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_libere(
    _env: JNIEnv,
    _classe: JClass,
    brut: jlong,
) {
    let Some(handle) = handle(brut) else { return };
    // SAFETY : `appareil` vient de `asl_appareil_neuf`, et n'est plus employé.
    unsafe { asl_appareil_libere(handle.appareil) };
    handle.appareil = core::ptr::null_mut();
    // SAFETY : le handle a été créé par `Box::into_raw` dans `neuf`, et Kotlin
    // ne l'emploie plus après `libere`.
    drop(unsafe { Box::from_raw(pointeur(brut)) });
}

/// `external fun annuaire(h: Long, adresse: String, nom: String): Int`
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_annuaire(
    mut env: JNIEnv,
    _classe: JClass,
    brut: jlong,
    adresse: JString,
    nom: JString,
) -> jint {
    let Some(handle) = handle(brut) else {
        return ASL_ARGUMENT;
    };
    let (Some(adresse), Some(nom)) = (lire_chaine(&mut env, &adresse), lire_chaine(&mut env, &nom))
    else {
        return ASL_ARGUMENT;
    };
    // SAFETY : deux chaînes C valides, un handle vivant.
    unsafe { asl_appareil_annuaire(handle.appareil, adresse.as_ptr(), nom.as_ptr()) }
}

/// `external fun racines(h: Long, pem: ByteArray): Int`
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_racines(
    env: JNIEnv,
    _classe: JClass,
    brut: jlong,
    pem: JByteArray,
) -> jint {
    let Some(handle) = handle(brut) else {
        return ASL_ARGUMENT;
    };
    let Some(pem) = lire_octets(&env, &pem) else {
        return ASL_ARGUMENT;
    };
    // SAFETY : `pem` vise `pem.len()` octets lisibles.
    unsafe { asl_appareil_racines(handle.appareil, pem.as_ptr(), pem.len()) }
}

/// `external fun cle(h: Long, cle: ByteArray, signataire: Signataire): Int`
///
/// `signataire` est n'importe quel objet portant `fun signer(message:
/// ByteArray): ByteArray?`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_cle(
    env: JNIEnv,
    _classe: JClass,
    brut: jlong,
    cle: JByteArray,
    signataire: JObject,
) -> jint {
    let Some(handle) = handle(brut) else {
        return ASL_ARGUMENT;
    };
    let Some(cle) = lire_octets(&env, &cle) else {
        return ASL_ARGUMENT;
    };
    if cle.len() != ASL_CLE_APPAREIL_OCTETS || signataire.is_null() {
        return ASL_ARGUMENT;
    }
    let (Ok(vm), Ok(objet)) = (env.get_java_vm(), env.new_global_ref(signataire)) else {
        return ASL_INTERNE;
    };
    let boite = Box::new(Signataire { vm, objet });
    let contexte = core::ptr::from_ref::<Signataire>(&boite)
        .cast_mut()
        .cast::<c_void>();
    // SAFETY : `cle` vise trente-trois octets ; le rappel et son contexte
    // vivent aussi longtemps que le handle, qui garde la boîte.
    let code = unsafe {
        asl_appareil_cle(
            handle.appareil,
            cle.as_ptr(),
            Some(rappel_de_signature),
            contexte,
        )
    };
    if code == ASL_OK {
        handle.signataire = Some(boite);
    }
    code
}

/// `external fun identite(h: Long, identifiant: String): Int`
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_identite(
    mut env: JNIEnv,
    _classe: JClass,
    brut: jlong,
    identifiant: JString,
) -> jint {
    let Some(handle) = handle(brut) else {
        return ASL_ARGUMENT;
    };
    let Some(identifiant) = lire_chaine(&mut env, &identifiant) else {
        return ASL_ARGUMENT;
    };
    // SAFETY : une chaîne C valide, un handle vivant.
    unsafe { asl_appareil_identite(handle.appareil, identifiant.as_ptr()) }
}

/// `external fun connecter(h: Long): Int`
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_connecter(
    _env: JNIEnv,
    _classe: JClass,
    brut: jlong,
) -> jint {
    let Some(handle) = handle(brut) else {
        return ASL_ARGUMENT;
    };
    // SAFETY : un handle vivant.
    unsafe { asl_appareil_connecter(handle.appareil) }
}

/// `external fun deconnecter(h: Long): Int`
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_deconnecter(
    _env: JNIEnv,
    _classe: JClass,
    brut: jlong,
) -> jint {
    let Some(handle) = handle(brut) else {
        return ASL_ARGUMENT;
    };
    // SAFETY : un handle vivant.
    unsafe { asl_appareil_deconnecter(handle.appareil) }
}

/// `external fun dernierCode(h: Long): Int` — le code du dernier verbe qui a
/// rendu `null`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_dernierCode(
    _env: JNIEnv,
    _classe: JClass,
    brut: jlong,
) -> jint {
    handle(brut).map_or(ASL_ARGUMENT, |handle| handle.dernier)
}

/// `external fun liaison(h: Long): ByteArray?`
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_liaison(
    env: JNIEnv,
    _classe: JClass,
    brut: jlong,
) -> jbyteArray {
    let Some(handle) = handle(brut) else {
        return core::ptr::null_mut();
    };
    let mut octets = [0_u8; ASL_DEFI_OCTETS];
    // SAFETY : trente-deux octets inscriptibles.
    handle.dernier = unsafe { asl_appareil_liaison(handle.appareil, octets.as_mut_ptr()) };
    if handle.dernier != ASL_OK {
        return core::ptr::null_mut();
    }
    rendre_octets(&env, &octets)
}

/// `external fun defi(h: Long): ByteArray?`
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_defi(
    env: JNIEnv,
    _classe: JClass,
    brut: jlong,
) -> jbyteArray {
    let Some(handle) = handle(brut) else {
        return core::ptr::null_mut();
    };
    let mut octets = [0_u8; ASL_DEFI_OCTETS];
    // SAFETY : trente-deux octets inscriptibles.
    handle.dernier = unsafe { asl_appareil_defi(handle.appareil, octets.as_mut_ptr()) };
    if handle.dernier != ASL_OK {
        return core::ptr::null_mut();
    }
    rendre_octets(&env, &octets)
}

/// `external fun messagePourAttestation(h: Long): ByteArray?`
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_messagePourAttestation(
    env: JNIEnv,
    _classe: JClass,
    brut: jlong,
) -> jbyteArray {
    let Some(handle) = handle(brut) else {
        return core::ptr::null_mut();
    };
    let mut sortie = [0_u8; ASL_MESSAGE_MAX];
    let mut ecrit = 0_usize;
    // SAFETY : `sortie` vise `ASL_MESSAGE_MAX` octets inscriptibles, `ecrit`
    // un `usize`.
    handle.dernier = unsafe {
        asl_appareil_message_pour_attestation(
            handle.appareil,
            sortie.as_mut_ptr(),
            sortie.len(),
            &raw mut ecrit,
        )
    };
    if handle.dernier != ASL_OK {
        return core::ptr::null_mut();
    }
    rendre_octets(&env, sortie.get(..ecrit).unwrap_or_default())
}

/// `external fun creerCompte(h: Long, plateforme: Int, attestation: ByteArray?): Array<String>?`
///
/// Rend `[compte, appareil]`, ou `null` — et `dernierCode` dit pourquoi.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_creerCompte(
    mut env: JNIEnv,
    _classe: JClass,
    brut: jlong,
    plateforme: jint,
    attestation: JByteArray,
) -> jobjectArray {
    let Some(handle) = handle(brut) else {
        return core::ptr::null_mut();
    };
    let Ok(plateforme) = u8::try_from(plateforme) else {
        handle.dernier = ASL_ARGUMENT;
        return core::ptr::null_mut();
    };
    let attestation = if attestation.is_null() {
        Vec::new()
    } else {
        match lire_octets(&env, &attestation) {
            Some(octets) => octets,
            None => {
                handle.dernier = ASL_ARGUMENT;
                return core::ptr::null_mut();
            }
        }
    };
    let mut compte = [0 as c_char; ASL_IDENTIFIANT_OCTETS];
    let mut appareil = [0 as c_char; ASL_IDENTIFIANT_OCTETS];
    let pointeur = if attestation.is_empty() {
        core::ptr::null()
    } else {
        attestation.as_ptr()
    };
    // SAFETY : `attestation` vise ses octets ou est nul avec zéro ; les deux
    // tampons font `ASL_IDENTIFIANT_OCTETS`.
    handle.dernier = unsafe {
        asl_appareil_creer_compte(
            handle.appareil,
            plateforme,
            pointeur,
            attestation.len(),
            compte.as_mut_ptr(),
            appareil.as_mut_ptr(),
        )
    };
    if handle.dernier != ASL_OK {
        return core::ptr::null_mut();
    }
    let texte = |brut: &[c_char]| -> String {
        // SAFETY : `ecrire_chaine` a posé un NUL dans le tampon.
        unsafe { core::ffi::CStr::from_ptr(brut.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    let Ok(classe) = env.find_class("java/lang/String") else {
        return core::ptr::null_mut();
    };
    let Ok(tableau) = env.new_object_array(2, classe, JObject::null()) else {
        return core::ptr::null_mut();
    };
    for (place, valeur) in [texte(&compte), texte(&appareil)].iter().enumerate() {
        let Ok(chaine) = env.new_string(valeur) else {
            return core::ptr::null_mut();
        };
        let Ok(place) = i32::try_from(place) else {
            return core::ptr::null_mut();
        };
        if env
            .set_object_array_element(&tableau, place, chaine)
            .is_err()
        {
            return core::ptr::null_mut();
        }
    }
    tableau.into_raw()
}

/// `external fun requete(h: Long, methode: String, chemin: String, corps: ByteArray?): ByteArray?`
///
/// Rend `statut (2 octets, gros-boutien) ‖ corps`, ou `null` si la requête n'a
/// pas pu partir — et `dernierCode` dit pourquoi. **Un `404` est un tableau**,
/// jamais `null`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_requete(
    mut env: JNIEnv,
    _classe: JClass,
    brut: jlong,
    methode: JString,
    chemin: JString,
    corps: JByteArray,
) -> jbyteArray {
    let Some(handle) = handle(brut) else {
        return core::ptr::null_mut();
    };
    let (Some(methode), Some(chemin)) = (
        lire_chaine(&mut env, &methode),
        lire_chaine(&mut env, &chemin),
    ) else {
        handle.dernier = ASL_ARGUMENT;
        return core::ptr::null_mut();
    };
    let corps = if corps.is_null() {
        Vec::new()
    } else {
        match lire_octets(&env, &corps) {
            Some(octets) => octets,
            None => {
                handle.dernier = ASL_ARGUMENT;
                return core::ptr::null_mut();
            }
        }
    };
    let mut sortie = vec![0_u8; CORPS_MAX];
    let mut ecrit = 0_usize;
    let mut statut = 0_u16;
    let pointeur = if corps.is_empty() {
        core::ptr::null()
    } else {
        corps.as_ptr()
    };
    // SAFETY : chaînes C valides ; `corps` vise ses octets ou est nul avec
    // zéro ; `sortie` vise `CORPS_MAX` octets ; `ecrit` et `statut` sont à nous.
    handle.dernier = unsafe {
        asl_appareil_requete(
            handle.appareil,
            methode.as_ptr(),
            chemin.as_ptr(),
            pointeur,
            corps.len(),
            sortie.as_mut_ptr(),
            sortie.len(),
            &raw mut ecrit,
            &raw mut statut,
        )
    };
    if handle.dernier != ASL_OK {
        return core::ptr::null_mut();
    }
    let mut rendu = Vec::with_capacity(ecrit.saturating_add(2));
    rendu.extend_from_slice(&statut.to_be_bytes());
    rendu.extend_from_slice(sortie.get(..ecrit).unwrap_or_default());
    rendre_octets(&env, &rendu)
}

/// `external fun identifiant(h: Long): String?`
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_identifiant(
    env: JNIEnv,
    _classe: JClass,
    brut: jlong,
) -> jstring {
    let Some(handle) = handle(brut) else {
        return core::ptr::null_mut();
    };
    let mut sortie = [0 as c_char; ASL_IDENTIFIANT_OCTETS];
    // SAFETY : `ASL_IDENTIFIANT_OCTETS` octets inscriptibles.
    handle.dernier = unsafe { asl_appareil_identifiant(handle.appareil, sortie.as_mut_ptr()) };
    if handle.dernier != ASL_OK {
        return core::ptr::null_mut();
    }
    // SAFETY : un NUL a été posé.
    let texte = unsafe { core::ffi::CStr::from_ptr(sortie.as_ptr()) }.to_string_lossy();
    rendre_chaine(&env, &texte)
}

/// `external fun fauteTexte(code: Int): String`
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_airdesktop_servicelocator_reseau_Natif_fauteTexte(
    env: JNIEnv,
    _classe: JClass,
    code: jint,
) -> jstring {
    // SAFETY : la chaîne est statique, terminée par NUL.
    let texte = unsafe { core::ffi::CStr::from_ptr(asl_faute_texte(code)) }.to_string_lossy();
    rendre_chaine(&env, &texte)
}
