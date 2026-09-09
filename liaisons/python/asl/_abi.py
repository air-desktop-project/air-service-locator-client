"""L'ABI C, transcrite pour `ctypes`. **Rien de pythonique ici.**

Ce module est la copie mot pour mot de ``crates/asl-client-ffi/include/asl.h``.
Il ne traduit pas les erreurs, ne nomme rien autrement, n'enveloppe rien : c'est
le rôle de ``asl/__init__.py``. Les séparer rend visible la seule chose qui
compte ici — **est-ce que ce fichier dit la même chose que l'en-tête ?** — et
``essais/test_abi.py`` répond à cette question en lisant les deux.

POURQUOI `ctypes` ET NON `cffi`
================================

`cffi` est plus rapide et attrape davantage de fautes à la construction. Il est
aussi une dépendance, et cette bibliothèque est faite pour être embarquée par des
daemons tiers : ce qu'elle tire, ils l'installent. `ctypes` est dans la
bibliothèque standard depuis Python 2.5, sur CPython comme sur PyPy, et ne coûte
rien à personne.

Le prix est réel et il est payé ci-dessous : **chaque signature doit être
déclarée à la main**, et une déclaration fausse ne se voit pas à l'import — elle
corrompt la pile à l'appel.

POURQUOI `CDLL` ET JAMAIS `PyDLL`
==================================

`CDLL` **relâche le GIL** pendant l'appel ; `PyDLL` le garde. Or ``asl_ou``
attend jusqu'à vingt secondes qu'un annuaire réponde, et ``asl_client_libere``
jusqu'à deux qu'une annonce se retire proprement. Avec `PyDLL`, tout le processus
hôte — son serveur web, ses tâches, son interface — gèlerait pendant ce temps.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import pathlib
import sys

# ── LES CODES ───────────────────────────────────────────────────────────────

ASL_OK = 0
ASL_ARGUMENT = -1
ASL_CONFIGURATION = -2
ASL_INJOIGNABLE = -3
ASL_REFUSE = -4
ASL_TAMPON_TROP_PETIT = -5
ASL_INTERNE = -6
ASL_PAS_D_IDENTITE = -7
ASL_DEJA = -8

ASL_IDENTIFIANT_OCTETS = 29
ASL_GRAINE_OCTETS = 32

ASL_TCP = 1
ASL_UDP = 2

ASL_REFLEXIF = 1
ASL_ANNONCE = 2

ASL_JOIGNABLE = 1
ASL_INJOIGNABLE_POINT = 2
ASL_NON_SONDE = 3
ASL_EN_COURS = 4


# ── LES STRUCTURES ──────────────────────────────────────────────────────────
#
# **AUCUN `_pack_`.** L'en-tête n'en demande pas : les champs y sont rangés du
# plus large au plus étroit précisément pour qu'aucun compilateur n'ait à
# inventer de bourrage. Poser un `_pack_` ici ferait diverger cette liaison de
# toutes les autres — et le seul symptôme serait un port lu à la place d'un
# protocole.


class Point(ctypes.Structure):
    """``asl_point`` — 4 octets."""

    _fields_ = [
        ("port", ctypes.c_uint16),
        ("protocole", ctypes.c_uint8),
        ("reserve", ctypes.c_uint8),
    ]


class Candidat(ctypes.Structure):
    """``asl_candidat`` — 24 octets."""

    _fields_ = [
        ("adresse", ctypes.c_uint8 * 16),
        ("port", ctypes.c_uint16),
        ("protocole", ctypes.c_uint8),
        ("famille", ctypes.c_uint8),
        ("origine", ctypes.c_uint8),
        ("verdict", ctypes.c_uint8),
        ("reserve", ctypes.c_uint8 * 2),
    ]


class Etat(ctypes.Structure):
    """``asl_etat_t`` — 24 octets."""

    _fields_ = [
        ("attaches", ctypes.c_uint64),
        ("ruptures", ctypes.c_uint64),
        ("attachee", ctypes.c_uint8),
        ("abandonnee", ctypes.c_uint8),
        ("reserve", ctypes.c_uint8 * 6),
    ]


# **LES TAILLES SONT VÉRIFIÉES À L'IMPORT, ET NON DANS UN ESSAI.**
#
# C'est le pendant Python des `const _: () = assert!` du côté Rust. Cinq langages
# calculent la disposition chacun de son côté ; si celui-ci se trompe, il vaut
# mieux qu'il refuse de se charger que d'écrire un port dans un champ de
# protocole pendant six mois.
for _structure, _taille in ((Point, 4), (Candidat, 24), (Etat, 24)):
    if ctypes.sizeof(_structure) != _taille:
        raise ImportError(
            f"{_structure.__name__} fait {ctypes.sizeof(_structure)} octets, "
            f"et l'ABI en annonce {_taille}. Cette liaison ne correspond pas à "
            f"la bibliothèque native : ne l'utilisez pas."
        )


# ── LE CHARGEMENT ───────────────────────────────────────────────────────────


def _noms_possibles() -> list[str]:
    """Comment l'objet natif s'appelle, selon le système."""
    if sys.platform == "darwin":
        return ["libasl_client_ffi.dylib"]
    if sys.platform == "win32":
        return ["asl_client_ffi.dll"]
    return ["libasl_client_ffi.so"]


def _chemins_candidats() -> list[pathlib.Path]:
    """Où chercher, dans l'ordre.

    **`ASL_BIBLIOTHEQUE` PASSE AVANT TOUT.** C'est ce qui permet d'éprouver cette
    liaison contre une construction locale sans l'installer, et à un porteur de
    pointer l'objet qu'il a lui-même compilé pour son architecture.
    """
    chemins: list[pathlib.Path] = []
    impose = os.environ.get("ASL_BIBLIOTHEQUE")
    if impose:
        chemins.append(pathlib.Path(impose))
    ici = pathlib.Path(__file__).resolve().parent
    chemins.extend(ici / nom for nom in _noms_possibles())
    return chemins


class BibliothequeIntrouvable(Exception):
    """L'objet natif n'a pas été trouvé.

    **CE N'EST PAS UNE FAUTE D'EXÉCUTION, C'EST UNE INSTALLATION INCOMPLÈTE**, et
    le message le dit — un `OSError` brut de `ctypes` enverrait chercher une
    panne là où il manque un fichier.
    """


def charger(chemin: str | os.PathLike[str] | None = None) -> ctypes.CDLL:
    """Charge la bibliothèque native et déclare toutes ses signatures."""
    essayes: list[str] = []
    candidats = [pathlib.Path(chemin)] if chemin else _chemins_candidats()

    for candidat in candidats:
        essayes.append(str(candidat))
        if candidat.exists():
            return _declarer(ctypes.CDLL(str(candidat)))

    # En dernier, le chargeur du système — qui connaît `LD_LIBRARY_PATH`,
    # `/etc/ld.so.conf` et les répertoires d'installation.
    trouve = ctypes.util.find_library("asl_client_ffi")
    if trouve:
        essayes.append(trouve)
        return _declarer(ctypes.CDLL(trouve))

    raise BibliothequeIntrouvable(
        "l'objet natif d'asl est introuvable.\n"
        "Cherché : " + ", ".join(essayes) + "\n"
        "Construisez-le avec `cargo build --release` dans le dépôt, puis posez\n"
        "ASL_BIBLIOTHEQUE sur target/release/" + _noms_possibles()[0]
    )


def _declarer(lib: ctypes.CDLL) -> ctypes.CDLL:
    """Pose `argtypes` et `restype` sur les onze fonctions.

    **SANS CELA, `ctypes` DEVINE, ET IL DEVINE `int`.** Un pointeur de
    soixante-quatre bits passé en `int` de trente-deux est tronqué, et le
    symptôme est une corruption à l'appel, pas une erreur au chargement. C'est la
    faute la plus coûteuse de toute cette liaison, et la moins visible.
    """
    opaque = ctypes.c_void_p
    i32 = ctypes.c_int32

    lib.asl_version.argtypes = [
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    lib.asl_version.restype = None

    lib.asl_faute_texte.argtypes = [i32]
    lib.asl_faute_texte.restype = ctypes.c_char_p

    lib.asl_client_neuf.argtypes = [ctypes.POINTER(opaque)]
    lib.asl_client_neuf.restype = i32

    lib.asl_client_annuaire.argtypes = [opaque, ctypes.c_char_p, ctypes.c_char_p]
    lib.asl_client_annuaire.restype = i32

    lib.asl_client_racines.argtypes = [
        opaque,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
    ]
    lib.asl_client_racines.restype = i32

    lib.asl_client_identite.argtypes = [
        opaque,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.asl_client_identite.restype = i32

    lib.asl_client_libere.argtypes = [opaque]
    lib.asl_client_libere.restype = None

    lib.asl_enroler.argtypes = [
        opaque,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.asl_enroler.restype = i32

    lib.asl_annoncer.argtypes = [
        opaque,
        ctypes.c_char_p,
        ctypes.POINTER(Point),
        ctypes.c_size_t,
    ]
    lib.asl_annoncer.restype = i32

    lib.asl_etat.argtypes = [opaque, ctypes.POINTER(Etat)]
    lib.asl_etat.restype = i32

    lib.asl_ou.argtypes = [
        opaque,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(Candidat),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.asl_ou.restype = i32

    return lib
