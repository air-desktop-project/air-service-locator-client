"""asl — annoncer un service et retrouver un port, depuis Python.

Un daemon qui écoute sur un port choisi au démarrage est un daemon que ses
clients ne savent plus joindre. Cette bibliothèque est l'autre moitié : le daemon
ANNONCE le port que le système lui a donné, et ses clients le DEMANDENT.

    import asl

    with asl.Client(
        annuaires=[("203.0.113.7:6630", "nitrogen.example")],
        racines=open("/etc/asl/ca.pem", "rb").read(),
        identite=(machine, graine),
    ) as client:
        client.annoncer("depot", [asl.Point(asl.Protocole.TCP, 8080)])
        ...                       # le daemon sert, l'annonce se tient toute seule

CE QUI TOURNE EN ARRIÈRE-PLAN, ET QU'IL FAUT SAVOIR
====================================================

**`annoncer` rend la main tout de suite et ne revient jamais dessus.** Un annuaire
injoignable ne doit pas empêcher un daemon de démarrer : votre service écoute
déjà pendant que l'annonce cherche encore.

Ce qui la tient est un fil natif, à l'intérieur de la bibliothèque — ni un
`threading.Thread`, ni une tâche `asyncio`, et il ne touche jamais à
l'interpréteur. Il se reconnecte seul, bascule sur l'autre annuaire racine quand
le premier tombe, et n'abandonne jamais. `etat()` dit où il en est.

**FERMER LE CLIENT RETIRE L'ANNONCE.** La connexion EST le bail : il n'y a pas de
« retrait » séparé à appeler, et laisser le `Client` se faire ramasser retire
l'annonce au moment où le ramasse-miettes passe — c'est-à-dire à un moment que
vous ne choisissez pas. **Employez `with`.**

CE QUE CETTE LIAISON N'INSTALLE PAS
====================================

Rien. Elle n'a aucune dépendance : `ctypes` et `dataclasses` sont dans la
bibliothèque standard. Un daemon qui vous embarque n'hérite d'aucun paquet.
"""

from __future__ import annotations

import ctypes
import dataclasses
import enum
import ipaddress
import threading
from collections.abc import Iterable, Sequence

from . import _abi
from ._abi import BibliothequeIntrouvable

__all__ = [
    "BibliothequeIntrouvable",
    "Poussee",
    "VerdictNat",
    "Candidat",
    "Client",
    "Configuration",
    "Deja",
    "Erreur",
    "Etat",
    "Injoignable",
    "Interne",
    "MauvaisArgument",
    "PasDIdentite",
    "Point",
    "Protocole",
    "Refuse",
    "Verdict",
    "version",
]


# ── LES ERREURS ─────────────────────────────────────────────────────────────
#
# **JAMAIS UN ENTIER NÉGATIF RENDU TEL QUEL.** Un utilisateur Python attend une
# exception : un code de retour qu'on oublie de tester est un bogue silencieux,
# une exception qu'on oublie d'attraper remonte et se voit.


class Erreur(Exception):
    """La racine de tout ce que cette bibliothèque lève.

    ``asl.Erreur`` suffit à tout attraper ; les classes filles servent à
    distinguer ce qui se corrige différemment.
    """

    code: int = 0

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or _phrase(self.code))


class MauvaisArgument(Erreur):
    """Un argument que l'ABI refuse : une adresse illisible, un port nul."""

    code = _abi.ASL_ARGUMENT


class Configuration(Erreur):
    """Il manque un annuaire, une racine, ou la racine ne se lit pas.

    **CE N'EST PAS UNE PANNE**, et c'est pourquoi elle est distincte de
    `Injoignable` : réessayer ne la réparerait jamais.
    """

    code = _abi.ASL_CONFIGURATION


class Injoignable(Erreur):
    """Personne n'a répondu.

    **UN CÂBLE DÉBRANCHÉ, ET NON UN DROIT MANQUANT** — voir `Refuse`. Les deux se
    corrigent à des endroits opposés.
    """

    code = _abi.ASL_INJOIGNABLE


class Refuse(Erreur):
    """L'annuaire a compris, et il a dit non.

    Une clé qui n'est pas (ou plus) liée, une machine sans le droit d'annoncer,
    un service auquel vous n'avez pas accès.
    """

    code = _abi.ASL_REFUSE


class Interne(Erreur):
    """L'impossible est arrivé, et la bibliothèque l'a rattrapé.

    **ELLE N'A PAS TUÉ VOTRE PROCESSUS**, et c'est délibéré : une panique qui
    traverse la frontière avorterait l'interpréteur entier.
    """

    code = _abi.ASL_INTERNE


class PasDIdentite(Erreur):
    """Cette machine n'a pas d'identité : enrôlez-la, ou posez-en une."""

    code = _abi.ASL_PAS_D_IDENTITE


class Deja(Erreur):
    """Ce client annonce déjà.

    Un second appel ne remplace pas la première annonce en silence — ce qui la
    retirerait.
    """

    code = _abi.ASL_DEJA


_PAR_CODE: dict[int, type[Erreur]] = {
    classe.code: classe
    for classe in (
        MauvaisArgument,
        Configuration,
        Injoignable,
        Refuse,
        Interne,
        PasDIdentite,
        Deja,
    )
}


def _phrase(code: int) -> str:
    """Ce que la bibliothèque native dit d'un code.

    **LA PHRASE VIENT DE LÀ-BAS, ET N'EST PAS RECOPIÉE ICI.** Deux listes de
    messages finiraient par diverger, et c'est celle qu'on oublie de corriger que
    l'utilisateur lirait.
    """
    try:
        brute = _bibliotheque().asl_faute_texte(code)
    except Exception:  # noqa: BLE001 — un message ne doit jamais faire échouer
        return f"code {code}"
    return brute.decode("utf-8", "replace") if brute else f"code {code}"


def _verifier(code: int) -> None:
    """Lève ce qu'il faut, ou ne fait rien."""
    if code == _abi.ASL_OK:
        return
    classe = _PAR_CODE.get(code)
    if classe is None:
        raise Erreur(f"code inattendu {code} : {_phrase(code)}")
    raise classe()


# ── CE QUI TRAVERSE ─────────────────────────────────────────────────────────


class Protocole(enum.IntEnum):
    """Le protocole d'un point d'écoute."""

    TCP = _abi.ASL_TCP
    UDP = _abi.ASL_UDP

    def __str__(self) -> str:
        return self.name.lower()


class Origine(enum.IntEnum):
    """D'où vient une adresse."""

    REFLEXIF = _abi.ASL_REFLEXIF
    """L'annuaire nous a VU sous cette adresse."""
    ANNONCE = _abi.ASL_ANNONCE
    """Le daemon l'a annoncée lui-même."""


class VerdictNat(enum.IntEnum):
    """Le daemon est-il derrière un NAT ?

    **TROIS VALEURS, ET NON UN BOOLÉEN.** L'annuaire tranche en comparant ce
    qu'il OBSERVE à ce que le daemon ANNONCE ; sans adresse locale annoncée, il
    n'y a rien à comparer. Un booléen forcerait à répondre « non », c'est-à-dire
    à affirmer une chose qu'on n'a pas mesurée — et un daemon derrière un NAT qui
    lirait « non » chercherait la panne partout sauf là où elle est.
    """

    NON = _abi.ASL_NAT_NON
    OUI = _abi.ASL_NAT_OUI
    INDETERMINE = _abi.ASL_NAT_INDETERMINE


class Verdict(enum.IntEnum):
    """Ce que l'annuaire sait d'un point d'écoute.

    **TROIS DE CES QUATRE VALEURS NE VEULENT PAS DIRE « ÇA NE MARCHE PAS. »**

    `EN_COURS` n'affirme rien : l'annuaire répond avant d'avoir sondé, pour ne
    pas faire attendre le démarrage d'un daemon. `NON_SONDE` dit qu'il ne
    mesurera pas — UDP n'a pas de poignée de main, donc une sonde n'y
    distinguerait pas « écoute et ignore » de « rien n'écoute ».

    Les aplatir en un booléen ferait écarter un candidat parfaitement bon. C'est
    pour cela qu'il n'y a pas de propriété ``joignable`` sur `Candidat` : elle
    serait juste une fois sur deux.
    """

    JOIGNABLE = _abi.ASL_JOIGNABLE
    INJOIGNABLE = _abi.ASL_INJOIGNABLE_POINT
    NON_SONDE = _abi.ASL_NON_SONDE
    EN_COURS = _abi.ASL_EN_COURS


@dataclasses.dataclass(frozen=True, slots=True)
class Point:
    """Un point d'écoute à annoncer."""

    protocole: Protocole
    port: int

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535:
            raise MauvaisArgument(f"{self.port} n'est pas un port")

    def __str__(self) -> str:
        return f"{self.protocole}:{self.port}"


@dataclasses.dataclass(frozen=True, slots=True)
class Candidat:
    """Où joindre un service, et ce que l'annuaire en sait."""

    protocole: Protocole
    adresse: ipaddress.IPv4Address | ipaddress.IPv6Address
    port: int
    origine: Origine
    verdict: Verdict

    def __str__(self) -> str:
        """La forme qu'on recopie dans une commande — **avec ses crochets**.

        Sans eux, ``2001:db8::1:8080`` est ambigu : le dernier ``:`` sépare-t-il
        un port ou un groupe d'adresse ?
        """
        if self.adresse.version == 6:
            return f"[{self.adresse}]:{self.port}"
        return f"{self.adresse}:{self.port}"


@dataclasses.dataclass(frozen=True, slots=True)
class Poussee:
    """Ce que l'annuaire a MESURÉ depuis, et poussé sur la connexion tenue.

    L'annuaire répond `en_cours` à une annonce pour ne pas faire attendre un
    démarrage le temps d'une sonde. **Sans les poussées, un daemon reste à croire
    que sa joignabilité est en cours de mesure**, pour toujours.

    **Elle porte la liste ENTIÈRE, et non un delta** : la dernière remplace tout
    ce qui précède.
    """

    candidats: list[Candidat]
    derriere_nat: VerdictNat


@dataclasses.dataclass(frozen=True, slots=True)
class Etat:
    """Ce que l'annonce a fait jusqu'ici."""

    attachee: bool
    """L'annuaire nous connaît EN CE MOMENT : authentifiés ET annoncés.

    **Ce n'est pas « la socket est ouverte »** : une connexion qui s'ouvre puis se
    fait refuser l'authentification n'annonce rien, et ce drapeau reste faux.
    """
    attaches: int
    """Combien de fois on s'est attaché depuis le départ."""
    ruptures: int
    """Combien de fois une attache établie s'est rompue."""
    abandonnee: bool
    """La tâche a renoncé, et ne réessaiera pas.

    **Elle ne renonce que sur une faute de configuration** — une racine
    illisible, aucun annuaire. Jamais sur une panne de réseau, quelle qu'en soit
    la durée. C'est le seul état dont un humain doit être averti.
    """


# ── LA BIBLIOTHÈQUE, CHARGÉE UNE FOIS ───────────────────────────────────────

_verrou_chargement = threading.Lock()
_lib: ctypes.CDLL | None = None


def _bibliotheque() -> ctypes.CDLL:
    """Charge l'objet natif au premier besoin, et une seule fois."""
    global _lib  # noqa: PLW0603 — un objet natif par processus, pas par appel
    with _verrou_chargement:
        if _lib is None:
            _lib = _abi.charger()
        return _lib


def version() -> tuple[int, int, int]:
    """La version de la bibliothèque NATIVE, et non de ce paquet.

    C'est celle qui compte : le paquet Python n'est qu'un habillage, et deux
    versions qui divergeraient se verraient ici.
    """
    lib = _bibliotheque()
    majeur = ctypes.c_uint32()
    mineur = ctypes.c_uint32()
    correctif = ctypes.c_uint32()
    lib.asl_version(
        ctypes.byref(majeur), ctypes.byref(mineur), ctypes.byref(correctif)
    )
    return (majeur.value, mineur.value, correctif.value)


# ── LE CLIENT ───────────────────────────────────────────────────────────────

# Combien de candidats on demande d'emblée.
#
# **LE DIMENSIONNEMENT EN DEUX TEMPS DU C COÛTERAIT DEUX ALLERS-RETOURS ICI** :
# `asl_ou` refait la requête à chaque appel, il ne garde pas de résultat. On
# demande donc large — le protocole borne un service à huit points d'écoute —, et
# l'on ne paie une seconde requête que si cette borne changeait un jour.
_CANDIDATS_D_EMBLEE = 8


class Client:
    """Un client d'annuaire : il annonce, il résout, il tient sa connexion.

    **IL SE FERME**, et le fermer retire l'annonce. Employez `with`.

    Cette classe est utilisable depuis plusieurs fils : elle sérialise ses
    appels. Voir la note de `_verrou`.
    """

    def __init__(
        self,
        annuaires: Iterable[tuple[str, str]] = (),
        racines: bytes | None = None,
        identite: tuple[str, bytes] | None = None,
    ) -> None:
        """Monte un client. **Il n'ouvre aucune connexion.**

        `annuaires` est une suite de couples ``(adresse, nom)``. L'adresse est
        LITTÉRALE — ``"203.0.113.7:6630"`` ou ``"[2001:db8::1]:6630"`` —, jamais
        un nom d'hôte : **la résolution vous appartient**, parce que vous avez
        déjà un résolveur, une politique de cache et des fils, et que vous en
        imposer un autre serait décider à votre place. ``socket.getaddrinfo``
        fait très bien l'affaire, et un nom qui rend plusieurs adresses les rend
        toutes utilisables ici.

        Le second membre est le nom qu'on EXIGE du certificat. Il n'est pas
        déduit de l'adresse, et il ne peut pas l'être : le déduire reviendrait à
        faire confiance à qui répond à cette adresse.

        `racines` est le contenu d'un fichier PEM. **Il n'y a pas de repli sur le
        magasin du système** : les annuaires sont signés par LEUR autorité.

        `identite` est le couple ``(machine, graine)`` rendu par `enroler`.
        """
        self._lib = _bibliotheque()
        # **UN SEUL VERROU, ET IL SÉRIALISE TOUT.**
        #
        # L'ABI dit qu'un client ne se partage pas entre fils. En Rust, deux
        # appels concurrents aliaseraient un `&mut` — un comportement indéfini,
        # pas un ralentissement. En Python, personne ne lit cette phrase : la
        # liaison la fait donc respecter, et transforme l'indéfini en file
        # d'attente.
        #
        # LE COÛT EST ÉCRIT : `etat()` attend pendant un `ou()` en cours, qui
        # peut durer vingt secondes. Un daemon qui annonce n'appelle pas `ou()`,
        # donc les deux se croisent rarement — mais quand cela arrive, c'est
        # cette ligne qui l'explique.
        self._verrou = threading.RLock()
        self._brut: ctypes.c_void_p | None = None

        brut = ctypes.c_void_p()
        _verifier(self._lib.asl_client_neuf(ctypes.byref(brut)))
        self._brut = brut

        try:
            for adresse, nom in annuaires:
                self.ajouter_annuaire(adresse, nom)
            if racines is not None:
                self.poser_racines(racines)
            if identite is not None:
                self.poser_identite(*identite)
        except BaseException:
            # **CE QUI EST OUVERT SE FERME, MÊME QUAND LE CONSTRUCTEUR ÉCHOUE.**
            # Sans ceci, une adresse mal écrite laisserait un objet natif que
            # plus rien ne référence — et qu'aucun ramasse-miettes ne sait
            # libérer, puisqu'il n'appartient pas à Python.
            self.fermer()
            raise

    # ── La configuration ────────────────────────────────────────────────────

    def ajouter_annuaire(self, adresse: str, nom: str) -> None:
        """Ajoute un annuaire à essayer. **Répétable, et l'ordre compte.**

        L'IPv6 est essayé d'abord quel que soit l'ordre des appels ; à
        l'intérieur d'une famille, c'est cet ordre qui décide.
        """
        with self._verrou:
            _verifier(
                self._lib.asl_client_annuaire(
                    self._exige(), _octets(adresse), _octets(nom)
                )
            )

    def poser_racines(self, pem: bytes) -> None:
        """Pose les certificats d'autorité, en PEM."""
        if not isinstance(pem, (bytes, bytearray)):
            raise MauvaisArgument("les racines sont des octets, pas du texte")
        tampon = (ctypes.c_uint8 * len(pem)).from_buffer_copy(pem)
        with self._verrou:
            _verifier(
                self._lib.asl_client_racines(self._exige(), tampon, len(pem))
            )

    def poser_identite(self, machine: str, graine: bytes) -> None:
        """Installe l'identité de cette machine.

        **LA GRAINE EST LE SECRET**, et sa conservation vous appartient : elle
        n'est pas chiffrée, et quiconque la lit devient cette machine. Un fichier
        en ``0600``, et rien de plus bavard.
        """
        if len(graine) != _abi.ASL_GRAINE_OCTETS:
            raise MauvaisArgument(
                f"une graine fait {_abi.ASL_GRAINE_OCTETS} octets, pas {len(graine)}"
            )
        tampon = (ctypes.c_uint8 * _abi.ASL_GRAINE_OCTETS).from_buffer_copy(graine)
        with self._verrou:
            _verifier(
                self._lib.asl_client_identite(
                    self._exige(), _octets(machine), tampon
                )
            )

    # ── Les verbes ──────────────────────────────────────────────────────────

    def enroler(self, code: str) -> tuple[str, bytes]:
        """Présente un code d'enrôlement, et rend ``(machine, graine)``.

        **CONSERVEZ LES DEUX.** La clé est générée sur cette machine et sa moitié
        privée n'en sort pas ; ce couple est le seul justificatif durable, et le
        code est dépensé — il ne servira plus.

        L'identité est installée dans ce client au passage : vous n'avez pas à
        rappeler `poser_identite`.

        **Cet appel bloque** — jusqu'à vingt secondes s'il faut attendre un
        annuaire. Le GIL est relâché pendant ce temps.
        """
        machine = ctypes.create_string_buffer(_abi.ASL_IDENTIFIANT_OCTETS)
        graine = (ctypes.c_uint8 * _abi.ASL_GRAINE_OCTETS)()
        with self._verrou:
            _verifier(
                self._lib.asl_enroler(
                    self._exige(), _octets(code), machine, graine
                )
            )
        return machine.value.decode("ascii"), bytes(graine)

    def annoncer(self, service: str, points: Sequence[Point]) -> None:
        """Annonce ce service, et **rend la main tout de suite**.

        L'annonce est ensuite tenue par un fil natif, aussi longtemps que ce
        client vit : elle se réauthentifie et se réannonce seule à chaque
        reconnexion, et bascule sur l'autre annuaire racine quand le premier
        tombe. `etat()` dit où elle en est.

        **UN CLIENT N'ANNONCE QU'UNE FOIS** : un second appel lève `Deja` plutôt
        que de remplacer la première en silence, ce qui la retirerait.
        """
        if not points:
            raise MauvaisArgument("une annonce sans point d'écoute n'annonce rien")
        tableau = (_abi.Point * len(points))()
        for place, point in enumerate(points):
            if not isinstance(point, Point):
                raise MauvaisArgument(f"{point!r} n'est pas un asl.Point")
            tableau[place].port = point.port
            tableau[place].protocole = int(point.protocole)
            tableau[place].reserve = 0
        with self._verrou:
            _verifier(
                self._lib.asl_annoncer(
                    self._exige(), _octets(service), tableau, len(points)
                )
            )

    def etat(self) -> Etat:
        """Où en est l'annonce. Un client qui n'a jamais annoncé rend tout à zéro."""
        brut = _abi.Etat()
        with self._verrou:
            _verifier(self._lib.asl_etat(self._exige(), ctypes.byref(brut)))
        return Etat(
            attachee=bool(brut.attachee),
            attaches=int(brut.attaches),
            ruptures=int(brut.ruptures),
            abandonnee=bool(brut.abandonnee),
        )

    def poussees_recues(self) -> int:
        """Combien de poussées de verdict sont arrivées depuis le départ.

        **ZÉRO N'EST PAS UNE ANOMALIE** : l'annuaire ne pousse que ce qui a
        CHANGÉ, et un service dont les sondes confirment ce qu'il disait déjà n'en
        produit aucune.
        """
        combien = ctypes.c_uint64()
        with self._verrou:
            _verifier(self._lib.asl_poussees_recues(self._exige(), ctypes.byref(combien)))
        return int(combien.value)

    def derniere_poussee(self) -> Poussee | None:
        """Le dernier verdict poussé, ou `None` si rien n'a encore été poussé.

        **`None` N'EST PAS UNE ERREUR, ET C'EST POURQUOI CE N'EST PAS UNE
        EXCEPTION.** Ne rien avoir reçu est le cas ordinaire ; lever ici
        obligerait un porteur à envelopper d'un `try` la boucle qu'il appelle
        chaque seconde.
        """
        place = _CANDIDATS_D_EMBLEE
        combien = ctypes.c_size_t(0)
        nat = ctypes.c_uint8(_abi.ASL_NAT_INDETERMINE)
        with self._verrou:
            brut = self._exige()
            tableau = (_abi.Candidat * place)()
            code = self._lib.asl_derniere_poussee(
                brut, tableau, place, ctypes.byref(combien), ctypes.byref(nat)
            )
            if code == _abi.ASL_TAMPON_TROP_PETIT:
                place = combien.value
                tableau = (_abi.Candidat * max(place, 1))()
                code = self._lib.asl_derniere_poussee(
                    brut, tableau, place, ctypes.byref(combien), ctypes.byref(nat)
                )
            if code == _abi.ASL_PAS_DE_POUSSEE:
                return None
            _verifier(code)
        return Poussee(
            candidats=[_candidat(tableau[rang]) for rang in range(combien.value)],
            derriere_nat=VerdictNat(nat.value),
        )

    def ou(self, machine: str, service: str) -> list[Candidat]:
        """Demande où joindre un service, et rend les candidats **dans l'ordre**.

        L'ordre est celui qu'un client doit suivre — IPv6 d'abord, adresse
        observée avant adresse annoncée — et il n'est pas à vous de le deviner.

        **Cet appel bloque**, comme `enroler`.
        """
        combien = ctypes.c_size_t(0)
        place = _CANDIDATS_D_EMBLEE
        with self._verrou:
            brut = self._exige()
            tableau = (_abi.Candidat * place)()
            code = self._lib.asl_ou(
                brut,
                _octets(machine),
                _octets(service),
                tableau,
                place,
                ctypes.byref(combien),
            )
            if code == _abi.ASL_TAMPON_TROP_PETIT:
                place = combien.value
                tableau = (_abi.Candidat * place)()
                code = self._lib.asl_ou(
                    brut,
                    _octets(machine),
                    _octets(service),
                    tableau,
                    place,
                    ctypes.byref(combien),
                )
            _verifier(code)
        return [_candidat(tableau[rang]) for rang in range(combien.value)]

    # ── La fin ──────────────────────────────────────────────────────────────

    def fermer(self) -> None:
        """Ferme le client, **et retire l'annonce en le faisant**.

        Elle est retirée PROPREMENT, ce qui épargne à l'annuaire la minute
        d'inactivité pendant laquelle il donnerait vos clients une adresse morte.
        Cet appel peut donc prendre jusqu'à deux secondes.

        Appeler deux fois ne fait rien la seconde.
        """
        with self._verrou:
            brut, self._brut = self._brut, None
            if brut is not None:
                self._lib.asl_client_libere(brut)

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *_oubli: object) -> None:
        self.fermer()

    def __del__(self) -> None:
        """Le filet, et non le moyen.

        **CE N'EST PAS LÀ QU'IL FAUT COMPTER FERMER** : le ramasse-miettes passe
        quand il veut, donc l'annonce serait retirée à un moment que vous ne
        choisissez pas — et pendant l'arrêt de l'interpréteur, cet appel peut ne
        jamais avoir lieu. Employez `with`.
        """
        try:
            self.fermer()
        except BaseException:  # noqa: BLE001 — un destructeur ne lève rien
            pass

    def _exige(self) -> ctypes.c_void_p:
        """Le pointeur natif, ou une erreur qui dit ce qui s'est passé."""
        if self._brut is None:
            raise Erreur("ce client est fermé")
        return self._brut


def _octets(texte: str) -> bytes:
    """Une chaîne C, terminée par NUL.

    **UN NUL AU MILIEU EST REFUSÉ ICI**, et non transmis : `ctypes` tronquerait
    silencieusement, et l'annuaire recevrait un nom de service plus court que
    celui qu'on croit lui avoir donné.
    """
    if not isinstance(texte, str):
        raise MauvaisArgument(f"{texte!r} n'est pas du texte")
    brut = texte.encode("utf-8")
    if b"\x00" in brut:
        raise MauvaisArgument("un NUL au milieu d'une chaîne")
    return brut


def _candidat(brut: _abi.Candidat) -> Candidat:
    """Un candidat de l'ABI, en objets Python."""
    octets = bytes(brut.adresse)
    if brut.famille == 6:
        adresse: ipaddress.IPv4Address | ipaddress.IPv6Address = (
            ipaddress.IPv6Address(octets)
        )
    else:
        adresse = ipaddress.IPv4Address(octets[:4])
    return Candidat(
        protocole=Protocole(brut.protocole),
        adresse=adresse,
        port=int(brut.port),
        origine=Origine(brut.origine),
        verdict=Verdict(brut.verdict),
    )
