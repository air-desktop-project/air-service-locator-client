"""L'ABI transcrite dit-elle la même chose que l'en-tête ?

C'EST LA SEULE QUESTION QUI COMPTE DANS `asl/_abi.py`
=====================================================

Une constante qui dériverait ne casserait rien nulle part : elle ferait seulement
lever `Refuse` là où l'ABI dit `Injoignable`, et personne ne s'en apercevrait
avant d'avoir cherché une panne de réseau pendant une heure.

Ces essais lisent `crates/asl-client-ffi/include/asl.h` — le contrat écrit à la
main — et le comparent à ce que Python croit. **C'est aussi ce qui rend la
séparation du paquet coûteuse** : le jour où cette liaison vivra dans son propre
dépôt, cet essai n'aura plus l'en-tête sous la main.
"""

from __future__ import annotations

import ctypes
import pathlib
import re
import unittest

from asl import _abi

RACINE = pathlib.Path(__file__).resolve().parents[3]
ENTETE = RACINE / "crates" / "asl-client-ffi" / "include" / "asl.h"


def constantes_de_l_entete() -> dict[str, int]:
    """Les `#define ASL_…` de l'en-tête, avec leur valeur."""
    trouvees: dict[str, int] = {}
    for ligne in ENTETE.read_text(encoding="utf-8").splitlines():
        trouve = re.match(r"#define\s+(ASL_[A-Z0-9_]+)\s+(-?\d+)\s*$", ligne.strip())
        if trouve:
            trouvees[trouve.group(1)] = int(trouve.group(2))
    return trouvees


def fonctions_de_l_entete() -> set[str]:
    """Les fonctions déclarées dans l'en-tête."""
    texte = ENTETE.read_text(encoding="utf-8")
    return set(re.findall(r"\b(asl_[a-z0-9_]+)\s*\(", texte))


class LEnteteEstLaReference(unittest.TestCase):
    def test_l_entete_est_bien_la(self):
        # Si ce fichier bouge, tous les essais suivants passeraient en ne
        # comparant rien. On le dit plutôt que de rendre un OK muet.
        self.assertTrue(ENTETE.is_file(), f"{ENTETE} est introuvable")

    def test_toutes_les_constantes_de_l_entete_sont_transcrites(self):
        declarees = constantes_de_l_entete()
        self.assertGreater(len(declarees), 10, "l'en-tête n'a pas été lu")
        for nom, valeur in declarees.items():
            self.assertTrue(
                hasattr(_abi, nom), f"`{nom}` est dans l'en-tête et pas dans `_abi`"
            )
            self.assertEqual(
                getattr(_abi, nom), valeur, f"`{nom}` diverge entre `asl.h` et Python"
            )

    def test_aucune_constante_inventee_de_ce_cote(self):
        # **L'INVERSE COMPTE AUTANT** : une constante que Python connaît et que
        # l'en-tête ignore est une valeur que personne n'a promise.
        declarees = constantes_de_l_entete()
        inventees = {
            nom
            for nom in dir(_abi)
            if nom.startswith("ASL_") and nom not in declarees
        }
        self.assertEqual(inventees, set(), "constantes sans contrepartie dans l'en-tête")

    def test_les_onze_fonctions_sont_declarees_a_ctypes(self):
        # Une fonction que l'en-tête déclare et que `_declarer` oublie s'appelle
        # quand même — sans `argtypes`, donc en devinant `int`, donc en tronquant
        # un pointeur de soixante-quatre bits. Le symptôme est une corruption,
        # pas une erreur.
        source = (pathlib.Path(_abi.__file__)).read_text(encoding="utf-8")
        for fonction in fonctions_de_l_entete():
            self.assertIn(
                f"lib.{fonction}.argtypes",
                source,
                f"`{fonction}` est déclarée dans l'en-tête et n'a pas d'`argtypes`",
            )

    def test_les_tailles_sont_celles_que_l_entete_annonce(self):
        # Elles sont déjà vérifiées à l'import de `_abi` — ce qui est vérifié ici
        # est l'accord avec les nombres ÉCRITS dans les commentaires de
        # l'en-tête, que les cinq liaisons recopient.
        texte = ENTETE.read_text(encoding="utf-8")
        for nom, structure in (
            ("asl_point", _abi.Point),
            ("asl_candidat", _abi.Candidat),
            ("asl_etat_t", _abi.Etat),
        ):
            # On part du `typedef` et l'on remonte : la taille est annoncée
            # dans le commentaire qui le précède immédiatement.
            fin = texte.index(f"}} {nom};")
            avant = texte[:fin]
            annonce = None
            for trouve in re.finditer(r"(\d+) octets\.", avant):
                annonce = trouve
            self.assertIsNotNone(annonce, f"l'en-tête n'annonce pas la taille de {nom}")
            self.assertEqual(
                ctypes.sizeof(structure),
                int(annonce.group(1)),
                f"{nom} : Python et l'en-tête ne comptent pas pareil",
            )

    def test_l_ordre_des_champs_suit_l_entete(self):
        # **UN CHAMP DÉPLACÉ NE CHANGE PAS LA TAILLE**, et ne se verrait donc
        # dans aucun des essais ci-dessus : on lirait un port là où il y a un
        # protocole, sans que rien ne proteste.
        self.assertEqual(
            [nom for nom, _type in _abi.Point._fields_],
            ["port", "protocole", "reserve"],
        )
        self.assertEqual(
            [nom for nom, _type in _abi.Candidat._fields_],
            ["adresse", "port", "protocole", "famille", "origine", "verdict", "reserve"],
        )
        self.assertEqual(
            [nom for nom, _type in _abi.Etat._fields_],
            ["attaches", "ruptures", "attachee", "abandonnee", "reserve"],
        )


if __name__ == "__main__":
    unittest.main()
