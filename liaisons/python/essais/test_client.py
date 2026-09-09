"""La surface Python, appelée comme un porteur l'appellerait.

CE QUI EST ÉPROUVÉ ICI, ET QUI NE L'EST NULLE PART AILLEURS
============================================================

Ce qui est derrière l'ABI est couvert : la politique de reprise à 100 %, le
transport de bout en bout, la frontière FFI elle-même. **Ce qui n'est couvert
nulle part est la traduction** — un code de retour devenu exception, un pointeur
opaque devenu objet, un tableau C devenu liste ordonnée.

Ce sont exactement les fautes qui ne se voient pas : `Refuse` levé là où l'ABI
disait `Injoignable` n'empêche rien de tourner, il envoie seulement chercher au
mauvais endroit.
"""

from __future__ import annotations

import gc
import ipaddress
import threading
import unittest

import asl

# Un identifiant de machine VALIDE — préfixe et somme de contrôle compris.
#
# Il est recopié plutôt que calculé : le calculer demanderait de réimplémenter
# l'alphabet de Crockford et la somme de contrôle d'`asl-id` dans cette liaison,
# c'est-à-dire d'en faire une seconde copie qui divergerait. Si `asl-id` change
# de forme un jour, cet essai le dira — bruyamment, ce qui est le bon moment.
MACHINE = "m-0H248H248H248H248H248H248H"
GRAINE = bytes(range(32))


def client_configure(**extra) -> asl.Client:
    """Un client dont la racine est illisible : de quoi atteindre `Configuration`."""
    return asl.Client(
        annuaires=[("127.0.0.1:1", "localhost")],
        racines=b"pas un PEM",
        **extra,
    )


class LaVersion(unittest.TestCase):
    def test_elle_vient_de_la_bibliotheque_native(self):
        # **C'EST CELLE QUI COMPTE** : le paquet Python n'est qu'un habillage, et
        # deux versions qui divergeraient se verraient ici.
        self.assertEqual(asl.version(), (0, 1, 0))


class LesErreurs(unittest.TestCase):
    def test_chaque_code_a_sa_classe_et_toutes_descendent_d_erreur(self):
        # `asl.Erreur` doit suffire à tout attraper : un porteur qui écrit
        # `except asl.Erreur` ne doit pas voir passer autre chose.
        for classe in (
            asl.MauvaisArgument,
            asl.Configuration,
            asl.Injoignable,
            asl.Refuse,
            asl.Interne,
            asl.PasDIdentite,
            asl.Deja,
        ):
            self.assertTrue(issubclass(classe, asl.Erreur), classe.__name__)
            self.assertLess(classe.code, 0, classe.__name__)

        codes = {classe.code for classe in asl.Erreur.__subclasses__()}
        self.assertEqual(len(codes), 7, "deux classes partagent un code")

    def test_le_message_vient_de_la_bibliotheque_et_non_d_une_copie(self):
        # **DEUX LISTES DE MESSAGES FINIRAIENT PAR DIVERGER**, et c'est celle
        # qu'on oublie de corriger que l'utilisateur lirait.
        message = str(asl.Injoignable())
        self.assertIn("repondu", message, message)
        self.assertNotEqual(message, "")


class LaConstruction(unittest.TestCase):
    def test_un_client_neuf_n_ouvre_rien_et_son_etat_est_a_zero(self):
        with asl.Client() as client:
            etat = client.etat()
            self.assertFalse(etat.attachee)
            self.assertEqual(etat.attaches, 0)
            self.assertEqual(etat.ruptures, 0)
            self.assertFalse(
                etat.abandonnee, "n'avoir rien tenté n'est pas avoir renoncé"
            )

    def test_une_adresse_illisible_leve_et_ne_laisse_rien_derriere(self):
        # **CE QUI EST OUVERT SE FERME MÊME QUAND LE CONSTRUCTEUR ÉCHOUE** :
        # sinon l'objet natif fuit, et aucun ramasse-miettes ne sait le libérer.
        for mauvaise in (
            "nitrogen.example:6630",  # un NOM : la résolution appartient à l'appelant
            "203.0.113.7",  # pas de port
            "2001:db8::1:6630",  # sans crochets, c'est ambigu
            "",
        ):
            with self.assertRaises(asl.MauvaisArgument, msg=mauvaise):
                asl.Client(annuaires=[(mauvaise, "localhost")])

    def test_une_adresse_litterale_des_deux_familles_est_acceptee(self):
        with asl.Client(
            annuaires=[
                ("203.0.113.7:6630", "nitrogen.example"),
                ("[2001:db8::1]:6630", "nitrogen.example"),
            ]
        ) as client:
            self.assertIsNotNone(client)

    def test_des_racines_en_texte_sont_refusees_avant_la_frontiere(self):
        # Le refus vient de Python, et il nomme la faute : `ctypes` aurait rendu
        # un `ArgumentError` illisible.
        with asl.Client() as client:
            with self.assertRaises(asl.MauvaisArgument):
                client.poser_racines("-----BEGIN CERTIFICATE-----")

    def test_une_graine_de_mauvaise_taille_est_refusee_avec_les_deux_nombres(self):
        with asl.Client() as client:
            with self.assertRaises(asl.MauvaisArgument) as leve:
                client.poser_identite(MACHINE, b"trop court")
            self.assertIn("32", str(leve.exception))

    def test_un_nul_au_milieu_d_une_chaine_est_refuse(self):
        # **`ctypes` TRONQUERAIT EN SILENCE**, et l'annuaire recevrait un nom
        # plus court que celui qu'on croit lui avoir donné.
        with asl.Client() as client:
            with self.assertRaises(asl.MauvaisArgument):
                client.ajouter_annuaire("127.0.0.1:1\x00tricherie", "localhost")


class LAnnonce(unittest.TestCase):
    def test_sans_identite_on_ne_peut_rien_signer(self):
        with client_configure() as client:
            with self.assertRaises(asl.PasDIdentite):
                client.annoncer("depot", [asl.Point(asl.Protocole.TCP, 8080)])

    def test_un_port_hors_bornes_est_refuse_a_la_construction_du_point(self):
        # Le refus est dans `Point`, donc AVANT qu'un client existe : un porteur
        # l'apprend en écrivant sa configuration.
        for port in (0, -1, 65536):
            with self.assertRaises(asl.MauvaisArgument, msg=str(port)):
                asl.Point(asl.Protocole.TCP, port)

    def test_une_annonce_sans_point_n_annonce_rien(self):
        with client_configure(identite=(MACHINE, GRAINE)) as client:
            with self.assertRaises(asl.MauvaisArgument):
                client.annoncer("depot", [])

    def test_un_client_n_annonce_qu_une_fois(self):
        with client_configure(identite=(MACHINE, GRAINE)) as client:
            client.annoncer("depot", [asl.Point(asl.Protocole.TCP, 8080)])
            with self.assertRaises(asl.Deja):
                client.annoncer("depot", [asl.Point(asl.Protocole.TCP, 8081)])

    def test_le_fil_natif_tourne_sans_que_personne_l_attende(self):
        # **C'EST L'ESSAI QUI COMPTE LE PLUS.** `annoncer` a rendu la main et
        # l'appelant est parti ; si le fil natif ne tournait pas, `abandonnee` ne
        # passerait jamais à vrai — et rien ici ne lèverait.
        with client_configure(identite=(MACHINE, GRAINE)) as client:
            client.annoncer("depot", [asl.Point(asl.Protocole.TCP, 8080)])
            for _ in range(250):
                etat = client.etat()
                if etat.abandonnee:
                    break
                threading.Event().wait(0.02)
            self.assertTrue(
                etat.abandonnee,
                "le fil natif n'a pas tourné, ou la racine illisible a été acceptée",
            )
            self.assertFalse(etat.attachee)
            self.assertEqual(etat.attaches, 0)

    def test_l_identite_survit_a_l_annonce(self):
        # L'annonce CONSOMME une identité côté Rust ; si le client la perdait,
        # `ou` répondrait « aucune identité » à un daemon qui vient de s'annoncer.
        with client_configure(identite=(MACHINE, GRAINE)) as client:
            client.annoncer("depot", [asl.Point(asl.Protocole.TCP, 8080)])
            with self.assertRaises(asl.Configuration):
                client.ou(MACHINE, "depot")


class LaFermeture(unittest.TestCase):
    def test_fermer_deux_fois_ne_fait_rien_la_seconde(self):
        client = asl.Client()
        client.fermer()
        client.fermer()

    def test_un_client_ferme_le_dit_au_lieu_de_deferencer_le_neant(self):
        # **DÉRÉFÉRENCER UN POINTEUR LIBÉRÉ TUERAIT L'INTERPRÉTEUR.** Ici la
        # sanction est une exception, et elle nomme la cause.
        client = asl.Client()
        client.fermer()
        with self.assertRaises(asl.Erreur) as leve:
            client.etat()
        self.assertIn("fermé", str(leve.exception))

    def test_le_destructeur_est_un_filet_et_il_tient(self):
        client = client_configure(identite=(MACHINE, GRAINE))
        client.annoncer("depot", [asl.Point(asl.Protocole.TCP, 8080)])
        del client
        gc.collect()


class LesTypesRendus(unittest.TestCase):
    def test_un_point_se_lit_comme_on_l_ecrit_dans_asl(self):
        self.assertEqual(str(asl.Point(asl.Protocole.TCP, 8080)), "tcp:8080")
        self.assertEqual(str(asl.Point(asl.Protocole.UDP, 9000)), "udp:9000")

    def test_un_candidat_v6_porte_ses_crochets(self):
        # Sans eux, `2001:db8::1:8080` est ambigu, et ce qu'on affiche ne se
        # recopie pas dans une commande.
        six = asl.Candidat(
            protocole=asl.Protocole.TCP,
            adresse=ipaddress.IPv6Address("2001:db8::1"),
            port=8080,
            origine=asl.Origine.REFLEXIF,
            verdict=asl.Verdict.EN_COURS,
        )
        self.assertEqual(str(six), "[2001:db8::1]:8080")

        quatre = asl.Candidat(
            protocole=asl.Protocole.TCP,
            adresse=ipaddress.IPv4Address("203.0.113.7"),
            port=8080,
            origine=asl.Origine.ANNONCE,
            verdict=asl.Verdict.JOIGNABLE,
        )
        self.assertEqual(str(quatre), "203.0.113.7:8080")

    def test_le_verdict_garde_ses_quatre_valeurs(self):
        # **TROIS D'ENTRE ELLES NE VEULENT PAS DIRE « ÇA NE MARCHE PAS ».** Les
        # aplatir en un booléen ferait écarter un candidat parfaitement bon.
        self.assertEqual(len(asl.Verdict), 4)
        self.assertFalse(
            hasattr(asl.Candidat, "joignable"),
            "une propriété `joignable` serait juste une fois sur deux",
        )


class LaLiaisonNAucuneDependance(unittest.TestCase):
    def test_elle_n_importe_que_la_bibliotheque_standard(self):
        # **CE QU'ELLE TIRE, SES PORTEURS L'INSTALLENT.** Un daemon qui embarque
        # cette liaison ne doit hériter d'aucun paquet.
        import pathlib
        import sys

        paquet = pathlib.Path(asl.__file__).parent
        interdits = set()
        for fichier in paquet.glob("*.py"):
            for ligne in fichier.read_text(encoding="utf-8").splitlines():
                depouillee = ligne.strip()
                nom = None
                if depouillee.startswith("import "):
                    nom = depouillee.removeprefix("import ").split()[0]
                elif depouillee.startswith("from ") and " import " in depouillee:
                    nom = depouillee.removeprefix("from ").split()[0]
                if not nom or nom.startswith("."):
                    continue
                racine = nom.split(".")[0]
                if racine == "asl":
                    continue
                if racine not in sys.stdlib_module_names:
                    interdits.add(racine)
        self.assertEqual(interdits, set(), "dépendances hors bibliothèque standard")


if __name__ == "__main__":
    unittest.main()
