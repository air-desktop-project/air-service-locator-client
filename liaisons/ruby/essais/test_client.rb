# frozen_string_literal: true

# La surface Ruby, appelée comme un porteur l'appellerait.
#
# CE QUI EST ÉPROUVÉ ICI, ET QUI NE L'EST NULLE PART AILLEURS
# ===========================================================
#
# Ce qui est derrière l'ABI est couvert : la politique de reprise à 100 %, le
# transport de bout en bout, la frontière FFI elle-même, et la liaison Python.
# **Ce qui n'est couvert nulle part est la traduction en Ruby** — un code de
# retour devenu exception, un pointeur opaque devenu objet, un finaliseur qui ne
# doit pas voir `self`, et un GVL qui doit être relâché.
#
# Ce sont les fautes qui ne se voient pas : `Refuse` levé là où l'ABI disait
# `Injoignable` n'empêche rien de tourner, il envoie seulement chercher au
# mauvais endroit.

require "minitest/autorun"
require "openssl"
require "socket"

require "asl"

# Un identifiant de machine VALIDE — préfixe et somme de contrôle compris.
#
# Il est recopié plutôt que calculé : le calculer demanderait de réimplémenter
# l'alphabet de Crockford et la somme de contrôle d'`asl-id` dans cette liaison,
# c'est-à-dire d'en faire une seconde copie qui divergerait. Si `asl-id` change de
# forme un jour, cet essai le dira — bruyamment, ce qui est le bon moment.
MACHINE = "m-0H248H248H248H248H248H248H"
GRAINE = (0...32).map(&:chr).join.b

module Aide
  # Un client dont la racine est illisible : de quoi atteindre `Configuration`.
  def client_configure(**extra)
    Asl::Client.new(
      annuaires: [["127.0.0.1:1", "localhost"]],
      racines: "pas un PEM",
      **extra
    )
  end

  # Une racine que `rustls` sait LIRE.
  #
  # Elle est fabriquée à l'essai plutôt que rangée dans le dépôt : un certificat
  # committé expire un jour, et l'essai se met alors à échouer pour une raison
  # qui n'a rien à voir avec ce qu'il éprouve. `openssl` est dans la distribution
  # de Ruby — ici seulement, jamais dans la bibliothèque.
  def racine_lisible
    cle = OpenSSL::PKey::EC.generate("prime256v1")
    nom = OpenSSL::X509::Name.parse("/CN=banc-asl-ruby")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = nom
    cert.issuer = nom
    cert.public_key = cle
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 3600
    extensions = OpenSSL::X509::ExtensionFactory.new(cert, cert)
    cert.add_extension(extensions.create_extension("basicConstraints", "CA:TRUE", true))
    cert.add_extension(extensions.create_extension("keyUsage", "keyCertSign,cRLSign", true))
    cert.sign(cle, OpenSSL::Digest.new("SHA256"))
    cert.to_pem
  end
end

class LaVersion < Minitest::Test
  def test_elle_vient_de_la_bibliotheque_native
    # **C'EST CELLE QUI COMPTE** : la gemme n'est qu'un habillage, et deux
    # versions qui divergeraient se verraient ici.
    assert_equal [0, 1, 0], Asl.version
  end
end

class LesErreurs < Minitest::Test
  CLASSES = [
    Asl::MauvaisArgument, Asl::Configuration, Asl::Injoignable,
    Asl::Refuse, Asl::Interne, Asl::PasDIdentite, Asl::Deja
  ].freeze

  def test_chaque_code_a_sa_classe_et_toutes_descendent_d_erreur
    # `rescue Asl::Erreur` doit suffire à tout attraper.
    CLASSES.each do |classe|
      assert_operator classe, :<, Asl::Erreur
      assert_operator classe.code, :<, 0, classe.name
    end
    assert_equal CLASSES.size, CLASSES.map(&:code).uniq.size,
                 "deux classes partagent un code"
  end

  def test_toutes_descendent_de_standard_error
    # **`rescue => e` SANS CLASSE N'ATTRAPE QUE `StandardError`.** Une exception
    # qui en sortirait échapperait à tous les `rescue` ordinaires d'un porteur.
    CLASSES.each { |classe| assert_operator classe, :<, StandardError }
  end

  def test_le_message_vient_de_la_bibliotheque_et_non_d_une_copie
    # **DEUX LISTES DE MESSAGES FINIRAIENT PAR DIVERGER**, et c'est celle qu'on
    # oublie de corriger que l'utilisateur lirait.
    message = Asl::Injoignable.new.message

    assert_includes message, "repondu"
    refute_empty message
  end
end

class LaConstruction < Minitest::Test
  include Aide

  def test_un_client_neuf_n_ouvre_rien_et_son_etat_est_a_zero
    Asl::Client.ouvrir do |client|
      etat = client.etat

      refute_predicate etat, :attachee?
      assert_equal 0, etat.attaches
      assert_equal 0, etat.ruptures
      refute_predicate etat, :abandonnee?
    end
  end

  def test_une_adresse_illisible_leve_et_ne_laisse_rien_derriere
    # **CE QUI EST OUVERT SE FERME MÊME QUAND LE CONSTRUCTEUR ÉCHOUE** : sinon
    # l'objet natif fuit, et aucun ramasse-miettes ne sait le libérer.
    [
      "nitrogen.example:6630", # un NOM : la résolution appartient à l'appelant
      "203.0.113.7",           # pas de port
      "2001:db8::1:6630",      # sans crochets, c'est ambigu
      ""
    ].each do |mauvaise|
      assert_raises(Asl::MauvaisArgument, mauvaise) do
        Asl::Client.new(annuaires: [[mauvaise, "localhost"]])
      end
    end
  end

  def test_une_adresse_litterale_des_deux_familles_est_acceptee
    Asl::Client.ouvrir(annuaires: [["203.0.113.7:6630", "nitrogen.example"],
                                   ["[2001:db8::1]:6630", "nitrogen.example"]]) do |client|
      assert_predicate client, :ouvert?
    end
  end

  def test_des_racines_qui_ne_sont_pas_des_octets_sont_refusees
    Asl::Client.ouvrir do |client|
      assert_raises(Asl::MauvaisArgument) { client.poser_racines(:pem) }
    end
  end

  def test_une_graine_de_mauvaise_taille_est_refusee_avec_les_deux_nombres
    Asl::Client.ouvrir do |client|
      leve = assert_raises(Asl::MauvaisArgument) { client.poser_identite(MACHINE, "court") }

      assert_includes leve.message, "32"
    end
  end

  def test_un_nul_au_milieu_d_une_chaine_est_refuse
    # **LE C S'ARRÊTERAIT AU PREMIER**, et l'annuaire recevrait un nom plus court
    # que celui qu'on croit lui avoir donné.
    Asl::Client.ouvrir do |client|
      assert_raises(Asl::MauvaisArgument) do
        client.ajouter_annuaire("127.0.0.1:1\0tricherie", "localhost")
      end
    end
  end
end

class LAnnonce < Minitest::Test
  include Aide

  def test_sans_identite_on_ne_peut_rien_signer
    Asl::Client.ouvrir(annuaires: [["127.0.0.1:1", "localhost"]],
                       racines: "pas un PEM") do |client|
      assert_raises(Asl::PasDIdentite) do
        client.annoncer("depot", [Asl::Point.new(:tcp, 8080)])
      end
    end
  end

  def test_un_point_mal_forme_est_refuse_a_sa_construction
    # Le refus est dans `Point`, donc AVANT qu'un client existe : un porteur
    # l'apprend en écrivant sa configuration.
    [0, -1, 65_536, "8080"].each do |port|
      assert_raises(Asl::MauvaisArgument, port.inspect) { Asl::Point.new(:tcp, port) }
    end
    assert_raises(Asl::MauvaisArgument) { Asl::Point.new(:sctp, 8080) }
  end

  def test_une_annonce_sans_point_n_annonce_rien
    client = client_configure(identite: [MACHINE, GRAINE])
    assert_raises(Asl::MauvaisArgument) { client.annoncer("depot", []) }
  ensure
    client&.fermer
  end

  def test_un_client_n_annonce_qu_une_fois
    client = client_configure(identite: [MACHINE, GRAINE])
    client.annoncer("depot", [Asl::Point.new(:tcp, 8080)])
    assert_raises(Asl::Deja) { client.annoncer("depot", [Asl::Point.new(:tcp, 8081)]) }
  ensure
    client&.fermer
  end

  def test_le_fil_natif_tourne_sans_que_personne_l_attende
    # **C'EST L'ESSAI QUI COMPTE LE PLUS.** `annoncer` a rendu la main et
    # l'appelant est parti ; si le fil natif ne tournait pas, `abandonnee` ne
    # passerait jamais à vrai — et rien ici ne lèverait.
    client = client_configure(identite: [MACHINE, GRAINE])
    client.annoncer("depot", [Asl::Point.new(:tcp, 8080)])

    etat = nil
    250.times do
      etat = client.etat
      break if etat.abandonnee?

      sleep 0.02
    end

    assert_predicate etat, :abandonnee?,
                     "le fil natif n'a pas tourné, ou la racine illisible a été acceptée"
    refute_predicate etat, :attachee?
    assert_equal 0, etat.attaches
  ensure
    client&.fermer
  end

  def test_l_identite_survit_a_l_annonce
    # L'annonce CONSOMME une identité côté Rust ; si le client la perdait, `ou`
    # répondrait « aucune identité » à un daemon qui vient de s'annoncer.
    client = client_configure(identite: [MACHINE, GRAINE])
    client.annoncer("depot", [Asl::Point.new(:tcp, 8080)])
    assert_raises(Asl::Configuration) { client.ou(MACHINE, "depot") }
  ensure
    client&.fermer
  end
end

class LeGvl < Minitest::Test
  include Aide

  def test_il_est_relache_pendant_un_appel_qui_bloque
    # **C'EST LA SEULE CHOSE QUI POURRAIT FIGER TOUTE UNE APPLICATION RUBY**, et
    # elle ne se voit pas autrement : avec le GVL tenu, tout compile, tout passe,
    # et le serveur web de l'hôte cesse de répondre pendant vingt secondes.
    #
    # Le montage : un pair MUET, donc une poignée de main qui n'aboutit pas ; le
    # fil natif reste dedans, et `fermer` attend deux secondes avant de
    # l'interrompre. Pendant ce temps, un fil Ruby doit AVANCER.
    muet = UDPSocket.new
    muet.bind("127.0.0.1", 0)
    port = muet.addr[1]

    client = Asl::Client.new(
      annuaires: [["127.0.0.1:#{port}", "localhost"]],
      racines: racine_lisible,
      identite: [MACHINE, GRAINE]
    )
    client.annoncer("depot", [Asl::Point.new(:tcp, 8080)])

    tours = 0
    continuer = true
    temoin = Thread.new { tours += 1 while continuer }
    sleep 0.05 # que le témoin soit bien parti

    # **LE DELTA, ET NON LE TOTAL.** Le témoin tourne déjà depuis un instant : son
    # compteur est haut avant même qu'on appelle. Ce qu'on mesure est ce qu'il
    # gagne PENDANT l'appel bloquant, et rien d'autre.
    avant = tours
    depart = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    client.fermer
    ecoule = Process.clock_gettime(Process::CLOCK_MONOTONIC) - depart
    pendant = tours - avant

    continuer = false
    temoin.join

    assert_operator ecoule, :>, 1.0,
                    "`fermer` n'a pas attendu : le montage n'éprouve rien"
    assert_operator pendant, :>, 1_000,
                    "le fil témoin n'a gagné que #{pendant} tours en " \
                    "#{ecoule.round(2)} s — le GVL n'a pas été relâché"
  ensure
    muet&.close
  end
end

class LaFermeture < Minitest::Test
  include Aide

  def test_fermer_deux_fois_ne_fait_rien_la_seconde
    client = Asl::Client.new
    client.fermer
    client.fermer

    refute_predicate client, :ouvert?
  end

  def test_un_client_ferme_le_dit_au_lieu_de_dereferencer_le_neant
    # **DÉRÉFÉRENCER UN POINTEUR LIBÉRÉ TUERAIT L'INTERPRÉTEUR.** Ici la sanction
    # est une exception, et elle nomme la cause.
    client = Asl::Client.new
    client.fermer
    leve = assert_raises(Asl::Erreur) { client.etat }

    assert_includes leve.message, "fermé"
  end

  def test_la_forme_a_bloc_ferme_meme_quand_le_bloc_leve
    dehors = nil
    assert_raises(RuntimeError) do
      Asl::Client.ouvrir do |client|
        dehors = client
        raise "quelque chose"
      end
    end
    refute_predicate dehors, :ouvert?
  end

  def test_le_finaliseur_libere_une_fois_et_une_seule
    # **UN FINALISEUR NE DOIT PAS VOIR `self`** : une lambda qui le capturerait le
    # garderait vivant pour toujours, et ne s'exécuterait donc jamais. C'est
    # pourquoi la fabrique est une méthode de CLASSE — et pourquoi elle s'éprouve
    # ici sans ramasse-miettes, donc sans hasard.
    liberes = []
    boite = [0x1234]
    finaliseur = Asl::Client.finaliseur(boite, ->(brut) { liberes << brut })

    finaliseur.call

    assert_equal [0x1234], liberes
    assert_nil boite[0]

    finaliseur.call

    assert_equal 1, liberes.size, "une double libération est un usage-après-libération"
  end
end

class LesTypesRendus < Minitest::Test
  def test_un_point_se_lit_comme_on_l_ecrit_dans_asl
    assert_equal "tcp:8080", Asl::Point.new(:tcp, 8080).to_s
    assert_equal "udp:9000", Asl::Point.new(:udp, 9000).to_s
  end

  def test_un_candidat_v6_porte_ses_crochets
    # Sans eux, `2001:db8::1:8080` est ambigu, et ce qu'on affiche ne se recopie
    # pas dans une commande.
    six = Asl::Candidat.new(protocole: :tcp, adresse: "2001:db8::1", port: 8080,
                            origine: :reflexif, verdict: :en_cours)

    assert_equal "[2001:db8::1]:8080", six.to_s

    quatre = Asl::Candidat.new(protocole: :tcp, adresse: "203.0.113.7", port: 8080,
                               origine: :annonce, verdict: :joignable)

    assert_equal "203.0.113.7:8080", quatre.to_s
  end

  def test_le_verdict_garde_ses_quatre_valeurs_et_il_n_y_a_pas_de_predicat
    # **TROIS D'ENTRE ELLES NE VEULENT PAS DIRE « ÇA NE MARCHE PAS ».** Un
    # `joignable?` les aplatirait, et ferait écarter un candidat parfaitement bon.
    assert_equal 4, Asl::VERDICTS.size
    refute_includes Asl::Candidat.instance_methods, :joignable?
  end

  def test_les_valeurs_sont_des_symboles_et_non_les_entiers_de_l_abi
    # `:tcp` se lit, s'écrit et s'inspecte ; `1` demande d'aller voir l'en-tête.
    assert_equal %i[tcp udp].sort, Asl::PROTOCOLES.values.sort
    assert_equal %i[reflexif annonce].sort, Asl::ORIGINES.values.sort
    assert_equal Asl::Abi::TCP, Asl::Point.new(:tcp, 1).protocole_brut
  end
end

class LaLiaisonNAucuneDependance < Minitest::Test
  def test_elle_ne_charge_que_la_distribution_de_ruby
    # **CE QU'ELLE TIRE, SES PORTEURS L'INSTALLENT.** Un daemon qui embarque
    # cette liaison ne doit hériter d'aucune gemme — et surtout pas d'une
    # extension native, qui compilerait du C dans son environnement.
    racine = File.expand_path("../lib", __dir__)
    tirees = Dir.glob(File.join(racine, "**", "*.rb")).flat_map do |fichier|
      File.readlines(fichier).filter_map do |ligne|
        ligne.strip[/\Arequire\s+["']([\w\/]+)["']/, 1]
      end
    end.uniq

    autorisees = %w[fiddle ipaddr objspace]

    assert_equal [], tirees - autorisees, "dépendances hors de la distribution"
  end
end

class LesVerdictsPousses < Minitest::Test
  include Aide

  def test_rien_recu_n_est_pas_une_erreur
    # **`nil` N'EST PAS UNE EXCEPTION**, et c'est délibéré : ne rien avoir reçu
    # est le cas ORDINAIRE — l'annuaire ne pousse que ce qui a CHANGÉ. Lever ici
    # obligerait à envelopper d'un `rescue` la boucle qu'on appelle chaque
    # seconde.
    Asl::Client.ouvrir do |client|
      assert_equal 0, client.poussees_recues
      assert_nil client.derniere_poussee
    end
  end

  def test_le_verdict_de_nat_a_trois_valeurs
    # **ET NON UN BOOLÉEN** : sans adresse locale annoncée, il n'y a rien à
    # comparer, et répondre « non » serait affirmer ce qu'on n'a pas mesuré.
    assert_equal 3, Asl::VERDICTS_DE_NAT.size
    assert_equal %i[non oui indetermine].sort, Asl::VERDICTS_DE_NAT.values.sort
    refute_includes Asl::VERDICTS_DE_NAT.keys, 0, "zéro n'est pas un verdict"
  end

  def test_une_poussee_porte_ses_candidats_et_son_nat
    poussee = Asl::Poussee.new(
      candidats: [Asl::Candidat.new(protocole: :tcp, adresse: "203.0.113.7", port: 8080,
                                    origine: :reflexif, verdict: :injoignable)],
      derriere_nat: :oui
    )

    assert_equal "203.0.113.7:8080", poussee.candidats.first.to_s
    assert_equal :oui, poussee.derriere_nat
  end

  def test_un_client_ferme_le_dit_aussi_pour_les_poussees
    client = Asl::Client.new
    client.fermer
    assert_raises(Asl::Erreur) { client.poussees_recues }
    assert_raises(Asl::Erreur) { client.derniere_poussee }
  end
end
