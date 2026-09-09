# frozen_string_literal: true

# asl — annoncer un service et retrouver un port, depuis Ruby.
#
# Un daemon qui écoute sur un port choisi au démarrage est un daemon que ses
# clients ne savent plus joindre. Cette bibliothèque est l'autre moitié : le
# daemon ANNONCE le port que le système lui a donné, et ses clients le DEMANDENT.
#
#   require "asl"
#
#   Asl::Client.ouvrir(
#     annuaires: [["203.0.113.7:6630", "nitrogen.example"]],
#     racines: File.binread("/etc/asl/ca.pem"),
#     identite: [machine, graine]
#   ) do |client|
#     client.annoncer("depot", [Asl::Point.new(:tcp, 8080)])
#     servir_pour_toujours            # l'annonce se tient toute seule
#   end
#
# ── CE QUI TOURNE EN ARRIÈRE-PLAN, ET QU'IL FAUT SAVOIR ─────────────────────
#
# **`annoncer` rend la main tout de suite et n'y revient jamais.** Un annuaire
# injoignable ne doit pas empêcher un daemon de démarrer : le service écoute déjà
# pendant que l'annonce cherche encore.
#
# Ce qui la tient est un fil NATIF, à l'intérieur de la bibliothèque — ni un
# `Thread` Ruby, ni un `Fiber`, et il ne touche jamais à l'interpréteur. Il se
# reconnecte seul, bascule sur l'autre annuaire racine quand le premier tombe, et
# n'abandonne jamais. `etat` dit où il en est.
#
# **FERMER LE CLIENT RETIRE L'ANNONCE.** La connexion EST le bail : il n'y a pas
# de « retrait » séparé à appeler. Laisser le client se faire ramasser retire donc
# l'annonce au moment où le ramasse-miettes passe — c'est-à-dire à un moment que
# l'on ne choisit pas. **Employez la forme à bloc.**
#
# ── CE QUE CETTE LIAISON N'INSTALLE PAS ─────────────────────────────────────
#
# Rien. `fiddle` est dans la distribution de Ruby ; la gemme `ffi`, elle, est une
# extension native — l'installer compilerait du C dans l'environnement de qui
# nous embarque, ce que C4 refuse par la porte d'à côté.

# `ipaddr` pour rendre une adresse lisible, `objspace` pour le finaliseur.
# Les deux sont dans la distribution de Ruby.
require "ipaddr"
require "objspace"

require_relative "asl/abi"

module Asl
  # ── LES ERREURS ─────────────────────────────────────────────────────────
  #
  # **JAMAIS UN ENTIER NÉGATIF RENDU TEL QUEL.** Un rubyiste attend une
  # exception : un code de retour qu'on oublie de tester est un bogue silencieux,
  # une exception qu'on oublie de rattraper remonte et se voit.

  # La racine de tout ce que cette bibliothèque lève.
  #
  # `rescue Asl::Erreur` suffit à tout attraper ; les sous-classes servent à
  # distinguer ce qui se corrige différemment.
  class Erreur < StandardError
    # Le code de l'ABI correspondant. Zéro pour la racine, qui n'en a pas.
    def self.code = 0

    def initialize(message = nil)
      super(message || Asl.phrase(self.class.code))
    end
  end

  # Un argument que l'ABI refuse : une adresse illisible, un port nul.
  class MauvaisArgument < Erreur
    def self.code = Abi::ARGUMENT
  end

  # Il manque un annuaire, une racine, ou la racine ne se lit pas.
  #
  # **CE N'EST PAS UNE PANNE**, et c'est pourquoi elle est distincte
  # d'{Injoignable} : réessayer ne la réparerait jamais.
  class Configuration < Erreur
    def self.code = Abi::CONFIGURATION
  end

  # Personne n'a répondu.
  #
  # **UN CÂBLE DÉBRANCHÉ, ET NON UN DROIT MANQUANT** — voir {Refuse}. Les deux se
  # corrigent à des endroits opposés.
  class Injoignable < Erreur
    def self.code = Abi::INJOIGNABLE
  end

  # L'annuaire a compris, et il a dit non.
  class Refuse < Erreur
    def self.code = Abi::REFUSE
  end

  # L'impossible est arrivé, et la bibliothèque l'a rattrapé.
  #
  # **ELLE N'A PAS TUÉ LE PROCESSUS**, et c'est délibéré : une panique qui
  # traverse la frontière avorterait l'interpréteur entier.
  class Interne < Erreur
    def self.code = Abi::INTERNE
  end

  # Cette machine n'a pas d'identité : enrôlez-la, ou posez-en une.
  class PasDIdentite < Erreur
    def self.code = Abi::PAS_D_IDENTITE
  end

  # Ce client annonce déjà.
  #
  # Un second appel ne remplace pas la première annonce en silence — ce qui la
  # retirerait.
  class Deja < Erreur
    def self.code = Abi::DEJA
  end

  # L'objet natif est introuvable.
  BibliothequeIntrouvable = Abi::BibliothequeIntrouvable

  PAR_CODE = [
    MauvaisArgument, Configuration, Injoignable, Refuse, Interne, PasDIdentite, Deja
  ].each_with_object({}) { |classe, table| table[classe.code] = classe }.freeze

  # ── CE QUI TRAVERSE ─────────────────────────────────────────────────────
  #
  # **DES SYMBOLES, ET NON LES ENTIERS DE L'ABI.** `:tcp` se lit, s'écrit et
  # s'inspecte ; `1` demande d'aller voir l'en-tête. La table est ici, une fois.

  PROTOCOLES = { Abi::TCP => :tcp, Abi::UDP => :udp }.freeze
  ORIGINES = { Abi::REFLEXIF => :reflexif, Abi::ANNONCE => :annonce }.freeze
  # **TROIS VALEURS, ET NON UN BOOLÉEN.** Sans adresse locale annoncée, il n'y a
  # rien à comparer — et répondre « non » serait affirmer ce qu'on n'a pas
  # mesuré. Un daemon derrière un NAT qui lirait « non » chercherait la panne
  # partout sauf là où elle est.
  VERDICTS_DE_NAT = {
    Abi::NAT_NON => :non,
    Abi::NAT_OUI => :oui,
    Abi::NAT_INDETERMINE => :indetermine
  }.freeze

  VERDICTS = {
    Abi::JOIGNABLE => :joignable,
    Abi::INJOIGNABLE_POINT => :injoignable,
    Abi::NON_SONDE => :non_sonde,
    Abi::EN_COURS => :en_cours
  }.freeze

  # Un point d'écoute à annoncer.
  Point = Data.define(:protocole, :port) do
    def initialize(protocole:, port:)
      unless PROTOCOLES.value?(protocole)
        raise MauvaisArgument, "#{protocole.inspect} n'est ni :tcp ni :udp"
      end
      raise MauvaisArgument, "#{port.inspect} n'est pas un port" unless
        port.is_a?(Integer) && port.between?(1, 65_535)

      super
    end

    # Le code de l'ABI pour ce protocole.
    def protocole_brut = PROTOCOLES.key(protocole)

    def to_s = "#{protocole}:#{port}"
  end

  # Où joindre un service, et ce que l'annuaire en sait.
  #
  # **IL N'Y A PAS DE `joignable?`**, et c'est délibéré : le verdict a QUATRE
  # valeurs, et trois d'entre elles ne veulent pas dire « ça ne marche pas ».
  # `:en_cours` n'affirme rien — l'annuaire répond avant d'avoir sondé, pour ne
  # pas faire attendre le démarrage d'un daemon. `:non_sonde` dit qu'il ne
  # mesurera pas : UDP n'a pas de poignée de main, donc une sonde n'y
  # distinguerait pas « écoute et ignore » de « rien n'écoute ».
  #
  # Un prédicat les aplatirait, et ferait écarter un candidat parfaitement bon.
  Candidat = Data.define(:protocole, :adresse, :port, :origine, :verdict) do
    # La forme qu'on recopie dans une commande — **avec ses crochets**.
    #
    # Sans eux, `2001:db8::1:8080` est ambigu : le dernier `:` sépare-t-il un
    # port ou un groupe d'adresse ?
    def to_s
      adresse.include?(":") ? "[#{adresse}]:#{port}" : "#{adresse}:#{port}"
    end
  end

  # Ce que l'annuaire a MESURÉ depuis, et poussé sur la connexion tenue.
  #
  # **ELLE PORTE LA LISTE ENTIÈRE, ET NON UN DELTA** : la dernière remplace tout
  # ce qui précède.
  Poussee = Data.define(:candidats, :derriere_nat)

  # Ce que l'annonce a fait jusqu'ici.
  Etat = Data.define(:attachee, :attaches, :ruptures, :abandonnee) do
    # L'annuaire nous connaît EN CE MOMENT : authentifiés ET annoncés.
    #
    # **Ce n'est pas « la socket est ouverte »** : une connexion qui s'ouvre puis
    # se fait refuser l'authentification n'annonce rien, et ceci reste faux.
    def attachee? = attachee

    # La tâche a renoncé, et ne réessaiera pas.
    #
    # **Elle ne renonce que sur une faute de configuration** — une racine
    # illisible, aucun annuaire. Jamais sur une panne de réseau, quelle qu'en soit
    # la durée. C'est le seul état dont un humain doit être averti.
    def abandonnee? = abandonnee
  end

  # ── LA BIBLIOTHÈQUE, CHARGÉE UNE FOIS ───────────────────────────────────

  @verrou_chargement = Mutex.new
  @fonctions = nil

  class << self
    # Charge l'objet natif au premier besoin, et une seule fois.
    def fonctions
      @verrou_chargement.synchronize { @fonctions ||= Abi.charger }
    end

    # Ce que la bibliothèque NATIVE dit d'un code.
    #
    # **LA PHRASE VIENT DE LÀ-BAS, ET N'EST PAS RECOPIÉE ICI.** Deux listes de
    # messages finiraient par diverger, et c'est celle qu'on oublie de corriger
    # que l'utilisateur lirait.
    def phrase(code)
      brute = fonctions[:asl_faute_texte].call(code)
      brute.null? ? "code #{code}" : brute.to_s
    rescue StandardError
      # Un message ne doit jamais faire échouer ce qu'il décrit.
      "code #{code}"
    end

    # La version de la bibliothèque NATIVE, et non de cette gemme.
    #
    # C'est celle qui compte : la gemme n'est qu'un habillage, et deux versions
    # qui divergeraient se verraient ici.
    def version
      tampons = Array.new(3) { Fiddle::Pointer.malloc(4, Fiddle::RUBY_FREE) }
      fonctions[:asl_version].call(*tampons)
      tampons.map { |tampon| tampon[0, 4].unpack1("L") }
    end

    # Lève ce qu'il faut, ou ne fait rien.
    def verifier(code)
      return if code == Abi::OK

      classe = PAR_CODE[code]
      raise Erreur, "code inattendu #{code} : #{phrase(code)}" if classe.nil?

      raise classe
    end

    # Une chaîne C, terminée par NUL.
    #
    # **UN NUL AU MILIEU EST REFUSÉ ICI**, et non transmis : le C s'arrêterait au
    # premier, et l'annuaire recevrait un nom de service plus court que celui
    # qu'on croit lui avoir donné.
    def chaine(texte)
      raise MauvaisArgument, "#{texte.inspect} n'est pas une chaîne" unless texte.is_a?(String)

      octets = texte.dup.force_encoding(Encoding::BINARY)
      raise MauvaisArgument, "un NUL au milieu d'une chaîne" if octets.include?("\0")

      octets
    end
  end

  # ── LE CLIENT ───────────────────────────────────────────────────────────

  # Combien de candidats on demande d'emblée.
  #
  # **LE DIMENSIONNEMENT EN DEUX TEMPS DU C COÛTERAIT DEUX ALLERS-RETOURS ICI** :
  # `asl_ou` refait la requête à chaque appel, il ne garde pas de résultat. On
  # demande donc large — le protocole borne un service à huit points d'écoute —,
  # et l'on ne paie une seconde requête que si cette borne changeait un jour.
  CANDIDATS_D_EMBLEE = 8

  # Un client d'annuaire : il annonce, il résout, il tient sa connexion.
  #
  # **IL SE FERME**, et le fermer retire l'annonce. Employez {Client.ouvrir}.
  class Client
    # Monte un client, le passe au bloc, et le ferme quoi qu'il arrive.
    #
    # C'est la forme à préférer, pour la même raison que `File.open` : ce qui est
    # ouvert se ferme, y compris quand le bloc lève.
    #
    # Sans bloc, rend le client — et c'est alors à l'appelant de le fermer.
    def self.ouvrir(**reglages)
      client = new(**reglages)
      return client unless block_given?

      begin
        yield client
      ensure
        client.fermer
      end
    end

    # Monte un client. **Il n'ouvre aucune connexion.**
    #
    # `annuaires` est une liste de couples `[adresse, nom]`. L'adresse est
    # LITTÉRALE — `"203.0.113.7:6630"` ou `"[2001:db8::1]:6630"` —, jamais un nom
    # d'hôte : **la résolution appartient à l'appelant**, parce qu'il a déjà un
    # résolveur, une politique de cache et des fils, et que lui en imposer un
    # autre serait décider à sa place. `Addrinfo.getaddrinfo` fait l'affaire, et
    # un nom qui rend plusieurs adresses les rend toutes utilisables ici.
    #
    # Le second membre est le nom qu'on EXIGE du certificat. Il n'est pas déduit
    # de l'adresse, et il ne peut pas l'être : le déduire reviendrait à faire
    # confiance à qui répond à cette adresse.
    #
    # `racines` est le contenu d'un fichier PEM. **Il n'y a pas de repli sur le
    # magasin du système** : les annuaires sont signés par LEUR autorité.
    #
    # `identite` est le couple `[machine, graine]` rendu par {#enroler}.
    def initialize(annuaires: [], racines: nil, identite: nil)
      @fonctions = Asl.fonctions
      # **UN SEUL VERROU, ET IL SÉRIALISE TOUT.**
      #
      # L'ABI dit qu'un client ne se partage pas entre fils. En Rust, deux appels
      # concurrents aliaseraient un `&mut` — un comportement indéfini, pas un
      # ralentissement. En Ruby, personne ne lit cette phrase : la liaison la fait
      # donc respecter, et transforme l'indéfini en file d'attente.
      #
      # LE COÛT EST ÉCRIT : `etat` attend pendant un `ou` en cours, qui peut durer
      # vingt secondes. Un daemon qui annonce n'appelle pas `ou`, donc les deux se
      # croisent rarement — mais quand cela arrive, c'est cette ligne qui
      # l'explique.
      @verrou = Mutex.new

      # **UNE BOÎTE, ET NON UN CHAMP.** Le finaliseur doit voir le pointeur sans
      # voir `self` — voir {Client.finaliseur}.
      @boite = [nil]

      sortie = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP, Fiddle::RUBY_FREE)
      Asl.verifier(@fonctions[:asl_client_neuf].call(sortie))
      @boite[0] = sortie[0, Fiddle::SIZEOF_VOIDP].unpack1("J")

      ObjectSpace.define_finalizer(
        self, self.class.finaliseur(@boite, @fonctions[:asl_client_libere])
      )

      begin
        annuaires.each { |adresse, nom| ajouter_annuaire(adresse, nom) }
        poser_racines(racines) unless racines.nil?
        poser_identite(*identite) unless identite.nil?
      rescue Exception # rubocop:disable Lint/RescueException
        # **CE QUI EST OUVERT SE FERME, MÊME QUAND LE CONSTRUCTEUR ÉCHOUE.**
        # Sans ceci, une adresse mal écrite laisserait un objet natif que plus
        # rien ne référence — et qu'aucun ramasse-miettes ne sait libérer,
        # puisqu'il n'appartient pas à Ruby.
        fermer
        raise
      end
    end

    # Le filet, et non le moyen.
    #
    # **UN FINALISEUR NE DOIT PAS VOIR `self`.** Une lambda qui le capturerait le
    # garderait vivant pour toujours — et ne s'exécuterait donc jamais. C'est le
    # piège classique de `define_finalizer`, et il est silencieux : rien ne fuit
    # visiblement, la mémoire native se contente de ne jamais être rendue.
    #
    # Cette fabrique est donc une méthode de CLASSE, et ne capture que la boîte
    # et la fonction.
    def self.finaliseur(boite, liberer)
      proc do
        brut = boite[0]
        next if brut.nil?

        boite[0] = nil
        liberer.call(brut)
      end
    end

    # ── La configuration ──────────────────────────────────────────────────

    # Ajoute un annuaire à essayer. **Répétable, et l'ordre compte.**
    #
    # L'IPv6 est essayé d'abord quel que soit l'ordre des appels ; à l'intérieur
    # d'une famille, c'est cet ordre qui décide.
    def ajouter_annuaire(adresse, nom)
      appeler(:asl_client_annuaire, Asl.chaine(adresse), Asl.chaine(nom))
    end

    # Pose les certificats d'autorité, en PEM.
    def poser_racines(pem)
      raise MauvaisArgument, "les racines sont des octets" unless pem.is_a?(String)

      octets = pem.dup.force_encoding(Encoding::BINARY)
      appeler(:asl_client_racines, octets, octets.bytesize)
    end

    # Installe l'identité de cette machine.
    #
    # **LA GRAINE EST LE SECRET**, et sa conservation appartient à l'appelant :
    # elle n'est pas chiffrée, et quiconque la lit devient cette machine. Un
    # fichier en `0600`, et rien de plus bavard.
    def poser_identite(machine, graine)
      unless graine.is_a?(String) && graine.bytesize == Abi::GRAINE_OCTETS
        raise MauvaisArgument,
              "une graine fait #{Abi::GRAINE_OCTETS} octets, pas #{graine.to_s.bytesize}"
      end

      appeler(:asl_client_identite, Asl.chaine(machine),
              graine.dup.force_encoding(Encoding::BINARY))
    end

    # ── Les verbes ────────────────────────────────────────────────────────

    # Présente un code d'enrôlement, et rend `[machine, graine]`.
    #
    # **CONSERVEZ LES DEUX.** La clé est générée sur cette machine et sa moitié
    # privée n'en sort pas ; ce couple est le seul justificatif durable, et le
    # code est dépensé — il ne servira plus.
    #
    # L'identité est installée dans ce client au passage.
    #
    # **Cet appel bloque** — jusqu'à vingt secondes s'il faut attendre un
    # annuaire. Le GVL est relâché pendant ce temps.
    def enroler(code)
      machine = Fiddle::Pointer.malloc(Abi::IDENTIFIANT_OCTETS, Fiddle::RUBY_FREE)
      graine = Fiddle::Pointer.malloc(Abi::GRAINE_OCTETS, Fiddle::RUBY_FREE)
      appeler(:asl_enroler, Asl.chaine(code), machine, graine)
      [machine.to_s, graine[0, Abi::GRAINE_OCTETS]]
    end

    # Annonce ce service, et **rend la main tout de suite**.
    #
    # L'annonce est ensuite tenue par un fil natif, aussi longtemps que ce client
    # vit : elle se réauthentifie et se réannonce seule à chaque reconnexion, et
    # bascule sur l'autre annuaire racine quand le premier tombe. {#etat} dit où
    # elle en est.
    #
    # **UN CLIENT N'ANNONCE QU'UNE FOIS** : un second appel lève {Deja} plutôt que
    # de remplacer la première en silence, ce qui la retirerait.
    def annoncer(service, points)
      raise MauvaisArgument, "une annonce sans point d'écoute n'annonce rien" if
        points.nil? || points.empty?

      emballes = points.map do |point|
        raise MauvaisArgument, "#{point.inspect} n'est pas un Asl::Point" unless
          point.is_a?(Point)

        [point.port, point.protocole_brut, 0].pack(Abi::GABARIT_POINT)
      end.join

      appeler(:asl_annoncer, Asl.chaine(service), emballes, points.size)
    end

    # Où en est l'annonce. Un client qui n'a jamais annoncé rend tout à zéro.
    def etat
      tampon = Fiddle::Pointer.malloc(Abi::TAILLE_ETAT, Fiddle::RUBY_FREE)
      appeler(:asl_etat, tampon)
      attaches, ruptures, attachee, abandonnee, _reserve =
        tampon[0, Abi::TAILLE_ETAT].unpack(Abi::GABARIT_ETAT)
      Etat.new(attachee: attachee == 1, attaches: attaches,
               ruptures: ruptures, abandonnee: abandonnee == 1)
    end

    # Demande où joindre un service, et rend les candidats **dans l'ordre**.
    #
    # L'ordre est celui qu'un client doit suivre — IPv6 d'abord, adresse observée
    # avant adresse annoncée — et il n'est pas à l'appelant de le deviner.
    #
    # **Cet appel bloque**, comme {#enroler}.
    def ou(machine, service)
      machine = Asl.chaine(machine)
      service = Asl.chaine(service)
      ecrit = Fiddle::Pointer.malloc(Fiddle::SIZEOF_SIZE_T, Fiddle::RUBY_FREE)

      @verrou.synchronize do
        brut = exige
        place = CANDIDATS_D_EMBLEE
        tampon = Fiddle::Pointer.malloc(place * Abi::TAILLE_CANDIDAT, Fiddle::RUBY_FREE)
        code = @fonctions[:asl_ou].call(brut, machine, service, tampon, place, ecrit)

        if code == Abi::TAMPON_TROP_PETIT
          place = ecrit[0, Fiddle::SIZEOF_SIZE_T].unpack1("J")
          tampon = Fiddle::Pointer.malloc([place, 1].max * Abi::TAILLE_CANDIDAT,
                                          Fiddle::RUBY_FREE)
          code = @fonctions[:asl_ou].call(brut, machine, service, tampon, place, ecrit)
        end
        Asl.verifier(code)

        combien = ecrit[0, Fiddle::SIZEOF_SIZE_T].unpack1("J")
        (0...combien).map do |rang|
          decoder_candidat(tampon[rang * Abi::TAILLE_CANDIDAT, Abi::TAILLE_CANDIDAT])
        end
      end
    end

    # Combien de poussées de verdict sont arrivées depuis le départ.
    #
    # **ZÉRO N'EST PAS UNE ANOMALIE** : l'annuaire ne pousse que ce qui a CHANGÉ.
    def poussees_recues
      tampon = Fiddle::Pointer.malloc(8, Fiddle::RUBY_FREE)
      appeler(:asl_poussees_recues, tampon)
      tampon[0, 8].unpack1("Q")
    end

    # Le dernier verdict poussé, ou `nil` si rien n'a encore été poussé.
    #
    # **`nil` N'EST PAS UNE ERREUR, ET C'EST POURQUOI CE N'EST PAS UNE
    # EXCEPTION.** Ne rien avoir reçu est le cas ordinaire ; lever ici
    # obligerait un porteur à envelopper d'un `rescue` la boucle qu'il appelle
    # chaque seconde.
    def derniere_poussee
      ecrit = Fiddle::Pointer.malloc(Fiddle::SIZEOF_SIZE_T, Fiddle::RUBY_FREE)
      nat = Fiddle::Pointer.malloc(1, Fiddle::RUBY_FREE)

      @verrou.synchronize do
        brut = exige
        place = CANDIDATS_D_EMBLEE
        tampon = Fiddle::Pointer.malloc(place * Abi::TAILLE_CANDIDAT, Fiddle::RUBY_FREE)
        code = @fonctions[:asl_derniere_poussee].call(brut, tampon, place, ecrit, nat)

        if code == Abi::TAMPON_TROP_PETIT
          place = [ecrit[0, Fiddle::SIZEOF_SIZE_T].unpack1("J"), 1].max
          tampon = Fiddle::Pointer.malloc(place * Abi::TAILLE_CANDIDAT, Fiddle::RUBY_FREE)
          code = @fonctions[:asl_derniere_poussee].call(brut, tampon, place, ecrit, nat)
        end
        return nil if code == Abi::PAS_DE_POUSSEE

        Asl.verifier(code)
        combien = ecrit[0, Fiddle::SIZEOF_SIZE_T].unpack1("J")
        Poussee.new(
          candidats: (0...combien).map do |rang|
            decoder_candidat(tampon[rang * Abi::TAILLE_CANDIDAT, Abi::TAILLE_CANDIDAT])
          end,
          derriere_nat: VERDICTS_DE_NAT.fetch(nat[0, 1].unpack1("C"))
        )
      end
    end

    # ── La fin ────────────────────────────────────────────────────────────

    # Ferme le client, **et retire l'annonce en le faisant**.
    #
    # Elle est retirée PROPREMENT, ce qui épargne à l'annuaire la minute
    # d'inactivité pendant laquelle il donnerait aux clients une adresse morte.
    # Cet appel peut donc prendre jusqu'à deux secondes.
    #
    # Appeler deux fois ne fait rien la seconde.
    def fermer
      @verrou.synchronize do
        brut = @boite[0]
        next if brut.nil?

        @boite[0] = nil
        @fonctions[:asl_client_libere].call(brut)
      end
      nil
    end

    # Le client est-il encore ouvert ?
    def ouvert? = !@boite[0].nil?

    private

    # Appelle une fonction de l'ABI sur ce client, et traduit son code.
    def appeler(nom, *arguments)
      @verrou.synchronize do
        Asl.verifier(@fonctions[nom].call(exige, *arguments))
      end
      nil
    end

    # Le pointeur natif, ou une erreur qui dit ce qui s'est passé.
    #
    # **DÉRÉFÉRENCER UN POINTEUR LIBÉRÉ TUERAIT L'INTERPRÉTEUR.** Ici la sanction
    # est une exception, et elle nomme la cause.
    def exige
      brut = @boite[0]
      raise Erreur, "ce client est fermé" if brut.nil?

      brut
    end

    # Un candidat de l'ABI, en objets Ruby.
    def decoder_candidat(octets)
      adresse, port, protocole, famille, origine, verdict, _reserve =
        octets.unpack(Abi::GABARIT_CANDIDAT)
      Candidat.new(
        protocole: PROTOCOLES.fetch(protocole),
        adresse: (famille == 6 ? IPAddr.new_ntoh(adresse) : IPAddr.new_ntoh(adresse[0, 4])).to_s,
        port: port,
        origine: ORIGINES.fetch(origine),
        verdict: VERDICTS.fetch(verdict)
      )
    end
  end
end
