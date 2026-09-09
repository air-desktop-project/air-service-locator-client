# frozen_string_literal: true

# L'ABI C, transcrite pour `fiddle`. **Rien d'idiomatique ici.**
#
# Ce fichier est la copie mot pour mot de `crates/asl-client-ffi/include/asl.h`.
# Il ne traduit pas les erreurs, ne nomme rien autrement, n'enveloppe rien :
# c'est le rôle de `lib/asl.rb`. Les séparer rend visible la seule question qui
# compte ici — **est-ce que ce fichier dit la même chose que l'en-tête ?** —, et
# `essais/test_abi.rb` y répond en lisant les deux.
#
# ── POURQUOI `fiddle` ET NON LA GEMME `ffi` ─────────────────────────────────
#
# La gemme `ffi` est plus agréable. Elle est aussi une **extension native** :
# l'installer compile du C dans l'environnement de qui nous embarque. Ce dépôt a
# une contrainte entière (C4) qui tient à ce qu'aucun C n'entre — la refuser ici
# et l'accepter par la porte du gestionnaire de gemmes n'aurait aucun sens.
#
# `fiddle` est dans la distribution de Ruby, et ne coûte rien à personne.
#
# ── POURQUOI `pack` ET `unpack`, ET NON UN CONSTRUCTEUR DE STRUCTURES ───────
#
# `pack` n'insère JAMAIS de bourrage. Ce serait normalement disqualifiant pour
# lire une structure C — sauf que celles-ci n'en ont aucun : l'en-tête range ses
# champs du plus large au plus étroit, exprès, pour que cinq langages qui
# calculent la disposition chacun de son côté tombent d'accord.
#
# **La disposition packée EST donc la disposition C**, et c'est le bénéfice
# direct de cette décision-là. Une structure à trou aurait rendu ceci impossible.
#
# Les gabarits emploient les tailles NATIVES (`S`, `Q`) et non des variantes
# petit-boutistes : la structure est native, pas un format de fil.

require "fiddle"

module Asl
  # La transcription de `asl.h`.
  module Abi
    # ── LES CODES ───────────────────────────────────────────────────────────
    OK = 0
    ARGUMENT = -1
    CONFIGURATION = -2
    INJOIGNABLE = -3
    REFUSE = -4
    TAMPON_TROP_PETIT = -5
    INTERNE = -6
    PAS_D_IDENTITE = -7
    DEJA = -8

    IDENTIFIANT_OCTETS = 29
    GRAINE_OCTETS = 32

    TCP = 1
    UDP = 2

    REFLEXIF = 1
    ANNONCE = 2

    JOIGNABLE = 1
    INJOIGNABLE_POINT = 2
    NON_SONDE = 3
    EN_COURS = 4

    # ── LES DISPOSITIONS ────────────────────────────────────────────────────

    # `asl_point` : `uint16 port`, `uint8 protocole`, `uint8 reserve`.
    GABARIT_POINT = "SCC"
    TAILLE_POINT = 4

    # `asl_candidat` : 16 octets d'adresse, puis port, protocole, famille,
    # origine, verdict, et deux octets réservés.
    GABARIT_CANDIDAT = "a16SCCCCa2"
    TAILLE_CANDIDAT = 24

    # `asl_etat_t` : deux compteurs de 64 bits, deux drapeaux, six réservés.
    GABARIT_ETAT = "QQCCa6"
    TAILLE_ETAT = 24

    # **LES NOMS DES CHAMPS, DANS L'ORDRE.**
    #
    # `unpack` rend un tableau : les noms n'existent nulle part, et un champ
    # déplacé ne changerait NI la taille NI le comportement de `pack` — on lirait
    # simplement un port là où il y a un protocole, sans que rien ne proteste.
    #
    # Ces listes sont ce que `essais/test_abi.rb` compare aux champs déclarés dans
    # l'en-tête. Elles ne servent qu'à cela, et c'est suffisant pour exister.
    CHAMPS_POINT = %i[port protocole reserve].freeze
    CHAMPS_CANDIDAT = %i[adresse port protocole famille origine verdict reserve].freeze
    CHAMPS_ETAT = %i[attaches ruptures attachee abandonnee reserve].freeze

    # **LES TAILLES SONT VÉRIFIÉES AU CHARGEMENT, ET NON DANS UN ESSAI.**
    #
    # C'est le pendant Ruby des `const _: () = assert!` du côté Rust. Si ce
    # fichier compte mal, il vaut mieux qu'il refuse de se charger que d'écrire un
    # port dans un champ de protocole pendant six mois.
    # Combien d'octets ce gabarit occupe, mesuré en l'employant.
    #
    # Il n'y a pas de « taille d'un gabarit » en Ruby : on en emballe un
    # exemplaire vide et l'on regarde. `a<N>` veut une chaîne, les autres
    # directives un entier — d'où ce petit tri.
    def self.mesurer(gabarit)
      exemplaire = gabarit.scan(/[a-zA-Z]\d*/).map do |directive|
        directive.start_with?("a") ? "" : 0
      end
      exemplaire.pack(gabarit).bytesize
    end

    {
      GABARIT_POINT => TAILLE_POINT,
      GABARIT_CANDIDAT => TAILLE_CANDIDAT,
      GABARIT_ETAT => TAILLE_ETAT
    }.each do |gabarit, taille|
      mesure = mesurer(gabarit)
      next if mesure == taille

      raise LoadError,
            "le gabarit #{gabarit.inspect} fait #{mesure} octets, et l'ABI en " \
            "annonce #{taille}. Cette liaison ne correspond pas à la " \
            "bibliothèque native : ne l'utilisez pas."
    end

    # ── LE CHARGEMENT ───────────────────────────────────────────────────────

    # L'objet natif n'a pas été trouvé.
    #
    # **CE N'EST PAS UNE FAUTE D'EXÉCUTION, C'EST UNE INSTALLATION INCOMPLÈTE**,
    # et le message le dit — l'exception brute de `fiddle` enverrait chercher une
    # panne là où il manque un fichier.
    class BibliothequeIntrouvable < StandardError; end

    # Comment l'objet natif s'appelle, selon le système.
    def self.noms_possibles
      case RbConfig::CONFIG["host_os"]
      when /darwin/ then ["libasl_client_ffi.dylib"]
      when /mswin|mingw/ then ["asl_client_ffi.dll"]
      else ["libasl_client_ffi.so"]
      end
    end

    # Où chercher, dans l'ordre.
    #
    # **`ASL_BIBLIOTHEQUE` PASSE AVANT TOUT.** C'est ce qui permet d'éprouver
    # cette liaison contre une construction locale sans l'installer, et à un
    # porteur de pointer l'objet qu'il a compilé pour son architecture.
    def self.chemins_candidats
      chemins = []
      impose = ENV["ASL_BIBLIOTHEQUE"]
      chemins << impose if impose && !impose.empty?
      ici = File.dirname(__dir__)
      noms_possibles.each { |nom| chemins << File.join(ici, nom) }
      chemins
    end

    # Les onze fonctions, une fois chargées.
    #
    # **CHAQUE SIGNATURE EST DÉCLARÉE À LA MAIN.** C'est le prix de `fiddle`, et
    # il est réel : une déclaration fausse ne se voit pas au chargement, elle
    # corrompt la pile à l'appel.
    SIGNATURES = {
      asl_version: [[Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
                    Fiddle::TYPE_VOID],
      asl_faute_texte: [[Fiddle::TYPE_INT32_T], Fiddle::TYPE_VOIDP],
      asl_client_neuf: [[Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT32_T],
      asl_client_annuaire: [[Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
                           Fiddle::TYPE_INT32_T],
      asl_client_racines: [[Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T],
                          Fiddle::TYPE_INT32_T],
      asl_client_identite: [[Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
                           Fiddle::TYPE_INT32_T],
      asl_client_libere: [[Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOID],
      asl_enroler: [[Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP,
                     Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT32_T],
      asl_annoncer: [[Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP,
                      Fiddle::TYPE_SIZE_T], Fiddle::TYPE_INT32_T],
      asl_etat: [[Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT32_T],
      asl_ou: [[Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP,
                Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T, Fiddle::TYPE_VOIDP],
               Fiddle::TYPE_INT32_T]
    }.freeze

    # Charge la bibliothèque native et rend ses fonctions, par nom.
    def self.charger(chemin = nil)
      essayes = []
      candidats = chemin ? [chemin.to_s] : chemins_candidats

      poignee = nil
      candidats.each do |candidat|
        essayes << candidat
        next unless File.exist?(candidat)

        poignee = Fiddle.dlopen(candidat)
        break
      end

      if poignee.nil?
        # En dernier, le chargeur du système — qui connaît `LD_LIBRARY_PATH`,
        # `/etc/ld.so.conf` et les répertoires d'installation.
        noms_possibles.each do |nom|
          essayes << nom
          begin
            poignee = Fiddle.dlopen(nom)
            break
          rescue Fiddle::DLError # rubocop:disable Lint/SuppressedException
          end
        end
      end

      if poignee.nil?
        raise BibliothequeIntrouvable,
              "l'objet natif d'asl est introuvable.\n" \
              "Cherché : #{essayes.join(', ')}\n" \
              "Construisez-le avec `cargo build --release` dans le dépôt, puis " \
              "posez ASL_BIBLIOTHEQUE sur target/release/#{noms_possibles.first}"
      end

      declarer(poignee)
    end

    # Pose les signatures. **`need_gvl: false` EST EXPLICITE, ET NON SUPPOSÉ.**
    #
    # Le GVL doit être RELÂCHÉ pendant l'appel : `asl_ou` attend jusqu'à vingt
    # secondes qu'un annuaire réponde, et `asl_client_libere` jusqu'à deux qu'une
    # annonce se retire proprement. Avec le GVL tenu, tout le processus hôte —
    # son serveur web, ses tâches, ses fils — gèlerait pendant ce temps.
    #
    # C'est la valeur par défaut de `fiddle` aujourd'hui. Elle est écrite quand
    # même : un défaut qui change ne casse rien à la compilation, il fige une
    # application en production.
    def self.declarer(poignee)
      SIGNATURES.each_with_object({}) do |(nom, (arguments, retour)), fonctions|
        fonctions[nom] = Fiddle::Function.new(
          poignee[nom.to_s], arguments, retour, name: nom.to_s, need_gvl: false
        )
      end
    end
  end
end
