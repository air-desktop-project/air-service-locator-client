# frozen_string_literal: true

# L'ABI transcrite dit-elle la même chose que l'en-tête ?
#
# C'EST LA SEULE QUESTION QUI COMPTE DANS `lib/asl/abi.rb`
# ========================================================
#
# Une constante qui dériverait ne casserait rien nulle part : elle ferait
# seulement lever `Refuse` là où l'ABI dit `Injoignable`, et personne ne s'en
# apercevrait avant d'avoir cherché une panne de réseau pendant une heure.
#
# Ces essais lisent `crates/asl-client-ffi/include/asl.h` — le contrat écrit à la
# main — et le comparent à ce que Ruby croit.

require "minitest/autorun"

require "asl/abi"

module Fixtures
  RACINE = File.expand_path("../../..", __dir__)
  ENTETE = File.join(RACINE, "crates", "asl-client-ffi", "include", "asl.h")

  def self.entete = File.read(ENTETE)

  # Les `#define ASL_…` de l'en-tête, avec leur valeur.
  def self.constantes
    entete.lines.each_with_object({}) do |ligne, trouvees|
      trouve = ligne.strip.match(/\A#define\s+ASL_([A-Z0-9_]+)\s+(-?\d+)\s*\z/)
      trouvees[trouve[1]] = Integer(trouve[2]) if trouve
    end
  end

  # Les fonctions déclarées dans l'en-tête.
  def self.fonctions = entete.scan(/\b(asl_[a-z0-9_]+)\s*\(/).flatten.uniq

  # Les champs d'une structure, dans l'ordre où l'en-tête les déclare.
  def self.champs(nom)
    # `[^{}]*` et non `.*?` : le second partirait du PREMIER `typedef struct {`
    # du fichier et avalerait les structures précédentes.
    corps = entete[/typedef struct \{([^{}]*)\} #{Regexp.escape(nom)};/m, 1]
    raise "l'en-tête ne déclare pas #{nom}" if corps.nil?

    corps.lines.filter_map do |ligne|
      sans_commentaire = ligne.sub(%r{/\*.*?\*/}, "").strip
      champ = sans_commentaire[/\A\w+\s+(\w+)\s*(\[\d+\])?\s*;/, 1]
      champ&.to_sym
    end
  end

  # La taille annoncée dans le commentaire qui précède un `typedef`.
  def self.taille_annoncee(nom)
    avant = entete[0, entete.index("} #{nom};")]
    Integer(avant.scan(/(\d+) octets\./).flatten.last)
  end
end

class LEnteteEstLaReference < Minitest::Test
  def test_l_entete_est_bien_la
    # Si ce fichier bouge, tous les essais suivants passeraient en ne comparant
    # rien. On le dit plutôt que de rendre un OK muet.
    assert File.file?(Fixtures::ENTETE), "#{Fixtures::ENTETE} est introuvable"
  end

  def test_toutes_les_constantes_de_l_entete_sont_transcrites
    declarees = Fixtures.constantes

    assert_operator declarees.size, :>, 10, "l'en-tête n'a pas été lu"
    declarees.each do |nom, valeur|
      assert Asl::Abi.const_defined?(nom),
             "`ASL_#{nom}` est dans l'en-tête et pas dans `Asl::Abi`"
      assert_equal valeur, Asl::Abi.const_get(nom),
                   "`ASL_#{nom}` diverge entre `asl.h` et Ruby"
    end
  end

  def test_aucune_constante_inventee_de_ce_cote
    # **L'INVERSE COMPTE AUTANT** : une constante que Ruby connaît et que
    # l'en-tête ignore est une valeur que personne n'a promise.
    declarees = Fixtures.constantes.keys
    connues = Asl::Abi.constants.map(&:to_s).grep(/\A[A-Z][A-Z0-9_]*\z/)
    # Les constantes propres à la transcription ne sont pas des promesses de
    # l'ABI : elles décrivent COMMENT on la lit, pas ce qu'elle vaut.
    internes = %w[GABARIT_POINT GABARIT_CANDIDAT GABARIT_ETAT
                  TAILLE_POINT TAILLE_CANDIDAT TAILLE_ETAT
                  CHAMPS_POINT CHAMPS_CANDIDAT CHAMPS_ETAT SIGNATURES]
    inventees = connues - declarees - internes

    assert_empty inventees, "constantes sans contrepartie dans l'en-tête"
  end

  def test_les_onze_fonctions_sont_declarees_a_fiddle
    # Une fonction que l'en-tête déclare et que `SIGNATURES` oublie ne se charge
    # pas du tout : `charger` lèverait. Mieux vaut le dire ici.
    declarees = Fixtures.fonctions

    assert_equal 11, declarees.size, "l'en-tête ne déclare plus onze fonctions"
    declarees.each do |fonction|
      assert Asl::Abi::SIGNATURES.key?(fonction.to_sym),
             "`#{fonction}` est déclarée dans l'en-tête et n'a pas de signature"
    end
    assert_equal declarees.map(&:to_sym).sort, Asl::Abi::SIGNATURES.keys.sort
  end

  def test_les_tailles_sont_celles_que_l_entete_annonce
    # Elles sont déjà vérifiées au chargement de `abi.rb` — ce qui l'est ici est
    # l'accord avec les nombres ÉCRITS dans les commentaires de l'en-tête, que
    # les cinq liaisons recopient.
    {
      "asl_point" => Asl::Abi::GABARIT_POINT,
      "asl_candidat" => Asl::Abi::GABARIT_CANDIDAT,
      "asl_etat_t" => Asl::Abi::GABARIT_ETAT
    }.each do |nom, gabarit|
      assert_equal Fixtures.taille_annoncee(nom), Asl::Abi.mesurer(gabarit),
                   "#{nom} : Ruby et l'en-tête ne comptent pas pareil"
    end
  end

  def test_l_ordre_des_champs_suit_l_entete
    # **UN CHAMP DÉPLACÉ NE CHANGE PAS LA TAILLE**, et ne se verrait donc dans
    # aucun des essais ci-dessus : `unpack` rendrait un port là où il y a un
    # protocole, sans que rien ne proteste.
    {
      "asl_point" => Asl::Abi::CHAMPS_POINT,
      "asl_candidat" => Asl::Abi::CHAMPS_CANDIDAT,
      "asl_etat_t" => Asl::Abi::CHAMPS_ETAT
    }.each do |nom, attendus|
      assert_equal Fixtures.champs(nom), attendus,
                   "#{nom} : l'ordre des champs a divergé"
    end
  end

  def test_le_gabarit_a_autant_de_directives_que_de_champs
    # Un gabarit et une liste de noms qui ne se correspondraient plus feraient
    # décaler TOUTES les valeurs d'un cran.
    {
      Asl::Abi::GABARIT_POINT => Asl::Abi::CHAMPS_POINT,
      Asl::Abi::GABARIT_CANDIDAT => Asl::Abi::CHAMPS_CANDIDAT,
      Asl::Abi::GABARIT_ETAT => Asl::Abi::CHAMPS_ETAT
    }.each do |gabarit, champs|
      assert_equal champs.size, gabarit.scan(/[a-zA-Z]\d*/).size, gabarit
    end
  end
end
