# frozen_string_literal: true

# La gemme d'air-service-locator.
#
# ── ELLE VIT DANS LE DÉPÔT DU CLIENT, ET C'EST PROVISOIRE ───────────────────
#
# Même raison que pour Python : la liaison et l'ABI qu'elle transcrit doivent
# bouger DANS LE MÊME COMMIT — `essais/test_abi.rb` lit
# `crates/asl-client-ffi/include/asl.h`, et il ne le pourrait pas d'ailleurs.
#
# **CE QUI DÉCLENCHERA LA SÉPARATION** : le jour où il faudra publier un binaire
# natif par plate-forme et par architecture.
#
# ── CETTE GEMME NE CONTIENT PAS ENCORE L'OBJET NATIF ────────────────────────
#
# C'est du Ruby pur qui CHERCHE la bibliothèque. Une vraie distribution
# l'embarquerait, une gemme par plate-forme. En attendant, `ASL_BIBLIOTHEQUE`
# pointe l'objet qu'on a construit, et l'erreur le dit quand il manque plutôt que
# de rendre une exception `fiddle` nue.

Gem::Specification.new do |gemme|
  gemme.name = "asl-client"
  gemme.version = "0.1.0"
  gemme.summary = "Annoncer un service et retrouver un port, par l'annuaire air-service-locator."
  gemme.description = <<~TEXTE
    Un daemon qui écoute sur un port choisi au démarrage est un daemon que ses
    clients ne savent plus joindre. Cette gemme est l'autre moitié : le daemon
    annonce le port que le système lui a donné, et ses clients le demandent.
  TEXTE
  gemme.authors = ["air-service-locator contributors"]
  gemme.license = "MPL-2.0"
  gemme.homepage = "https://github.com/air-desktop-project/air-service-locator-client"
  gemme.metadata = {
    "source_code_uri" => gemme.homepage,
    "rubygems_mfa_required" => "true"
  }

  gemme.required_ruby_version = ">= 3.2"

  gemme.files = Dir["lib/**/*.rb"] + ["README.md"]
  gemme.require_paths = ["lib"]

  # **AUCUNE DÉPENDANCE, ET CE N'EST PAS UN OUBLI.**
  #
  # `fiddle`, `ipaddr` et `objspace` sont dans la distribution de Ruby. La gemme
  # `ffi` serait plus agréable — et elle est une EXTENSION NATIVE : l'installer
  # compilerait du C dans l'environnement de qui nous embarque, ce que la
  # contrainte C4 de ce dépôt refuse par la porte d'à côté.
  #
  # Ce que cette bibliothèque tire, ses porteurs l'installent.
end
