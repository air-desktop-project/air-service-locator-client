// Les essais de la liaison Swift.
//
// CE QU'ILS ÉPROUVENT, ET QUI NE L'EST NULLE PART AILLEURS
// ========================================================
//
// Ce qui est derrière l'ABI est couvert, et la conformité de la transcription
// n'a pas à l'être : **Swift INCLUT le contrat**, comme C++. La carte de module
// pointe `asl.h`, le compilateur lit la source, et une signature qui aurait bougé
// ne compile pas.
//
// Ce qui n'est couvert nulle part est ce que Swift ajoute : `deinit` déterministe
// — la seule des cinq liaisons où « le laisser sortir de portée » est une réponse
// juste —, et un `Client` fermé qui doit lever au lieu de déréférencer le néant.
//
// PAS DE CADRE D'ESSAI TIERS
// ==========================
//
// Ni XCTest ni swift-testing : vingt lignes font le même travail, et
// `scripts/check-swift.sh` n'a besoin d'aucune résolution de paquets — donc
// d'aucun réseau. Une barrière qui téléchargerait ne serait pas une barrière.

import Asl

#if canImport(Glibc)
  import Glibc
#elseif canImport(Darwin)
  import Darwin
#endif

// `nonisolated(unsafe)` : ces compteurs ne sont touchés que par le fil
// principal, et le mode Swift 6 exige qu'on le DISE plutôt que de le supposer.
nonisolated(unsafe) var echecs = 0
nonisolated(unsafe) var verifications = 0

func verifie(_ tenu: Bool, _ quoi: String) {
  verifications += 1
  if !tenu {
    echecs += 1
    // Sur la sortie standard, et non sur `stderr` : celui-ci est une variable
    // globale mutable de la libc, que le mode Swift 6 refuse de laisser
    // toucher sans cérémonie. Le code de sortie reste ce qui décide.
    print("ÉCHEC — \(quoi)")
  }
}

func verifieEgal<T: Equatable>(_ obtenu: T, _ attendu: T, _ quoi: String) {
  verifie(obtenu == attendu, "\(quoi) : obtenu \(obtenu), attendu \(attendu)")
}

/// Un identifiant de machine VALIDE — préfixe et somme de contrôle compris.
///
/// Recopié plutôt que calculé : le calculer demanderait de réimplémenter
/// l'alphabet de Crockford d'`asl-id` ici, c'est-à-dire d'en faire une copie qui
/// divergerait. Si `asl-id` change de forme, cet essai le dira.
let machineDEssai = "m-0H248H248H248H248H248H248H"

func identiteDEssai() throws -> Identite {
  try Identite(machine: machineDEssai, graine: (0..<32).map { UInt8($0) })
}

/// Un client dont la racine est illisible : de quoi atteindre `.configuration`.
func clientConfigure(avecIdentite: Bool) throws -> Client {
  try Client(
    annuaires: [("127.0.0.1:1", "localhost")],
    racines: Array("pas un PEM".utf8),
    identite: avecIdentite ? try identiteDEssai() : nil)
}

/// Rend la faute levée, ou `nil` si rien ne l'a été.
func fauteDe(_ corps: () throws -> Void) -> Faute? {
  do {
    try corps()
    return nil
  } catch let quoi as Faute {
    return quoi
  } catch {
    return .interne
  }
}

// ── LA VERSION ET LES MESSAGES ─────────────────────────────────────────────

func laVersionVientDeLaBibliothequeNative() {
  let lue = version()
  verifieEgal(lue.majeur, 0, "majeur")
  verifieEgal(lue.mineur, 1, "mineur")
  verifieEgal(lue.correctif, 0, "correctif")
}

func chaqueFauteASaPhraseEtAucuneNEstPartagee() {
  // **UNE PHRASE PARTAGÉE EST UN CODE PERDU** : deux causes différentes que
  // l'appelant lirait pareil.
  let codes: [Faute] = [
    .argument, .configuration, .injoignable, .refuse,
    .tamponTropPetit, .interne, .pasDIdentite, .deja, .ferme,
  ]
  var vues: [String] = []
  for code in codes {
    let phrase = code.message
    verifie(!phrase.isEmpty, "\(code) doit avoir une phrase")
    verifie(!vues.contains(phrase), "« \(phrase) » sert déjà à un autre code")
    vues.append(phrase)
  }
  // **`ferme` N'EST PAS UN CODE DE L'ABI** : sa phrase vient d'ici, et elle dit
  // autre chose qu'« argument invalide ».
  verifie(Faute.ferme.message.contains("fermé"), "`ferme` doit se nommer")
}

// ── LA CONSTRUCTION ────────────────────────────────────────────────────────

func unClientNeufNOuvreRienEtSonEtatEstAZero() throws {
  let client = try Client()
  verifie(client.ouvert, "un client neuf est ouvert")
  let etat = try client.etat()
  verifie(!etat.attachee, "rien n'est attaché")
  verifieEgal(etat.attaches, 0, "attaches")
  verifieEgal(etat.ruptures, 0, "ruptures")
  verifie(!etat.abandonnee, "n'avoir rien tenté n'est pas avoir renoncé")
}

func uneAdresseIllisibleEstRefusee() {
  for mauvaise in [
    "nitrogen.example:6630",  // un NOM : la résolution appartient à l'appelant
    "203.0.113.7",  // pas de port
    "2001:db8::1:6630",  // sans crochets, c'est ambigu
    "",
  ] {
    let faute = fauteDe { _ = try Client(annuaires: [(mauvaise, "localhost")]) }
    verifieEgal(faute, .argument, "« \(mauvaise) » doit être refusée")
  }
  let bonnes = fauteDe {
    _ = try Client(annuaires: [
      ("203.0.113.7:6630", "nitrogen.example"),
      ("[2001:db8::1]:6630", "nitrogen.example"),
    ])
  }
  verifie(bonnes == nil, "les deux familles sont acceptées")
}

func unNulAuMilieuDUneChaineEstRefuse() throws {
  // **LE C S'ARRÊTERAIT AU PREMIER**, et l'annuaire recevrait un nom plus court
  // que celui qu'on croit lui avoir donné.
  let client = try Client()
  let tricherie = "127.0.0.1:1\u{0}et la suite"
  let faute = fauteDe { try client.ajouterAnnuaire(tricherie, nom: "localhost") }
  verifieEgal(faute, .argument, "un NUL doit être refusé")
}

func uneGraineDeMauvaiseTailleEstRefusee() {
  let faute = fauteDe {
    _ = try Identite(machine: machineDEssai, graine: [UInt8](repeating: 0, count: 31))
  }
  verifieEgal(faute, .argument, "une graine de 31 octets")
}

func unSecretNeSeMetPasDansUnJournal() throws {
  // La description par défaut d'une `struct` aurait imprimé la graine au premier
  // `print(identite)`.
  let texte = String(describing: try identiteDEssai())
  verifie(texte.contains(machineDEssai), "la machine se lit")
  verifie(!texte.contains("[0, 1, 2"), "la graine ne doit pas apparaître : \(texte)")
  verifie(texte.contains("<32 octets>"), "et l'on dit qu'elle est là : \(texte)")
}

// ── L'ANNONCE ──────────────────────────────────────────────────────────────

func sansIdentiteOnNePeutRienSigner() throws {
  let client = try clientConfigure(avecIdentite: false)
  let faute = fauteDe {
    try client.annoncer(service: "depot", points: [try Point(.tcp, 8080)])
  }
  verifieEgal(faute, .pasDIdentite, "sans identité, rien à signer")
}

func unPortNulEstRefuseALaConstructionDuPoint() {
  // Le refus est dans `Point`, donc AVANT qu'un client existe : un porteur
  // l'apprend en écrivant sa configuration.
  verifieEgal(fauteDe { _ = try Point(.tcp, 0) }, .argument, "le port zéro")
}

func uneAnnonceSansPointNAnnonceRien() throws {
  let client = try clientConfigure(avecIdentite: true)
  let faute = fauteDe { try client.annoncer(service: "depot", points: []) }
  verifieEgal(faute, .argument, "aucun point")
}

func unClientNAnnonceQuUneFois() throws {
  let client = try clientConfigure(avecIdentite: true)
  try client.annoncer(service: "depot", points: [try Point(.tcp, 8080)])
  let faute = fauteDe {
    try client.annoncer(service: "depot", points: [try Point(.tcp, 8081)])
  }
  verifieEgal(faute, .deja, "la seconde annonce")
}

func leFilNatifTourneSansQuePersonneLAttende() throws {
  // **C'EST L'ESSAI QUI COMPTE LE PLUS.** `annoncer` a rendu la main et
  // l'appelant est parti ; si le fil natif ne tournait pas, `abandonnee` ne
  // passerait jamais à vrai — et tout compilerait.
  let client = try clientConfigure(avecIdentite: true)
  try client.annoncer(service: "depot", points: [try Point(.tcp, 8080)])

  var etat = try client.etat()
  for _ in 0..<250 {
    etat = try client.etat()
    if etat.abandonnee { break }
    usleep(20_000)
  }
  verifie(etat.abandonnee, "le fil natif n'a pas tourné")
  verifie(!etat.attachee, "et rien n'est attaché")
  verifieEgal(etat.attaches, 0, "une racine illisible n'attache rien")
}

func lIdentiteSurvitALAnnonce() throws {
  // L'annonce CONSOMME une identité côté Rust ; si le client la perdait, `ou`
  // répondrait « aucune identité » à un daemon qui vient de s'annoncer.
  let client = try clientConfigure(avecIdentite: true)
  try client.annoncer(service: "depot", points: [try Point(.tcp, 8080)])
  let faute = fauteDe { _ = try client.ou(machine: machineDEssai, service: "depot") }
  verifie(faute != .pasDIdentite, "l'annonce a emporté l'identité")
  verifieEgal(faute, .configuration, "la racine reste illisible")
}

// ── LA DURÉE DE VIE ────────────────────────────────────────────────────────

func arcLibereALaSortieDePortee() throws {
  // **C'EST LA RAISON POUR LAQUELLE CETTE LIAISON N'A PAS DE FINALISEUR.**
  //
  // Ruby et Kotlin en ont besoin : leur ramasse-miettes passe quand il veut,
  // donc l'annonce serait retirée à un moment que personne ne choisit. Le
  // comptage de références de Swift, lui, est DÉTERMINISTE — la dernière
  // référence qui disparaît appelle `deinit`, tout de suite.
  weak var faible: Client?
  do {
    let client = try Client()
    faible = client
    verifie(faible != nil, "la référence faible voit le client")
  }
  verifie(faible == nil, "ARC a libéré à la sortie de portée, sans ramasse-miettes")
}

func fermerDeuxFoisNeFaitRienLaSeconde() throws {
  let client = try Client()
  client.fermer()
  client.fermer()
  verifie(!client.ouvert, "un client fermé le reste")
}

func unClientFermeLeveAuLieuDeDereferencerLeNeant() throws {
  // **DÉRÉFÉRENCER UN POINTEUR LIBÉRÉ TUERAIT LE PROCESSUS DE L'HÔTE.** Ici la
  // sanction est une faute, et elle nomme la cause.
  let client = try Client()
  client.fermer()
  verifieEgal(fauteDe { _ = try client.etat() }, .ferme, "l'état")
  verifieEgal(
    fauteDe { try client.ajouterAnnuaire("127.0.0.1:1", nom: "x") }, .ferme, "un annuaire")
  verifieEgal(fauteDe { _ = try client.ou(machine: machineDEssai, service: "d") }, .ferme, "où")
  verifieEgal(fauteDe { _ = try client.enroler(code: "4K9M2P7R1T") }, .ferme, "l'enrôlement")
}

// ── CE QUI TRAVERSE ────────────────────────────────────────────────────────

func unCandidatV6PorteSesCrochets() {
  // Sans eux, `2001:db8::1:8080` est ambigu, et ce qu'on affiche ne se recopie
  // pas dans une commande.
  let six = Candidat(
    protocole: .tcp, adresse: "2001:db8::1", port: 8080,
    origine: .reflexif, verdict: .enCours)
  verifieEgal(String(describing: six), "[2001:db8::1]:8080", "IPv6")

  let quatre = Candidat(
    protocole: .tcp, adresse: "203.0.113.7", port: 8080,
    origine: .annonce, verdict: .joignable)
  verifieEgal(String(describing: quatre), "203.0.113.7:8080", "IPv4")
}

func unPointSeLitCommeOnLEcritDansAsl() throws {
  verifieEgal(String(describing: try Point(.tcp, 8080)), "tcp:8080", "tcp")
  verifieEgal(String(describing: try Point(.udp, 9000)), "udp:9000", "udp")
}

func leVerdictGardeSesQuatreValeurs() {
  // **TROIS D'ENTRE ELLES NE VEULENT PAS DIRE « ÇA NE MARCHE PAS ».**
  let toutes: [Verdict] = [.joignable, .injoignable, .nonSonde, .enCours]
  verifieEgal(Set(toutes.map(\.rawValue)).count, 4, "quatre valeurs distinctes")
}

@main
struct Essais {
  static func main() throws {
    laVersionVientDeLaBibliothequeNative()
    chaqueFauteASaPhraseEtAucuneNEstPartagee()
    try unClientNeufNOuvreRienEtSonEtatEstAZero()
    uneAdresseIllisibleEstRefusee()
    try unNulAuMilieuDUneChaineEstRefuse()
    uneGraineDeMauvaiseTailleEstRefusee()
    try unSecretNeSeMetPasDansUnJournal()
    try sansIdentiteOnNePeutRienSigner()
    unPortNulEstRefuseALaConstructionDuPoint()
    try uneAnnonceSansPointNAnnonceRien()
    try unClientNAnnonceQuUneFois()
    try leFilNatifTourneSansQuePersonneLAttende()
    try lIdentiteSurvitALAnnonce()
    try arcLibereALaSortieDePortee()
    try fermerDeuxFoisNeFaitRienLaSeconde()
    try unClientFermeLeveAuLieuDeDereferencerLeNeant()
    unCandidatV6PorteSesCrochets()
    try unPointSeLitCommeOnLEcritDansAsl()
    leVerdictGardeSesQuatreValeurs()

    print("\(verifications) vérifications, \(echecs) échec(s)")
    if echecs != 0 { exit(1) }
  }
}
