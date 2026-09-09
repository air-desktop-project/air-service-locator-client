// asl — annoncer un service et retrouver un port, depuis Swift.
//
// Un daemon qui écoute sur un port choisi au démarrage est un daemon que ses
// clients ne savent plus joindre. Cette bibliothèque est l'autre moitié : le
// daemon ANNONCE le port que le système lui a donné, et ses clients le DEMANDENT.
//
//     let client = try Client(
//         annuaires: [("203.0.113.7:6630", "nitrogen.example")],
//         racines: pem,
//         identite: identite)
//     try client.annoncer(service: "depot", points: [Point(.tcp, 8080)])
//     servirPourToujours()          // l'annonce se tient toute seule
//
// ── ELLE NE TRANSCRIT RIEN ─────────────────────────────────────────────────
//
// Python, Ruby et Kotlin doivent RECOPIER `asl.h` — constantes, dispositions,
// tailles — et une barrière existe de chaque côté pour comparer la copie à
// l'original. Swift, comme C++, sait INCLURE le contrat : la carte de module
// pointe l'en-tête, et le compilateur lit la source. Il n'y a pas de seconde
// source à faire diverger.
//
// ── CE QUI TOURNE EN ARRIÈRE-PLAN ──────────────────────────────────────────
//
// **`annoncer` rend la main tout de suite et n'y revient jamais.** Un annuaire
// injoignable ne doit pas empêcher un daemon de démarrer : le service écoute déjà
// pendant que l'annonce cherche encore.
//
// Ce qui la tient est un fil NATIF, à l'intérieur de la bibliothèque — ni une
// `Task`, ni un fil du pool coopératif, et il n'entre jamais dans le moteur
// Swift. Il se reconnecte seul, bascule sur l'autre annuaire racine quand le
// premier tombe, et n'abandonne jamais.
//
// ── SUR LA CONCURRENCE : LE COMPILATEUR REFUSE, IL N'Y A PAS DE VERROU ──────
//
// `Client` n'est **pas** `Sendable`, délibérément. Sous le mode Swift 6, le
// compilateur interdit alors de le PARTAGER entre domaines d'isolement — ce qui
// est exactement ce que l'ABI demande, obtenu sans verrou et sans coût.
//
// **Il laisse passer le DÉPLACEMENT**, et c'est juste : l'isolement par régions
// sait prouver qu'un client dont plus rien ne se sert peut partir ailleurs. Ce
// n'est pas un partage, et l'ABI ne l'interdit pas.
//
// C'est la quatrième réponse à la même question. Python et Ruby posent un verrou
// parce que personne n'y lit la phrase ; Kotlin en pose un parce qu'un objet
// partagé entre fils y est le cas ordinaire ; C++ se contente de la phrase, parce
// que sa convention est universelle. Swift, lui, la fait vérifier.

import CAsl

#if canImport(Glibc)
  import Glibc
#elseif canImport(Darwin)
  import Darwin
#endif

// ── LES FAUTES ──────────────────────────────────────────────────────────────
//
// **JAMAIS UN ENTIER NÉGATIF RENDU TEL QUEL.** Les verbes `throw` : le
// compilateur exige un `try` sur chaque appel, donc une faute ne s'ignore pas en
// silence. C'est le pendant de `[[nodiscard]]` en C++ et de `Result` en Kotlin.

/// Ce qui a empêché un appel d'aboutir.
///
/// **`injoignable` ET `refuse` SONT DEUX CHOSES.** Un câble débranché et un droit
/// manquant se corrigent à des endroits opposés, et les confondre envoie chercher
/// au mauvais.
public enum Faute: Int32, Error, Sendable {
  /// Une adresse illisible, un port nul, une graine de mauvaise taille.
  case argument = -1
  /// Il manque un annuaire ou une racine. **Réessayer ne réparerait rien.**
  case configuration = -2
  /// Personne n'a répondu.
  case injoignable = -3
  /// L'annuaire a compris, et il a dit non.
  case refuse = -4
  /// Le tampon fourni était trop petit. **La liaison le rattrape seule.**
  case tamponTropPetit = -5
  /// L'impossible, rattrapé — le processus n'a pas été tué.
  case interne = -6
  /// Cette machine n'est pas enrôlée.
  case pasDIdentite = -7
  /// Ce client annonce déjà.
  case deja = -8
  /// L'annuaire n'a encore rien poussé. **Ce n'est pas une panne.**
  ///
  /// **`dernierePoussee` NE LA LÈVE PAS** — elle rend `nil`. Ce cas est nommé ici
  /// pour que le code brut ne se confonde pas avec `.interne` s'il remontait
  /// d'ailleurs, et pour que sa phrase vienne de la bibliothèque comme les autres.
  case pasDePoussee = -9
  /// Ce client a été fermé.
  ///
  /// **CELLE-CI N'EST PAS UN CODE DE L'ABI** : elle est levée avant de traverser
  /// la frontière, parce que déréférencer un pointeur libéré tuerait le
  /// processus de l'hôte. Sa valeur brute est celle d'un argument invalide,
  /// puisque c'en est un.
  case ferme = -100

  /// Ce que la bibliothèque NATIVE dit de cette faute.
  ///
  /// **LA PHRASE VIENT DE LÀ-BAS, ET N'EST PAS RECOPIÉE ICI.** Deux listes de
  /// messages finiraient par diverger, et c'est celle qu'on oublie de corriger
  /// que l'utilisateur lirait. Rien à libérer : elle est statique.
  public var message: String {
    if self == .ferme { return "ce client est fermé" }
    guard let brute = asl_faute_texte(rawValue) else { return "code \(rawValue)" }
    return String(cString: brute)
  }

  /// Traduit un code de l'ABI, ou ne fait rien si c'est un succès.
  static func verifier(_ code: Int32) throws {
    guard code != ASL_OK else { return }
    throw Faute(rawValue: code) ?? .interne
  }
}

extension Faute: CustomStringConvertible {
  public var description: String { message }
}

// ── CE QUI TRAVERSE ─────────────────────────────────────────────────────────

/// Le protocole d'un point d'écoute.
public enum Protocole: UInt8, Sendable {
  case tcp = 1
  case udp = 2
}

/// D'où vient une adresse.
public enum Origine: UInt8, Sendable {
  /// L'annuaire nous a VU sous cette adresse.
  case reflexif = 1
  /// Le daemon l'a annoncée lui-même.
  case annonce = 2
}

/// Ce que l'annuaire sait d'un point d'écoute.
///
/// **TROIS DE CES QUATRE VALEURS NE VEULENT PAS DIRE « ÇA NE MARCHE PAS ».**
/// `enCours` n'affirme rien — l'annuaire répond avant d'avoir sondé, pour ne pas
/// faire attendre le démarrage d'un daemon. `nonSonde` dit qu'il ne mesurera pas :
/// UDP n'a pas de poignée de main, donc une sonde n'y distinguerait pas « écoute
/// et ignore » de « rien n'écoute ».
///
/// C'est pourquoi `Candidat` n'a pas de propriété `joignable` : elle serait juste
/// une fois sur deux, et ferait écarter un candidat parfaitement bon.
public enum Verdict: UInt8, Sendable {
  case joignable = 1
  case injoignable = 2
  case nonSonde = 3
  case enCours = 4
}

/// Cette machine est-elle derrière un NAT ?
///
/// **TROIS VALEURS, ET NON UN `Bool`.** Un daemon qui n'a annoncé aucune adresse
/// locale ne donne rien à comparer à l'adresse réflexive, et répondre `false`
/// serait affirmer ce qui n'a pas été mesuré.
public enum VerdictNat: UInt8, Sendable {
  /// L'adresse sous laquelle l'annuaire nous voit est une des nôtres.
  case non = 1
  /// Elle n'en est aucune : quelque chose traduit entre nous et lui.
  case oui = 2
  /// Rien à comparer. **Aucune conclusion n'en découle.**
  case indetermine = 3
}

/// Un point d'écoute à annoncer.
public struct Point: Sendable, Equatable {
  public let protocole: Protocole
  public let port: UInt16

  /// - Throws: `Faute.argument` si le port est nul.
  public init(_ protocole: Protocole, _ port: UInt16) throws {
    guard port != 0 else { throw Faute.argument }
    self.protocole = protocole
    self.port = port
  }
}

extension Point: CustomStringConvertible {
  public var description: String { "\(protocole):\(port)" }
}

/// Où joindre un service, et ce que l'annuaire en sait.
public struct Candidat: Sendable, Equatable {
  public let protocole: Protocole
  /// L'adresse, déjà mise en texte.
  public let adresse: String
  public let port: UInt16
  public let origine: Origine
  public let verdict: Verdict

  /// **PUBLIC, ALORS QUE SEULE LA BIBLIOTHÈQUE EN FABRIQUE.** Une `struct`
  /// publique n'expose PAS son initialiseur par défaut : sans celui-ci, un
  /// porteur ne pourrait pas écrire un cas d'essai à lui.
  public init(
    protocole: Protocole, adresse: String, port: UInt16,
    origine: Origine, verdict: Verdict
  ) {
    self.protocole = protocole
    self.adresse = adresse
    self.port = port
    self.origine = origine
    self.verdict = verdict
  }
}

extension Candidat: CustomStringConvertible {
  /// La forme qu'on recopie dans une commande — **avec ses crochets en IPv6**.
  ///
  /// Sans eux, `2001:db8::1:8080` est ambigu : le dernier `:` sépare-t-il un
  /// port ou un groupe d'adresse ?
  public var description: String {
    adresse.contains(":") ? "[\(adresse)]:\(port)" : "\(adresse):\(port)"
  }
}

/// Ce que l'annuaire a mesuré APRÈS coup, et poussé sur la connexion tenue.
///
/// **ELLE N'A NI SERVICE NI BAIL** — elle ne répond à aucune question, elle corrige
/// ce qu'une réponse antérieure disait « en cours ». C'est pourquoi elle n'a pas la
/// forme de ce que rend `ou`.
public struct Poussee: Sendable, Equatable {
  /// La liste ENTIÈRE des candidats, dans l'ordre, et non un delta.
  public let candidats: [Candidat]
  public let derriereNat: VerdictNat

  /// **PUBLIC, ALORS QUE SEULE LA BIBLIOTHÈQUE EN FABRIQUE**, pour la même raison
  /// que celui de `Candidat` : un porteur doit pouvoir écrire un cas d'essai.
  public init(candidats: [Candidat], derriereNat: VerdictNat) {
    self.candidats = candidats
    self.derriereNat = derriereNat
  }
}

/// Ce que l'annonce a fait jusqu'ici.
public struct Etat: Sendable, Equatable {
  /// L'annuaire nous connaît EN CE MOMENT : authentifiés ET annoncés.
  ///
  /// **Ce n'est pas « la socket est ouverte »** : une connexion qui s'ouvre puis
  /// se fait refuser l'authentification n'annonce rien.
  public let attachee: Bool
  /// Combien de fois on s'est attaché depuis le départ.
  public let attaches: UInt64
  /// Combien de fois une attache établie s'est rompue.
  public let ruptures: UInt64
  /// La tâche a renoncé, et ne réessaiera pas.
  ///
  /// **Elle ne renonce que sur une faute de configuration.** Jamais sur une
  /// panne de réseau, quelle qu'en soit la durée. C'est le seul état dont un
  /// humain doit être averti.
  public let abandonnee: Bool

  /// Voir `Candidat.init` : une `struct` publique n'expose pas son
  /// initialiseur par défaut.
  public init(attachee: Bool, attaches: UInt64, ruptures: UInt64, abandonnee: Bool) {
    self.attachee = attachee
    self.attaches = attaches
    self.ruptures = ruptures
    self.abandonnee = abandonnee
  }
}

/// L'identité d'une machine. **Conservez les deux.**
///
/// La clé est générée sur la machine et sa moitié privée n'en sort pas ; ce couple
/// est le seul justificatif durable, et le code d'enrôlement est dépensé.
///
/// **LA GRAINE EST LE SECRET**, et sa conservation vous appartient : elle n'est pas
/// chiffrée, et quiconque la lit devient cette machine.
public struct Identite: Sendable, Equatable {
  public let machine: String
  public let graine: [UInt8]

  /// - Throws: `Faute.argument` si la graine ne fait pas trente-deux octets.
  public init(machine: String, graine: [UInt8]) throws {
    guard graine.count == Int(ASL_GRAINE_OCTETS) else { throw Faute.argument }
    self.machine = machine
    self.graine = graine
  }
}

extension Identite: CustomStringConvertible {
  /// Sans la graine. **UN SECRET NE SE MET PAS DANS UN JOURNAL**, et la
  /// description par défaut d'une `struct` l'aurait imprimé au premier
  /// `print(identite)`.
  public var description: String { "Identite(machine: \(machine), graine: <32 octets>)" }
}

/// La version de la bibliothèque NATIVE, et non de ce paquet.
///
/// C'est celle qui compte : le paquet Swift n'est qu'un habillage, et deux
/// versions qui divergeraient se verraient ici.
public func version() -> (majeur: UInt32, mineur: UInt32, correctif: UInt32) {
  var majeur: UInt32 = 0
  var mineur: UInt32 = 0
  var correctif: UInt32 = 0
  asl_version(&majeur, &mineur, &correctif)
  return (majeur, mineur, correctif)
}

// ── LE CLIENT ───────────────────────────────────────────────────────────────

/// Combien de candidats on demande d'emblée.
///
/// **LE DIMENSIONNEMENT EN DEUX TEMPS DU C COÛTERAIT DEUX ALLERS-RETOURS** :
/// `asl_ou` refait la requête à chaque appel, il ne garde pas de résultat. On
/// demande donc large — le protocole borne un service à huit points d'écoute.
private let candidatsDEmblee = 8

/// Un client d'annuaire : il annonce, il résout, il tient sa connexion.
///
/// # SA DESTRUCTION RETIRE L'ANNONCE, ET ELLE EST DÉTERMINISTE
///
/// La connexion EST le bail : il n'y a pas de « retrait » séparé à appeler.
///
/// **Swift est le seul des cinq où « le laisser sortir de portée » est une
/// réponse juste.** Ruby et Kotlin ont besoin d'un finaliseur — un filet, qui
/// s'exécute quand le ramasse-miettes passe, c'est-à-dire à un moment qu'on ne
/// choisit pas. Ici le comptage de références rend `deinit` déterministe : la
/// dernière référence qui disparaît ferme, tout de suite.
///
/// `fermer()` existe pour rendre l'instant explicite, et il est idempotent.
///
/// # IL N'EST PAS `Sendable`, ET C'EST LE POINT
///
/// L'ABI dit qu'un client ne se partage pas entre fils. Sous le mode Swift 6, le
/// compilateur REFUSE de le partager entre domaines d'isolement — pas de verrou,
/// pas de coût, et la faute est attrapée avant d'exister. Le déplacer d'un
/// domaine à un autre reste permis, et reste correct : ce n'est pas un partage.
///
/// # LES APPELS QUI BLOQUENT
///
/// `enroler` et `ou` attendent jusqu'à vingt secondes. **Ne les appelez pas depuis
/// le pool coopératif** : un fil bloqué là-bas ne se remplace pas. Un fil à vous,
/// ou `DispatchQueue.global()`.
public final class Client {
  private var brut: OpaquePointer?

  /// Monte un client. **Il n'ouvre aucune connexion** : un annuaire injoignable
  /// ne doit pas empêcher un daemon de démarrer.
  ///
  /// `annuaires` est une liste de couples `(adresse, nom)`. L'adresse est
  /// LITTÉRALE — `"203.0.113.7:6630"` ou `"[2001:db8::1]:6630"` —, jamais un nom
  /// d'hôte : **la résolution vous appartient**, parce que vous avez déjà un
  /// résolveur, une politique de cache et des fils.
  ///
  /// Le second membre est le nom qu'on EXIGE du certificat. Il n'est pas déduit
  /// de l'adresse : le déduire reviendrait à faire confiance à qui répond à
  /// cette adresse.
  ///
  /// `racines` est le contenu d'un fichier PEM. **Il n'y a pas de repli sur le
  /// magasin du système** : les annuaires sont signés par LEUR autorité.
  ///
  /// - Throws: `Faute`.
  public init(
    annuaires: [(String, String)] = [],
    racines: [UInt8]? = nil,
    identite: Identite? = nil
  ) throws {
    var neuf: OpaquePointer?
    try Faute.verifier(asl_client_neuf(&neuf))
    brut = neuf

    // **CE QUI EST OUVERT SE FERME, MÊME QUAND L'INITIALISATION ÉCHOUE.**
    // Un `init` qui lève n'appelle PAS `deinit` : sans ce `do`, une adresse
    // mal écrite laisserait un objet natif que plus rien ne référence.
    do {
      for (adresse, nom) in annuaires {
        try ajouterAnnuaire(adresse, nom: nom)
      }
      if let racines { try poserRacines(racines) }
      if let identite { try poserIdentite(identite) }
    } catch {
      fermer()
      throw error
    }
  }

  deinit { fermer() }

  /// Ce client tient-il encore quelque chose ?
  public var ouvert: Bool { brut != nil }

  /// Ferme le client, **et retire l'annonce en le faisant**.
  ///
  /// Elle est retirée PROPREMENT, ce qui épargne à l'annuaire la minute
  /// d'inactivité pendant laquelle il donnerait à vos clients une adresse morte.
  /// Cet appel peut donc prendre jusqu'à deux secondes.
  ///
  /// Appeler deux fois ne fait rien la seconde.
  public func fermer() {
    if let ouvert = brut {
      brut = nil
      asl_client_libere(ouvert)
    }
  }

  // ── La configuration ────────────────────────────────────────────────────

  /// Ajoute un annuaire à essayer. **Répétable, et l'ordre compte.**
  ///
  /// L'IPv6 est essayé d'abord quel que soit l'ordre des appels ; à l'intérieur
  /// d'une famille, c'est cet ordre qui décide.
  ///
  /// - Throws: `Faute`.
  public func ajouterAnnuaire(_ adresse: String, nom: String) throws {
    let vivant = try exige()
    try Self.verifierChaine(adresse)
    try Self.verifierChaine(nom)
    try Faute.verifier(
      adresse.withCString { a in
        nom.withCString { n in asl_client_annuaire(vivant, a, n) }
      })
  }

  /// Pose les certificats d'autorité, en PEM.
  ///
  /// - Throws: `Faute`.
  public func poserRacines(_ pem: [UInt8]) throws {
    let vivant = try exige()
    try Faute.verifier(
      pem.withUnsafeBufferPointer { tampon in
        asl_client_racines(vivant, tampon.baseAddress, tampon.count)
      })
  }

  /// Installe l'identité de cette machine.
  ///
  /// - Throws: `Faute`.
  public func poserIdentite(_ identite: Identite) throws {
    let vivant = try exige()
    try Self.verifierChaine(identite.machine)
    try Faute.verifier(
      identite.machine.withCString { machine in
        identite.graine.withUnsafeBufferPointer { graine in
          asl_client_identite(vivant, machine, graine.baseAddress)
        }
      })
  }

  // ── Les verbes ──────────────────────────────────────────────────────────

  /// Présente un code d'enrôlement, et rend l'identité obtenue.
  ///
  /// L'identité est installée dans ce client au passage.
  ///
  /// **Cet appel bloque** — jusqu'à vingt secondes s'il faut attendre.
  ///
  /// - Throws: `Faute`.
  public func enroler(code: String) throws -> Identite {
    let vivant = try exige()
    try Self.verifierChaine(code)

    var machine = [CChar](repeating: 0, count: Int(ASL_IDENTIFIANT_OCTETS))
    var graine = [UInt8](repeating: 0, count: Int(ASL_GRAINE_OCTETS))

    try Faute.verifier(
      code.withCString { c in
        machine.withUnsafeMutableBufferPointer { m in
          graine.withUnsafeMutableBufferPointer { g in
            asl_enroler(vivant, c, m.baseAddress, g.baseAddress)
          }
        }
      })
    return try Identite(machine: Self.texte(machine), graine: graine)
  }

  /// Annonce ce service, et **rend la main tout de suite**.
  ///
  /// L'annonce est ensuite tenue par un fil natif, aussi longtemps que ce client
  /// vit : elle se réauthentifie et se réannonce seule à chaque reconnexion, et
  /// bascule sur l'autre annuaire racine quand le premier tombe.
  ///
  /// **UN CLIENT N'ANNONCE QU'UNE FOIS** : un second appel lève `Faute.deja`
  /// plutôt que de remplacer la première en silence, ce qui la retirerait.
  ///
  /// - Throws: `Faute`.
  public func annoncer(service: String, points: [Point]) throws {
    let vivant = try exige()
    guard !points.isEmpty else { throw Faute.argument }
    try Self.verifierChaine(service)

    var bruts = points.map { point in
      asl_point(port: point.port, protocole: point.protocole.rawValue, reserve: 0)
    }
    try Faute.verifier(
      service.withCString { s in
        bruts.withUnsafeMutableBufferPointer { tableau in
          asl_annoncer(vivant, s, tableau.baseAddress, tableau.count)
        }
      })
  }

  /// Où en est l'annonce. Un client qui n'a jamais annoncé rend tout à zéro.
  ///
  /// - Throws: `Faute`.
  public func etat() throws -> Etat {
    let vivant = try exige()
    var brute = asl_etat_t()
    try Faute.verifier(asl_etat(vivant, &brute))
    return Etat(
      attachee: brute.attachee == 1,
      attaches: brute.attaches,
      ruptures: brute.ruptures,
      abandonnee: brute.abandonnee == 1)
  }

  /// Demande où joindre un service, et rend les candidats **dans l'ordre**.
  ///
  /// L'ordre est celui qu'un client doit suivre — IPv6 d'abord, adresse observée
  /// avant adresse annoncée — et il n'est pas à vous de le deviner.
  ///
  /// **`tamponTropPetit` NE REMONTE PAS** : la liaison redemande avec la taille
  /// qu'on lui a dite. C'est tout ce qu'un porteur veut savoir.
  ///
  /// **Cet appel bloque**, comme `enroler`.
  ///
  /// - Throws: `Faute`.
  public func ou(machine: String, service: String) throws -> [Candidat] {
    let vivant = try exige()
    try Self.verifierChaine(machine)
    try Self.verifierChaine(service)

    var place = candidatsDEmblee
    var ecrit = 0
    var code = ASL_TAMPON_TROP_PETIT
    var bruts = [asl_candidat]()

    // Deux tours au plus : le premier avec la borne du protocole, le second
    // avec la taille que l'ABI vient d'écrire.
    for tour in 0..<2 {
      bruts = [asl_candidat](repeating: asl_candidat(), count: max(place, 1))
      code = machine.withCString { m in
        service.withCString { s in
          bruts.withUnsafeMutableBufferPointer { tampon in
            asl_ou(vivant, m, s, tampon.baseAddress, place, &ecrit)
          }
        }
      }
      if code != ASL_TAMPON_TROP_PETIT { break }
      if tour == 0 { place = max(ecrit, 1) }
    }
    try Faute.verifier(code)

    return bruts.prefix(ecrit).map(Self.decoder)
  }

  /// Combien de poussées de verdict sont arrivées depuis le départ.
  ///
  /// **ZÉRO N'EST PAS UNE ANOMALIE** : l'annuaire ne pousse que ce qui a CHANGÉ,
  /// et un service dont les sondes confirment ce qu'il disait déjà n'en produit
  /// aucune.
  ///
  /// **C'EST LE COMPTEUR QU'ON SURVEILLE, PAS LE CONTENU** : une poussée porte
  /// toute la liste, donc relire `dernierePoussee` sans que celui-ci ait bougé
  /// rend deux fois la même chose.
  ///
  /// - Throws: `Faute`.
  public func pousseesRecues() throws -> UInt64 {
    let vivant = try exige()
    var combien: UInt64 = 0
    try Faute.verifier(asl_poussees_recues(vivant, &combien))
    return combien
  }

  /// Le dernier verdict poussé, ou `nil` si rien ne l'a encore été.
  ///
  /// **`nil` N'EST PAS UNE FAUTE, ET C'EST POURQUOI CE N'EST PAS UN `throw`.** Ne
  /// rien avoir reçu est le cas ordinaire au démarrage — l'annuaire répond « en
  /// cours » avant d'avoir sondé —, et lever ici obligerait un porteur à écrire un
  /// `try?` autour de ce qu'il appelle chaque seconde, ce qui lui ferait avaler
  /// aussi les fautes qui, elles, comptent.
  ///
  /// Comme pour `ou`, `tamponTropPetit` ne remonte pas.
  ///
  /// - Throws: `Faute`.
  public func dernierePoussee() throws -> Poussee? {
    let vivant = try exige()

    var place = candidatsDEmblee
    var ecrit = 0
    var nat = UInt8(ASL_NAT_INDETERMINE)
    var code = ASL_TAMPON_TROP_PETIT
    var bruts = [asl_candidat]()

    for tour in 0..<2 {
      bruts = [asl_candidat](repeating: asl_candidat(), count: max(place, 1))
      code = bruts.withUnsafeMutableBufferPointer { tampon in
        asl_derniere_poussee(vivant, tampon.baseAddress, place, &ecrit, &nat)
      }
      if code != ASL_TAMPON_TROP_PETIT { break }
      if tour == 0 { place = max(ecrit, 1) }
    }
    if code == ASL_PAS_DE_POUSSEE { return nil }
    try Faute.verifier(code)

    return Poussee(
      candidats: bruts.prefix(ecrit).map(Self.decoder),
      // **UN OCTET INCONNU DEVIENT `.indetermine`, ET NON UNE FAUTE.** Une
      // bibliothèque native plus récente qui ajouterait une quatrième valeur ne
      // doit pas faire échouer un programme déjà déployé : ne rien conclure est
      // exactement ce que ce verdict veut dire.
      derriereNat: VerdictNat(rawValue: nat) ?? .indetermine)
  }

  // ── Ce qui ne traverse pas ──────────────────────────────────────────────

  /// Le pointeur natif, ou une faute qui dit ce qui s'est passé.
  ///
  /// **DÉRÉFÉRENCER UN POINTEUR LIBÉRÉ TUERAIT LE PROCESSUS DE L'HÔTE.** Ici la
  /// sanction est une faute, et elle nomme la cause.
  private func exige() throws -> OpaquePointer {
    guard let vivant = brut else { throw Faute.ferme }
    return vivant
  }

  /// **UN NUL AU MILIEU EST REFUSÉ ICI**, et non transmis : `withCString` le
  /// laisserait passer, le C s'arrêterait au premier, et l'annuaire recevrait un
  /// nom plus court que celui qu'on croit lui avoir donné.
  private static func verifierChaine(_ texte: String) throws {
    guard !texte.utf8.contains(0) else { throw Faute.argument }
  }

  /// Une chaîne C rendue par l'ABI, tronquée à son NUL.
  ///
  /// `String(cString:)` sur un tableau est déprécié depuis Swift 6, et pour une
  /// bonne raison : il lisait au-delà du tampon si le NUL manquait. Ici la
  /// troncature est explicite.
  private static func texte(_ octets: [CChar]) -> String {
    let utf8 = octets.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
    return String(decoding: utf8, as: UTF8.self)
  }

  /// Un candidat de l'ABI, en objets Swift.
  private static func decoder(_ brut: asl_candidat) -> Candidat {
    var adresse = brut.adresse
    let texte = withUnsafeBytes(of: &adresse) { octets -> String in
      var place = [CChar](repeating: 0, count: 64)
      // **`inet_ntop` MET L'ADRESSE EN TEXTE, ET IL LE FAIT BIEN.** Écrire
      // soi-même la compression de la RFC 5952 est un piège — une seule
      // série de zéros, la plus longue, la première en cas d'égalité. La
      // liaison C++ a préféré ne pas abréger du tout, faute de l'avoir sous
      // la main ; ici la bibliothèque C que l'on lie déjà le sait.
      let famille = brut.famille == 6 ? AF_INET6 : AF_INET
      let rendu = place.withUnsafeMutableBufferPointer { sortie in
        inet_ntop(famille, octets.baseAddress, sortie.baseAddress, socklen_t(sortie.count))
      }
      return rendu == nil ? "" : Self.texte(place)
    }
    return Candidat(
      protocole: Protocole(rawValue: brut.protocole) ?? .tcp,
      adresse: texte,
      port: brut.port,
      origine: Origine(rawValue: brut.origine) ?? .reflexif,
      verdict: Verdict(rawValue: brut.verdict) ?? .enCours)
  }
}
