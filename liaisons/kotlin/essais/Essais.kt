// Les essais de la liaison Kotlin.
//
// DEUX QUESTIONS, ET ELLES SONT DISTINCTES
// ========================================
//
// **La transcription dit-elle la même chose que l'en-tête ?** La JVM ne peut pas
// INCLURE un en-tête C — contrairement à C++, qui obtient cette réponse
// gratuitement. Kotlin est donc de retour dans le camp de Python et de Ruby :
// il recopie, et il faut comparer. Une constante qui dériverait ne casserait rien
// nulle part ; elle ferait lever `Refuse` là où l'ABI dit `Injoignable`.
//
// **La traduction est-elle juste ?** Un code de retour devenu `Result`, un
// segment natif devenu objet fermable, un `Cleaner` qui ne doit pas voir son
// objet. Rien de cela n'est éprouvé ailleurs.
//
// PAS DE CADRE D'ESSAI TIERS
// ==========================
//
// Ni JUnit ni Kotest : ce dépôt n'impose de dépendance à personne, pas même pour
// ses propres essais. Vingt lignes font le même travail, et il n'y a rien à
// télécharger pour construire ce dépôt.

package io.github.airdesktopproject.asl.essais

import io.github.airdesktopproject.asl.Abi
import io.github.airdesktopproject.asl.AslErreur
import io.github.airdesktopproject.asl.Candidat
import io.github.airdesktopproject.asl.Client
import io.github.airdesktopproject.asl.Configuration
import io.github.airdesktopproject.asl.Deja
import io.github.airdesktopproject.asl.Ferme
import io.github.airdesktopproject.asl.Identite
import io.github.airdesktopproject.asl.Injoignable
import io.github.airdesktopproject.asl.MauvaisArgument
import io.github.airdesktopproject.asl.Nettoyage
import io.github.airdesktopproject.asl.Origine
import io.github.airdesktopproject.asl.PasDIdentite
import io.github.airdesktopproject.asl.Point
import io.github.airdesktopproject.asl.Poussee
import io.github.airdesktopproject.asl.Protocole
import io.github.airdesktopproject.asl.Verdict
import io.github.airdesktopproject.asl.VerdictNat
import io.github.airdesktopproject.asl.version
import java.lang.foreign.MemorySegment
import java.lang.invoke.MethodHandles
import java.lang.invoke.MethodType
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicReference

private var echecs = 0
private var verifications = 0

private fun verifie(tenu: Boolean, quoi: String) {
    verifications += 1
    if (!tenu) {
        echecs += 1
        System.err.println("ÉCHEC — $quoi")
    }
}

private fun <T> verifieEgal(obtenu: T, attendu: T, quoi: String) {
    verifie(obtenu == attendu, "$quoi : obtenu $obtenu, attendu $attendu")
}

/** Un identifiant de machine VALIDE — préfixe et somme de contrôle compris.
 *
 * Recopié plutôt que calculé : le calculer demanderait de réimplémenter
 * l'alphabet de Crockford d'`asl-id` ici, c'est-à-dire d'en faire une copie qui
 * divergerait. Si `asl-id` change de forme, cet essai le dira.
 */
private const val MACHINE = "m-0H248H248H248H248H248H248H"

private fun identiteDEssai() = Identite(MACHINE, ByteArray(32) { it.toByte() })

/** Un client dont la racine est illisible : de quoi atteindre `Configuration`. */
private fun clientConfigure(avecIdentite: Boolean): Client =
    Client.ouvrir(
        annuaires = listOf("127.0.0.1:1" to "localhost"),
        racines = "pas un PEM".toByteArray(),
        identite = if (avecIdentite) identiteDEssai() else null,
    ).getOrThrow()

// ── L'EN-TÊTE EST LA RÉFÉRENCE ─────────────────────────────────────────────

private fun entete(): String {
    val chemin = Path.of("crates", "asl-client-ffi", "include", "asl.h")
    check(Files.isRegularFile(chemin)) {
        "$chemin est introuvable — lancez les essais depuis la racine du dépôt"
    }
    return Files.readString(chemin)
}

private fun constantesDeLEntete(): Map<String, Int> {
    val motif = Regex("""^#define\s+ASL_([A-Z0-9_]+)\s+(-?\d+)\s*$""")
    return entete().lines().mapNotNull { ligne ->
        motif.find(ligne.trim())?.let { it.groupValues[1] to it.groupValues[2].toInt() }
    }.toMap()
}

private fun champsDeLEntete(nom: String): List<String> {
    // `[^{}]*` et non `.*?` : le second partirait du PREMIER `typedef struct {`
    // du fichier et avalerait les structures précédentes.
    val corps = Regex("""typedef struct \{([^{}]*)\} $nom;""", RegexOption.DOT_MATCHES_ALL)
        .find(entete())?.groupValues?.get(1)
    checkNotNull(corps) { "l'en-tête ne déclare pas $nom" }
    val champ = Regex("""^\w+\s+(\w+)\s*(\[\d+\])?\s*;""")
    return corps.lines().mapNotNull { ligne ->
        champ.find(ligne.replace(Regex("""/\*.*?\*/"""), "").trim())?.groupValues?.get(1)
    }
}

private fun tailleAnnoncee(nom: String): Int {
    val texte = entete()
    val avant = texte.substring(0, texte.indexOf("} $nom;"))
    return Regex("""(\d+) octets\.""").findAll(avant).last().groupValues[1].toInt()
}

private fun lEnteteEstLaReference() {
    val declarees = constantesDeLEntete()
    verifie(declarees.size > 10, "l'en-tête n'a pas été lu")

    val transcrites = mapOf(
        "OK" to Abi.OK, "ARGUMENT" to Abi.ARGUMENT, "CONFIGURATION" to Abi.CONFIGURATION,
        "INJOIGNABLE" to Abi.INJOIGNABLE, "REFUSE" to Abi.REFUSE,
        "TAMPON_TROP_PETIT" to Abi.TAMPON_TROP_PETIT, "INTERNE" to Abi.INTERNE,
        "PAS_D_IDENTITE" to Abi.PAS_D_IDENTITE, "DEJA" to Abi.DEJA,
        "PAS_DE_POUSSEE" to Abi.PAS_DE_POUSSEE,
        "IDENTIFIANT_OCTETS" to Abi.IDENTIFIANT_OCTETS, "GRAINE_OCTETS" to Abi.GRAINE_OCTETS,
        "TCP" to Abi.TCP, "UDP" to Abi.UDP,
        "REFLEXIF" to Abi.REFLEXIF, "ANNONCE" to Abi.ANNONCE,
        "JOIGNABLE" to Abi.JOIGNABLE, "INJOIGNABLE_POINT" to Abi.INJOIGNABLE_POINT,
        "NON_SONDE" to Abi.NON_SONDE, "EN_COURS" to Abi.EN_COURS,
        "NAT_NON" to Abi.NAT_NON, "NAT_OUI" to Abi.NAT_OUI,
        "NAT_INDETERMINE" to Abi.NAT_INDETERMINE,
    )

    for ((nom, valeur) in declarees) {
        verifie(transcrites.containsKey(nom), "`ASL_$nom` est dans l'en-tête et pas ici")
        transcrites[nom]?.let { verifieEgal(it, valeur, "`ASL_$nom`") }
    }
    // **L'INVERSE COMPTE AUTANT** : une constante que Kotlin connaît et que
    // l'en-tête ignore est une valeur que personne n'a promise.
    for (nom in transcrites.keys) {
        verifie(declarees.containsKey(nom), "`ASL_$nom` est ici et pas dans l'en-tête")
    }
}

private fun lesDispositionsSuiventLEntete() {
    // Les tailles sont déjà vérifiées au chargement d'`Abi` — ce qui l'est ici est
    // l'accord avec les nombres ÉCRITS dans les commentaires de l'en-tête, que les
    // cinq liaisons recopient.
    verifieEgal(Abi.POINT.byteSize().toInt(), tailleAnnoncee("asl_point"), "asl_point")
    verifieEgal(Abi.CANDIDAT.byteSize().toInt(), tailleAnnoncee("asl_candidat"), "asl_candidat")
    verifieEgal(Abi.ETAT.byteSize().toInt(), tailleAnnoncee("asl_etat_t"), "asl_etat_t")

    // **UN CHAMP DÉPLACÉ NE CHANGE PAS LA TAILLE** : on lirait un port là où il y
    // a un protocole, sans que rien ne proteste. Les décalages viennent de la
    // disposition, donc les comparer aux noms de l'en-tête suffit.
    for ((nom, disposition) in listOf(
        "asl_point" to Abi.POINT,
        "asl_candidat" to Abi.CANDIDAT,
        "asl_etat_t" to Abi.ETAT,
    )) {
        val attendus = champsDeLEntete(nom)
        var decalage = 0L
        for (champ in attendus) {
            verifieEgal(Abi.decalage(disposition, champ), decalage, "$nom.$champ")
            decalage = Abi.decalage(disposition, champ) +
                disposition.select(
                    java.lang.foreign.MemoryLayout.PathElement.groupElement(champ),
                ).byteSize()
        }
        verifieEgal(decalage, disposition.byteSize(), "$nom : la somme des champs")
    }
}

// ── LA VERSION ET LES ERREURS ──────────────────────────────────────────────

private fun laVersionVientDeLaBibliothequeNative() {
    verifieEgal(version(), Triple(0, 1, 0), "la version native")
}

private fun chaqueCodeASaClasse() {
    val client = Client.ouvrir().getOrThrow()
    client.close()
    // Un client fermé : la classe `Ferme` porte le code d'un argument invalide,
    // mais elle DIT autre chose — « ce client est fermé » et non « argument ».
    val quoi = client.etat().exceptionOrNull()
    verifie(quoi is Ferme, "un client fermé doit rendre `Ferme`, pas ${quoi?.javaClass}")
    verifie(quoi is AslErreur, "tout doit descendre d'`AslErreur`")
    verifie(quoi?.message?.contains("fermé") == true, "et le message doit le dire")
}

private fun lesMessagesViennentDeLaBibliotheque() {
    // **DEUX LISTES DE MESSAGES FINIRAIENT PAR DIVERGER**, et c'est celle qu'on
    // oublie de corriger que l'utilisateur lirait.
    val client = clientConfigure(true)
    client.use {
        val quoi = it.ou(MACHINE, "depot").exceptionOrNull()
        verifie(quoi is Configuration, "une racine illisible est une configuration")
        verifie(
            quoi?.message?.isNotEmpty() == true,
            "le message vient de la bibliothèque native",
        )
    }
}

// ── LA CONSTRUCTION ────────────────────────────────────────────────────────

private fun unClientNeufNOuvreRienEtSonEtatEstAZero() {
    Client.ouvrir().getOrThrow().use { client ->
        val etat = client.etat().getOrThrow()
        verifie(!etat.attachee, "rien n'est attaché")
        verifieEgal(etat.attaches, 0L, "attaches")
        verifieEgal(etat.ruptures, 0L, "ruptures")
        verifie(!etat.abandonnee, "n'avoir rien tenté n'est pas avoir renoncé")
    }
}

private fun uneAdresseIllisibleEstRefusee() {
    for (mauvaise in listOf(
        "nitrogen.example:6630", // un NOM : la résolution appartient à l'appelant
        "203.0.113.7", // pas de port
        "2001:db8::1:6630", // sans crochets, c'est ambigu
        "",
    )) {
        val issue = Client.ouvrir(annuaires = listOf(mauvaise to "localhost"))
        verifie(
            issue.exceptionOrNull() is MauvaisArgument,
            "`$mauvaise` doit être refusée : ${issue.exceptionOrNull()}",
        )
    }
    Client.ouvrir(
        annuaires = listOf(
            "203.0.113.7:6630" to "nitrogen.example",
            "[2001:db8::1]:6630" to "nitrogen.example",
        ),
    ).getOrThrow().use { verifie(it.ouvert, "les deux familles sont acceptées") }
}

private fun unNulAuMilieuDUneChaineEstRefuse() {
    // **LE C S'ARRÊTERAIT AU PREMIER**, et l'annuaire recevrait un nom plus court
    // que celui qu'on croit lui avoir donné.
    Client.ouvrir().getOrThrow().use { client ->
        val tricherie = "127.0.0.1:1" + Char(0) + "et la suite"
        val issue = client.ajouterAnnuaire(tricherie, "localhost")
        verifie(issue.exceptionOrNull() is MauvaisArgument, "un NUL doit être refusé")
    }
}

private fun uneGraineDeMauvaiseTailleEstRefusee() {
    var leve = false
    try {
        Identite(MACHINE, ByteArray(31))
    } catch (quoi: IllegalArgumentException) {
        leve = quoi.message?.contains("32") == true
    }
    verifie(leve, "une graine de 31 octets doit être refusée, avec les deux nombres")
}

private fun unSecretNeSeMetPasDansUnJournal() {
    // Une `data class` aurait imprimé la graine au premier `log.debug`.
    val texte = identiteDEssai().toString()
    verifie(texte.contains(MACHINE), "la machine se lit")
    verifie(!texte.contains("[B@"), "la graine ne doit pas apparaître : $texte")
    verifie(texte.contains("<32 octets>"), "et l'on dit qu'elle est là : $texte")
}

// ── L'ANNONCE ──────────────────────────────────────────────────────────────

private fun sansIdentiteOnNePeutRienSigner() {
    clientConfigure(false).use { client ->
        val issue = client.annoncer("depot", listOf(Point(Protocole.TCP, 8080)))
        verifie(issue.exceptionOrNull() is PasDIdentite, "sans identité, rien à signer")
    }
}

private fun unPointMalFormeEstRefuseASaConstruction() {
    // Le refus est dans `Point`, donc AVANT qu'un client existe : un porteur
    // l'apprend en écrivant sa configuration.
    for (port in listOf(0, -1, 65536)) {
        var leve = false
        try {
            Point(Protocole.TCP, port)
        } catch (_: IllegalArgumentException) {
            leve = true
        }
        verifie(leve, "le port $port doit être refusé")
    }
}

private fun uneAnnonceSansPointNAnnonceRien() {
    clientConfigure(true).use { client ->
        val issue = client.annoncer("depot", emptyList())
        verifie(issue.exceptionOrNull() is MauvaisArgument, "aucun point")
    }
}

private fun unClientNAnnonceQuUneFois() {
    clientConfigure(true).use { client ->
        verifie(client.annoncer("depot", listOf(Point(Protocole.TCP, 8080))).isSuccess, "la première")
        val issue = client.annoncer("depot", listOf(Point(Protocole.TCP, 8081)))
        verifie(issue.exceptionOrNull() is Deja, "la seconde doit rendre `Deja`")
    }
}

private fun leFilNatifTourneSansQuePersonneLAttende() {
    // **C'EST L'ESSAI QUI COMPTE LE PLUS.** `annoncer` a rendu la main et
    // l'appelant est parti ; si le fil natif ne tournait pas, `abandonnee` ne
    // passerait jamais à vrai — et tout compilerait.
    clientConfigure(true).use { client ->
        verifie(client.annoncer("depot", listOf(Point(Protocole.TCP, 8080))).isSuccess, "annoncée")
        var etat = client.etat().getOrThrow()
        for (tour in 0 until 250) {
            etat = client.etat().getOrThrow()
            if (etat.abandonnee) break
            Thread.sleep(20)
        }
        verifie(etat.abandonnee, "le fil natif n'a pas tourné")
        verifie(!etat.attachee, "et rien n'est attaché")
        verifieEgal(etat.attaches, 0L, "une racine illisible n'attache rien")
    }
}

private fun lIdentiteSurvitALAnnonce() {
    // L'annonce CONSOMME une identité côté Rust ; si le client la perdait, `ou`
    // répondrait « aucune identité » à un daemon qui vient de s'annoncer.
    clientConfigure(true).use { client ->
        verifie(client.annoncer("depot", listOf(Point(Protocole.TCP, 8080))).isSuccess, "annoncée")
        val quoi = client.ou(MACHINE, "depot").exceptionOrNull()
        verifie(quoi !is PasDIdentite, "l'annonce a emporté l'identité")
        verifie(quoi is Configuration, "la racine reste illisible : ${quoi?.javaClass}")
    }
}

// ── LA FERMETURE ───────────────────────────────────────────────────────────

private fun fermerDeuxFoisNeFaitRienLaSeconde() {
    val client = Client.ouvrir().getOrThrow()
    client.close()
    client.close()
    verifie(!client.ouvert, "un client fermé le reste")
}

private fun useFermeMemeQuandLeBlocLeve() {
    var dehors: Client? = null
    var leve = false
    try {
        Client.ouvrir().getOrThrow().use { client ->
            dehors = client
            error("quelque chose")
        }
    } catch (_: IllegalStateException) {
        leve = true
    }
    verifie(leve, "l'exception traverse")
    verifie(dehors?.ouvert == false, "et le client a été fermé quand même")
}

private object Temoin {
    @JvmStatic
    var appels = 0

    @JvmStatic
    fun liberer(segment: MemorySegment) {
        appels += 1
        require(segment.address() == 0x1234L)
    }
}

private fun leNettoyageLibereUneFoisEtUneSeule() {
    // **UN NETTOYEUR NE DOIT PAS VOIR SON OBJET** : une lambda qui le capturerait
    // le garderait accessible pour toujours, et ne s'exécuterait donc jamais.
    // C'est pourquoi `Nettoyage` est une classe de premier niveau — et pourquoi
    // elle s'éprouve ici sans ramasse-miettes, donc sans hasard.
    Temoin.appels = 0
    val boite = AtomicReference<MemorySegment?>(MemorySegment.ofAddress(0x1234L))
    val liberer = MethodHandles.lookup().findStatic(
        Temoin::class.java, "liberer", MethodType.methodType(Void.TYPE, MemorySegment::class.java),
    )
    val nettoyage = Nettoyage(boite, liberer)

    nettoyage.run()
    verifieEgal(Temoin.appels, 1, "libéré une fois")
    verifie(boite.get() == null, "la boîte est vidée")

    nettoyage.run()
    verifieEgal(Temoin.appels, 1, "une double libération est un usage-après-libération")
}

// ── CE QUI TRAVERSE ────────────────────────────────────────────────────────

private fun unCandidatV6PorteSesCrochets() {
    // Sans eux, `2001:db8::1:8080` est ambigu, et ce qu'on affiche ne se recopie
    // pas dans une commande.
    val six = Candidat(Protocole.TCP, "2001:db8::1", 8080, Origine.REFLEXIF, Verdict.EN_COURS)
    verifieEgal(six.toString(), "[2001:db8::1]:8080", "IPv6")

    val quatre = Candidat(Protocole.TCP, "203.0.113.7", 8080, Origine.ANNONCE, Verdict.JOIGNABLE)
    verifieEgal(quatre.toString(), "203.0.113.7:8080", "IPv4")

    verifieEgal(Point(Protocole.UDP, 9000).toString(), "udp:9000", "un point")
}

private fun leVerdictGardeSesQuatreValeurs() {
    // **TROIS D'ENTRE ELLES NE VEULENT PAS DIRE « ÇA NE MARCHE PAS ».**
    verifieEgal(Verdict.entries.size, 4, "le verdict")
    verifie(
        Candidat::class.java.methods.none { it.name == "getJoignable" },
        "une propriété `joignable` serait juste une fois sur deux",
    )
}

// ── LES VERDICTS POUSSÉS ────────────────────────────────────────────────────

private fun rienDePousseNEstPasUnePanne() {
    // **C'EST L'ÉTAT ORDINAIRE**, et non une faute : un daemon qui vient
    // d'annoncer n'a pas de verdict, l'annuaire sonde encore. Rendre `null` plutôt
    // qu'un `Result.failure` épargne à un porteur d'écrire `onFailure { }` autour
    // de ce qu'il appelle chaque seconde.
    Client.ouvrir().getOrThrow().use { client ->
        verifieEgal(client.pousseesRecues().getOrThrow(), 0L, "aucune poussée au départ")
        verifieEgal(client.dernierePoussee().getOrThrow(), null, "rien à rendre")
        verifie(client.dernierePoussee().isSuccess, "l'absence n'est pas un échec")
    }
}

private fun unClientFermeLeDitAussiPourLesPoussees() {
    // Et le dit par un `Ferme`, comme les autres verbes — pas par un `null`, qui
    // ferait passer un client fermé pour un client qui attend son premier verdict.
    val client = Client.ouvrir().getOrThrow()
    client.close()
    verifie(client.pousseesRecues().exceptionOrNull() is Ferme, "pousseesRecues sur un fermé")
    verifie(client.dernierePoussee().exceptionOrNull() is Ferme, "dernierePoussee sur un fermé")
}

private fun leVerdictDeNatATroisValeursEtPasDeux() {
    // Un `Boolean` n'aurait pas de place pour « je n'ai rien mesuré », et forcerait
    // à répondre `false` quand aucune adresse locale n'a été annoncée.
    verifieEgal(VerdictNat.entries.size, 3, "le verdict de NAT")
    verifie(VerdictNat.entries.none { it.brut == 0 }, "zéro n'est pas un verdict")

    // Une poussée porte la liste ENTIÈRE, et le dit dans son type : `List`, et non
    // un delta qu'il faudrait appliquer.
    val poussee = Poussee(
        candidats = listOf(
            Candidat(Protocole.TCP, "203.0.113.7", 8080, Origine.REFLEXIF, Verdict.JOIGNABLE),
        ),
        derriereNat = VerdictNat.OUI,
    )
    verifieEgal(poussee.candidats.first().toString(), "203.0.113.7:8080", "le candidat poussé")
    verifieEgal(poussee.derriereNat, VerdictNat.OUI, "le NAT")
}

private fun laLiaisonNaAucuneDependance() {
    // **CE QU'ELLE TIRE, SES PORTEURS L'INSTALLENT.** Un daemon qui embarque
    // cette liaison ne doit hériter d'aucune bibliothèque — et surtout pas de JNA,
    // qui embarque ses propres objets natifs.
    val racine = Path.of("liaisons", "kotlin", "src", "main", "kotlin")
    check(Files.isDirectory(racine)) { "$racine est introuvable" }

    val autorises = listOf("java.", "javax.", "kotlin.", "io.github.airdesktopproject.asl")
    Files.walk(racine).use { chemins ->
        chemins.filter { it.toString().endsWith(".kt") }.forEach { fichier ->
            Files.readAllLines(fichier).forEach { ligne ->
                val depouillee = ligne.trim()
                if (depouillee.startsWith("import ")) {
                    val quoi = depouillee.removePrefix("import ").substringBefore(' ')
                    verifie(
                        autorises.any { quoi.startsWith(it) },
                        "`$quoi` est hors du JDK et de la bibliothèque standard Kotlin",
                    )
                }
            }
        }
    }
}

fun main() {
    lEnteteEstLaReference()
    laLiaisonNaAucuneDependance()
    lesDispositionsSuiventLEntete()
    laVersionVientDeLaBibliothequeNative()
    chaqueCodeASaClasse()
    lesMessagesViennentDeLaBibliotheque()
    unClientNeufNOuvreRienEtSonEtatEstAZero()
    uneAdresseIllisibleEstRefusee()
    unNulAuMilieuDUneChaineEstRefuse()
    uneGraineDeMauvaiseTailleEstRefusee()
    unSecretNeSeMetPasDansUnJournal()
    sansIdentiteOnNePeutRienSigner()
    unPointMalFormeEstRefuseASaConstruction()
    uneAnnonceSansPointNAnnonceRien()
    unClientNAnnonceQuUneFois()
    leFilNatifTourneSansQuePersonneLAttende()
    lIdentiteSurvitALAnnonce()
    fermerDeuxFoisNeFaitRienLaSeconde()
    useFermeMemeQuandLeBlocLeve()
    leNettoyageLibereUneFoisEtUneSeule()
    unCandidatV6PorteSesCrochets()
    leVerdictGardeSesQuatreValeurs()
    rienDePousseNEstPasUnePanne()
    unClientFermeLeDitAussiPourLesPoussees()
    leVerdictDeNatATroisValeursEtPasDeux()

    println("$verifications vérifications, $echecs échec(s)")
    if (echecs != 0) {
        kotlin.system.exitProcess(1)
    }
}
