// asl — annoncer un service et retrouver un port, depuis Kotlin.
//
// Un daemon qui écoute sur un port choisi au démarrage est un daemon que ses
// clients ne savent plus joindre. Cette bibliothèque est l'autre moitié : le
// daemon ANNONCE le port que le système lui a donné, et ses clients le DEMANDENT.
//
//     Client.ouvrir(
//         annuaires = listOf("203.0.113.7:6630" to "nitrogen.example"),
//         racines = Files.readAllBytes(Path.of("/etc/asl/ca.pem")),
//         identite = Identite(machine, graine),
//     ).getOrThrow().use { client ->
//         client.annoncer("depot", listOf(Point(Protocole.TCP, 8080))).getOrThrow()
//         servirPourToujours()          // l'annonce se tient toute seule
//     }
//
// ── CE QUI TOURNE EN ARRIÈRE-PLAN, ET QU'IL FAUT SAVOIR ────────────────────
//
// **`annoncer` rend la main tout de suite et n'y revient jamais.** Un annuaire
// injoignable ne doit pas empêcher un daemon de démarrer : le service écoute déjà
// pendant que l'annonce cherche encore.
//
// Ce qui la tient est un fil NATIF, à l'intérieur de la bibliothèque — ni un
// `Thread`, ni un dispatcher de coroutine, et il n'entre jamais dans la JVM. Il
// se reconnecte seul, bascule sur l'autre annuaire racine quand le premier tombe,
// et n'abandonne jamais. `etat()` dit où il en est.
//
// **FERMER LE CLIENT RETIRE L'ANNONCE.** La connexion EST le bail : il n'y a pas
// de « retrait » séparé à appeler. Laisser le client se faire ramasser retire donc
// l'annonce quand le ramasse-miettes passe — c'est-à-dire à un moment que l'on ne
// choisit pas. **Employez `use`.**

package io.github.airdesktopproject.asl

import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle
import java.lang.ref.Cleaner
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

// ── LES ERREURS ─────────────────────────────────────────────────────────────
//
// **JAMAIS UN ENTIER NÉGATIF RENDU TEL QUEL.** Les verbes rendent un
// `Result<T>` : l'échec fait partie du TYPE, et l'on ne peut pas en tirer une
// valeur sans avoir dit quoi faire de l'autre cas.

/** La racine de tout ce que cette bibliothèque met dans un `Result` en échec.
 *
 * `catch (e: AslErreur)` suffit à tout attraper ; les sous-classes servent à
 * distinguer ce qui se corrige différemment.
 */
public sealed class AslErreur(message: String) : Exception(message) {
    /** Le code de l'ABI correspondant. */
    public abstract val code: Int
}

/** Un argument que l'ABI refuse : une adresse illisible, un port nul. */
public class MauvaisArgument internal constructor(message: String) : AslErreur(message) {
    override val code: Int get() = Abi.ARGUMENT
}

/** Il manque un annuaire, une racine, ou la racine ne se lit pas.
 *
 * **CE N'EST PAS UNE PANNE**, et c'est pourquoi elle est distincte
 * d'[Injoignable] : réessayer ne la réparerait jamais.
 */
public class Configuration internal constructor(message: String) : AslErreur(message) {
    override val code: Int get() = Abi.CONFIGURATION
}

/** Personne n'a répondu.
 *
 * **UN CÂBLE DÉBRANCHÉ, ET NON UN DROIT MANQUANT** — voir [Refuse]. Les deux se
 * corrigent à des endroits opposés.
 */
public class Injoignable internal constructor(message: String) : AslErreur(message) {
    override val code: Int get() = Abi.INJOIGNABLE
}

/** L'annuaire a compris, et il a dit non. */
public class Refuse internal constructor(message: String) : AslErreur(message) {
    override val code: Int get() = Abi.REFUSE
}

/** L'impossible est arrivé, et la bibliothèque l'a rattrapé.
 *
 * **ELLE N'A PAS TUÉ LA JVM**, et c'est délibéré : une panique qui traverse la
 * frontière avorterait le processus entier.
 */
public class Interne internal constructor(message: String) : AslErreur(message) {
    override val code: Int get() = Abi.INTERNE
}

/** Cette machine n'a pas d'identité : enrôlez-la, ou posez-en une. */
public class PasDIdentite internal constructor(message: String) : AslErreur(message) {
    override val code: Int get() = Abi.PAS_D_IDENTITE
}

/** Ce client annonce déjà.
 *
 * Un second appel ne remplace pas la première annonce en silence — ce qui la
 * retirerait.
 */
public class Deja internal constructor(message: String) : AslErreur(message) {
    override val code: Int get() = Abi.DEJA
}

/** Le client a été fermé. */
public class Ferme internal constructor(message: String) : AslErreur(message) {
    override val code: Int get() = Abi.ARGUMENT
}

// ── CE QUI TRAVERSE ─────────────────────────────────────────────────────────

/** Le protocole d'un point d'écoute. */
public enum class Protocole(internal val brut: Int) {
    TCP(Abi.TCP),
    UDP(Abi.UDP),
    ;

    override fun toString(): String = name.lowercase()
}

/** D'où vient une adresse. */
public enum class Origine(internal val brut: Int) {
    /** L'annuaire nous a VU sous cette adresse. */
    REFLEXIF(Abi.REFLEXIF),

    /** Le daemon l'a annoncée lui-même. */
    ANNONCE(Abi.ANNONCE),
}

/** Ce que l'annuaire sait d'un point d'écoute.
 *
 * **TROIS DE CES QUATRE VALEURS NE VEULENT PAS DIRE « ÇA NE MARCHE PAS ».**
 * [EN_COURS] n'affirme rien — l'annuaire répond avant d'avoir sondé, pour ne pas
 * faire attendre le démarrage d'un daemon. [NON_SONDE] dit qu'il ne mesurera pas :
 * UDP n'a pas de poignée de main, donc une sonde n'y distinguerait pas « écoute
 * et ignore » de « rien n'écoute ».
 *
 * C'est pourquoi [Candidat] n'a pas de propriété `joignable` : elle serait juste
 * une fois sur deux, et ferait écarter un candidat parfaitement bon.
 */
public enum class Verdict(internal val brut: Int) {
    JOIGNABLE(Abi.JOIGNABLE),
    INJOIGNABLE(Abi.INJOIGNABLE_POINT),
    NON_SONDE(Abi.NON_SONDE),
    EN_COURS(Abi.EN_COURS),
}

/** Cette machine est-elle derrière un NAT ?
 *
 * **TROIS VALEURS, ET NON UN `Boolean`.** Un daemon qui n'a annoncé aucune adresse
 * locale ne donne rien à comparer à l'adresse réflexive, et répondre `false`
 * serait affirmer ce qui n'a pas été mesuré.
 */
public enum class VerdictNat(internal val brut: Int) {
    /** L'adresse sous laquelle l'annuaire nous voit est une des nôtres. */
    NON(Abi.NAT_NON),

    /** Elle n'en est aucune : quelque chose traduit entre nous et lui. */
    OUI(Abi.NAT_OUI),

    /** Rien à comparer. **Aucune conclusion n'en découle.** */
    INDETERMINE(Abi.NAT_INDETERMINE),
}

/** Un point d'écoute à annoncer. */
public data class Point(val protocole: Protocole, val port: Int) {
    init {
        require(port in 1..65535) { "$port n'est pas un port" }
    }

    override fun toString(): String = "$protocole:$port"
}

/** Où joindre un service, et ce que l'annuaire en sait. */
public data class Candidat(
    val protocole: Protocole,
    /** L'adresse, déjà mise en texte. */
    val adresse: String,
    val port: Int,
    val origine: Origine,
    val verdict: Verdict,
) {
    /** La forme qu'on recopie dans une commande — **avec ses crochets en IPv6**.
     *
     * Sans eux, `2001:db8::1:8080` est ambigu : le dernier `:` sépare-t-il un
     * port ou un groupe d'adresse ?
     */
    override fun toString(): String =
        if (adresse.contains(':')) "[$adresse]:$port" else "$adresse:$port"
}

/** Ce que l'annonce a fait jusqu'ici. */
public data class Etat(
    /** L'annuaire nous connaît EN CE MOMENT : authentifiés ET annoncés.
     *
     * **Ce n'est pas « la socket est ouverte »** : une connexion qui s'ouvre puis
     * se fait refuser l'authentification n'annonce rien.
     */
    val attachee: Boolean,
    /** Combien de fois on s'est attaché depuis le départ. */
    val attaches: Long,
    /** Combien de fois une attache établie s'est rompue. */
    val ruptures: Long,
    /** La tâche a renoncé, et ne réessaiera pas.
     *
     * **Elle ne renonce que sur une faute de configuration.** Jamais sur une
     * panne de réseau, quelle qu'en soit la durée. C'est le seul état dont un
     * humain doit être averti.
     */
    val abandonnee: Boolean,
)

/** Ce que l'annuaire a mesuré APRÈS coup, et poussé sur la connexion tenue.
 *
 * **ELLE N'A NI SERVICE NI BAIL** — elle ne répond à aucune question, elle corrige
 * ce qu'une réponse antérieure disait « en cours ». C'est pourquoi elle n'a pas la
 * forme de ce que rend [Client.ou].
 */
public data class Poussee(
    /** La liste ENTIÈRE des candidats, dans l'ordre, et non un delta. */
    val candidats: List<Candidat>,
    val derriereNat: VerdictNat,
)

/** L'identité d'une machine. **Conservez les deux.**
 *
 * La clé est générée sur la machine et sa moitié privée n'en sort pas ; ce couple
 * est le seul justificatif durable, et le code d'enrôlement est dépensé.
 *
 * **LA GRAINE EST LE SECRET**, et sa conservation vous appartient : elle n'est pas
 * chiffrée, et quiconque la lit devient cette machine.
 */
public class Identite(public val machine: String, graine: ByteArray) {
    /** Les trente-deux octets dont la clé se dérive. */
    public val graine: ByteArray = graine.copyOf()

    init {
        require(this.graine.size == Abi.GRAINE_OCTETS) {
            "une graine fait ${Abi.GRAINE_OCTETS} octets, pas ${this.graine.size}"
        }
    }

    override fun equals(other: Any?): Boolean =
        this === other ||
            (other is Identite && machine == other.machine && graine.contentEquals(other.graine))

    override fun hashCode(): Int = 31 * machine.hashCode() + graine.contentHashCode()

    /** Sans la graine. **UN SECRET NE SE MET PAS DANS UN JOURNAL**, et une
     * `data class` l'aurait imprimé au premier `log.debug`. */
    override fun toString(): String = "Identite(machine=$machine, graine=<32 octets>)"
}

// ── LA BIBLIOTHÈQUE, CHARGÉE UNE FOIS ───────────────────────────────────────

private val fonctions: Abi.Fonctions by lazy { Abi.charger() }

private val nettoyeur: Cleaner = Cleaner.create()

/** La version de la bibliothèque NATIVE, et non de ce paquet. */
public fun version(): Triple<Int, Int, Int> = Arena.ofConfined().use { arene ->
    val majeur = arene.allocate(ValueLayout.JAVA_INT)
    val mineur = arene.allocate(ValueLayout.JAVA_INT)
    val correctif = arene.allocate(ValueLayout.JAVA_INT)
    fonctions["asl_version"].invoke(majeur, mineur, correctif)
    Triple(
        majeur.get(ValueLayout.JAVA_INT, 0),
        mineur.get(ValueLayout.JAVA_INT, 0),
        correctif.get(ValueLayout.JAVA_INT, 0),
    )
}

/** Ce que la bibliothèque NATIVE dit d'un code.
 *
 * **LA PHRASE VIENT DE LÀ-BAS, ET N'EST PAS RECOPIÉE ICI.** Deux listes de
 * messages finiraient par diverger, et c'est celle qu'on oublie de corriger que
 * l'utilisateur lirait.
 */
internal fun phrase(code: Int): String = try {
    val brute = fonctions["asl_faute_texte"].invoke(code) as MemorySegment
    if (brute.address() == 0L) "code $code" else brute.reinterpret(Long.MAX_VALUE).getString(0)
} catch (_: Throwable) {
    // Un message ne doit jamais faire échouer ce qu'il décrit.
    "code $code"
}

/** Traduit un code en `Result`. */
internal fun <T> issue(code: Int, valeur: () -> T): Result<T> = when (code) {
    Abi.OK -> Result.success(valeur())
    Abi.ARGUMENT -> Result.failure(MauvaisArgument(phrase(code)))
    Abi.CONFIGURATION -> Result.failure(Configuration(phrase(code)))
    Abi.INJOIGNABLE -> Result.failure(Injoignable(phrase(code)))
    Abi.REFUSE -> Result.failure(Refuse(phrase(code)))
    Abi.INTERNE -> Result.failure(Interne(phrase(code)))
    Abi.PAS_D_IDENTITE -> Result.failure(PasDIdentite(phrase(code)))
    Abi.DEJA -> Result.failure(Deja(phrase(code)))
    else -> Result.failure(Interne("code inattendu $code : ${phrase(code)}"))
}

/** Une chaîne C, ou un refus.
 *
 * **UN NUL AU MILIEU EST REFUSÉ ICI**, et non transmis : le C s'arrêterait au
 * premier, et l'annuaire recevrait un nom plus court que celui qu'on croit lui
 * avoir donné.
 */
internal fun chaineC(arene: Arena, texte: String): MemorySegment {
    require(texte.none { it.code == 0 }) { "un NUL au milieu d'une chaîne" }
    return arene.allocateFrom(texte)
}

// ── LE CLIENT ───────────────────────────────────────────────────────────────

/** Combien de candidats on demande d'emblée.
 *
 * **LE DIMENSIONNEMENT EN DEUX TEMPS DU C COÛTERAIT DEUX ALLERS-RETOURS** :
 * `asl_ou` refait la requête à chaque appel, il ne garde pas de résultat. On
 * demande donc large — le protocole borne un service à huit points d'écoute.
 */
private const val CANDIDATS_D_EMBLEE = 8L

/** Ce que le nettoyeur exécute quand un [Client] oublié est ramassé.
 *
 * **IL NE DOIT PAS VOIR LE `Client`.** Une lambda qui le capturerait le garderait
 * accessible pour toujours — et ne s'exécuterait donc jamais. C'est le piège
 * classique de `Cleaner`, et il est silencieux : rien ne fuit visiblement, la
 * mémoire NATIVE se contente de ne jamais être rendue.
 *
 * Cette classe est donc de premier niveau, et ne tient que la boîte et la
 * fonction.
 */
internal class Nettoyage(
    private val boite: AtomicReference<MemorySegment?>,
    private val liberer: MethodHandle,
) : Runnable {
    override fun run() {
        boite.getAndSet(null)?.let { liberer.invoke(it) }
    }
}

/** Un client d'annuaire : il annonce, il résout, il tient sa connexion.
 *
 * **IL SE FERME**, et le fermer retire l'annonce. Employez `use`.
 */
public class Client private constructor(brut: MemorySegment) : AutoCloseable {
    private val boite = AtomicReference<MemorySegment?>(brut)

    // **UN SEUL VERROU, ET IL SÉRIALISE TOUT.**
    //
    // L'ABI dit qu'un client ne se partage pas entre fils. En Rust, deux appels
    // concurrents aliaseraient un `&mut` — un comportement indéfini, pas un
    // ralentissement.
    //
    // En C++, la phrase suffit : « objets distincts, sûr ; même objet, non sûr »
    // y est la convention de la bibliothèque standard. **Sur la JVM, non** — un
    // objet rangé dans un conteneur d'injection et appelé depuis un pool de fils
    // est le cas ORDINAIRE, pas l'exception. Le verrou transforme donc l'indéfini
    // en file d'attente.
    //
    // LE COÛT EST ÉCRIT : `etat()` attend pendant un `ou()` en cours, qui peut
    // durer vingt secondes. Un daemon qui annonce n'appelle pas `ou()`, donc les
    // deux se croisent rarement.
    private val verrou = ReentrantLock()

    private val nettoyage = nettoyeur.register(
        this,
        Nettoyage(boite, fonctions["asl_client_libere"]),
    )

    public companion object {
        /** Monte un client. **Il n'ouvre aucune connexion** : un annuaire
         * injoignable ne doit pas empêcher un daemon de démarrer.
         *
         * `annuaires` est une liste de couples `adresse to nom`. L'adresse est
         * LITTÉRALE — `"203.0.113.7:6630"` ou `"[2001:db8::1]:6630"` —, jamais un
         * nom d'hôte : **la résolution vous appartient**, parce que vous avez déjà
         * un résolveur, une politique de cache et des fils. `InetAddress` fait
         * l'affaire, et un nom qui rend plusieurs adresses les rend toutes
         * utilisables ici.
         *
         * Le second membre est le nom qu'on EXIGE du certificat. Il n'est pas
         * déduit de l'adresse : le déduire reviendrait à faire confiance à qui
         * répond à cette adresse.
         *
         * `racines` est le contenu d'un fichier PEM. **Il n'y a pas de repli sur
         * le magasin du système** : les annuaires sont signés par LEUR autorité.
         */
        @JvmStatic
        public fun ouvrir(
            annuaires: List<Pair<String, String>> = emptyList(),
            racines: ByteArray? = null,
            identite: Identite? = null,
        ): Result<Client> {
            val neuf = Arena.ofConfined().use { arene ->
                val sortie = arene.allocate(ValueLayout.ADDRESS)
                val code = fonctions["asl_client_neuf"].invoke(sortie) as Int
                issue(code) { Client(sortie.get(ValueLayout.ADDRESS, 0)) }
            }
            val client = neuf.getOrElse { return Result.failure(it) }

            // **CE QUI EST OUVERT SE FERME, MÊME QUAND LA CONFIGURATION ÉCHOUE.**
            // Sans ceci, une adresse mal écrite laisserait un objet natif que seul
            // le ramasse-miettes finirait par rendre, un jour.
            try {
                for ((adresse, nom) in annuaires) {
                    client.ajouterAnnuaire(adresse, nom).getOrElse {
                        client.close()
                        return Result.failure(it)
                    }
                }
                if (racines != null) {
                    client.poserRacines(racines).getOrElse {
                        client.close()
                        return Result.failure(it)
                    }
                }
                if (identite != null) {
                    client.poserIdentite(identite).getOrElse {
                        client.close()
                        return Result.failure(it)
                    }
                }
            } catch (quoi: Throwable) {
                client.close()
                throw quoi
            }
            return Result.success(client)
        }
    }

    /** Ce client tient-il encore quelque chose ? */
    public val ouvert: Boolean get() = boite.get() != null

    // ── La configuration ────────────────────────────────────────────────────

    /** Ajoute un annuaire à essayer. **Répétable, et l'ordre compte.**
     *
     * L'IPv6 est essayé d'abord quel que soit l'ordre des appels ; à l'intérieur
     * d'une famille, c'est cet ordre qui décide.
     */
    public fun ajouterAnnuaire(adresse: String, nom: String): Result<Unit> =
        appeler { brut, arene ->
            fonctions["asl_client_annuaire"].invoke(
                brut, chaineC(arene, adresse), chaineC(arene, nom),
            ) as Int
        }

    /** Pose les certificats d'autorité, en PEM. */
    public fun poserRacines(pem: ByteArray): Result<Unit> = appeler { brut, arene ->
        val tampon = arene.allocate(pem.size.toLong().coerceAtLeast(1L))
        MemorySegment.copy(pem, 0, tampon, ValueLayout.JAVA_BYTE, 0L, pem.size)
        fonctions["asl_client_racines"].invoke(brut, tampon, pem.size.toLong()) as Int
    }

    /** Installe l'identité de cette machine. */
    public fun poserIdentite(identite: Identite): Result<Unit> = appeler { brut, arene ->
        val graine = arene.allocate(Abi.GRAINE_OCTETS.toLong())
        MemorySegment.copy(
            identite.graine, 0, graine, ValueLayout.JAVA_BYTE, 0L, Abi.GRAINE_OCTETS,
        )
        fonctions["asl_client_identite"].invoke(
            brut, chaineC(arene, identite.machine), graine,
        ) as Int
    }

    // ── Les verbes ──────────────────────────────────────────────────────────

    /** Présente un code d'enrôlement, et rend l'identité obtenue.
     *
     * L'identité est installée dans ce client au passage.
     *
     * **Cet appel bloque** — jusqu'à vingt secondes s'il faut attendre un
     * annuaire. Ne l'appelez pas depuis un dispatcher destiné au calcul.
     */
    public fun enroler(code: String): Result<Identite> = verrou.withLock {
        val brut = boite.get() ?: return Result.failure(Ferme("ce client est fermé"))
        Arena.ofConfined().use { arene ->
            val machine = arene.allocate(Abi.IDENTIFIANT_OCTETS.toLong())
            val graine = arene.allocate(Abi.GRAINE_OCTETS.toLong())
            val rendu = fonctions["asl_enroler"].invoke(
                brut, chaineC(arene, code), machine, graine,
            ) as Int
            issue(rendu) {
                Identite(machine.getString(0), graine.toArray(ValueLayout.JAVA_BYTE))
            }
        }
    }

    /** Annonce ce service, et **rend la main tout de suite**.
     *
     * L'annonce est ensuite tenue par un fil natif, aussi longtemps que ce client
     * vit : elle se réauthentifie et se réannonce seule à chaque reconnexion, et
     * bascule sur l'autre annuaire racine quand le premier tombe. [etat] dit où
     * elle en est.
     *
     * **UN CLIENT N'ANNONCE QU'UNE FOIS** : un second appel rend [Deja] plutôt que
     * de remplacer la première en silence, ce qui la retirerait.
     */
    public fun annoncer(service: String, points: List<Point>): Result<Unit> {
        if (points.isEmpty()) {
            return Result.failure(
                MauvaisArgument("une annonce sans point d'écoute n'annonce rien"),
            )
        }
        return appeler { brut, arene ->
            val tableau = arene.allocate(Abi.POINT, points.size.toLong())
            val decalagePort = Abi.decalage(Abi.POINT, "port")
            val decalageProtocole = Abi.decalage(Abi.POINT, "protocole")
            points.forEachIndexed { rang, point ->
                val base = rang * Abi.POINT.byteSize()
                tableau.set(ValueLayout.JAVA_SHORT, base + decalagePort, point.port.toShort())
                tableau.set(
                    ValueLayout.JAVA_BYTE,
                    base + decalageProtocole,
                    point.protocole.brut.toByte(),
                )
            }
            fonctions["asl_annoncer"].invoke(
                brut, chaineC(arene, service), tableau, points.size.toLong(),
            ) as Int
        }
    }

    /** Où en est l'annonce. Un client qui n'a jamais annoncé rend tout à zéro. */
    public fun etat(): Result<Etat> = verrou.withLock {
        val brut = boite.get() ?: return Result.failure(Ferme("ce client est fermé"))
        Arena.ofConfined().use { arene ->
            val tampon = arene.allocate(Abi.ETAT)
            val code = fonctions["asl_etat"].invoke(brut, tampon) as Int
            issue(code) {
                Etat(
                    attachee = tampon.get(
                        ValueLayout.JAVA_BYTE, Abi.decalage(Abi.ETAT, "attachee"),
                    ).toInt() == 1,
                    attaches = tampon.get(
                        ValueLayout.JAVA_LONG, Abi.decalage(Abi.ETAT, "attaches"),
                    ),
                    ruptures = tampon.get(
                        ValueLayout.JAVA_LONG, Abi.decalage(Abi.ETAT, "ruptures"),
                    ),
                    abandonnee = tampon.get(
                        ValueLayout.JAVA_BYTE, Abi.decalage(Abi.ETAT, "abandonnee"),
                    ).toInt() == 1,
                )
            }
        }
    }

    /** Demande où joindre un service, et rend les candidats **dans l'ordre**.
     *
     * L'ordre est celui qu'un client doit suivre — IPv6 d'abord, adresse observée
     * avant adresse annoncée — et il n'est pas à vous de le deviner.
     *
     * **`TAMPON_TROP_PETIT` NE REMONTE PAS** : la liaison redemande avec la taille
     * qu'on lui a dite. C'est tout ce qu'un porteur veut savoir.
     *
     * **Cet appel bloque**, comme [enroler].
     */
    public fun ou(machine: String, service: String): Result<List<Candidat>> = verrou.withLock {
        val brut = boite.get() ?: return Result.failure(Ferme("ce client est fermé"))
        Arena.ofConfined().use { arene ->
            val m = chaineC(arene, machine)
            val s = chaineC(arene, service)
            val ecrit = arene.allocate(Abi.TAILLE)

            var place = CANDIDATS_D_EMBLEE
            var tampon = arene.allocate(Abi.CANDIDAT, place)
            var code = fonctions["asl_ou"].invoke(brut, m, s, tampon, place, ecrit) as Int

            if (code == Abi.TAMPON_TROP_PETIT) {
                place = lireTaille(ecrit).coerceAtLeast(1L)
                tampon = arene.allocate(Abi.CANDIDAT, place)
                code = fonctions["asl_ou"].invoke(brut, m, s, tampon, place, ecrit) as Int
            }

            val fige = tampon
            issue(code) {
                (0 until lireTaille(ecrit)).map { rang -> decoderCandidat(fige, rang) }
            }
        }
    }

    /** Combien de poussées de verdict sont arrivées depuis le départ.
     *
     * **ZÉRO N'EST PAS UNE ANOMALIE** : l'annuaire ne pousse que ce qui a CHANGÉ,
     * et un service dont les sondes confirment ce qu'il disait déjà n'en produit
     * aucune.
     *
     * **C'EST LE COMPTEUR QU'ON SURVEILLE, PAS LE CONTENU** : une poussée porte
     * toute la liste, donc relire [dernierePoussee] sans que celui-ci ait bougé
     * rend deux fois la même chose.
     */
    public fun pousseesRecues(): Result<Long> = verrou.withLock {
        val brut = boite.get() ?: return Result.failure(Ferme("ce client est fermé"))
        Arena.ofConfined().use { arene ->
            val combien = arene.allocate(ValueLayout.JAVA_LONG)
            val code = fonctions["asl_poussees_recues"].invoke(brut, combien) as Int
            issue(code) { combien.get(ValueLayout.JAVA_LONG, 0) }
        }
    }

    /** Le dernier verdict poussé, ou `null` si rien ne l'a encore été.
     *
     * **`null` N'EST PAS UNE FAUTE, ET C'EST POURQUOI CE N'EST PAS UN
     * `Result.failure`.** Ne rien avoir reçu est le cas ordinaire au démarrage —
     * l'annuaire répond « en cours » avant d'avoir sondé —, et échouer ici
     * obligerait un porteur à traiter comme une panne ce qu'il verra à chaque tour
     * de sa boucle pendant les premières secondes.
     *
     * Comme pour [ou], `TAMPON_TROP_PETIT` ne remonte pas.
     */
    public fun dernierePoussee(): Result<Poussee?> = verrou.withLock {
        val brut = boite.get() ?: return Result.failure(Ferme("ce client est fermé"))
        Arena.ofConfined().use { arene ->
            val ecrit = arene.allocate(Abi.TAILLE)
            val nat = arene.allocate(ValueLayout.JAVA_BYTE)
            nat.set(ValueLayout.JAVA_BYTE, 0, Abi.NAT_INDETERMINE.toByte())

            var place = CANDIDATS_D_EMBLEE
            var tampon = arene.allocate(Abi.CANDIDAT, place)
            var code = fonctions["asl_derniere_poussee"]
                .invoke(brut, tampon, place, ecrit, nat) as Int

            if (code == Abi.TAMPON_TROP_PETIT) {
                place = lireTaille(ecrit).coerceAtLeast(1L)
                tampon = arene.allocate(Abi.CANDIDAT, place)
                code = fonctions["asl_derniere_poussee"]
                    .invoke(brut, tampon, place, ecrit, nat) as Int
            }
            if (code == Abi.PAS_DE_POUSSEE) {
                return@use Result.success(null)
            }

            val fige = tampon
            issue(code) {
                Poussee(
                    candidats = (0 until lireTaille(ecrit)).map { rang ->
                        decoderCandidat(fige, rang)
                    },
                    derriereNat = verdictNat(nat.get(ValueLayout.JAVA_BYTE, 0).toInt()),
                )
            }
        }
    }

    // ── La fin ──────────────────────────────────────────────────────────────

    /** Ferme le client, **et retire l'annonce en le faisant**.
     *
     * Elle est retirée PROPREMENT, ce qui épargne à l'annuaire la minute
     * d'inactivité pendant laquelle il donnerait à vos clients une adresse morte.
     * Cet appel peut donc prendre jusqu'à deux secondes.
     *
     * Appeler deux fois ne fait rien la seconde.
     */
    override fun close() {
        verrou.withLock {
            // `clean()` exécute l'action MAINTENANT et la désenregistre : c'est ce
            // qui rend la fermeture explicite et le filet exclusifs l'un de
            // l'autre, donc une double libération impossible.
            nettoyage.clean()
        }
    }

    /** Prend le verrou, vérifie que le client est ouvert, appelle, traduit. */
    private fun appeler(corps: (MemorySegment, Arena) -> Int): Result<Unit> = verrou.withLock {
        val brut = boite.get() ?: return Result.failure(Ferme("ce client est fermé"))
        try {
            Arena.ofConfined().use { arene -> issue(corps(brut, arene)) { } }
        } catch (quoi: IllegalArgumentException) {
            Result.failure(MauvaisArgument(quoi.message ?: "argument invalide"))
        }
    }

    private fun lireTaille(segment: MemorySegment): Long = when (Abi.TAILLE.byteSize()) {
        8L -> segment.get(ValueLayout.JAVA_LONG, 0)
        else -> segment.get(ValueLayout.JAVA_INT, 0).toLong() and 0xFFFF_FFFFL
    }

    /** L'octet rendu par l'ABI, en verdict.
     *
     * **UN OCTET INCONNU DEVIENT `INDETERMINE`, ET NON UNE EXCEPTION.** Une
     * bibliothèque native plus récente qui ajouterait une quatrième valeur ne doit
     * pas faire tomber un programme déjà déployé : ne rien conclure est
     * exactement ce que ce verdict veut dire.
     */
    private fun verdictNat(brut: Int): VerdictNat =
        VerdictNat.entries.firstOrNull { it.brut == brut } ?: VerdictNat.INDETERMINE

    private fun decoderCandidat(tampon: MemorySegment, rang: Long): Candidat {
        val base = rang * Abi.CANDIDAT.byteSize()
        val adresse = tampon.asSlice(base + Abi.decalage(Abi.CANDIDAT, "adresse"), 16L)
            .toArray(ValueLayout.JAVA_BYTE)
        val famille = tampon.get(
            ValueLayout.JAVA_BYTE, base + Abi.decalage(Abi.CANDIDAT, "famille"),
        ).toInt()
        val brutProtocole = tampon.get(
            ValueLayout.JAVA_BYTE, base + Abi.decalage(Abi.CANDIDAT, "protocole"),
        ).toInt()
        val brutOrigine = tampon.get(
            ValueLayout.JAVA_BYTE, base + Abi.decalage(Abi.CANDIDAT, "origine"),
        ).toInt()
        val brutVerdict = tampon.get(
            ValueLayout.JAVA_BYTE, base + Abi.decalage(Abi.CANDIDAT, "verdict"),
        ).toInt()
        val port = tampon.get(
            ValueLayout.JAVA_SHORT, base + Abi.decalage(Abi.CANDIDAT, "port"),
        ).toInt() and 0xFFFF

        // **`InetAddress` MET L'ADRESSE EN TEXTE, ET IL LE FAIT BIEN.** Écrire
        // soi-même la compression de la RFC 5952 est un piège — une seule série de
        // zéros, la plus longue, la première en cas d'égalité. La liaison C++ a
        // préféré ne pas abréger du tout, faute d'avoir cela sous la main ; ici la
        // plate-forme le sait.
        val octets = if (famille == 6) adresse else adresse.copyOfRange(0, 4)
        return Candidat(
            protocole = Protocole.entries.first { it.brut == brutProtocole },
            adresse = java.net.InetAddress.getByAddress(octets).hostAddress,
            port = port,
            origine = Origine.entries.first { it.brut == brutOrigine },
            verdict = Verdict.entries.first { it.brut == brutVerdict },
        )
    }
}
