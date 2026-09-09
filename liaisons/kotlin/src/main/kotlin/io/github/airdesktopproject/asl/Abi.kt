// L'ABI C, transcrite pour l'API FFM. **Rien d'idiomatique ici.**
//
// Ce fichier est la copie mot pour mot de `crates/asl-client-ffi/include/asl.h`.
// Il ne traduit pas les fautes, ne nomme rien autrement, n'enveloppe rien :
// c'est le rôle de `Asl.kt`. Les séparer rend visible la seule question qui
// compte ici — **est-ce que ce fichier dit la même chose que l'en-tête ?** —, et
// `essais/Essais.kt` y répond en lisant les deux.
//
// ── POURQUOI `java.lang.foreign` ET NON JNI, JNA OU JNR ────────────────────
//
// **JNI demande d'écrire du C.** Une glu native à compiler, à distribuer par
// plate-forme, et à maintenir — c'est-à-dire exactement ce que la contrainte C4
// de ce dépôt refuse partout ailleurs.
//
// **JNA et JNR sont des dépendances**, et JNA embarque ses propres stubs natifs.
// Ce que cette bibliothèque tire, ses porteurs l'installent.
//
// L'API FFM est dans le JDK depuis la version 22, sans dépendance et sans une
// ligne de C. C'est la même décision que `ctypes` en Python et `fiddle` en Ruby,
// prise pour la même raison.
//
// **CE QU'ELLE COÛTE, ET QUI EST RÉEL** : elle exige un JDK 22 ou plus, et
// `--enable-native-access` au lancement. Android n'en dispose pas — voir
// `liaisons/kotlin/README.md`.

package io.github.airdesktopproject.asl

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemoryLayout.PathElement
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle
import java.nio.file.Files
import java.nio.file.Path

/** L'objet natif n'a pas été trouvé.
 *
 * **CE N'EST PAS UNE FAUTE D'EXÉCUTION, C'EST UNE INSTALLATION INCOMPLÈTE**, et
 * le message le dit — un `UnsatisfiedLinkError` nu enverrait chercher une panne
 * là où il manque un fichier.
 */
public class BibliothequeIntrouvable(message: String) : RuntimeException(message)

/** La transcription de `asl.h`. */
internal object Abi {
    // ── LES CODES ───────────────────────────────────────────────────────────
    const val OK: Int = 0
    const val ARGUMENT: Int = -1
    const val CONFIGURATION: Int = -2
    const val INJOIGNABLE: Int = -3
    const val REFUSE: Int = -4
    const val TAMPON_TROP_PETIT: Int = -5
    const val INTERNE: Int = -6
    const val PAS_D_IDENTITE: Int = -7
    const val DEJA: Int = -8

    const val IDENTIFIANT_OCTETS: Int = 29
    const val GRAINE_OCTETS: Int = 32

    const val TCP: Int = 1
    const val UDP: Int = 2

    const val REFLEXIF: Int = 1
    const val ANNONCE: Int = 2

    const val JOIGNABLE: Int = 1
    const val INJOIGNABLE_POINT: Int = 2
    const val NON_SONDE: Int = 3
    const val EN_COURS: Int = 4

    // ── LES DISPOSITIONS ────────────────────────────────────────────────────
    //
    // **AUCUN `paddingLayout` N'EST NÉCESSAIRE**, et c'est un fait à vérifier, pas
    // à supposer : `MemoryLayout.structLayout` REFUSE une disposition dont un
    // membre serait mal aligné. Si l'en-tête introduisait un jour un trou
    // implicite, cette classe ne se chargerait pas — ce qui est le bon moment
    // pour l'apprendre.

    val POINT: MemoryLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_SHORT.withName("port"),
        ValueLayout.JAVA_BYTE.withName("protocole"),
        ValueLayout.JAVA_BYTE.withName("reserve"),
    )

    val CANDIDAT: MemoryLayout = MemoryLayout.structLayout(
        MemoryLayout.sequenceLayout(16, ValueLayout.JAVA_BYTE).withName("adresse"),
        ValueLayout.JAVA_SHORT.withName("port"),
        ValueLayout.JAVA_BYTE.withName("protocole"),
        ValueLayout.JAVA_BYTE.withName("famille"),
        ValueLayout.JAVA_BYTE.withName("origine"),
        ValueLayout.JAVA_BYTE.withName("verdict"),
        MemoryLayout.sequenceLayout(2, ValueLayout.JAVA_BYTE).withName("reserve"),
    )

    val ETAT: MemoryLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_LONG.withName("attaches"),
        ValueLayout.JAVA_LONG.withName("ruptures"),
        ValueLayout.JAVA_BYTE.withName("attachee"),
        ValueLayout.JAVA_BYTE.withName("abandonnee"),
        MemoryLayout.sequenceLayout(6, ValueLayout.JAVA_BYTE).withName("reserve"),
    )

    /** Le décalage d'un champ, par son nom. */
    fun decalage(disposition: MemoryLayout, champ: String): Long =
        disposition.byteOffset(PathElement.groupElement(champ))

    // **LES TAILLES SONT VÉRIFIÉES AU CHARGEMENT DE LA CLASSE.**
    //
    // C'est le pendant JVM des `static_assert` du côté C++ et des `const _: () =
    // assert!` du côté Rust. Si cette transcription compte mal, il vaut mieux
    // qu'elle refuse de se charger que d'écrire un port dans un champ de
    // protocole pendant six mois.
    init {
        require(POINT.byteSize() == 4L) { "asl_point fait ${POINT.byteSize()} octets, pas 4" }
        require(CANDIDAT.byteSize() == 24L) {
            "asl_candidat fait ${CANDIDAT.byteSize()} octets, pas 24"
        }
        require(ETAT.byteSize() == 24L) { "asl_etat_t fait ${ETAT.byteSize()} octets, pas 24" }
    }

    // ── LES TYPES DE L'ABI, TELS QUE LA PLATE-FORME LES DÉFINIT ─────────────
    //
    // **`size_t` N'EST PAS `long`.** Il l'est sur les plates-formes qui nous
    // intéressent aujourd'hui, et il ne l'était pas hier. L'API FFM publie les
    // dispositions canoniques de la plate-forme courante : les employer est ce
    // qui évite d'écrire `JAVA_LONG` et de découvrir le contraire ailleurs.
    private val LIEUR: Linker = Linker.nativeLinker()
    val TAILLE: ValueLayout = LIEUR.canonicalLayouts()["size_t"] as ValueLayout
    private val ENTIER = ValueLayout.JAVA_INT
    private val ADRESSE = ValueLayout.ADDRESS

    /** Les onze fonctions, avec leur signature. */
    private val SIGNATURES: Map<String, FunctionDescriptor> = mapOf(
        "asl_version" to FunctionDescriptor.ofVoid(ADRESSE, ADRESSE, ADRESSE),
        "asl_faute_texte" to FunctionDescriptor.of(ADRESSE, ENTIER),
        "asl_client_neuf" to FunctionDescriptor.of(ENTIER, ADRESSE),
        "asl_client_annuaire" to FunctionDescriptor.of(ENTIER, ADRESSE, ADRESSE, ADRESSE),
        "asl_client_racines" to FunctionDescriptor.of(ENTIER, ADRESSE, ADRESSE, TAILLE),
        "asl_client_identite" to FunctionDescriptor.of(ENTIER, ADRESSE, ADRESSE, ADRESSE),
        "asl_client_libere" to FunctionDescriptor.ofVoid(ADRESSE),
        "asl_enroler" to FunctionDescriptor.of(ENTIER, ADRESSE, ADRESSE, ADRESSE, ADRESSE),
        "asl_annoncer" to FunctionDescriptor.of(ENTIER, ADRESSE, ADRESSE, ADRESSE, TAILLE),
        "asl_etat" to FunctionDescriptor.of(ENTIER, ADRESSE, ADRESSE),
        "asl_ou" to FunctionDescriptor.of(
            ENTIER, ADRESSE, ADRESSE, ADRESSE, ADRESSE, TAILLE, ADRESSE,
        ),
    )

    /** Comment l'objet natif s'appelle, selon le système. */
    fun nomsPossibles(): List<String> {
        val systeme = System.getProperty("os.name").orEmpty().lowercase()
        return when {
            systeme.contains("mac") -> listOf("libasl_client_ffi.dylib")
            systeme.contains("win") -> listOf("asl_client_ffi.dll")
            else -> listOf("libasl_client_ffi.so")
        }
    }

    /** Le couple système-architecture, tel qu'il nomme un répertoire de
     * ressources.
     *
     * **`os.arch` NE DIT PAS LA MÊME CHOSE QUE `rustc`** : la JVM dit `amd64` là
     * où Rust dit `x86_64`, et `arm64` là où il dit `aarch64`. Les normaliser ici
     * est ce qui évite de chercher un répertoire qui n'existera jamais.
     */
    fun cleDePlateforme(): String {
        val systeme = System.getProperty("os.name").orEmpty().lowercase()
        val machine = System.getProperty("os.arch").orEmpty().lowercase()
        val quel = when {
            systeme.contains("mac") -> "macos"
            systeme.contains("win") -> "windows"
            else -> "linux"
        }
        val laquelle = when (machine) {
            "amd64", "x86_64" -> "x86_64"
            "aarch64", "arm64" -> "aarch64"
            else -> machine
        }
        return "$quel-$laquelle"
    }

    /** Extrait l'objet natif du JAR, s'il s'y trouve.
     *
     * # POURQUOI IL FAUT EXTRAIRE, ET QUE C'EST LE SEUL CAS DES CINQ
     *
     * Python et Ruby posent l'objet À CÔTÉ de leur paquet, et le trouvent par un
     * chemin. **Un JAR n'est pas un système de fichiers** : une ressource y est
     * un flux, et `SymbolLookup.libraryLookup` veut un chemin. Il n'y a donc pas
     * d'autre façon que de l'écrire quelque part.
     *
     * Le fichier est temporaire et marqué pour effacement à la sortie de la JVM.
     * **Le coût est réel** : un mégaoctet écrit et une ouverture de fichier au
     * premier appel, une fois par processus. C'est le prix d'un JAR autonome, et
     * un porteur qui ne le veut pas pose `ASL_BIBLIOTHEQUE`.
     */
    private fun depuisLesRessources(): Path? {
        val nom = nomsPossibles().first()
        val chemin = "/natif/${cleDePlateforme()}/$nom"
        val flux = Abi::class.java.getResourceAsStream(chemin) ?: return null
        return flux.use { entrant ->
            val vers = Files.createTempFile("asl-", "-$nom")
            vers.toFile().deleteOnExit()
            Files.copy(entrant, vers, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            vers
        }
    }

    /** Où chercher, dans l'ordre.
     *
     * **`ASL_BIBLIOTHEQUE` PASSE AVANT TOUT.** C'est ce qui permet d'éprouver
     * cette liaison contre une construction locale sans l'installer, et à un
     * porteur de pointer l'objet qu'il a compilé pour son architecture.
     *
     * Ensuite `java.library.path`, que la JVM offre déjà pour cela. Puis le JAR
     * lui-même — voir [depuisLesRessources].
     */
    fun cheminsCandidats(): List<Path> {
        val chemins = mutableListOf<Path>()
        System.getenv("ASL_BIBLIOTHEQUE")?.takeIf { it.isNotEmpty() }?.let {
            chemins.add(Path.of(it))
        }
        val repertoires = System.getProperty("java.library.path").orEmpty()
            .split(java.io.File.pathSeparator)
            .filter { it.isNotEmpty() }
        for (repertoire in repertoires) {
            for (nom in nomsPossibles()) {
                chemins.add(Path.of(repertoire, nom))
            }
        }
        depuisLesRessources()?.let { chemins.add(it) }
        return chemins
    }

    /** Les fonctions, une fois la bibliothèque chargée. */
    class Fonctions internal constructor(private val table: Map<String, MethodHandle>) {
        operator fun get(nom: String): MethodHandle =
            table[nom] ?: error("`$nom` n'a pas été lié : ce n'est pas censé arriver")
    }

    /** Charge la bibliothèque native et lie ses onze fonctions.
     *
     * L'`Arena.global()` n'est pas un oubli : cette bibliothèque vit aussi
     * longtemps que la JVM. La décharger demanderait de garantir qu'aucun fil
     * natif ne tourne encore — or c'est précisément ce qu'une annonce tenue fait.
     */
    fun charger(chemin: Path? = null): Fonctions {
        val essayes = mutableListOf<String>()
        val candidats = chemin?.let { listOf(it) } ?: cheminsCandidats()

        var recherche: SymbolLookup? = null
        for (candidat in candidats) {
            essayes.add(candidat.toString())
            if (Files.exists(candidat)) {
                recherche = SymbolLookup.libraryLookup(candidat, Arena.global())
                break
            }
        }

        if (recherche == null) {
            // En dernier, le chargeur du système.
            for (nom in nomsPossibles()) {
                essayes.add(nom)
                try {
                    recherche = SymbolLookup.libraryLookup(nom, Arena.global())
                    break
                } catch (_: IllegalArgumentException) {
                    // Ce nom-là n'existe pas ; on essaie le suivant.
                }
            }
        }

        if (recherche == null) {
            throw BibliothequeIntrouvable(
                "l'objet natif d'asl est introuvable.\n" +
                    "Cherché : ${essayes.joinToString(", ")}\n" +
                    "Construisez-le avec `cargo build --release` dans le dépôt, puis " +
                    "posez ASL_BIBLIOTHEQUE sur target/release/${nomsPossibles().first()}",
            )
        }

        val table = SIGNATURES.entries.associate { (nom, signature) ->
            val adresse = recherche.find(nom).orElseThrow {
                BibliothequeIntrouvable(
                    "la bibliothèque native n'exporte pas `$nom`. " +
                        "Elle ne correspond pas à cette liaison.",
                )
            }
            nom to LIEUR.downcallHandle(adresse, signature)
        }
        return Fonctions(table)
    }
}
