// La liaison Kotlin d'air-service-locator.
//
// ── CE FICHIER EST POUR LES PORTEURS, PAS POUR NOUS ────────────────────────
//
// `scripts/check-kotlin.sh` appelle `kotlinc` directement : il n'a besoin ni de
// Gradle, ni de son enveloppe, ni des dépendances qu'un `gradle-wrapper.jar`
// télécharge au premier lancement. **Une barrière qui dépendrait d'un réseau ne
// serait pas une barrière.**
//
// Ce fichier existe pour qu'un projet Gradle puisse consommer cette liaison de la
// façon qu'il attend. Il n'est jamais exécuté par la CI de ce dépôt.
//
// ── CE QU'IL NE FAIT PAS ───────────────────────────────────────────────────
//
// **Il ne construit ni ne cherche l'objet natif.** Celui-ci vient de
// `cargo build --release`, et son emplacement dépend du déploiement. Le deviner
// obligerait à supposer une arborescence, et à échouer de façon obscure chez tous
// ceux qui en ont une autre.
//
// Posez `ASL_BIBLIOTHEQUE`, ou ajoutez son répertoire à `java.library.path`.

plugins {
    kotlin("jvm") version "2.0.0"
}

group = "io.github.airdesktopproject"
version = "0.1.0"

kotlin {
    // **L'API FFM EST STABLE DEPUIS LE JDK 22.** C'est ce que cette liaison
    // exige, et c'est aussi pourquoi Android n'est pas couvert : il n'a pas
    // `java.lang.foreign`. Voir le README.
    jvmToolchain(22)
    explicitApi()
}

sourceSets {
    named("main") {
        kotlin.srcDir("src/main/kotlin")
    }
}

repositories {
    mavenCentral()
}

// **AUCUNE DÉPENDANCE, ET CE N'EST PAS UN OUBLI.**
//
// `java.lang.foreign` est dans le JDK. JNA et JNR seraient des dépendances, et
// JNA embarque ses propres objets natifs ; JNI demanderait d'écrire du C. Ce que
// cette bibliothèque tire, ses porteurs l'installent.
dependencies {
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    compilerOptions {
        allWarningsAsErrors.set(true)
    }
}

// Un porteur qui exécute du code appelant cette liaison doit ouvrir l'accès
// natif : sans cela la JVM avertit aujourd'hui, et REFUSERA demain.
tasks.withType<JavaExec>().configureEach {
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}
