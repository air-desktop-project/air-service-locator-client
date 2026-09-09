// swift-tools-version: 6.0

// La liaison Swift d'air-service-locator.
//
// ── CE FICHIER EST POUR LES PORTEURS, PAS POUR NOUS ────────────────────────
//
// `scripts/check-swift.sh` appelle `swiftc` directement : il n'a besoin d'aucune
// résolution de paquets, donc d'aucun réseau. **Une barrière qui téléchargerait
// ne serait pas une barrière.**
//
// Ce fichier existe pour qu'un projet SwiftPM puisse consommer cette liaison de
// la façon qu'il attend. Il n'est jamais exécuté par la CI de ce dépôt.
//
// ── IL NE CONSTRUIT NI NE CHERCHE L'OBJET NATIF ────────────────────────────
//
// Celui-ci vient de `cargo build --release`, et son emplacement dépend du
// déploiement. Le deviner obligerait à supposer une arborescence, et à échouer de
// façon obscure chez tous ceux qui en ont une autre.
//
//     swift build -Xlinker -L/chemin/vers/target/release

import PackageDescription

let package = Package(
    name: "Asl",
    products: [
        .library(name: "Asl", targets: ["Asl"])
    ],
    targets: [
        // La cible système : elle ne contient que la carte de module, qui pointe
        // `crates/asl-client-ffi/include/asl.h`. **Pas de copie de l'en-tête** —
        // Swift, comme C++, sait inclure le contrat, et une copie serait la
        // seconde source que tout ce dépôt s'emploie à éviter.
        .systemLibrary(name: "CAsl"),
        .target(
            name: "Asl",
            dependencies: ["CAsl"],
            swiftSettings: [
                // Le mode Swift 6 : c'est lui qui fait REFUSER le partage d'un
                // `Client` entre domaines d'isolement, là où les autres liaisons
                // posent un verrou.
                .swiftLanguageMode(.v6)
            ]
        ),
    ]
)
