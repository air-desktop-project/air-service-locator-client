#!/usr/bin/env bash
#
# construire-mobile — les objets natifs que les deux applications mobiles
# embarquent : un xcframework pour iOS, un objet partagé JNI pour Android.
#
# # CE QUE CE SCRIPT PRODUIT, ET OÙ
#
#   target/mobile/AslClient.xcframework   iOS : appareil (arm64) et simulateur
#                                         (arm64 + x86_64, réunis par lipo),
#                                         avec `include/asl.h` et une carte de
#                                         module pour que Swift l'importe.
#   target/mobile/jniLibs/arm64-v8a/libasl_client_android.so
#                                         Android : la voie mobile par JNI.
#
# Les deux dépôts d'applications pointent là par un chemin relatif
# (`../air-service-locator-client/target/mobile/…`). Rien de ceci n'est commis :
# ce sont des SORTIES, au même titre qu'un binaire.
#
# # CE QU'IL FAUT
#
#   • les cibles Rust : `rustup target add aarch64-apple-ios x86_64-apple-ios
#     aarch64-apple-ios-sim aarch64-linux-android --toolchain <celle du dépôt>`
#   • Xcode, pour `lipo` et `xcodebuild -create-xcframework` ;
#   • le NDK Android, désigné par `ANDROID_NDK` (ou trouvé sous
#     `$ANDROID_HOME/ndk/*`), pour l'éditeur de liens d'`aarch64-linux-android`.
#
# Ce n'est PAS une barrière : ce script construit pour d'autres plates-formes
# que celle où il tourne, et une CI Linux n'a pas Xcode. Il se lance à la main,
# sur le Mac qui construit les applications.

set -euo pipefail
cd "$(dirname "$0")/.."

sortie="target/mobile"
mkdir -p "$sortie"

echo 'construire-mobile — les objets natifs des applications iOS et Android'
echo

# ── iOS ──────────────────────────────────────────────────────────────────────
for cible in aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim; do
    echo "iOS : $cible"
    cargo build --release --quiet -p asl-client-ffi --target "$cible"
done

# Les deux tranches de simulateur dans un seul objet : un xcframework ne porte
# qu'une bibliothèque par plate-forme, et « simulateur » en est une.
simulateur="$sortie/libasl_client_ffi-simulateur.a"
lipo -create \
    target/x86_64-apple-ios/release/libasl_client_ffi.a \
    target/aarch64-apple-ios-sim/release/libasl_client_ffi.a \
    -output "$simulateur"

# L'en-tête et sa carte de module : c'est ce qui rend `import CAsl` possible
# côté Swift, sans copier l'en-tête dans le dépôt de l'application.
entetes="$sortie/include"
rm -rf "$entetes"
mkdir -p "$entetes"
cp crates/asl-client-ffi/include/asl.h "$entetes/"
cat > "$entetes/module.modulemap" <<'MM'
module CAsl {
    header "asl.h"
    export *
}
MM

rm -rf "$sortie/AslClient.xcframework"
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libasl_client_ffi.a -headers "$entetes" \
    -library "$simulateur" -headers "$entetes" \
    -output "$sortie/AslClient.xcframework" >/dev/null
echo "  → $sortie/AslClient.xcframework"

# ── Android ──────────────────────────────────────────────────────────────────
ndk="${ANDROID_NDK:-}"
if [ -z "$ndk" ] && [ -n "${ANDROID_HOME:-}" ]; then
    ndk=$(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1 || true)
fi
if [ -z "$ndk" ]; then
    echo "ÉCHEC : aucun NDK Android — posez ANDROID_NDK, ou ANDROID_HOME avec ndk/."
    exit 1
fi
hote=$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64
clang="$ndk/toolchains/llvm/prebuilt/$hote/bin/aarch64-linux-android28-clang"
if [ ! -x "$clang" ]; then
    echo "ÉCHEC : $clang est introuvable — le NDK $ndk ne porte pas cet hôte."
    exit 1
fi
echo "Android : aarch64-linux-android (API 28, $(basename "$ndk"))"
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$clang" \
    cargo build --release --quiet -p asl-client-android --target aarch64-linux-android
mkdir -p "$sortie/jniLibs/arm64-v8a"
cp target/aarch64-linux-android/release/libasl_client_android.so "$sortie/jniLibs/arm64-v8a/"
echo "  → $sortie/jniLibs/arm64-v8a/libasl_client_android.so"

echo
echo "OK : les objets natifs sont dans $sortie/."
