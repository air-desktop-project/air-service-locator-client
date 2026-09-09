# La liaison C++ d'air-service-locator.
#
# ── UNE CIBLE `INTERFACE`, ET RIEN À CONSTRUIRE ────────────────────────────
#
# `asl.hpp` est un en-tête seul : il n'y a pas de bibliothèque à compiler ici.
# Ce fichier ne fait que deux choses — porter les répertoires d'inclusion (le
# nôtre ET celui de l'en-tête C, qu'il inclut) et dire la norme minimale.
#
# **IL NE CONSTRUIT PAS L'OBJET NATIF, ET NE LE CHERCHE PAS.** Celui-ci vient de
# `cargo build --release`, et son emplacement dépend du déploiement de qui nous
# embarque. Le deviner ici obligerait à supposer une arborescence, et à échouer
# de façon obscure chez tous ceux qui en ont une autre. À l'appelant de faire
# `target_link_libraries(le_sien PRIVATE asl::asl <chemin>/libasl_client_ffi.so)`.
#
# ── POURQUOI C++17 ─────────────────────────────────────────────────────────
#
# Cette bibliothèque est embarquée par du code dont nous ne choisissons pas la
# chaîne de compilation. `std::expected` (C++23) et `std::span` (C++20) auraient
# été agréables ; les exiger aurait écarté des porteurs pour notre confort.

cmake_minimum_required(VERSION 3.16)

project(asl_cpp LANGUAGES CXX VERSION 0.1.0)

add_library(asl_cpp INTERFACE)
add_library(asl::asl ALIAS asl_cpp)

target_include_directories(asl_cpp INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../crates/asl-client-ffi/include")

target_compile_features(asl_cpp INTERFACE cxx_std_17)

# Les essais ne se construisent pas par défaut : `scripts/check-cpp.sh` les
# compile lui-même, avec plusieurs compilateurs et plusieurs normes — ce qu'un
# unique passage CMake ne ferait pas.
option(ASL_CPP_ESSAIS "Construire les essais de la liaison C++" OFF)

if(ASL_CPP_ESSAIS)
    enable_testing()
    add_executable(asl_cpp_essais essais/essais.cpp)
    target_link_libraries(asl_cpp_essais PRIVATE asl::asl)
    target_compile_options(asl_cpp_essais PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME asl_cpp_essais COMMAND asl_cpp_essais)
endif()
