// **CE FICHIER NE DOIT PAS COMPILER**, et c'est tout son objet.
//
// Python et Ruby lèvent des exceptions : un code de retour oublié y est
// impossible. C++ ne lève pas — c'est une décision, prise pour les bases qui se
// construisent avec `-fno-exceptions`. Ce qui la rend tenable est `[[nodiscard]]`
// sur chaque fonction qui rend une `Faute`.
//
// Sans essai, cette annotation se perdrait au premier remaniement, et personne ne
// s'en apercevrait : le code continuerait de compiler, simplement sans filet.
//
// `scripts/check-cpp.sh` compile ce fichier avec `-Werror` et exige un ÉCHEC.

#include "asl.hpp"

int main() {
    asl::Client client;
    // Le résultat est jeté. Avec `[[nodiscard]]` et `-Werror`, c'est une erreur.
    asl::Client::ouvrir(client);
    client.ajouter_annuaire("127.0.0.1:1", "localhost");
    return 0;
}
