# `asl` pour Ruby

Annoncer un service et retrouver un port, sans qu'aucun daemon ait de numéro de
port fixe.

```ruby
require "asl"

Asl::Client.ouvrir(
  annuaires: [["203.0.113.7:6630", "nitrogen.example"]],
  racines: File.binread("/etc/asl/ca.pem"),
  identite: [machine, graine]
) do |client|
  client.annoncer("depot", [Asl::Point.new(:tcp, 8080)])
  servir_pour_toujours          # l'annonce se tient toute seule
end
```

Et du côté qui consomme :

```ruby
client.ou(machine, "depot").each do |candidat|
  puts "#{candidat} #{candidat.verdict}"    # [2001:db8::1]:8080 en_cours
end
```

## Ce qui tourne en arrière-plan

`annoncer` **rend la main tout de suite** : un annuaire injoignable ne doit pas
empêcher un daemon de démarrer. Le service écoute déjà pendant que l'annonce
cherche encore.

Ce qui la tient ensuite est **un fil natif**, à l'intérieur de la bibliothèque —
ni un `Thread`, ni un `Fiber`, et il ne touche jamais à l'interpréteur. Il se
reconnecte seul, bascule sur l'autre annuaire racine quand le premier tombe, et
n'abandonne jamais.

`client.etat` dit où il en est. Le seul champ dont un humain doit être averti est
`abandonnee?` : la tâche **ne renonce que sur une faute de configuration**,
jamais sur une panne de réseau, quelle qu'en soit la durée.

## Le GVL est relâché, et c'est éprouvé

`asl_ou` attend jusqu'à vingt secondes qu'un annuaire réponde ; `fermer` jusqu'à
deux qu'une annonce se retire. **Si le GVL était tenu pendant ce temps,
l'interpréteur entier gèlerait** — serveur web compris, sans une ligne d'erreur.

Chaque fonction est donc déclarée `need_gvl: false`, explicitement et non par
confiance dans un défaut. Un essai le mesure : un fil témoin doit avancer pendant
un appel bloquant. Avec le GVL tenu, il gagne **zéro tour en deux secondes**.

## Fermer le client retire l'annonce

La connexion **est** le bail : il n'y a pas de « retrait » séparé à appeler.
Laisser le client se faire ramasser retire donc l'annonce au moment où le
ramasse-miettes passe, c'est-à-dire à un moment que vous ne choisissez pas.

**Employez `Asl::Client.ouvrir` avec un bloc**, pour la même raison que
`File.open` : ce qui est ouvert se ferme, y compris quand le bloc lève. Un
finaliseur existe, mais c'est un filet, pas un moyen.

## Ce que cette liaison n'installe pas

Rien. `fiddle`, `ipaddr` et `objspace` sont dans la distribution de Ruby, et la
gemspec ne déclare aucune dépendance.

La gemme `ffi` serait plus agréable. Elle est aussi une **extension native** :
l'installer compilerait du C dans l'environnement de qui vous embarque — ce que
la contrainte C4 de ce dépôt refuse partout ailleurs, et qu'il serait absurde de
laisser entrer par la porte du gestionnaire de gemmes.

Le prix de `fiddle` est payé dans `lib/asl/abi.rb` : **chaque signature est
déclarée à la main**, et une déclaration fausse ne se voit pas au chargement —
elle corrompt la pile à l'appel.

## Les structures se lisent avec `pack` et `unpack`

`pack` n'insère jamais de bourrage, ce qui serait normalement disqualifiant pour
lire une structure C. Sauf que celles de l'ABI n'en ont aucun : l'en-tête range
ses champs du plus large au plus étroit, **exprès**, pour que cinq langages qui
calculent la disposition chacun de son côté tombent d'accord.

La disposition packée *est* donc la disposition C. C'est le bénéfice direct de
cette décision-là, et une structure à trou aurait rendu ceci impossible.

## L'objet natif

Cette gemme est du Ruby pur : elle **cherche** `libasl_client_ffi.so`, elle ne
l'embarque pas encore.

```sh
cargo build --release
export ASL_BIBLIOTHEQUE=$PWD/target/release/libasl_client_ffi.so
```

Cherché dans l'ordre : `ASL_BIBLIOTHEQUE`, puis à côté de la gemme, puis le
chargeur du système. À défaut, `Asl::BibliothequeIntrouvable` est levée avec la
liste de ce qui a été essayé — **une installation incomplète n'est pas une panne
d'exécution**.

## Les erreurs

Jamais un entier négatif rendu tel quel. Toutes descendent de `StandardError`,
donc un `rescue => e` ordinaire les attrape ; `rescue Asl::Erreur` suffit à les
attraper toutes.

| | |
|---|---|
| `Asl::MauvaisArgument` | Une adresse illisible, un port nul, une graine de mauvaise taille. |
| `Asl::Configuration` | Il manque un annuaire ou une racine. **Réessayer ne réparerait rien.** |
| `Asl::Injoignable` | Personne n'a répondu. Un câble débranché. |
| `Asl::Refuse` | L'annuaire a compris, et il a dit non. Un droit manquant. |
| `Asl::PasDIdentite` | Cette machine n'est pas enrôlée. |
| `Asl::Deja` | Ce client annonce déjà. |
| `Asl::Interne` | L'impossible, rattrapé — **le processus n'a pas été tué**. |

## Le verdict a quatre valeurs, et il n'y a pas de `joignable?`

`:en_cours` n'affirme rien : l'annuaire répond avant d'avoir sondé, pour ne pas
faire attendre le démarrage d'un daemon. `:non_sonde` dit qu'il ne mesurera pas —
UDP n'a pas de poignée de main, donc une sonde n'y distinguerait pas « écoute et
ignore » de « rien n'écoute ».

Un prédicat `candidat.joignable?` serait juste une fois sur deux, et ferait
écarter un candidat parfaitement bon. Il n'y en a pas.

## Plusieurs fils

`Asl::Client` sérialise ses appels. L'ABI dit qu'un client ne se partage pas
entre fils ; en Rust deux appels concurrents aliaseraient un `&mut`, ce qui est
un comportement indéfini et non un ralentissement. En Ruby personne ne lit cette
phrase : la liaison la fait respecter, et **transforme l'indéfini en file
d'attente**.

Le coût est réel : `etat` attend pendant un `ou` en cours, qui peut durer vingt
secondes. Un daemon qui annonce n'appelle pas `ou`, donc les deux se croisent
rarement.

## Les essais

```sh
./scripts/check-ruby.sh
```

Ils lisent `crates/asl-client-ffi/include/asl.h` et comparent : constantes,
tailles, **ordre des champs**. Rien dans les deux langages ne relie ces fichiers,
et une divergence ne plante pas — elle ment.
