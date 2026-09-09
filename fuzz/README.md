# Le fuzz d'air-service-locator-client

**Ce que le fuzz attrape et que rien d'autre n'attrape** : une borne oubliée. Les
lints `deny` du workspace — `cast_possible_truncation`, `arithmetic_side_effects`
— voient une conversion douteuse ; ils ne voient jamais un index qui déborde d'un
cran sur une entrée que personne n'a imaginée. C'est la contrainte C3.

## Les cibles

| Cible | Graines | Ce qu'elle éprouve |
|---|---|---|
| `fuzz_asl_client_reprise` | `reprise` | **Le mécanisme de haute disponibilité du produit.** L'état vivant n'est pas répliqué entre les annuaires racines : c'est la reconnexion du client qui reconstruit tout. Un délai nul fait tourner une boucle serrée ; un délai qui ne croît pas fait marteler l'annuaire par mille daemons à la seconde où il se relève. |

## Lancer

```sh
# Ce que la CI lance : quelques secondes par cible, depuis les graines.
scripts/check-fuzz.sh --smoke

# Une vraie campagne, sans borne de temps.
cd fuzz && cargo fuzz run fuzz_asl_client_reprise corpus/fuzz_asl_client_reprise seeds/reprise
```

**Le smoke-test N'EST PAS une campagne.** Quelques secondes par cible depuis un
corpus neuf n'explorent pas ce que des heures explorent : ce job attrape la
panique qu'un changement vient d'introduire sur un chemin déjà connu, et rien de
plus. S'en réclamer davantage serait affirmer une garantie qu'il n'a pas.

## Les graines

Chacune est **nommée pour ce qu'elle éprouve** — `debordement`,
`crockford-rattrape`, `symbole-u-refuse`. Une graine qu'on ne sait pas nommer est
une graine dont personne ne sait ce qu'elle apporte, et `check-fuzz.sh` refuse
les noms de quarante caractères hexadécimaux : ce sont des trouvailles brutes de
libFuzzer, dont la place est `corpus/`.

**Une trouvaille peut devenir une graine, à condition d'être renommée.**
`session/regression-keepalive-tardif` est l'entrée qui a fait tomber
`fuzz_asl_annuaire_session` à sa première campagne : une session expirée y
ressuscitait au premier keepalive. Elle est gardée pour que cela ne repasse
jamais — sous un nom qui dit ce qu'elle prouve, et non sous son SHA-1.

## Le corpus n'est pas versionné

libFuzzer garde **toute** entrée qui apporte un chemin nouveau, y compris des
milliers de variantes du même : sur `air-mail-server`, treize campagnes de vingt
secondes ont laissé 135 000 fichiers.

Le versionner avant d'avoir de quoi le réduire (`cargo fuzz cmin`) coûterait plus
qu'il n'apporterait — et l'historique garde ce qu'on y met. À reconsidérer le
jour où une campagne longue aura trouvé quelque chose qui mérite d'être gardé.

## Cette crate vit hors du workspace

Les QUATRE raisons sont en tête de [`Cargo.toml`](Cargo.toml). La quatrième
n'appartient qu'à ce dépôt : **c'est lui que des tiers embarquent**, et une
dépendance de plus dans son lock est une dépendance de plus dans l'interpréteur
Python de quelqu'un d'autre.

La conséquence, elle, est la même et elle a coûté cher là-bas : `cargo build
--workspace` ne touche pas cette crate. `scripts/check-compile.sh` et
`scripts/check-format.sh` couvrent donc les DEUX portées.
