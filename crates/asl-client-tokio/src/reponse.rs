//! Ce que l'annuaire a répondu.

use asl_id::Identifiant;

use crate::Faute;

/// Une réponse de l'annuaire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reponse {
    /// Le code d'état.
    pub statut: u16,
    /// Le corps, tel qu'il est arrivé.
    pub corps: Vec<u8>,
}

impl Reponse {
    /// Depuis ce que le conducteur HTTP/3 a rendu.
    pub(crate) fn depuis(quoi: ams_h3::ReponseRecue) -> Self {
        Self {
            statut: quoi.statut.value(),
            corps: quoi.corps,
        }
    }

    /// Exige ce code d'état, et rien d'autre.
    ///
    /// # POURQUOI UN CODE EXACT, ET NON « 2xx »
    ///
    /// L'annuaire dit exactement ce qu'il a fait : `200` rend quelque chose,
    /// `201` a créé, `204` n'a rien à dire. **Accepter la famille entière ferait
    /// prendre un `204` pour un `200`**, et le client chercherait un corps qui
    /// n'existe pas — ou pire, croirait avoir créé ce qu'on lui a seulement lu.
    ///
    /// # Errors
    ///
    /// [`Faute::Statut`].
    pub fn exige(&self, attendu: u16) -> Result<(), Faute> {
        if self.statut == attendu {
            return Ok(());
        }
        Err(Faute::Statut(self.statut))
    }

    /// L'identifiant que ce champ JSON porte.
    ///
    /// # UNE RECHERCHE, ET NON UN ANALYSEUR
    ///
    /// Ces corps sont écrits par `asl-session`, à champs fixes et sans
    /// échappement : `{"machine":"m-…"}`. Tirer un analyseur JSON dans une
    /// bibliothèque que des tiers embarquent pour lire vingt-huit caractères
    /// serait leur faire porter un risque qu'ils n'ont pas choisi.
    ///
    /// **Et l'identifiant est validé, lui.** `Identifiant::analyser` refuse ce
    /// qui n'a pas la bonne forme, donc une recherche qui se tromperait de champ
    /// ne rendrait pas un identifiant — elle rendrait une faute.
    ///
    /// # Errors
    ///
    /// [`Faute::Illisible`].
    pub fn identifiant(&self, champ: &str) -> Result<Identifiant, Faute> {
        let texte = core::str::from_utf8(&self.corps).map_err(|_| Faute::Illisible)?;
        let marque = format!("\"{champ}\":\"");
        let debut = texte
            .find(&marque)
            .ok_or(Faute::Illisible)?
            .saturating_add(marque.len());
        let reste = texte.get(debut..).ok_or(Faute::Illisible)?;
        let fin = reste.find('"').ok_or(Faute::Illisible)?;
        let valeur = reste.get(..fin).ok_or(Faute::Illisible)?;
        Identifiant::analyser(valeur).map_err(|_| Faute::Illisible)
    }
}
