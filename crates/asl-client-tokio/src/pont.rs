//! Le pont entre le conducteur HTTP/3 et la connexion QUIC.
//!
//! # POURQUOI IL EXISTE, ET POURQUOI IL NE FAIT RIEN
//!
//! `ams_h3::Transport` et `ams_quic_tls::Connection` vivent dans deux crates que
//! nous ne possédons pas. **La règle d'orphelin interdit donc d'implémenter l'un
//! pour l'autre ici** — il faut un type à nous entre les deux.
//!
//! C'est exactement le même pont que celui du serveur, dans `asl-loop-tokio`, et
//! pour exactement la même raison.

use ams_proto_quic::{Directional, StreamId};
use ams_quic::RecvState;
use ams_quic_tls::Connection;

/// Le pont, le temps d'un appel.
#[derive(Debug)]
pub struct Pont<'a>(pub &'a mut Connection);

impl ams_h3::Transport for Pont<'_> {
    fn open_uni(&mut self) -> Result<StreamId, ams_h3::Error> {
        self.0
            .open_stream(Directional::Unidirectional)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn open_bi(&mut self) -> Result<StreamId, ams_h3::Error> {
        self.0
            .open_stream(Directional::Bidirectional)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn read(&mut self, flux: StreamId, vers: &mut [u8]) -> usize {
        self.0.read(flux, vers)
    }

    fn write(&mut self, flux: StreamId, octets: &[u8]) -> Result<usize, ams_h3::Error> {
        self.0
            .write(flux, octets)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn reset(&mut self, flux: StreamId, code: u64) -> Result<(), ams_h3::Error> {
        self.0
            .reset(flux, code)
            .map_err(|_| ams_h3::Error::transport())
    }

    fn finish(&mut self, flux: StreamId) -> Result<(), ams_h3::Error> {
        self.0.finish(flux).map_err(|_| ams_h3::Error::transport())
    }

    fn recv_state(&self, flux: StreamId) -> Option<RecvState> {
        self.0.recv_state(flux)
    }
}
