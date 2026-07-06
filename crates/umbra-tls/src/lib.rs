//! `umbra-tls` — self-contained TLS 1.3 surface used by Umbra.
//!
//! The crate owns Chrome-shaped ClientHello construction, safe ClientHello
//! parsing, RFC 8446 key-schedule helpers, TLS 1.3 record protection, and the
//! small client/server state objects that higher protocol layers compose.

pub mod clienthello;
pub mod error;
pub mod handshake;
pub mod keyschedule;
pub mod parse;
pub mod quic;
pub mod records;
pub mod server;

pub use error::TlsError;
