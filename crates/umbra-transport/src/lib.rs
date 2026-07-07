//! `umbra-transport` implements outer transports.
//!
//! `tcp` builds and writes the profile-shaped TCP ClientHello, `quic` carries
//! REALITY authentication through QUIC/HTTP-3 surfaces while reusing
//! `umbra-tls`, and the planned Geneva path covers TCP segmentation and
//! desynchronization policies.
//!
//! QUIC fingerprints and REALITY-over-QUIC carriers must be checked against
//! real Chrome captures. Advanced Geneva policies require raw-socket
//! privileges; the default path stays with low-risk segmentation and falls back
//! to ordinary writes on failure.
//!
//! The normative design lives in the outer transport section of
//! `docs/protocol-design.md`; matching OpenSpec capabilities are
//! `transport-tcp`, `transport-quic`, and `tcp-evasion`.

pub mod error;
pub mod evasion;
pub mod quic;
pub mod tcp;

pub use error::TransportError;
