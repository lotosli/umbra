//! Transport errors.

use thiserror::Error;
use umbra_proto::ProtocolError;

/// Errors returned by outer transport helpers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransportError {
    /// Underlying I/O failed.
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Shared wire-format parser or serializer failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// TLS ClientHello construction failed.
    #[error(transparent)]
    Tls(#[from] umbra_tls::TlsError),
    /// TCP evasion strategy is invalid.
    #[error("invalid TCP evasion strategy: {0}")]
    InvalidEvasionStrategy(&'static str),
    /// QUIC fingerprint or carrier data is invalid.
    #[error("invalid QUIC surface: {0}")]
    InvalidQuicSurface(&'static str),
}
