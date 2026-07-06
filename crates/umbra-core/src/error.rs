//! Core runtime errors.

use thiserror::Error;

/// Errors returned by Umbra orchestration helpers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoreError {
    /// I/O failed while reading or writing connection bytes.
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The incoming TLS record or ClientHello is malformed.
    #[error("invalid ClientHello: {0}")]
    InvalidClientHello(&'static str),
    /// The initial ClientHello exceeded configured read limits.
    #[error("ClientHello read limit exceeded")]
    ClientHelloTooLarge,
    /// Runtime configuration is invalid.
    #[error("invalid runtime configuration: {0}")]
    InvalidConfig(&'static str),
    /// TLS component failed.
    #[error(transparent)]
    Tls(#[from] umbra_tls::TlsError),
    /// REALITY component failed.
    #[error(transparent)]
    Reality(#[from] umbra_reality::RealityError),
    /// Cryptographic primitive failed.
    #[error(transparent)]
    Crypto(#[from] umbra_crypto::CryptoError),
}
