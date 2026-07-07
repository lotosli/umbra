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
    /// A connection made no progress within the configured timeout.
    #[error("idle timeout: {0}")]
    IdleTimeout(&'static str),
    /// Runtime configuration could not be parsed.
    #[error("configuration parse failed: {0}")]
    ConfigParse(String),
    /// SOCKS5 negotiation or request parsing failed.
    #[error("SOCKS5 error: {0}")]
    Socks(&'static str),
    /// Shared wire protocol parser failed.
    #[error(transparent)]
    Protocol(#[from] umbra_proto::ProtocolError),
    /// Inner transport failed.
    #[error(transparent)]
    Inner(#[from] umbra_inner::InnerError),
    /// QUIC runtime failed.
    #[error("QUIC runtime failed: {0}")]
    Quic(String),
    /// Outer transport failed.
    #[error(transparent)]
    Transport(#[from] umbra_transport::TransportError),
    /// Fingerprint profile loading or validation failed.
    #[error(transparent)]
    Fingerprint(#[from] umbra_fingerprint::FingerprintError),
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
