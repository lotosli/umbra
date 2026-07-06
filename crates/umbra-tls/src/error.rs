//! TLS component errors.

use thiserror::Error;

/// Errors returned by the TLS 1.3 component.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum TlsError {
    /// An input byte slice is malformed for the expected TLS structure.
    #[error("invalid TLS input: {0}")]
    InvalidInput(&'static str),
    /// A variable-length field exceeded the maximum representable TLS length.
    #[error("TLS field length is out of range")]
    LengthOutOfRange,
    /// The requested cipher suite is not implemented by the minimal stack.
    #[error("unsupported TLS cipher suite: {0:#06x}")]
    UnsupportedCipherSuite(u16),
    /// AEAD authentication failed.
    #[error("TLS record authentication failed")]
    AuthenticationFailed,
    /// The peer certificate callback rejected the peer.
    #[error("peer certificate verification failed")]
    PeerRejected,
}
