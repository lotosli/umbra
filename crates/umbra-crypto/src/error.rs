//! Error types for cryptographic primitive wrappers.

use thiserror::Error;

/// Errors returned by `umbra-crypto` APIs.
#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum CryptoError {
    /// A key had the wrong length for the selected primitive.
    #[error("invalid key length")]
    InvalidKeyLength,
    /// A nonce had the wrong length for the selected primitive.
    #[error("invalid nonce length")]
    InvalidNonceLength,
    /// Output keying material length is not supported by the KDF.
    #[error("invalid output length")]
    InvalidOutputLength,
    /// Authentication failed while opening or verifying data.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// Input bytes had the wrong length for a fixed-size primitive.
    #[error("invalid input length")]
    InvalidInputLength,
}
