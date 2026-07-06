//! Shared protocol error types.

use thiserror::Error;

/// Errors returned by Umbra wire-format parsers and serializers.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProtocolError {
    /// The input ended before a complete object could be decoded.
    #[error("truncated input")]
    TruncatedInput,
    /// The input contains bytes after an object that must occupy the full buffer.
    #[error("trailing bytes")]
    TrailingBytes,
    /// A protocol version byte is not supported.
    #[error("unsupported version {0}")]
    UnsupportedVersion(u8),
    /// A command byte is not supported.
    #[error("unsupported command {0:#04x}")]
    UnsupportedCommand(u8),
    /// An address type or address value is invalid.
    #[error("invalid address")]
    InvalidAddress,
    /// A length field exceeds either the input size or configured maximum.
    #[error("length violation")]
    LengthViolation,
}
