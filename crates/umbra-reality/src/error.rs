//! REALITY component errors.

use thiserror::Error;

/// Errors returned by REALITY authentication and replay validation.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum RealityError {
    /// Short ids are fixed to at most eight bytes by the protocol.
    #[error("short_id length must be 0..=8 bytes")]
    InvalidShortIdLength,
    /// The u64 timestamp cannot be encoded into the 32-bit wire field.
    #[error("timestamp does not fit the REALITY token")]
    TimestampOutOfRange,
    /// The timestamp window is invalid.
    #[error("max_time_diff is invalid")]
    InvalidTimeWindow,
    /// AES-GCM authentication failed.
    #[error("REALITY token authentication failed")]
    AuthenticationFailed,
    /// Token version is not supported.
    #[error("unsupported REALITY token version: {0}")]
    InvalidVersion(u8),
    /// Token timestamp is outside the allowed server window.
    #[error("REALITY token timestamp is outside the allowed window")]
    Expired,
    /// Token short id is not allowed by the server configuration.
    #[error("REALITY token short_id is not allowed")]
    ShortIdRejected,
    /// ClientHello SNI is not allowed by the server configuration.
    #[error("REALITY server name is not allowed")]
    ServerNameRejected,
    /// Replay cache rejected a repeated token/key.
    #[error("REALITY replay detected")]
    Replay,
    /// Replay cache capacity must be nonzero.
    #[error("replay cache capacity must be nonzero")]
    InvalidReplayCapacity,
    /// Replay cache lock was poisoned by a previous panic.
    #[error("replay cache lock is poisoned")]
    ReplayCachePoisoned,
}
