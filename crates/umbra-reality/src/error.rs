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
    /// Destination address or collected destination data is invalid.
    #[error("invalid destination profile: {0}")]
    InvalidDestProfile(&'static str),
    /// No destination profile has been built yet.
    #[error("no active destination profile")]
    NoActiveProfile,
    /// Destination probing failed.
    #[error("destination probing failed: {0}")]
    ProbeFailed(&'static str),
    /// Forged certificate generation failed.
    #[error("forged certificate generation failed: {0}")]
    CertificateForgeFailed(&'static str),
    /// Peer certificate binding data is malformed.
    #[error("certificate binding is invalid: {0}")]
    CertificateBindingInvalid(&'static str),
    /// Replay cache rejected a repeated token/key.
    #[error("REALITY replay detected")]
    Replay,
    /// Replay cache capacity must be nonzero.
    #[error("replay cache capacity must be nonzero")]
    InvalidReplayCapacity,
    /// Replay cache has no capacity available without evicting a live entry.
    #[error("replay cache is full")]
    ReplayCacheFull,
    /// The inclusive replay expiry cannot be represented in u64 seconds.
    #[error("replay expiry timestamp overflow")]
    ReplayExpiryOverflow,
    /// Replay cache lock was poisoned by a previous panic.
    #[error("replay cache lock is poisoned")]
    ReplayCachePoisoned,
}
