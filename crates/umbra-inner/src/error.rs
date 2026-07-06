//! Inner transport errors.

use thiserror::Error;
use umbra_proto::ProtocolError;

/// Errors returned by inner transport sessions.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InnerError {
    /// Underlying I/O failed.
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Shared wire-format parser or serializer failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// Padding scheme string is invalid.
    #[error("invalid padding scheme: {0}")]
    InvalidPaddingScheme(&'static str),
    /// RealSite spider path is invalid.
    #[error("invalid spider path: {0}")]
    InvalidSpiderPath(&'static str),
    /// Flow-control arithmetic overflowed.
    #[error("flow-control window overflow")]
    WindowOverflow,
    /// A stream was reset.
    #[error("stream was reset")]
    StreamReset,
    /// A stream is closed.
    #[error("stream is closed")]
    StreamClosed,
}
