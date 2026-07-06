//! Bidirectional relay helpers with explicit half-close accounting.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::CoreError;

/// Result of one bidirectional relay.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RelayOutcome {
    /// Bytes copied from the first stream to the second stream.
    pub left_to_right: u64,
    /// Bytes copied from the second stream to the first stream.
    pub right_to_left: u64,
}

/// Relay bytes in both directions and let `tokio` propagate EOF and half-closes.
pub async fn relay_bidirectional<L, R>(
    left: &mut L,
    right: &mut R,
) -> Result<RelayOutcome, CoreError>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let (left_to_right, right_to_left) = tokio::io::copy_bidirectional(left, right).await?;
    Ok(RelayOutcome {
        left_to_right,
        right_to_left,
    })
}
