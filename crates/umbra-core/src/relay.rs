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

/// Copy both directions independently, with one inactivity clock for the owner.
pub(crate) async fn relay_until_idle<L, R>(
    left: &mut L,
    right: &mut R,
    idle: std::time::Duration,
) -> Result<(u64, u64), CoreError>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let clock = ProgressClock::new();
    let mut left = ProgressIo {
        inner: left,
        clock: &clock,
    };
    let mut right = ProgressIo {
        inner: right,
        clock: &clock,
    };
    let transfer = async {
        let (left_read, left_write) = tokio::io::split(&mut left);
        let (right_read, right_write) = tokio::io::split(&mut right);
        tokio::try_join!(
            copy_direction(left_read, right_write),
            copy_direction(right_read, left_write)
        )
        .map_err(CoreError::from)
    };
    tokio::select! {
        result = transfer => result,
        () = clock.expired(idle) => Err(CoreError::IdleTimeout("bidirectional relay")),
    }
}

async fn copy_direction<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut read: R,
    mut write: W,
) -> std::io::Result<u64> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buffer = vec![0; 16 * 1024];
    let mut count = 0_u64;
    loop {
        let length = read.read(&mut buffer).await?;
        if length == 0 {
            write.shutdown().await?;
            return Ok(count);
        }
        write.write_all(&buffer[..length]).await?;
        count = count
            .checked_add(
                u64::try_from(length)
                    .map_err(|_| std::io::Error::other("relay byte count overflow"))?,
            )
            .ok_or_else(|| std::io::Error::other("relay byte count overflow"))?;
    }
}

pub(crate) struct ProgressClock {
    started: std::time::Instant,
    latest: std::sync::atomic::AtomicU64,
}

impl ProgressClock {
    pub(crate) fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
            latest: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub(crate) fn track<'a, IO>(&'a self, inner: &'a mut IO) -> ProgressIo<'a, IO> {
        ProgressIo { inner, clock: self }
    }

    fn elapsed(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    pub(crate) fn advance(&self) {
        self.latest
            .store(self.elapsed(), std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) async fn expired(&self, idle: std::time::Duration) {
        let maximum = u64::try_from(idle.as_nanos()).unwrap_or(u64::MAX);
        let mut remaining = maximum;
        loop {
            tokio::time::sleep(std::time::Duration::from_nanos(remaining)).await;
            let elapsed = self
                .elapsed()
                .saturating_sub(self.latest.load(std::sync::atomic::Ordering::Relaxed));
            if elapsed >= maximum {
                return;
            }
            remaining = maximum - elapsed;
        }
    }
}

pub(crate) struct ProgressIo<'a, IO> {
    inner: &'a mut IO,
    clock: &'a ProgressClock,
}

impl<IO: AsyncRead + Unpin> AsyncRead for ProgressIo<'_, IO> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut *self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.clock.advance();
        }
        result
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for ProgressIo<'_, IO> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result = std::pin::Pin::new(&mut *self.inner).poll_write(cx, buf);
        if matches!(result, std::task::Poll::Ready(Ok(n)) if n > 0) {
            self.clock.advance();
        }
        result
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}
