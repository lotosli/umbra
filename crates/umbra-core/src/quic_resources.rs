//! Native QUIC receive commitments, including retained application readers.

use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use tokio::io::{AsyncRead, ReadBuf};
use umbra_inner::budget::BudgetLease;

use crate::{resources::ResourceGroup, CoreError};

// Reviewed quinn-proto 0.11.18 defaults; setting these explicitly keeps the
// memory commitment and actual transport limits in agreement.
const STREAM_RECEIVE_BYTES: u32 = 1_250_000;
const SEND_BYTES: usize = 10_000_000;
// Two bounded datagram queues plus crypto, frame and connection staging.
const TRANSPORT_BYTES: usize = 3 * 1024 * 1024;
const FIXED_BYTES: usize = TRANSPORT_BYTES + SEND_BYTES;
/// Two 16KiB copy buffers, framing and task allowance per accepted stream.
pub(crate) const STREAM_STORAGE_BYTES: usize = 64 * 1024;

/// One receive controller; all readers and the socket retain its commitment.
pub(crate) struct QuicBudget {
    lease: BudgetLease,
    consumed: Arc<AtomicU64>,
    window: u32,
    maximum: u32,
    epoch: Instant,
    epoch_consumed: u64,
}

impl QuicBudget {
    pub(crate) fn new(group: &ResourceGroup) -> Result<Self, CoreError> {
        let maximum = group.resources.config.max_window_mib * 1024 * 1024;
        let window = maximum.min(2 * STREAM_RECEIVE_BYTES);
        Ok(Self {
            lease: group.reserve(FIXED_BYTES + window as usize)?,
            consumed: Arc::new(AtomicU64::new(0)),
            window,
            maximum,
            epoch: Instant::now(),
            epoch_consumed: 0,
        })
    }

    pub(crate) fn configure(&self, transport: &mut quinn::TransportConfig) {
        transport
            .send_window(SEND_BYTES as u64)
            .receive_window(self.window.into())
            .stream_receive_window((self.window / 2).min(STREAM_RECEIVE_BYTES).into());
    }

    pub(crate) fn lease(&self) -> BudgetLease {
        self.lease.clone()
    }

    pub(crate) fn reader<R>(&self, inner: R) -> QuicRead<R> {
        QuicRead {
            inner,
            consumed: self.consumed.clone(),
            _lease: self.lease(),
        }
    }

    /// Return a larger funded window for Quinn to advertise, never a revocation.
    pub(crate) fn grow(&mut self, rtt: Duration, now: Instant) -> Option<u32> {
        let consumed = self.consumed.load(Ordering::Relaxed);
        if consumed.saturating_sub(self.epoch_consumed) < u64::from(self.window / 2) {
            return None;
        }
        let elapsed = now.saturating_duration_since(self.epoch);
        self.epoch = now;
        self.epoch_consumed = consumed;
        let desired = self.window.saturating_mul(2).min(self.maximum);
        if desired <= self.window
            || elapsed > rtt.max(Duration::from_millis(1)).saturating_mul(2)
            || !self.lease.grow_to(FIXED_BYTES + desired as usize)
        {
            return None;
        }
        self.window = desired;
        Some(desired)
    }
}

/// Count actual Quinn consumption and retain credit while stream data is owned.
pub(crate) struct QuicRead<R> {
    inner: R,
    consumed: Arc<AtomicU64>,
    _lease: BudgetLease,
}

impl<R: AsyncRead + Unpin> AsyncRead for QuicRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        let bytes = buffer.filled().len() - before;
        if bytes > 0 {
            let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
            let _ = self
                .consumed
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    Some(n.saturating_add(bytes))
                });
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::{PerformanceCfg, Resources};
    use tokio::io::AsyncReadExt;

    fn group(memory_mib: usize, max_window_mib: u32) -> ResourceGroup {
        ResourceGroup {
            resources: Resources::new(PerformanceCfg {
                memory_mib,
                group_memory_mib: memory_mib,
                max_window_mib,
                ..PerformanceCfg::default()
            })
            .unwrap(),
            id: 0,
        }
    }

    #[tokio::test]
    async fn consumption_growth_stops_at_budget_and_retained_reader_owns_credit() {
        let group = group(32, 64);
        let mut budget = QuicBudget::new(&group).unwrap();
        let mut reader = budget.reader(std::io::Cursor::new(vec![0x42; 12_500_000]));
        let mut buffer = vec![0; 1_250_000];
        let rtt = Duration::from_secs(1);
        assert_eq!(budget.grow(rtt, Instant::now()), None, "idle is not demand");
        reader.read_exact(&mut buffer).await.unwrap();
        assert!(buffer.iter().all(|byte| *byte == 0x42));
        assert_eq!(budget.grow(rtt, Instant::now()), Some(5_000_000));
        for _ in 0..2 {
            reader.read_exact(&mut buffer).await.unwrap();
        }
        assert_eq!(budget.grow(rtt, Instant::now()), Some(10_000_000));
        for _ in 0..4 {
            reader.read_exact(&mut buffer).await.unwrap();
        }
        assert_eq!(
            budget.grow(rtt, Instant::now()),
            None,
            "unfunded growth refused"
        );
        assert_eq!(budget.window, 10_000_000);
        let committed = group.resources.pool.committed();
        assert_eq!(committed, FIXED_BYTES + 10_000_000);
        let socket = budget.lease();
        drop(budget);
        drop(socket);
        assert_eq!(group.resources.pool.committed(), committed);
        drop(reader);
        assert_eq!(group.resources.pool.committed(), 0);
    }

    #[test]
    fn slow_consumption_and_configured_maximum_do_not_expand_credit() {
        let group = group(16, 1);
        let mut budget = QuicBudget::new(&group).unwrap();
        assert_eq!(budget.window, 1024 * 1024);
        budget.consumed.store(1_000_000, Ordering::Relaxed);
        assert_eq!(budget.grow(Duration::from_secs(1), Instant::now()), None);
        drop(budget);
        let group = self::group(32, 64);
        let mut budget = QuicBudget::new(&group).unwrap();
        budget.consumed.store(2_000_000, Ordering::Relaxed);
        assert_eq!(
            budget.grow(
                Duration::from_millis(10),
                budget.epoch + Duration::from_secs(1)
            ),
            None
        );
        assert_eq!(budget.window, 2_500_000);
    }
}
