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

// Two bounded datagram queues plus crypto, frame and connection staging.
const TRANSPORT_BYTES: usize = 3 * 1024 * 1024;
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
    policy: crate::resources::QuicWindows,
    fixed_bytes: usize,
}

impl QuicBudget {
    pub(crate) fn new(group: &ResourceGroup) -> Result<Self, CoreError> {
        let maximum = group.resources.config.max_window_mib * 1024 * 1024;
        let policy = group.resources.config.quic_windows();
        let window = policy.receive;
        let fixed_bytes = TRANSPORT_BYTES
            + usize::try_from(policy.send)
                .map_err(|_| CoreError::InvalidConfig("QUIC send storage overflows"))?;
        Ok(Self {
            lease: group.reserve(fixed_bytes + window as usize)?,
            consumed: Arc::new(AtomicU64::new(0)),
            window,
            maximum,
            epoch: Instant::now(),
            epoch_consumed: 0,
            policy,
            fixed_bytes,
        })
    }

    pub(crate) fn configure(&self, transport: &mut quinn::TransportConfig) {
        self.policy.configure(transport);
    }

    pub(crate) fn lease(&self) -> BudgetLease {
        self.lease.clone()
    }

    pub(crate) fn observation(
        &self,
        connection: &quinn::Connection,
    ) -> crate::diagnostics::CreditSnapshot {
        let stats = connection.stats();
        crate::diagnostics::CreditSnapshot {
            receive_window: u64::from(self.window),
            consumed: Some(self.consumed.load(Ordering::Relaxed)),
            quic_blocked_tx: Some(
                stats
                    .frame_tx
                    .data_blocked
                    .saturating_add(stats.frame_tx.stream_data_blocked),
            ),
            quic_blocked_rx: Some(
                stats
                    .frame_rx
                    .data_blocked
                    .saturating_add(stats.frame_rx.stream_data_blocked),
            ),
            rtt: Some(connection.rtt()),
            ..crate::diagnostics::CreditSnapshot::default()
        }
    }

    pub(crate) fn reader<R>(&self, inner: R) -> QuicRead<R> {
        self.read_owner().reader(inner)
    }

    pub(crate) fn read_owner(&self) -> QuicReadOwner {
        QuicReadOwner {
            consumed: self.consumed.clone(),
            lease: self.lease(),
        }
    }

    pub(crate) fn start_sampling(&mut self) {
        self.epoch = Instant::now();
        self.epoch_consumed = self.consumed.load(Ordering::Relaxed);
    }

    /// Return a larger funded window for Quinn to advertise, never a revocation.
    pub(crate) fn grow(&mut self, rtt: Duration, now: Instant) -> Option<u32> {
        let consumed = self.consumed.load(Ordering::Relaxed);
        let delta = consumed.saturating_sub(self.epoch_consumed);
        if delta < u64::from(self.window / 2) {
            return None;
        }
        let elapsed = now.saturating_duration_since(self.epoch);
        self.epoch = now;
        self.epoch_consumed = consumed;
        let desired = self.window.saturating_mul(2).min(self.maximum);
        // Compare rates rather than the timer interval: consuming several
        // windows between 50ms samples is still demand on a 10ms-RTT path.
        let delivered = u128::from(delta).saturating_mul(
            rtt.max(Duration::from_millis(1))
                .as_nanos()
                .saturating_mul(2),
        );
        let threshold = u128::from(self.window / 2).saturating_mul(elapsed.as_nanos());
        if desired <= self.window
            || delivered < threshold
            || !self.lease.grow_to(self.fixed_bytes + desired as usize)
        {
            return None;
        }
        self.window = desired;
        Some(desired)
    }
}

/// Read-side ownership can outlive the controller and connection handle.
#[derive(Clone)]
pub(crate) struct QuicReadOwner {
    consumed: Arc<AtomicU64>,
    lease: BudgetLease,
}

impl QuicReadOwner {
    pub(crate) fn reader<R>(&self, inner: R) -> QuicRead<R> {
        QuicRead {
            inner,
            consumed: self.consumed.clone(),
            _lease: self.lease.clone(),
        }
    }
}

pub(crate) async fn control_receive_window(mut budget: QuicBudget, connection: quinn::Connection) {
    budget.start_sampling();
    let mut timer = tokio::time::interval(Duration::from_millis(50));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = connection.closed() => return,
            _ = timer.tick() => {
                if let Some(window) = budget.grow(connection.rtt(), Instant::now()) {
                    connection.set_receive_window(window.into());
                }
            }
        }
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
            observation: None,
        }
    }

    #[tokio::test]
    async fn consumption_growth_stops_at_budget_and_retained_reader_owns_credit() {
        let group = group(32, 64);
        let mut budget = QuicBudget::new(&group).unwrap();
        let mut reader = budget.reader(std::io::Cursor::new(vec![0x42; 16 * 1024 * 1024]));
        let mut buffer = vec![0; 2 * 1024 * 1024];
        let rtt = Duration::from_secs(1);
        assert_eq!(budget.grow(rtt, Instant::now()), None, "idle is not demand");
        reader.read_exact(&mut buffer).await.unwrap();
        assert!(buffer.iter().all(|byte| *byte == 0x42));
        assert_eq!(budget.grow(rtt, Instant::now()), Some(8 * 1024 * 1024));
        for _ in 0..2 {
            reader.read_exact(&mut buffer).await.unwrap();
        }
        assert_eq!(budget.grow(rtt, Instant::now()), Some(16 * 1024 * 1024));
        for _ in 0..4 {
            reader.read_exact(&mut buffer).await.unwrap();
        }
        assert_eq!(
            budget.grow(rtt, Instant::now()),
            None,
            "unfunded growth refused"
        );
        assert_eq!(budget.window, 16 * 1024 * 1024);
        let committed = group.resources.pool.committed();
        assert_eq!(committed, budget.fixed_bytes + 16 * 1024 * 1024);
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
        budget
            .consumed
            .store(u64::from(budget.window), Ordering::Relaxed);
        assert_eq!(
            budget.grow(
                Duration::from_millis(10),
                budget.epoch + Duration::from_secs(1)
            ),
            None
        );
        assert_eq!(budget.window, 4 * 1024 * 1024);
    }

    #[test]
    fn low_rtt_growth_uses_consumption_rate_across_timer_ticks() {
        let group = group(512, 64);
        let mut budget = QuicBudget::new(&group).unwrap();
        let mut now = budget.epoch;
        let mut consumed = 0;
        for expected in [30, 60, 64] {
            consumed += u64::from(budget.window) * 2;
            budget.consumed.store(consumed, Ordering::Relaxed);
            now += Duration::from_millis(50);
            assert_eq!(
                budget.grow(Duration::from_millis(10), now),
                Some(expected * 1024 * 1024)
            );
        }
        assert_eq!(
            budget.grow(Duration::from_millis(10), now + Duration::from_millis(50)),
            None
        );
        drop(budget);
        assert_eq!(group.resources.pool.committed(), 0);
        let mut slow = QuicBudget::new(&group).unwrap();
        let original = slow.window;
        slow.consumed
            .store(u64::from(original / 2), Ordering::Relaxed);
        assert_eq!(
            slow.grow(
                Duration::from_millis(10),
                slow.epoch + Duration::from_millis(50)
            ),
            None
        );
        assert_eq!(slow.window, original);
    }
}
