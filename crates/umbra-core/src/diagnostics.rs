//! Opt-in anonymous pipeline observations; counters do not control transport.

use std::{
    collections::{BTreeMap, VecDeque},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, Weak,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Authenticated outer mode, with no address or user-provided label.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Mode {
    /// TCP multiplexed sessions, including stream-zero UDP associations.
    TcpMux,
    /// TCP Vision wrapped/raw forwarding.
    TcpVision,
    /// Native QUIC streams and UDP associations.
    Quic,
}

/// Progress at one I/O boundary; bytes are not remote application acknowledgments.
#[derive(Debug, Clone, Default)]
pub struct IoSnapshot {
    /// Bytes returned by the corresponding read/write interface.
    pub bytes: u64,
    /// Polls reporting Pending, or nonblocking UDP sends reporting WouldBlock.
    pub pending_polls: u64,
    /// Observed wait across owned I/O polling; unavailable for raw UDP callbacks.
    pub observed_wait: Option<Duration>,
}

/// Last sampled flow-control state; absent fields are unavailable, not zero.
#[derive(Debug, Clone, Default)]
pub struct CreditSnapshot {
    /// QUIC retained ingress storage and saturation observations, when available.
    pub quic_ingress: Option<IngressSnapshot>,
    /// Funded aggregate receive window in bytes.
    pub receive_window: u64,
    /// DATA received but not consumed, when available.
    pub buffered_receive: Option<u64>,
    /// Bytes consumed at the observed receive boundary.
    pub consumed: Option<u64>,
    /// Current connection send credit, when available.
    pub send_credit: Option<u64>,
    /// Serialized output retained by mux, including its current partial frame.
    pub queued_output: Option<usize>,
    /// Mux send attempts blocked by flow credit, not distinct stalls.
    pub mux_credit_waits: Option<u64>,
    /// QUIC DATA_BLOCKED plus STREAM_DATA_BLOCKED frames transmitted (may repeat).
    pub quic_blocked_tx: Option<u64>,
    /// The corresponding QUIC blocked frames reported by the peer.
    pub quic_blocked_rx: Option<u64>,
    /// Measured or bootstrap round-trip observation.
    pub rtt: Option<Duration>,
}

/// Anonymous QUIC input-queue memory and refusal observations.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct IngressSnapshot {
    /// Allocated batch storage retained by queues or packet views.
    pub retained_bytes: usize,
    /// Largest observed retained allocation total.
    pub peak_bytes: usize,
    /// Datagrams refused because byte or batch capacity was full.
    pub dropped_datagrams: u64,
    /// Payload bytes in refused datagrams.
    pub dropped_bytes: u64,
}

/// Snapshot of one observed outer; no target, peer, credential or session bytes.
#[derive(Debug, Clone)]
pub struct FlowSnapshot {
    /// Monotone local observation number, unrelated to protocol identifiers.
    pub id: u64,
    /// Canonical credential-group index.
    pub group: usize,
    /// Selected outer mode.
    pub mode: Mode,
    /// True after the final observation owner drops.
    pub closed: bool,
    /// Time since observation registration.
    pub elapsed: Duration,
    /// Client-to-server transport bytes, including protocol overhead.
    pub transport_read: IoSnapshot,
    /// Server-to-client transport bytes, including protocol overhead.
    pub transport_write: IoSnapshot,
    /// Business bytes read from targets; may still be buffered for clients.
    pub target_read: IoSnapshot,
    /// Business bytes accepted by target writes.
    pub target_write: IoSnapshot,
    /// Target setup attempts observed, including failures and cancellations.
    pub target_setup_attempts: u64,
    /// Observed DNS/connect setup time, summed across logical targets.
    pub target_setup_time: Duration,
    /// Last sampled credit state, if the selected mode exposes it.
    pub credit: Option<CreditSnapshot>,
    /// Time since the last credit sample; None when no sample is available.
    pub credit_sample_age: Option<Duration>,
}

/// Process observations, including enforceable budgets even when collection is off.
#[derive(Debug, Clone)]
pub struct PerformanceSnapshot {
    /// Active observations and at most 128 most recently closed observations.
    pub flows: Vec<FlowSnapshot>,
    /// Committed receive/storage capacity and refusal counters.
    pub budget: umbra_inner::budget::BudgetSnapshot,
    /// Ready-task processing observations.
    pub scheduling: Vec<crate::resources::WorkGroupSnapshot>,
}

#[derive(Default)]
struct Counter {
    bytes: AtomicU64,
    pending: AtomicU64,
    nanos: AtomicU64,
    clocked: AtomicBool,
}

fn add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(old.saturating_add(value))
    });
}

impl Counter {
    fn snapshot(&self) -> IoSnapshot {
        IoSnapshot {
            bytes: self.bytes.load(Ordering::Relaxed),
            pending_polls: self.pending.load(Ordering::Relaxed),
            observed_wait: self
                .clocked
                .load(Ordering::Relaxed)
                .then(|| Duration::from_nanos(self.nanos.load(Ordering::Relaxed))),
        }
    }
}

#[derive(Default)]
struct Registry {
    next: u64,
    active: BTreeMap<u64, Weak<Counters>>,
    closed: VecDeque<FlowSnapshot>,
}

#[derive(Clone)]
pub(crate) struct Diagnostics(Option<Arc<Mutex<Registry>>>);

impl Diagnostics {
    pub(crate) fn new(enabled: bool) -> Self {
        Self(enabled.then(|| Arc::new(Mutex::new(Registry::default()))))
    }

    pub(crate) fn register(&self, group: usize, mode: Mode) -> Option<Observation> {
        let owner = self.0.as_ref()?;
        let mut registry = owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let id = registry.next;
        registry.next = id.checked_add(1)?;
        let counters = Arc::new(Counters {
            owner: Arc::downgrade(owner),
            id,
            group,
            mode,
            started: Instant::now(),
            io: std::array::from_fn(|_| Counter::default()),
            credit: Mutex::new(None),
            setups: AtomicU64::new(0),
            setup_nanos: AtomicU64::new(0),
        });
        registry.active.insert(id, Arc::downgrade(&counters));
        Some(Observation(counters))
    }

    pub(crate) fn snapshot(&self) -> Vec<FlowSnapshot> {
        let Some(owner) = &self.0 else {
            return Vec::new();
        };
        let (active, mut snapshots) = {
            let registry = owner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                registry
                    .active
                    .values()
                    .filter_map(Weak::upgrade)
                    .collect::<Vec<_>>(),
                registry.closed.iter().cloned().collect::<Vec<_>>(),
            )
        };
        // Never drop the last observation while holding its registry mutex.
        snapshots.extend(active.iter().map(|counters| counters.snapshot(false)));
        snapshots
    }
}

struct Counters {
    owner: Weak<Mutex<Registry>>,
    id: u64,
    group: usize,
    mode: Mode,
    started: Instant,
    io: [Counter; 4],
    credit: Mutex<Option<(Instant, CreditSnapshot)>>,
    setups: AtomicU64,
    setup_nanos: AtomicU64,
}

impl Counters {
    fn snapshot(&self, closed: bool) -> FlowSnapshot {
        let credit = self
            .credit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        FlowSnapshot {
            id: self.id,
            group: self.group,
            mode: self.mode,
            closed,
            elapsed: self.started.elapsed(),
            transport_read: self.io[0].snapshot(),
            transport_write: self.io[1].snapshot(),
            target_read: self.io[2].snapshot(),
            target_write: self.io[3].snapshot(),
            credit: credit.as_ref().map(|(_, snapshot)| snapshot.clone()),
            credit_sample_age: credit.as_ref().map(|(at, _)| at.elapsed()),
            target_setup_attempts: self.setups.load(Ordering::Relaxed),
            target_setup_time: Duration::from_nanos(self.setup_nanos.load(Ordering::Relaxed)),
        }
    }
}

impl Drop for Counters {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.upgrade() {
            let mut registry = owner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry.active.remove(&self.id);
            if registry.closed.len() == 128 {
                registry.closed.pop_front();
            }
            registry.closed.push_back(self.snapshot(true));
        }
    }
}

#[derive(Clone)]
pub(crate) struct Observation(Arc<Counters>);

#[derive(Clone, Copy)]
pub(crate) enum Point {
    TransportRead = 0,
    TransportWrite = 1,
    TargetRead = 2,
    TargetWrite = 3,
}

impl Observation {
    pub(crate) fn record(&self, point: Point, bytes: usize, pending: bool) {
        let counter = &self.0.io[point as usize];
        add(&counter.bytes, u64::try_from(bytes).unwrap_or(u64::MAX));
        if pending {
            add(&counter.pending, 1);
        }
    }

    pub(crate) fn credit(&self, credit: CreditSnapshot) {
        *self
            .0
            .credit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((Instant::now(), credit));
    }
}

pub(crate) struct Waiter {
    observation: Option<Observation>,
    point: Point,
    since: Option<Instant>,
}

impl Waiter {
    pub(crate) fn new(observation: Option<Observation>, point: Point) -> Self {
        if let Some(observation) = &observation {
            observation.0.io[point as usize]
                .clocked
                .store(true, Ordering::Relaxed);
        }
        Self {
            observation,
            point,
            since: None,
        }
    }

    pub(crate) fn record(&mut self, bytes: usize, pending: bool) {
        let Some(observation) = &self.observation else {
            return;
        };
        observation.record(self.point, bytes, pending);
        if pending {
            self.since.get_or_insert_with(Instant::now);
        } else {
            self.finish();
        }
    }

    fn finish(&mut self) {
        if let (Some(observation), Some(since)) = (&self.observation, self.since.take()) {
            add(
                &observation.0.io[self.point as usize].nanos,
                u64::try_from(since.elapsed().as_nanos()).unwrap_or(u64::MAX),
            );
        }
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        self.finish();
    }
}

pub(crate) struct SetupWait(Option<(Observation, Instant)>);
impl SetupWait {
    pub(crate) fn new(observation: Option<Observation>) -> Self {
        Self(observation.map(|observation| {
            add(&observation.0.setups, 1);
            (observation, Instant::now())
        }))
    }
}
impl Drop for SetupWait {
    fn drop(&mut self) {
        if let Some((observation, started)) = &self.0 {
            add(
                &observation.0.setup_nanos,
                u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
            );
        }
    }
}

pub(crate) async fn connecting<F: std::future::Future>(
    observation: Option<Observation>,
    future: F,
) -> F::Output {
    let _setup = SetupWait::new(observation);
    future.await
}

pub(crate) struct ObservedIo<IO> {
    inner: IO,
    read: Waiter,
    write: Waiter,
}

impl<IO> ObservedIo<IO> {
    pub(crate) fn new(inner: IO, observation: Option<Observation>, target: bool) -> Self {
        let (read, write) = if target {
            (Point::TargetRead, Point::TargetWrite)
        } else {
            (Point::TransportRead, Point::TransportWrite)
        };
        Self {
            inner,
            read: Waiter::new(observation.clone(), read),
            write: Waiter::new(observation, write),
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for ObservedIo<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        self.read
            .record(buffer.filled().len() - before, result.is_pending());
        result
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for ObservedIo<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        self.write.record(
            if let Poll::Ready(Ok(n)) = &result {
                *n
            } else {
                0
            },
            result.is_pending(),
        );
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        self.write.record(0, result.is_pending());
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.write.record(0, result.is_pending());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{poll_fn, Future};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn partial_io_waits_and_last_owner_produce_a_closed_snapshot() {
        let diagnostics = Diagnostics::new(true);
        let observation = diagnostics.register(7, Mode::TcpVision).unwrap();
        let (io, mut peer) = tokio::io::duplex(4);
        let mut io = ObservedIo::new(io, Some(observation.clone()), false);
        let mut bytes = [0; 2];
        {
            let mut reading = std::pin::pin!(io.read_exact(&mut bytes));
            poll_fn(|cx| {
                assert!(reading.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        peer.write_all(b"xy").await.unwrap();
        io.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"xy");
        assert_eq!(io.write(b"abcdef").await.unwrap(), 4);
        {
            let mut writing = std::pin::pin!(io.write(b"e"));
            poll_fn(|cx| {
                assert!(writing.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        let mut drained = [0; 4];
        peer.read_exact(&mut drained).await.unwrap();
        assert_eq!(&drained, b"abcd");
        io.write_all(b"e").await.unwrap();
        io.flush().await.unwrap();
        io.shutdown().await.unwrap();
        let mut target = ObservedIo::new(
            std::io::Cursor::new(vec![0x42; 3]),
            Some(observation.clone()),
            true,
        );
        let mut input = Vec::new();
        target.read_to_end(&mut input).await.unwrap();
        assert_eq!(input, [0x42; 3]);
        target.write_all(b"1234").await.unwrap();
        connecting(Some(observation.clone()), async {}).await;
        drop(target);
        drop(observation);
        assert!(!diagnostics.snapshot()[0].closed);
        drop(io);
        let snapshot = diagnostics.snapshot().pop().unwrap();
        assert!(snapshot.closed);
        assert_eq!(snapshot.group, 7);
        assert_eq!(snapshot.mode, Mode::TcpVision);
        assert_eq!(snapshot.transport_read.bytes, 2);
        assert_eq!(snapshot.transport_write.bytes, 5);
        assert!(
            snapshot.transport_read.pending_polls > 0 && snapshot.transport_write.pending_polls > 0
        );
        assert!(snapshot.transport_read.observed_wait.is_some());
        assert_eq!(snapshot.target_read.bytes, 3);
        assert_eq!(snapshot.target_write.bytes, 4);
        assert_eq!(snapshot.target_setup_attempts, 1);
    }

    #[test]
    fn disabled_collection_bounded_history_and_unavailable_udp_wait_clock() {
        let disabled = Diagnostics::new(false);
        assert!(disabled.register(0, Mode::Quic).is_none());
        assert!(disabled.snapshot().is_empty());
        let diagnostics = Diagnostics::new(true);
        for _ in 0..200 {
            drop(diagnostics.register(0, Mode::TcpMux).unwrap());
        }
        let history = diagnostics.snapshot();
        assert_eq!(history.len(), 128);
        assert_eq!(history[0].id, 72);
        let observation = diagnostics.register(1, Mode::Quic).unwrap();
        observation.record(Point::TransportRead, 1200, true);
        observation.credit(CreditSnapshot {
            receive_window: 2_500_000,
            quic_blocked_rx: Some(3),
            ..CreditSnapshot::default()
        });
        let snapshot = diagnostics.snapshot().pop().unwrap();
        assert_eq!(snapshot.transport_read.bytes, 1200);
        assert_eq!(snapshot.transport_read.pending_polls, 1);
        assert!(snapshot.transport_read.observed_wait.is_none());
        assert_eq!(snapshot.credit.unwrap().quic_blocked_rx, Some(3));
        assert!(snapshot.credit_sample_age.is_some());
        drop(observation);
        assert_eq!(diagnostics.snapshot().len(), 128);
    }
}
