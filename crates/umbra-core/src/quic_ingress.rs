//! Byte-bounded QUIC batches with shared payload and commitment ownership.

use quinn::udp::RecvMeta;
use std::{
    collections::VecDeque,
    ops::{Deref, Range},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};
use tokio::sync::mpsc;
use umbra_inner::budget::BudgetLease;

pub(crate) const MAX_RETAINED_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_BATCH_DATAGRAMS: usize = 64;

#[derive(Default)]
pub(crate) struct Stats {
    retained: AtomicUsize,
    peak: AtomicUsize,
    dropped_datagrams: AtomicU64,
    dropped_bytes: AtomicU64,
}

impl Stats {
    pub(crate) fn snapshot(&self) -> crate::diagnostics::IngressSnapshot {
        crate::diagnostics::IngressSnapshot {
            retained_bytes: self.retained.load(Ordering::Relaxed),
            peak_bytes: self.peak.load(Ordering::Relaxed),
            dropped_datagrams: self.dropped_datagrams.load(Ordering::Relaxed),
            dropped_bytes: self.dropped_bytes.load(Ordering::Relaxed),
        }
    }

    fn refuse(&self, bytes: usize, datagrams: usize) {
        let _ = self
            .dropped_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX)))
            });
        let _ = self
            .dropped_datagrams
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(u64::try_from(datagrams).unwrap_or(u64::MAX)))
            });
    }
}

struct State {
    stats: Arc<Stats>,
    // Packet storage retains this state after the receiver and socket drop.
    lease: Mutex<Option<BudgetLease>>,
}

struct Storage {
    bytes: Vec<u8>,
    owner: Option<Arc<State>>,
    charged: usize,
}

impl Drop for Storage {
    fn drop(&mut self) {
        drop(std::mem::take(&mut self.bytes));
        if let Some(owner) = &self.owner {
            owner
                .stats
                .retained
                .fetch_sub(self.charged, Ordering::Relaxed);
        }
    }
}

/// A datagram view retains one shared batch allocation and its resource lease.
#[derive(Clone)]
pub(crate) struct Datagram {
    storage: Arc<Storage>,
    range: Range<usize>,
    pub(crate) meta: Option<RecvMeta>,
}

impl Deref for Datagram {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.storage.bytes[self.range.clone()]
    }
}

impl From<Vec<u8>> for Datagram {
    fn from(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        Self {
            storage: Arc::new(Storage {
                bytes,
                owner: None,
                charged: 0,
            }),
            range: 0..len,
            meta: None,
        }
    }
}

impl Datagram {
    pub(crate) fn received(bytes: Vec<u8>, mut meta: RecvMeta) -> Self {
        meta.len = bytes.len();
        meta.stride = meta.len;
        let mut packet = Self::from(bytes);
        packet.meta = Some(meta);
        packet
    }
}

impl core::fmt::Debug for Datagram {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Datagram")
            .field("bytes", &self.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl PartialEq<Vec<u8>> for Datagram {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &**self == other.as_slice()
    }
}

#[derive(Clone)]
pub(crate) struct Sender {
    inner: mpsc::Sender<VecDeque<Datagram>>,
    state: Arc<State>,
}

pub(crate) struct Receiver {
    inner: mpsc::Receiver<VecDeque<Datagram>>,
    pending: VecDeque<Datagram>,
    state: Arc<State>,
}

pub(crate) fn channel(batches: usize) -> (Sender, Receiver) {
    let (sender, receiver) = mpsc::channel(batches);
    let state = Arc::new(State {
        stats: Arc::new(Stats::default()),
        lease: Mutex::new(None),
    });
    (
        Sender {
            inner: sender,
            state: state.clone(),
        },
        Receiver {
            inner: receiver,
            pending: VecDeque::new(),
            state,
        },
    )
}

impl Sender {
    pub(crate) fn same_channel(&self, other: &Self) -> bool {
        self.inner.same_channel(&other.inner)
    }

    #[cfg(test)]
    pub(crate) fn try_send(
        &self,
        bytes: Vec<u8>,
    ) -> Result<(), mpsc::error::TrySendError<Vec<u8>>> {
        self.try_send_batch(bytes, None)
    }

    pub(crate) fn try_send_batch(
        &self,
        bytes: Vec<u8>,
        meta: Option<RecvMeta>,
    ) -> Result<(), mpsc::error::TrySendError<Vec<u8>>> {
        let stride = meta.map_or(bytes.len().max(1), |m| m.stride.max(1));
        let count = bytes.len().div_ceil(stride).max(1);
        let permit = match self.inner.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Closed(())) => {
                return Err(mpsc::error::TrySendError::Closed(bytes))
            }
            Err(mpsc::error::TrySendError::Full(())) => {
                self.state.stats.refuse(bytes.len(), count);
                return Err(mpsc::error::TrySendError::Full(bytes));
            }
        };
        let batch = self
            .batch(bytes, meta, count, stride)
            .map_err(mpsc::error::TrySendError::Full)?;
        permit.send(batch);
        Ok(())
    }

    fn batch(
        &self,
        bytes: Vec<u8>,
        meta: Option<RecvMeta>,
        count: usize,
        stride: usize,
    ) -> Result<VecDeque<Datagram>, Vec<u8>> {
        let charged = bytes.capacity();
        let previous = if count > MAX_BATCH_DATAGRAMS {
            None
        } else {
            self.state
                .stats
                .retained
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    n.checked_add(charged)
                        .filter(|next| *next <= MAX_RETAINED_BYTES)
                })
                .ok()
        };
        let Some(previous) = previous else {
            self.state.stats.refuse(bytes.len(), count);
            return Err(bytes);
        };
        self.state
            .stats
            .peak
            .fetch_max(previous + charged, Ordering::Relaxed);
        let length = bytes.len();
        let storage = Arc::new(Storage {
            bytes,
            owner: Some(self.state.clone()),
            charged,
        });
        let mut batch = VecDeque::with_capacity(count);
        for index in 0..count {
            let start = index * stride;
            let end = start.saturating_add(stride).min(length);
            let meta = meta.map(|mut m| {
                m.len = end - start;
                m.stride = m.len;
                m
            });
            batch.push_back(Datagram {
                storage: storage.clone(),
                range: start..end,
                meta,
            });
        }
        Ok(batch)
    }

    #[cfg(test)]
    pub(crate) async fn send(&self, bytes: Vec<u8>) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        let permit = self
            .inner
            .reserve()
            .await
            .map_err(|_| mpsc::error::SendError(bytes.clone()))?;
        let stride = bytes.len().max(1);
        let batch = self
            .batch(bytes, None, 1, stride)
            .map_err(mpsc::error::SendError)?;
        permit.send(batch);
        Ok(())
    }
}

impl Receiver {
    pub(crate) fn stats(&self) -> Arc<Stats> {
        self.state.stats.clone()
    }

    pub(crate) fn retain_lease(&self, lease: BudgetLease) {
        *self
            .state
            .lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(lease);
    }

    pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Datagram>> {
        if let Some(packet) = self.pending.pop_front() {
            return Poll::Ready(Some(packet));
        }
        match self.inner.poll_recv(cx) {
            Poll::Ready(Some(batch)) => {
                self.pending = batch;
                Poll::Ready(self.pending.pop_front())
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    pub(crate) async fn recv(&mut self) -> Option<Datagram> {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn gro_burst_and_last_packet_retain_one_allocation_and_lease() {
        let pool = umbra_inner::budget::BudgetPool::new(2 * MAX_RETAINED_BYTES, MAX_RETAINED_BYTES)
            .unwrap();
        let (tx, mut rx) = channel(64);
        rx.retain_lease(pool.reserve(0, MAX_RETAINED_BYTES).unwrap());
        let stats = rx.stats();
        let bytes: Vec<u8> = (0..48).flat_map(|i| vec![i; 1200]).collect();
        let meta = RecvMeta {
            addr: "127.0.0.1:443".parse().unwrap(),
            len: bytes.len(),
            stride: 1200,
            ecn: Some(quinn::udp::EcnCodepoint::Ce),
            dst_ip: Some("127.0.0.2".parse().unwrap()),
        };
        tx.try_send_batch(bytes, Some(meta)).unwrap();
        let first = rx.recv().await.unwrap();
        for expected in 1..48 {
            let packet = rx.recv().await.unwrap();
            assert!(Arc::ptr_eq(&first.storage, &packet.storage));
            assert_eq!(&*packet, vec![expected; 1200]);
            let received = packet.meta.unwrap();
            assert_eq!(
                (
                    received.addr,
                    received.len,
                    received.stride,
                    received.ecn,
                    received.dst_ip
                ),
                (meta.addr, 1200, 1200, meta.ecn, meta.dst_ip)
            );
        }
        assert_eq!(&*first, vec![0; 1200]);
        assert_eq!(stats.snapshot().dropped_datagrams, 0);
        assert!(stats.snapshot().retained_bytes >= 48 * 1200);
        drop((tx, rx));
        assert_eq!(pool.committed(), MAX_RETAINED_BYTES);
        drop(first);
        assert_eq!(stats.snapshot().retained_bytes, 0);
        assert_eq!(pool.committed(), 0);
    }

    #[tokio::test]
    async fn saturation_is_observable_and_does_not_block_healthy_flow() {
        let (full, mut retained) = channel(64);
        let stats = retained.stats();
        full.try_send(vec![0; MAX_RETAINED_BYTES]).unwrap();
        assert!(full.try_send(vec![1; 1200]).is_err());
        let (healthy, mut rx) = channel(1);
        healthy.try_send(vec![2; 1200]).unwrap();
        assert_eq!(rx.recv().await.unwrap(), vec![2; 1200]);
        assert_eq!(stats.snapshot().dropped_datagrams, 1);
        assert_eq!(stats.snapshot().dropped_bytes, 1200);
        assert_eq!(stats.snapshot().peak_bytes, MAX_RETAINED_BYTES);
        let last = retained.recv().await.unwrap();
        drop((full, retained));
        assert_eq!(stats.snapshot().retained_bytes, MAX_RETAINED_BYTES);
        drop(last);
        assert_eq!(stats.snapshot().retained_bytes, 0);
        drop(rx);
        assert!(matches!(
            healthy.try_send(Vec::new()),
            Err(mpsc::error::TrySendError::Closed(_))
        ));
    }

    #[tokio::test]
    async fn batch_count_empty_packets_and_pending_receives_are_bounded() {
        let (tx, mut rx) = channel(1);
        let stats = rx.stats();
        let input = vec![1; 65];
        let meta = RecvMeta {
            stride: 1,
            len: input.len(),
            ..RecvMeta::default()
        };
        assert!(
            matches!(tx.try_send_batch(input.clone(), Some(meta)), Err(mpsc::error::TrySendError::Full(bytes)) if bytes == input)
        );
        assert_eq!(stats.snapshot().dropped_datagrams, 65);
        assert_eq!(stats.snapshot().retained_bytes, 0);
        tx.try_send(Vec::new()).unwrap();
        assert!(tx.try_send(vec![2]).is_err());
        assert_eq!(rx.recv().await.unwrap(), Vec::<u8>::new());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), rx.recv())
                .await
                .is_err()
        );
        tx.send(vec![3]).await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), vec![3]);
        drop(tx);
        assert!(rx.recv().await.is_none());
        assert_eq!(stats.snapshot().retained_bytes, 0);
    }

    #[tokio::test]
    #[ignore = "explicit serial release-mode per-packet versus shared-batch ingress diagnostic"]
    async fn measure_shared_batch_ingress() {
        for batched in [false, true] {
            let (tx, mut rx) = channel(64);
            let payload = vec![0xa5; 32 * 1200];
            let started = std::time::Instant::now();
            let mut delivered = 0_u64;
            for _ in 0..4096 {
                if batched {
                    tx.try_send_batch(
                        payload.clone(),
                        Some(RecvMeta {
                            len: payload.len(),
                            stride: 1200,
                            ..RecvMeta::default()
                        }),
                    )
                    .unwrap();
                } else {
                    for packet in payload.chunks(1200) {
                        tx.try_send(packet.to_vec()).unwrap();
                    }
                }
                for _ in 0..32 {
                    let packet = rx.recv().await.unwrap();
                    assert_eq!(packet.len(), 1200);
                    assert!(packet.iter().all(|byte| *byte == 0xa5));
                    delivered += 1200;
                    std::hint::black_box(&packet);
                }
            }
            assert_eq!(rx.stats().snapshot().retained_bytes, 0);
            assert_eq!(rx.stats().snapshot().dropped_datagrams, 0);
            println!(
                "quic_ingress batched={batched} bytes={delivered} seconds={:.6}",
                started.elapsed().as_secs_f64()
            );
        }
    }
}
