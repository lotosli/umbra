//! Credential-group scheduling at authenticated Tokio task boundaries.

use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex, Weak,
    },
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant},
};

const QUEUED: u8 = 1;
const GRANTED: u8 = 2;
const RUNNING: u8 = 4;
const AGAIN: u8 = 8;
const CLOSED: u8 = 16;

/// Non-secret scheduler observations for one canonical credential group.
#[derive(Clone, Debug, Default)]
pub struct WorkGroupSnapshot {
    /// Opaque configuration-group index, not a credential or source address.
    pub group: usize,
    /// Currently owned authenticated task gates.
    pub tasks: usize,
    /// Ready tasks awaiting a processing permit.
    pub queued: usize,
    /// Granted or executing synchronous polls, excluding pending network I/O.
    pub active: usize,
    /// Completed cooperative task polls, not packets or payload bytes.
    pub polls: u64,
    /// Total queue wait across task polls.
    pub queue_time: Duration,
    /// Wall time inside task polls; this is not a process CPU measurement.
    pub poll_time: Duration,
}

#[derive(Clone)]
pub(crate) struct Scheduler(Arc<Inner>);

struct Inner {
    state: Mutex<State>,
}

struct State {
    limit: usize,
    available: usize,
    order: VecDeque<usize>,
    ready: BTreeMap<usize, VecDeque<(Weak<Gate>, Instant)>>,
    stats: BTreeMap<usize, WorkGroupSnapshot>,
}

impl State {
    fn grant(&mut self) -> Option<Arc<Gate>> {
        if self.available == 0 {
            return None;
        }
        while let Some(group) = self.order.pop_front() {
            let queue = self.ready.get_mut(&group)?;
            let entry = queue.pop_front();
            if !queue.is_empty() {
                self.order.push_back(group);
            }
            let Some((gate, since)) = entry else { continue };
            let Some(gate) = gate.upgrade() else { continue };
            if gate
                .state
                .compare_exchange(QUEUED, GRANTED, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            self.available -= 1;
            let stats = self.stats.entry(group).or_default();
            stats.active += 1;
            stats.queue_time = stats.queue_time.saturating_add(since.elapsed());
            return Some(gate);
        }
        None
    }

    fn release(&mut self, group: usize, elapsed: Option<Duration>) {
        self.available = self.available.saturating_add(1).min(self.limit);
        let stats = self.stats.entry(group).or_default();
        stats.active = stats.active.saturating_sub(1);
        if let Some(elapsed) = elapsed {
            stats.polls = stats.polls.saturating_add(1);
            stats.poll_time = stats.poll_time.saturating_add(elapsed);
        }
    }
}

impl Scheduler {
    pub(crate) fn new() -> Self {
        let workers = tokio::runtime::Handle::try_current()
            .map_or(1, |handle| handle.metrics().num_workers());
        Self::with_capacity(workers)
    }

    fn with_capacity(limit: usize) -> Self {
        Self(Arc::new(Inner {
            state: Mutex::new(State {
                limit: limit.max(1),
                available: limit.max(1),
                order: VecDeque::new(),
                ready: BTreeMap::new(),
                stats: BTreeMap::new(),
            }),
        }))
    }

    pub(crate) fn group(&self, id: usize) -> WorkGroup {
        WorkGroup {
            scheduler: self.clone(),
            id,
        }
    }

    pub(crate) fn snapshot(&self) -> Vec<WorkGroupSnapshot> {
        let state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .stats
            .iter()
            .map(|(&group, counters)| {
                let mut counters = counters.clone();
                counters.group = group;
                counters.queued = state.ready.get(&group).map_or(0, VecDeque::len);
                counters
            })
            .collect()
    }
}

#[derive(Clone)]
pub(crate) struct WorkGroup {
    scheduler: Scheduler,
    id: usize,
}

impl WorkGroup {
    /// Wrap exactly once at a Tokio task boundary; never nest inside another gate.
    pub(crate) fn wrap<F: Future>(&self, future: F) -> Scheduled<F> {
        self.scheduler
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stats
            .entry(self.id)
            .or_default()
            .tasks += 1;
        Scheduled {
            future: Box::pin(future),
            gate: Arc::new(Gate {
                group: self.id,
                owner: Arc::downgrade(&self.scheduler.0),
                state: AtomicU8::new(0),
                parent: Mutex::new(None),
            }),
            started: false,
            _owner: self.scheduler.clone(),
        }
    }

    pub(crate) fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        tokio::spawn(self.wrap(future))
    }
}

pub(crate) fn spawn<F>(group: Option<&WorkGroup>, future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    match group {
        Some(group) => group.spawn(future),
        None => tokio::spawn(future),
    }
}

struct Gate {
    group: usize,
    owner: Weak<Inner>,
    state: AtomicU8,
    parent: Mutex<Option<Waker>>,
}

impl Gate {
    fn wake_parent(&self) {
        let parent = self
            .parent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(parent) = parent {
            parent.wake();
        }
    }

    fn request(self: &Arc<Self>, wake_current: bool) {
        loop {
            let state = self.state.load(Ordering::Acquire);
            if state & (CLOSED | QUEUED | GRANTED) != 0 {
                return;
            }
            let next = if state & RUNNING != 0 {
                state | AGAIN
            } else {
                QUEUED
            };
            if self
                .state
                .compare_exchange(state, next, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            if next != QUEUED {
                return;
            }
            break;
        }
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        let granted = {
            let mut state = owner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.state.load(Ordering::Acquire) != QUEUED {
                return;
            }
            if state.ready.get(&self.group).is_none_or(VecDeque::is_empty) {
                state.order.push_back(self.group);
            }
            state
                .ready
                .entry(self.group)
                .or_default()
                .push_back((Arc::downgrade(self), Instant::now()));
            state.grant()
        };
        if let Some(granted) = granted {
            if wake_current || !Arc::ptr_eq(self, &granted) {
                granted.wake_parent();
            }
        }
    }

    fn pending(self: &Arc<Self>, elapsed: Duration) {
        // Preserve a self-wake before granting the next permit. Re-enqueueing
        // afterward would give an already queued multi-task group two turns
        // for each turn of a continuously ready single-task group.
        let next = loop {
            let previous = self.state.load(Ordering::Acquire);
            let next = if previous & AGAIN != 0 { QUEUED } else { 0 };
            if self
                .state
                .compare_exchange(previous, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break next;
            }
        };
        if let Some(owner) = self.owner.upgrade() {
            let granted = {
                let mut state = owner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if next == QUEUED {
                    if state.ready.get(&self.group).is_none_or(VecDeque::is_empty) {
                        state.order.push_back(self.group);
                    }
                    state
                        .ready
                        .entry(self.group)
                        .or_default()
                        .push_back((Arc::downgrade(self), Instant::now()));
                }
                state.release(self.group, Some(elapsed));
                state.grant()
            };
            if let Some(granted) = granted {
                granted.wake_parent();
            }
        }
    }

    fn close(&self, elapsed: Option<Duration>) {
        let previous = self.state.swap(CLOSED, Ordering::AcqRel);
        if previous == CLOSED {
            return;
        }
        self.parent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        let granted = {
            let mut state = owner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if previous & (GRANTED | RUNNING) != 0 {
                state.release(self.group, elapsed);
            }
            if let Some(queue) = state.ready.get_mut(&self.group) {
                queue.retain(|(gate, _)| gate.as_ptr() != std::ptr::from_ref(self));
                if queue.is_empty() {
                    state.order.retain(|group| *group != self.group);
                }
            }
            let counters = state.stats.entry(self.group).or_default();
            counters.tasks = counters.tasks.saturating_sub(1);
            if counters.tasks == 0 {
                state.ready.remove(&self.group);
            }
            state.grant()
        };
        if let Some(granted) = granted {
            granted.wake_parent();
        }
    }
}

impl Wake for Gate {
    fn wake(self: Arc<Self>) {
        self.request(true);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.request(true);
    }
}

/// The original Tokio task continues to own, cancel and drop the actual future.
pub(crate) struct Scheduled<F: Future> {
    future: Pin<Box<F>>,
    gate: Arc<Gate>,
    started: bool,
    _owner: Scheduler,
}

impl<F: Future> Future for Scheduled<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        {
            let mut parent = this
                .gate
                .parent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if parent
                .as_ref()
                .is_none_or(|parent| !parent.will_wake(cx.waker()))
            {
                *parent = Some(cx.waker().clone());
            }
        }
        if !this.started {
            this.started = true;
            this.gate.request(false);
        }
        if this
            .gate
            .state
            .compare_exchange(GRANTED, RUNNING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Poll::Pending;
        }
        let waker = Waker::from(this.gate.clone());
        let started = Instant::now();
        let result = this.future.as_mut().poll(&mut Context::from_waker(&waker));
        if result.is_ready() {
            this.gate.close(Some(started.elapsed()));
        } else {
            this.gate.pending(started.elapsed());
        }
        result
    }
}

impl<F: Future> Drop for Scheduled<F> {
    fn drop(&mut self) {
        self.gate.close(None);
    }
}

/// Apply the group gate to Quinn-owned driver tasks without replacing its I/O.
pub(crate) struct GroupRuntime {
    pub(crate) inner: Arc<dyn quinn::Runtime>,
    pub(crate) group: WorkGroup,
}

impl std::fmt::Debug for GroupRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GroupRuntime")
    }
}

impl quinn::Runtime for GroupRuntime {
    fn new_timer(&self, at: Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        self.inner.new_timer(at)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.inner.spawn(Box::pin(self.group.wrap(future)));
    }
    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        self.inner.wrap_udp_socket(socket)
    }
    fn now(&self) -> Instant {
        self.inner.now()
    }
}

#[cfg(test)]
mod tests {
    use super::{Scheduler, WorkGroup};
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        task::Poll,
    };

    async fn ready_work(group: usize, counts: Arc<[AtomicUsize; 2]>, remaining: Arc<AtomicUsize>) {
        std::future::poll_fn(move |cx| {
            if remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_err()
            {
                return Poll::Ready(());
            }
            counts[group].fetch_add(1, Ordering::Relaxed);
            cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await;
    }

    #[tokio::test]
    async fn baseline_ready_tasks_are_scheduled_without_group_identity() {
        let counts = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let remaining = Arc::new(AtomicUsize::new(90_000));
        let mut tasks = tokio::task::JoinSet::new();
        for task in 0..9 {
            tasks.spawn(ready_work(
                usize::from(task == 8),
                counts.clone(),
                remaining.clone(),
            ));
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        let first = counts[0].load(Ordering::Relaxed);
        let second = counts[1].load(Ordering::Relaxed);
        assert_eq!(first + second, 90_000);
        assert!(first > 0 && second > 0);
        println!(
            "baseline_ready_polls group_with_eight_tasks={first} group_with_one_task={second}"
        );
    }

    #[tokio::test]
    async fn ready_groups_share_opportunities_despite_unequal_task_counts() {
        let scheduler = Scheduler::with_capacity(1);
        let counts = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let remaining = Arc::new(AtomicUsize::new(90_000));
        let mut tasks = tokio::task::JoinSet::new();
        for task in 0..9 {
            let group = usize::from(task == 8);
            tasks.spawn(scheduler.group(group).wrap(ready_work(
                group,
                counts.clone(),
                remaining.clone(),
            )));
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        })
        .await
        .unwrap();
        let first = counts[0].load(Ordering::Relaxed);
        let second = counts[1].load(Ordering::Relaxed);
        assert_eq!(first + second, 90_000);
        assert!(
            first.abs_diff(second) <= 16,
            "group opportunities: {first} vs {second}"
        );
        assert!(scheduler
            .snapshot()
            .iter()
            .all(|s| s.tasks == 0 && s.queued == 0 && s.active == 0));
        println!(
            "scheduled_ready_polls group_with_eight_tasks={first} group_with_one_task={second}"
        );
    }

    fn busy(group: &WorkGroup) -> super::Scheduled<impl std::future::Future<Output = ()>> {
        group.wrap(std::future::poll_fn(|cx| {
            cx.waker().wake_by_ref();
            Poll::Pending
        }))
    }

    #[test]
    fn cancellation_and_blocked_io_return_capacity_and_remove_queued_work() {
        use std::{
            future::Future,
            pin::Pin,
            task::{Context, Waker},
        };
        let scheduler = Scheduler::with_capacity(1);
        let mut cx = Context::from_waker(Waker::noop());
        let mut active = busy(&scheduler.group(0));
        assert!(Pin::new(&mut active).poll(&mut cx).is_pending());
        let mut cancelled = busy(&scheduler.group(1));
        assert!(Pin::new(&mut cancelled).poll(&mut cx).is_pending());
        let mut slow = scheduler.group(2).wrap(std::future::pending::<()>());
        assert!(Pin::new(&mut slow).poll(&mut cx).is_pending());
        assert_eq!(
            scheduler.snapshot().iter().map(|s| s.queued).sum::<usize>(),
            2
        );
        drop(cancelled);
        assert_eq!(
            scheduler.snapshot().iter().map(|s| s.queued).sum::<usize>(),
            1
        );
        drop(active);
        assert!(Pin::new(&mut slow).poll(&mut cx).is_pending());
        assert_eq!(
            scheduler.snapshot().iter().map(|s| s.active).sum::<usize>(),
            0
        );
        let mut progress = scheduler.group(3).wrap(std::future::ready(7));
        assert_eq!(Pin::new(&mut progress).poll(&mut cx), Poll::Ready(7));
        drop(slow);
        assert!(scheduler
            .snapshot()
            .iter()
            .all(|s| s.tasks == 0 && s.queued == 0 && s.active == 0));
    }

    #[test]
    fn lone_group_can_borrow_every_parallel_permit() {
        use std::{
            future::Future,
            pin::Pin,
            task::{Context, Waker},
        };
        let scheduler = Scheduler::with_capacity(4);
        let mut cx = Context::from_waker(Waker::noop());
        let mut tasks = (0..4)
            .map(|_| busy(&scheduler.group(0)))
            .collect::<Vec<_>>();
        for task in &mut tasks {
            assert!(Pin::new(task).poll(&mut cx).is_pending());
        }
        assert_eq!(scheduler.snapshot()[0].active, 4);
        drop(tasks);
        assert_eq!(scheduler.snapshot()[0].active, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_wakes_coalesce_without_losing_permits() {
        let scheduler = Scheduler::with_capacity(2);
        let counts = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let remaining = Arc::new(AtomicUsize::new(20_000));
        let mut gates = Vec::new();
        let mut tasks = tokio::task::JoinSet::new();
        for task in 0..16 {
            let future = scheduler.group(task % 2).wrap(ready_work(
                task % 2,
                counts.clone(),
                remaining.clone(),
            ));
            gates.push(future.gate.clone());
            tasks.spawn(future);
        }
        let waking = tokio::spawn(async move {
            for _ in 0..128 {
                for gate in &gates {
                    gate.request(true);
                    gate.request(true);
                }
                tokio::task::yield_now().await;
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
            waking.await.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(
            counts[0].load(Ordering::Relaxed) + counts[1].load(Ordering::Relaxed),
            20_000
        );
        assert!(scheduler
            .snapshot()
            .iter()
            .all(|s| s.tasks == 0 && s.queued == 0 && s.active == 0));
        assert_eq!(scheduler.0.state.lock().unwrap().available, 2);
    }

    async fn record_work() {
        let plaintext = vec![0x5a; 16 * 1024];
        for record in 0_u64..4096 {
            let mut nonce = [0; 12];
            nonce[4..].copy_from_slice(&record.to_be_bytes());
            let ciphertext = umbra_crypto::aead::seal(
                umbra_crypto::aead::AeadAlgorithm::Aes128Gcm,
                &[0x42; 16],
                &nonce,
                &plaintext,
                b"record-diagnostic",
            )
            .unwrap();
            assert_eq!(ciphertext.len(), plaintext.len() + 16);
            std::hint::black_box(ciphertext);
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    #[ignore = "explicit release-mode scheduler/record-cost diagnostic, not a timing gate"]
    async fn measure_record_work_with_and_without_group_gate() {
        for gated in [false, true] {
            let scheduler = Scheduler::with_capacity(1);
            let started = std::time::Instant::now();
            if gated {
                scheduler.group(0).wrap(record_work()).await;
            } else {
                record_work().await;
            }
            let elapsed = started.elapsed().as_secs_f64();
            println!("record_work gated={gated} records=4096 payload_bytes=67108864 elapsed_s={elapsed:.6} payload_mbps={:.3}", 67_108_864.0 * 8.0 / elapsed / 1_000_000.0);
        }
    }
}
