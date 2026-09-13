//! Bounded, staggered TCP target connection attempts across resolved addresses.
//!
//! A slow first address must not hold up every other address. TCP attempts are
//! owned by a `JoinSet`, so dropping the caller aborts them; successful connects
//! explicitly reap the remaining attempts before handing the socket to a relay.
//! DNS timeouts stop waiting for the resolver, but cannot interrupt an OS
//! `getaddrinfo` call which Tokio has already started on its blocking pool.

use std::{
    collections::{HashSet, VecDeque},
    future::Future,
    io,
    net::SocketAddr,
    time::Duration,
};

use tokio::{
    net::{lookup_host, TcpStream},
    task::{AbortHandle, Id, JoinSet},
    time::{sleep_until, timeout_at, Instant},
};

const MAX_RESOLVER_ADDRESSES: usize = 64;
const MAX_TARGET_ADDRESSES: usize = 16;
const MAX_IN_FLIGHT: usize = 4;

#[derive(Clone, Copy)]
struct ConnectPolicy {
    dns_timeout: Duration,
    total_timeout: Duration,
    attempt_timeout: Duration,
    stagger: Duration,
}

const POLICY: ConnectPolicy = ConnectPolicy {
    dns_timeout: Duration::from_secs(5),
    // Leave room for cancellation/reaping before the runtime's 15-second limit.
    total_timeout: Duration::from_secs(14),
    // When more candidates are waiting, recycle black-hole attempts in time to
    // reach them. A final batch instead retains the remaining overall budget.
    attempt_timeout: Duration::from_secs(3),
    stagger: Duration::from_millis(250),
};

/// Resolve and connect a target without serially waiting on black-hole addresses.
///
/// Errors identify DNS versus TCP failure without retaining the target, resolved
/// addresses, or resolver-specific error text. The caller may impose a shorter
/// overall deadline; cancellation aborts all in-flight TCP attempts.
pub(crate) async fn connect_tcp_target(target: String) -> io::Result<TcpStream> {
    connect_with(
        target,
        |target| async move {
            lookup_host(target)
                .await
                .map(|addresses| addresses.take(MAX_RESOLVER_ADDRESSES).collect())
        },
        TcpStream::connect,
        POLICY,
    )
    .await
}

async fn connect_with<Resolve, Resolving, Connect, Connecting, Connection>(
    target: String,
    resolve: Resolve,
    connect: Connect,
    policy: ConnectPolicy,
) -> io::Result<Connection>
where
    Resolve: FnOnce(String) -> Resolving,
    Resolving: Future<Output = io::Result<Vec<SocketAddr>>>,
    Connect: FnMut(SocketAddr) -> Connecting,
    Connecting: Future<Output = io::Result<Connection>> + Send + 'static,
    Connection: Send + 'static,
{
    let started = Instant::now();
    let deadline = started + policy.total_timeout;
    let addresses = timeout_at(deadline.min(started + policy.dns_timeout), resolve(target))
        .await
        .map_err(|_| stage_error("target DNS resolution timed out", io::ErrorKind::TimedOut))?
        .map_err(|error| stage_error("target DNS resolution failed", error.kind()))?;
    let addresses = order_addresses(addresses);
    if addresses.is_empty() {
        return Err(stage_error(
            "target DNS resolution returned no addresses",
            io::ErrorKind::NotFound,
        ));
    }
    race_addresses(addresses, connect, deadline, policy).await
}

/// Inspect a bounded resolver result before applying the final candidate limit.
/// This retains the other family even when the resolver lists many IPv6 answers
/// before its first IPv4 answer (or vice versa).
fn order_addresses(addresses: impl IntoIterator<Item = SocketAddr>) -> VecDeque<SocketAddr> {
    let mut seen = HashSet::new();
    let mut ipv4 = VecDeque::new();
    let mut ipv6 = VecDeque::new();
    let mut first_is_ipv6 = None;
    for address in addresses.into_iter().take(MAX_RESOLVER_ADDRESSES) {
        if !seen.insert(address) {
            continue;
        }
        first_is_ipv6.get_or_insert(address.is_ipv6());
        if address.is_ipv6() {
            ipv6.push_back(address);
        } else {
            ipv4.push_back(address);
        }
    }
    let (first, second) = if first_is_ipv6 == Some(true) {
        (&mut ipv6, &mut ipv4)
    } else {
        (&mut ipv4, &mut ipv6)
    };
    let mut ordered = VecDeque::new();
    while ordered.len() < MAX_TARGET_ADDRESSES {
        let mut progressed = false;
        for family in [&mut *first, &mut *second] {
            if ordered.len() == MAX_TARGET_ADDRESSES {
                break;
            }
            if let Some(address) = family.pop_front() {
                ordered.push_back(address);
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    ordered
}

struct Attempt {
    id: Id,
    abort: AbortHandle,
    recycle_at: Instant,
    retiring: bool,
}

fn remove_attempt(active: &mut Vec<Attempt>, id: Id) -> bool {
    active
        .iter()
        .position(|attempt| attempt.id == id)
        .is_some_and(|index| active.remove(index).retiring)
}

async fn race_addresses<Connect, Connecting, Connection>(
    mut addresses: VecDeque<SocketAddr>,
    mut connect: Connect,
    deadline: Instant,
    policy: ConnectPolicy,
) -> io::Result<Connection>
where
    Connect: FnMut(SocketAddr) -> Connecting,
    Connecting: Future<Output = io::Result<Connection>> + Send + 'static,
    Connection: Send + 'static,
{
    let mut attempts = JoinSet::new();
    let mut active = Vec::new();
    let mut launch_now = true;
    let mut next_launch = Instant::now();
    let mut last_error = io::ErrorKind::NotConnected;
    loop {
        if launch_now && attempts.len() < MAX_IN_FLIGHT {
            if let Some(address) = addresses.pop_front() {
                let abort = attempts.spawn(connect(address));
                active.push(Attempt {
                    id: abort.id(),
                    abort,
                    recycle_at: Instant::now() + policy.attempt_timeout,
                    retiring: false,
                });
                next_launch = Instant::now() + policy.stagger;
            }
            launch_now = false;
        }
        if attempts.is_empty() && addresses.is_empty() {
            return Err(stage_error("target TCP connection failed", last_error));
        }
        let recycle_at = active
            .first()
            .map_or(deadline, |attempt| attempt.recycle_at);
        let can_recycle = !addresses.is_empty()
            && attempts.len() == MAX_IN_FLIGHT
            && !active.iter().any(|attempt| attempt.retiring);
        tokio::select! {
            biased;
            () = sleep_until(deadline) => {
                attempts.shutdown().await;
                return Err(stage_error("target TCP connection timed out", io::ErrorKind::TimedOut));
            }
            joined = attempts.join_next_with_id(), if !attempts.is_empty() => {
                if let Some(joined) = joined {
                    let id = match &joined {
                        Ok((id, _)) => *id,
                        Err(error) => error.id(),
                    };
                    let retired = remove_attempt(&mut active, id);
                    match joined {
                        Ok((_, Ok(connection))) => {
                            // Also drops any successful loser already waiting in the set.
                            attempts.shutdown().await;
                            return Ok(connection);
                        }
                        Ok((_, Err(error))) => last_error = error.kind(),
                        Err(_) if retired => last_error = io::ErrorKind::TimedOut,
                        Err(_) => last_error = io::ErrorKind::Other,
                    }
                    // Fast failure advances immediately, without waiting out the stagger.
                    launch_now = true;
                }
            }
            () = sleep_until(recycle_at), if can_recycle => {
                // Retire only one attempt, then await its join before considering
                // another. Simultaneous timers must not discard an entire batch
                // when just one pending address needs a slot.
                if let Some(attempt) = active.first_mut() {
                    attempt.retiring = true;
                    attempt.abort.abort();
                }
            }
            () = sleep_until(next_launch),
                if !addresses.is_empty() && attempts.len() < MAX_IN_FLIGHT => {
                launch_now = true;
            }
        }
    }
}

fn stage_error(stage: &'static str, kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, format!("{stage} ({kind:?})"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::{pending, ready},
        net::{Ipv4Addr, Ipv6Addr},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::{Barrier, Notify},
        time::timeout,
    };

    const TEST_POLICY: ConnectPolicy = ConnectPolicy {
        dns_timeout: Duration::from_millis(50),
        total_timeout: Duration::from_secs(1),
        attempt_timeout: Duration::from_millis(40),
        stagger: Duration::from_millis(2),
    };

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv6Addr::LOCALHOST, port))
    }

    #[derive(Default)]
    struct Counts {
        active: AtomicUsize,
        peak: AtomicUsize,
        started: AtomicUsize,
    }

    struct Tracked(Arc<Counts>);

    impl Tracked {
        fn new(counts: &Arc<Counts>) -> Self {
            let active = counts.active.fetch_add(1, Ordering::SeqCst) + 1;
            counts.peak.fetch_max(active, Ordering::SeqCst);
            counts.started.fetch_add(1, Ordering::SeqCst);
            Self(Arc::clone(counts))
        }
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn scenario_addresses_are_deduplicated_and_families_alternate() {
        assert_eq!(
            order_addresses([v6(1), v6(2), v6(1), v4(1), v4(2)]),
            VecDeque::from([v6(1), v4(1), v6(2), v4(2)])
        );
        assert_eq!(
            order_addresses([v4(1), v6(1), v4(2), v4(3)]),
            VecDeque::from([v4(1), v6(1), v4(2), v4(3)])
        );
        assert_eq!(order_addresses([v4(1), v4(1)]), VecDeque::from([v4(1)]));
        assert_eq!(
            order_addresses([v6(1), v6(2)]),
            VecDeque::from([v6(1), v6(2)])
        );
    }

    #[test]
    fn scenario_address_limits_retain_a_later_address_family() {
        let addresses = (1..=20).map(v6).chain([v4(1)]);
        let ordered = order_addresses(addresses);
        assert_eq!(ordered.len(), MAX_TARGET_ADDRESSES);
        assert_eq!(ordered[0], v6(1));
        assert_eq!(ordered[1], v4(1));
        let examined = AtomicUsize::new(0);
        let repeated = std::iter::repeat_with(|| {
            examined.fetch_add(1, Ordering::SeqCst);
            v4(1)
        });
        assert_eq!(order_addresses(repeated), VecDeque::from([v4(1)]));
        assert_eq!(examined.load(Ordering::SeqCst), MAX_RESOLVER_ADDRESSES);
    }

    #[tokio::test]
    async fn scenario_pending_first_address_does_not_block_family_fallback() {
        let counts = Arc::new(Counts::default());
        let used = Arc::clone(&counts);
        let connected = connect_with(
            "test.invalid:443".to_owned(),
            |_| ready(Ok(vec![v6(1), v4(1)])),
            move |address| {
                let used = Arc::clone(&used);
                async move {
                    let _attempt = Tracked::new(&used);
                    if address.is_ipv6() {
                        pending::<()>().await;
                    }
                    Ok(address)
                }
            },
            TEST_POLICY,
        )
        .await
        .expect("IPv4 succeeds while IPv6 remains pending");
        assert_eq!(connected, v4(1));
        assert_eq!(counts.started.load(Ordering::SeqCst), 2);
        assert_eq!(counts.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn scenario_pending_attempts_observe_the_stagger() {
        let starts = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&starts);
        let policy = ConnectPolicy {
            stagger: Duration::from_millis(10),
            ..TEST_POLICY
        };
        let result = connect_with(
            "test.invalid:443".to_owned(),
            |_| ready(Ok(vec![v4(1), v6(1)])),
            move |address| {
                observed.lock().expect("record start").push(Instant::now());
                async move {
                    if address.is_ipv4() {
                        pending::<()>().await;
                    }
                    Ok(address)
                }
            },
            policy,
        )
        .await
        .expect("second address connects after the stagger");
        assert_eq!(result, v6(1));
        let starts = starts.lock().expect("recorded starts");
        assert_eq!(starts.len(), 2);
        assert!(starts[1].duration_since(starts[0]) >= policy.stagger);
    }

    #[tokio::test]
    async fn scenario_fast_failure_skips_the_stagger_delay() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&order);
        let result = connect_with(
            "test.invalid:443".to_owned(),
            |_| ready(Ok(vec![v4(1), v6(1)])),
            move |address| {
                observed.lock().expect("record order").push(address);
                ready(if address.is_ipv4() {
                    Err(io::Error::from(io::ErrorKind::NetworkUnreachable))
                } else {
                    Ok(address)
                })
            },
            ConnectPolicy {
                stagger: Duration::from_mins(1),
                ..TEST_POLICY
            },
        )
        .await
        .expect("failure advances before the one-second overall deadline");
        assert_eq!(result, v6(1));
        assert_eq!(*order.lock().expect("recorded order"), [v4(1), v6(1)]);
    }

    #[tokio::test]
    async fn scenario_four_black_holes_do_not_starve_the_fifth_address() {
        let counts = Arc::new(Counts::default());
        let used = Arc::clone(&counts);
        let result = connect_with(
            "test.invalid:443".to_owned(),
            |_| ready(Ok((1..=5).map(v4).collect())),
            move |address| {
                let used = Arc::clone(&used);
                async move {
                    let _attempt = Tracked::new(&used);
                    if address.port() < 5 {
                        pending::<()>().await;
                    }
                    Ok(address)
                }
            },
            TEST_POLICY,
        )
        .await
        .expect("per-attempt timeouts make room for the fifth address");
        assert_eq!(result, v4(5));
        assert_eq!(counts.started.load(Ordering::SeqCst), 5);
        assert!(counts.peak.load(Ordering::SeqCst) <= MAX_IN_FLIGHT);
        assert_eq!(counts.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn scenario_single_address_retains_time_for_tcp_retransmission() {
        let result = connect_with(
            "test.invalid:443".to_owned(),
            |_| ready(Ok(vec![v4(1)])),
            |address| async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(address)
            },
            ConnectPolicy {
                attempt_timeout: Duration::from_millis(5),
                ..TEST_POLICY
            },
        )
        .await
        .expect("no waiting addresses require early slot recycling");
        assert_eq!(result, v4(1));
    }

    #[tokio::test]
    async fn scenario_draining_the_queue_preserves_slow_existing_attempts() {
        let result = connect_with(
            "test.invalid:443".to_owned(),
            |_| ready(Ok((1..=5).map(v4).collect())),
            |address| async move {
                match address.port() {
                    1 => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok(address)
                    }
                    5 => pending::<io::Result<SocketAddr>>().await,
                    _ => Err(io::ErrorKind::ConnectionRefused.into()),
                }
            },
            ConnectPolicy {
                attempt_timeout: Duration::from_millis(5),
                stagger: Duration::ZERO,
                ..TEST_POLICY
            },
        )
        .await
        .expect("no remaining candidate needs the slow first attempt's slot");
        assert_eq!(result, v4(1));
    }

    #[tokio::test]
    async fn scenario_one_waiting_address_retires_only_one_slow_attempt() {
        let counts = Arc::new(Counts::default());
        let used = Arc::clone(&counts);
        let release = Arc::new(Notify::new());
        let connected = Arc::clone(&release);
        let task = tokio::spawn(connect_with(
            "test.invalid:443".to_owned(),
            |_| ready(Ok((1..=5).map(v4).collect())),
            move |address| {
                let used = Arc::clone(&used);
                let connected = Arc::clone(&connected);
                async move {
                    let _attempt = Tracked::new(&used);
                    if address.port() == 2 {
                        connected.notified().await;
                        Ok(address)
                    } else {
                        pending::<io::Result<SocketAddr>>().await
                    }
                }
            },
            ConnectPolicy {
                stagger: Duration::ZERO,
                ..TEST_POLICY
            },
        ));
        timeout(Duration::from_secs(1), async {
            while counts.started.load(Ordering::SeqCst) < 5 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("one expired attempt makes room for the fifth address");
        assert_eq!(counts.active.load(Ordering::SeqCst), 4);
        release.notify_one();
        let result = task
            .await
            .expect("connector joins")
            .expect("second address survives");
        assert_eq!(result, v4(2));
        assert_eq!(counts.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn scenario_all_failures_are_reported_without_target_details() {
        let error = connect_with(
            "private-target.invalid:443".to_owned(),
            |_| ready(Ok(vec![v4(1), v4(2)])),
            |_| {
                ready(Err::<(), _>(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "private-target.invalid must never appear in the error",
                )))
            },
            TEST_POLICY,
        )
        .await
        .expect_err("all addresses fail");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert!(error.to_string().contains("target TCP connection failed"));
        assert!(!error.to_string().contains("private-target"));
    }

    #[tokio::test]
    async fn scenario_dns_errors_and_empty_results_are_distinct() {
        let error = connect_with(
            "private-target.invalid:443".to_owned(),
            |_| {
                ready(Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "private-target.invalid",
                )))
            },
            |_| ready(Ok(())),
            TEST_POLICY,
        )
        .await
        .expect_err("resolver fails");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("target DNS resolution failed"));
        assert!(!error.to_string().contains("private-target"));
        let empty = connect_with(
            "test.invalid:443".to_owned(),
            |_| ready(Ok(Vec::new())),
            |_| ready(Ok(())),
            TEST_POLICY,
        )
        .await
        .expect_err("empty DNS result");
        assert_eq!(empty.kind(), io::ErrorKind::NotFound);
        assert!(empty.to_string().contains("returned no addresses"));
    }

    #[tokio::test]
    async fn scenario_dns_timeout_does_not_start_tcp_attempts() {
        let started = AtomicUsize::new(0);
        let error = connect_with(
            "test.invalid:443".to_owned(),
            |_| pending::<io::Result<Vec<SocketAddr>>>(),
            |_| {
                started.fetch_add(1, Ordering::SeqCst);
                ready(Ok(()))
            },
            ConnectPolicy {
                dns_timeout: Duration::from_millis(5),
                ..TEST_POLICY
            },
        )
        .await
        .expect_err("bounded DNS wait");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error
            .to_string()
            .contains("target DNS resolution timed out"));
        assert_eq!(started.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn scenario_dns_time_is_part_of_the_total_connection_budget() {
        let policy = ConnectPolicy {
            dns_timeout: Duration::from_millis(200),
            total_timeout: Duration::from_millis(250),
            attempt_timeout: Duration::from_secs(1),
            ..TEST_POLICY
        };
        let error = timeout(
            Duration::from_millis(350),
            connect_with(
                "test.invalid:443".to_owned(),
                |_| async {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    Ok(vec![v4(1)])
                },
                |_| pending::<io::Result<()>>(),
                policy,
            ),
        )
        .await
        .expect("TCP does not receive a fresh 250ms after DNS completes")
        .expect_err("combined connection deadline");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error
            .to_string()
            .contains("target TCP connection timed out"));
    }

    #[tokio::test]
    async fn scenario_global_tcp_deadline_reaps_pending_attempts() {
        let counts = Arc::new(Counts::default());
        let used = Arc::clone(&counts);
        let error = connect_with(
            "test.invalid:443".to_owned(),
            |_| ready(Ok(vec![v4(1), v6(1)])),
            move |_| {
                let used = Arc::clone(&used);
                async move {
                    let _attempt = Tracked::new(&used);
                    pending::<io::Result<()>>().await
                }
            },
            ConnectPolicy {
                total_timeout: Duration::from_millis(10),
                attempt_timeout: Duration::from_secs(1),
                ..TEST_POLICY
            },
        )
        .await
        .expect_err("overall deadline expires first");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error
            .to_string()
            .contains("target TCP connection timed out"));
        assert_eq!(counts.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn scenario_success_reaps_other_successful_connections() {
        let counts = Arc::new(Counts::default());
        let used = Arc::clone(&counts);
        let barrier = Arc::new(Barrier::new(2));
        let winner = connect_with(
            "test.invalid:443".to_owned(),
            |_| ready(Ok(vec![v4(1), v6(1)])),
            move |_| {
                let used = Arc::clone(&used);
                let barrier = Arc::clone(&barrier);
                async move {
                    let connection = Tracked::new(&used);
                    barrier.wait().await;
                    Ok(connection)
                }
            },
            TEST_POLICY,
        )
        .await
        .expect("one successful connection survives");
        assert_eq!(counts.started.load(Ordering::SeqCst), 2);
        assert_eq!(counts.active.load(Ordering::SeqCst), 1);
        drop(winner);
        assert_eq!(counts.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn scenario_cancelling_the_caller_aborts_all_tcp_attempts() {
        let counts = Arc::new(Counts::default());
        let used = Arc::clone(&counts);
        let task = tokio::spawn(connect_with(
            "test.invalid:443".to_owned(),
            |_| ready(Ok(vec![v4(1), v6(1)])),
            move |_| {
                let used = Arc::clone(&used);
                async move {
                    let _attempt = Tracked::new(&used);
                    pending::<io::Result<()>>().await
                }
            },
            TEST_POLICY,
        ));
        timeout(Duration::from_secs(1), async {
            while counts.started.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("two attempts started");
        task.abort();
        assert!(task.await.expect_err("caller aborted").is_cancelled());
        timeout(Duration::from_secs(1), async {
            while counts.active.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled attempts are dropped");
    }

    #[tokio::test]
    async fn scenario_loopback_target_transfers_bytes() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept loopback");
            let mut request = [0; 4];
            socket.read_exact(&mut request).await.expect("read request");
            assert_eq!(&request, b"ping");
            socket.write_all(b"pong").await.expect("reply");
        });
        let mut socket = connect_tcp_target(address.to_string())
            .await
            .expect("connect loopback");
        socket.write_all(b"ping").await.expect("send request");
        let mut response = [0; 4];
        socket.read_exact(&mut response).await.expect("read reply");
        assert_eq!(&response, b"pong");
        peer.await.expect("loopback peer completes");
    }
}
