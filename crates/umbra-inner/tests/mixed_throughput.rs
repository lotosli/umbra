//! Shared-link heterogeneous mux diagnostic. Timing is reported, never a CI gate.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    sync::{mpsc, watch, Barrier, Mutex},
    task::JoinHandle,
    time::{sleep_until, Instant},
};
use umbra_inner::{
    budget::BudgetPool,
    mux::{MuxEvent, MuxRole, MuxSession, MuxSettings},
    padding::PadScheme,
};
use umbra_proto::{addr::TargetAddr, flow::FlowSettings};

const MIB: usize = 1024 * 1024;
const PAYLOAD: usize = 4 * MIB;
const SHARED_BYTES_PER_SECOND: u64 = 62_500_000;

#[derive(Clone, Copy)]
struct Path {
    client: usize,
    group: usize,
    streams: usize,
    rtt_ms: u64,
    mbps: u64,
}

// The first two clients intentionally share a credential and have unequal
// stream counts. The last receiver stops consuming until client 2 has finished.
const PATHS: [Path; 4] = [
    Path {
        client: 0,
        group: 0,
        streams: 4,
        rtt_ms: 20,
        mbps: 100,
    },
    Path {
        client: 1,
        group: 0,
        streams: 1,
        rtt_ms: 20,
        mbps: 100,
    },
    Path {
        client: 2,
        group: 1,
        streams: 1,
        rtt_ms: 100,
        mbps: 1000,
    },
    Path {
        client: 3,
        group: 2,
        streams: 1,
        rtt_ms: 200,
        mbps: 10,
    },
];

struct Measurement {
    path: Path,
    started: Instant,
    finished: Instant,
    waits: Waits,
    receive_window: usize,
    held_bytes: usize,
}

#[derive(Default)]
struct Waits {
    credit_events: usize,
    credit: Duration,
    output: Duration,
}

fn direction<R, W>(
    mut read: R,
    mut write: W,
    path: Path,
    shared: Arc<Mutex<Instant>>,
) -> Vec<JoinHandle<()>>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<(Instant, Vec<u8>)>(64);
    let receive = tokio::spawn(async move {
        let mut path_ready = Instant::now();
        let mut buffer = vec![0; 16 * 1024];
        while let Ok(len) = read.read(&mut buffer).await {
            if len == 0 {
                break;
            }
            let size = u64::try_from(len).expect("bounded chunk");
            let at = {
                let mut shared_ready = shared.lock().await;
                *shared_ready = (*shared_ready).max(Instant::now())
                    + Duration::from_nanos(size * 1_000_000_000 / SHARED_BYTES_PER_SECOND);
                *shared_ready
            };
            path_ready = path_ready.max(at) + Duration::from_nanos(size * 8_000 / path.mbps);
            let arrival = path_ready + Duration::from_millis(path.rtt_ms / 2);
            if tx.send((arrival, buffer[..len].to_vec())).await.is_err() {
                break;
            }
        }
    });
    let transmit = tokio::spawn(async move {
        while let Some((at, bytes)) = rx.recv().await {
            sleep_until(at).await;
            if write.write_all(&bytes).await.is_err() {
                return;
            }
        }
        let _ = write.shutdown().await;
    });
    vec![receive, transmit]
}

fn link(
    path: Path,
    shared: Arc<Mutex<Instant>>,
) -> (DuplexStream, DuplexStream, Vec<JoinHandle<()>>) {
    let (client, left) = tokio::io::duplex(64 * 1024);
    let (right, server) = tokio::io::duplex(64 * 1024);
    let (left_read, left_write) = tokio::io::split(left);
    let (right_read, right_write) = tokio::io::split(right);
    let mut links = direction(left_read, right_write, path, shared);
    // ACK/control traffic uses a separate reverse serialization timeline.
    links.extend(direction(
        right_read,
        left_write,
        path,
        Arc::new(Mutex::new(Instant::now())),
    ));
    (client, server, links)
}

fn session(
    io: DuplexStream,
    role: MuxRole,
    pool: &BudgetPool,
    group: usize,
    adaptive: bool,
) -> MuxSession<DuplexStream> {
    if adaptive {
        let limits = FlowSettings {
            max_stream: 8 * 1024 * 1024,
            max_connection: 8 * 1024 * 1024,
            ..FlowSettings::default()
        };
        let lease = pool
            .reserve(group, limits.connection as usize)
            .expect("initial credit");
        MuxSession::adaptive(io, role, &PadScheme::none(), limits, lease).expect("adaptive session")
    } else {
        let mut mux =
            MuxSession::with_settings(io, role, &PadScheme::none(), MuxSettings::default())
                .expect("legacy session");
        mux.retain_lease(pool.reserve(group, 8 * MIB).expect("legacy credit ceiling"));
        mux
    }
}

async fn receive(
    mut mux: MuxSession<DuplexStream>,
    path: Path,
    release: watch::Sender<bool>,
) -> (usize, usize) {
    for _ in 0..path.streams {
        mux.accept().await.expect("accept");
    }
    let mut gate = release.subscribe();
    let mut paused = path.client == 3;
    let mut queued = BTreeMap::<u32, Vec<Vec<u8>>>::new();
    let mut held_bytes = 0;
    let mut received = BTreeMap::<u32, usize>::new();
    let mut finished = 0;
    loop {
        if paused && *gate.borrow() {
            paused = false;
            for (id, chunks) in std::mem::take(&mut queued) {
                let bytes = chunks.iter().map(Vec::len).sum::<usize>();
                drop(chunks);
                mux.send_window_update(id, u32::try_from(bytes).expect("bounded held bytes"))
                    .await
                    .expect("release held credit");
            }
        }
        let event = tokio::select! {
            event = mux.receive_next() => event.expect("receive event"),
            changed = gate.changed(), if paused => { changed.expect("live release owner"); continue; }
        };
        match event {
            MuxEvent::Data { stream_id, payload } => {
                assert!(payload.iter().all(|byte| *byte == 0x5a));
                *received.entry(stream_id).or_default() += payload.len();
                if paused {
                    held_bytes += payload.len();
                    queued.entry(stream_id).or_default().push(payload);
                    assert!(
                        held_bytes <= 256 * 1024,
                        "paused consumer must not receive more than initial stream credit"
                    );
                } else {
                    mux.send_window_update(stream_id, u32::try_from(payload.len()).expect("frame"))
                        .await
                        .expect("consume");
                }
            }
            MuxEvent::Fin { stream_id } => {
                assert_eq!(received[&stream_id], PAYLOAD / path.streams);
                finished += 1;
                if finished == path.streams {
                    assert_eq!(received.values().sum::<usize>(), PAYLOAD);
                    if path.client == 2 {
                        release.send_replace(true);
                    }
                    return (mux.receive_capacity(), held_bytes);
                }
            }
            _ => {}
        }
    }
}

async fn send(mux: &mut MuxSession<DuplexStream>, streams: &[u32]) -> Waits {
    let payload = vec![0x5a; PAYLOAD / streams.len()];
    let mut offsets = vec![0; streams.len()];
    let mut waits = Waits::default();
    while offsets.iter().any(|offset| *offset < payload.len()) {
        let mut accepted = 0;
        for (id, offset) in streams.iter().zip(&mut offsets) {
            let length = mux
                .try_send_data(*id, &payload[*offset..])
                .expect("send data");
            *offset += length;
            accepted += length;
        }
        let flushing = Instant::now();
        mux.flush_pending().await.expect("flush data");
        waits.output += flushing.elapsed();
        if accepted == 0 {
            assert!(streams
                .iter()
                .zip(&offsets)
                .all(|(id, offset)| *offset == payload.len()
                    || mux.send_credit(*id).expect("credit") == 0));
            waits.credit_events += 1;
            let waiting = Instant::now();
            mux.receive_next().await.expect("credit progress");
            waits.credit += waiting.elapsed();
        }
    }
    for id in streams {
        mux.queue_finish(*id).expect("finish");
    }
    mux.flush_pending().await.expect("flush finish");
    waits
}

async fn transfer(
    path: Path,
    adaptive: bool,
    pool: BudgetPool,
    shared: Arc<Mutex<Instant>>,
    barrier: Arc<Barrier>,
    release: watch::Sender<bool>,
) -> Measurement {
    let (client, server, links) = link(path, shared);
    let server = session(server, MuxRole::Server, &pool, path.group, adaptive);
    let receiving = tokio::spawn(receive(server, path, release));
    let local_pool = BudgetPool::new(64 * MIB, 64 * MIB).expect("client memory");
    let mut client = session(client, MuxRole::Client, &local_pool, 0, adaptive);
    let mut streams = Vec::new();
    for _ in 0..path.streams {
        streams.push(
            client
                .open(&TargetAddr::Domain("benchmark.invalid".into(), 443))
                .await
                .expect("open")
                .stream_id,
        );
    }
    barrier.wait().await;
    let started = Instant::now();
    let waits = send(&mut client, &streams).await;
    let (receive_window, held_bytes) = receiving.await.expect("receiver");
    let finished = Instant::now();
    drop(client);
    assert_eq!(local_pool.committed(), 0);
    for task in links {
        task.abort();
        let _ = task.await;
    }
    Measurement {
        path,
        started,
        finished,
        waits,
        receive_window,
        held_bytes,
    }
}

async fn measure(adaptive: bool) {
    let pool = BudgetPool::new(64 * MIB, 32 * MIB).expect("shared memory");
    let shared = Arc::new(Mutex::new(Instant::now()));
    let barrier = Arc::new(Barrier::new(PATHS.len()));
    let (release, _) = watch::channel(false);
    let mut jobs = Vec::new();
    for path in PATHS {
        jobs.push(tokio::spawn(transfer(
            path,
            adaptive,
            pool.clone(),
            shared.clone(),
            barrier.clone(),
            release.clone(),
        )));
    }
    let mut results = Vec::new();
    for job in jobs {
        results.push(job.await.expect("client"));
    }
    assert_eq!(pool.committed(), 0, "all receive owners are gone");
    let started = results
        .iter()
        .map(|result| result.started)
        .min()
        .expect("start");
    let finished = results
        .iter()
        .map(|result| result.finished)
        .max()
        .expect("finish");
    let payload_mbits = f64::from(u32::try_from(PAYLOAD).expect("payload")) * 8.0 / 1_000_000.0;
    let mut groups = BTreeMap::<usize, (usize, Instant)>::new();
    for result in results {
        let Path {
            client,
            group,
            streams,
            rtt_ms,
            mbps,
        } = result.path;
        let elapsed = result.finished.duration_since(result.started).as_secs_f64();
        println!("adaptive={adaptive} client={client} group={group} streams={streams} rtt_ms={rtt_ms} path_mbps={mbps} elapsed_s={elapsed:.6} goodput_mbps={:.3} credit_wait_events={} credit_wait_ms={:.3} output_flush_ms={:.3} receive_window={} held_bytes={}", payload_mbits / elapsed, result.waits.credit_events, result.waits.credit.as_secs_f64() * 1000.0, result.waits.output.as_secs_f64() * 1000.0, result.receive_window, result.held_bytes);
        let entry = groups.entry(group).or_insert((0, result.finished));
        entry.0 += 1;
        entry.1 = entry.1.max(result.finished);
    }
    for (group, (outers, done)) in groups {
        let mbps = payload_mbits * f64::from(u32::try_from(outers).expect("outers"))
            / done.duration_since(started).as_secs_f64();
        println!("adaptive={adaptive} group={group} outers={outers} group_goodput_mbps={mbps:.3}");
    }
    println!("adaptive={adaptive} common_link_mbps=500 payload_bytes={} aggregate_goodput_mbps={:.3} remaining_committed_bytes={}", PAYLOAD * PATHS.len(), payload_mbits * 4.0 / finished.duration_since(started).as_secs_f64(), pool.committed());
}

#[tokio::test]
#[ignore = "explicit release-mode mixed-link diagnostic, not a CI timing gate"]
async fn mixed_clients_share_resources_and_isolate_paused_consumption() {
    for adaptive in [false, true] {
        tokio::time::timeout(Duration::from_secs(20), measure(adaptive))
            .await
            .expect("bounded mixed-client progress");
    }
}
