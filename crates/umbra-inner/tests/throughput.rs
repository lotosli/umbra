//! Explicit, synthetic release-mode diagnostics; never a CI timing assertion.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::mpsc,
    task::JoinHandle,
    time::{sleep_until, Instant},
};
use umbra_inner::{
    mux::{MuxEvent, MuxSession},
    padding::PadScheme,
};
use umbra_proto::addr::TargetAddr;

const PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const LINK_BYTES_PER_SECOND: u64 = 125_000_000;

/// Each chunk traverses a pipelined propagation delay plus serialization time.
/// A sleep after every record would model stop-and-wait, not a network path.
fn delayed_link(delay: Duration) -> (DuplexStream, DuplexStream, Vec<JoinHandle<()>>) {
    let (client, left) = tokio::io::duplex(256 * 1024);
    let (right, server) = tokio::io::duplex(256 * 1024);
    let (left_read, left_write) = tokio::io::split(left);
    let (right_read, right_write) = tokio::io::split(right);
    let mut tasks = direction(left_read, right_write, delay);
    tasks.extend(direction(right_read, left_write, delay));
    (client, server, tasks)
}

fn direction<R, W>(mut read: R, mut write: W, delay: Duration) -> Vec<JoinHandle<()>>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<(Instant, Vec<u8>)>(1024);
    let receive = tokio::spawn(async move {
        let mut ready_at = Instant::now();
        let mut buffer = vec![0_u8; 16 * 1024];
        while let Ok(len) = read.read(&mut buffer).await {
            if len == 0 {
                break;
            }
            let nanos =
                u64::try_from(len).expect("bounded chunk") * 1_000_000_000 / LINK_BYTES_PER_SECOND;
            ready_at = ready_at.max(Instant::now()) + Duration::from_nanos(nanos);
            if tx
                .send((ready_at + delay, buffer[..len].to_vec()))
                .await
                .is_err()
            {
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

async fn measured_transfer(one_way_ms: u64, adaptive: bool) -> Duration {
    let (client, server, links) = delayed_link(Duration::from_millis(one_way_ms));
    let receiving = tokio::spawn(async move {
        let mut mux = if adaptive {
            adaptive_session(server, umbra_inner::mux::MuxRole::Server)
        } else {
            MuxSession::server(server, &PadScheme::none()).expect("server")
        };
        let (stream, _) = mux.accept().await.expect("accept");
        let mut received = 0;
        loop {
            match mux.receive_next().await.expect("receive") {
                MuxEvent::Data { stream_id, payload } => {
                    assert!(payload.iter().all(|byte| *byte == 0x5a));
                    received += payload.len();
                    mux.send_window_update(
                        stream_id,
                        u32::try_from(payload.len()).expect("frame length"),
                    )
                    .await
                    .expect("consumption");
                }
                MuxEvent::Fin { .. } => {
                    assert_eq!(received, PAYLOAD_BYTES);
                    mux.queue_finish(stream.stream_id).expect("finish");
                    mux.flush_pending().await.expect("flush");
                    break;
                }
                _ => {}
            }
        }
    });
    let mut mux = if adaptive {
        adaptive_session(client, umbra_inner::mux::MuxRole::Client)
    } else {
        MuxSession::client(client, &PadScheme::none()).expect("client")
    };
    let target = TargetAddr::Domain("benchmark.invalid".into(), 443);
    let mut stream = mux.open(&target).await.expect("open");
    let payload = vec![0x5a; PAYLOAD_BYTES];
    let start = Instant::now();
    mux.send_data_wait_window(&mut stream, &payload)
        .await
        .expect("send");
    mux.queue_finish(stream.stream_id).expect("finish");
    mux.flush_pending().await.expect("flush");
    receiving.await.expect("receiver task");
    let elapsed = start.elapsed();
    for link in links {
        link.abort();
        let _ = link.await;
    }
    elapsed
}

#[tokio::test]
#[ignore = "explicit release-mode throughput diagnostic, not a CI timing gate"]
async fn measure_fixed_window_throughput() {
    for delay in [0, 25, 50] {
        for sample in 0..3 {
            let elapsed =
                tokio::time::timeout(Duration::from_secs(30), measured_transfer(delay, false))
                    .await
                    .expect("bounded measurement");
            let mib = u32::try_from(PAYLOAD_BYTES / (1024 * 1024)).expect("MiB");
            let mbps = f64::from(mib) * 1_048_576.0 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0;
            println!("mode=legacy-mux window=262144 rtt_ms={} link_mbps=1000 payload_bytes={PAYLOAD_BYTES} sample={sample} elapsed_s={:.6} goodput_mbps={mbps:.3}", delay * 2, elapsed.as_secs_f64());
        }
    }
}

fn adaptive_session(io: DuplexStream, role: umbra_inner::mux::MuxRole) -> MuxSession<DuplexStream> {
    let limits = umbra_proto::flow::FlowSettings::default();
    let pool =
        umbra_inner::budget::BudgetPool::new(256 * 1024 * 1024, 128 * 1024 * 1024).expect("budget");
    let lease = pool
        .reserve(0, limits.connection as usize)
        .expect("initial receive commitment");
    MuxSession::adaptive(io, role, &PadScheme::none(), limits, lease).expect("adaptive session")
}

#[tokio::test]
#[ignore = "explicit release-mode throughput diagnostic, not a CI timing gate"]
async fn measure_adaptive_window_throughput() {
    for delay in [0, 25, 50] {
        for sample in 0..3 {
            let elapsed =
                tokio::time::timeout(Duration::from_secs(30), measured_transfer(delay, true))
                    .await
                    .expect("bounded adaptive measurement");
            let mib = u32::try_from(PAYLOAD_BYTES / (1024 * 1024)).expect("MiB");
            let mbps = f64::from(mib) * 1_048_576.0 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0;
            println!("mode=adaptive-mux rtt_ms={} link_mbps=1000 payload_bytes={PAYLOAD_BYTES} sample={sample} elapsed_s={:.6} goodput_mbps={mbps:.3}", delay * 2, elapsed.as_secs_f64());
        }
    }
}
