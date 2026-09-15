//! Explicit production-driver diagnostics with a pipelined synthetic link.

use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::oneshot,
    task::JoinSet,
};
use umbra_inner::{budget::BudgetPool, padding::PadScheme};

fn session(io: DuplexStream, role: MuxRole, production: bool) -> MuxSession<DuplexStream> {
    let limits = if production {
        crate::resources::PerformanceCfg::default().flow()
    } else {
        umbra_proto::flow::FlowSettings::default()
    };
    let pool = BudgetPool::new(256 * 1024 * 1024, 128 * 1024 * 1024).unwrap();
    let lease = pool.reserve(0, limits.connection as usize).unwrap();
    MuxSession::adaptive(io, role, &PadScheme::none(), limits, lease).unwrap()
}

fn link(rtt_ms: u64) -> (DuplexStream, DuplexStream, Vec<JoinHandle<()>>) {
    if rtt_ms == 0 {
        let (left, right) = tokio::io::duplex(1024 * 1024);
        return (left, right, Vec::new());
    }
    let (left, a) = tokio::io::duplex(256 * 1024);
    let (b, right) = tokio::io::duplex(256 * 1024);
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    let mut tasks = direction(ar, bw, rtt_ms / 2);
    tasks.extend(direction(br, aw, rtt_ms / 2));
    (left, right, tasks)
}

fn direction<R, W>(mut read: R, mut write: W, delay_ms: u64) -> Vec<JoinHandle<()>>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<(tokio::time::Instant, Vec<u8>)>(2048);
    let receiving = tokio::spawn(async move {
        let mut ready = tokio::time::Instant::now();
        let mut buffer = [0; 16 * 1024];
        while let Ok(n) = read.read(&mut buffer).await {
            if n == 0 {
                break;
            }
            ready = ready.max(tokio::time::Instant::now())
                + Duration::from_nanos(u64::try_from(n).unwrap() * 8);
            if tx
                .send((
                    ready + Duration::from_millis(delay_ms),
                    buffer[..n].to_vec(),
                ))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let sending = tokio::spawn(async move {
        while let Some((at, bytes)) = rx.recv().await {
            tokio::time::sleep_until(at).await;
            if write.write_all(&bytes).await.is_err() {
                return;
            }
        }
        let _ = write.shutdown().await;
    });
    vec![receiving, sending]
}

async fn measure(rtt_ms: u64, streams: usize, production: bool, warm: usize, measured: usize) {
    let (left, right, links) = link(rtt_ms);
    let (client_owner, client) = start_client(session(left, MuxRole::Client, production)).unwrap();
    let (server_owner, mut server) =
        start_server(session(right, MuxRole::Server, production)).unwrap();
    let (warmed, warm_done) = oneshot::channel();
    let (completed, finished) = oneshot::channel();
    let receiving = tokio::spawn(async move {
        let mut idle = Vec::new();
        let mut hot = None;
        for _ in 0..streams {
            let pending = server.accept().await.unwrap();
            let first = pending.target == TargetAddr::Domain("benchmark.invalid".into(), 1);
            let stream = pending.accept().await.unwrap();
            if first {
                hot = Some(stream);
            } else {
                idle.push(stream);
            }
        }
        let mut stream = hot.unwrap();
        let mut bytes = vec![0; 64 * 1024];
        let mut remaining = warm;
        while remaining != 0 {
            let amount = bytes.len().min(remaining);
            stream.read_exact(&mut bytes[..amount]).await.unwrap();
            assert!(bytes[..amount].iter().all(|byte| *byte == 0x5a));
            remaining -= amount;
        }
        warmed.send(Instant::now()).unwrap();
        let mut remaining = measured;
        while remaining != 0 {
            let amount = bytes.len().min(remaining);
            stream.read_exact(&mut bytes[..amount]).await.unwrap();
            assert!(bytes[..amount].iter().all(|byte| *byte == 0x5a));
            remaining -= amount;
        }
        completed.send(Instant::now()).unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        stream.shutdown().await.unwrap();
        drop(idle);
    });
    let mut opening = JoinSet::new();
    for index in 1..=streams {
        let client = client.clone();
        opening.spawn(async move {
            (
                index,
                client
                    .open(TargetAddr::Domain(
                        "benchmark.invalid".into(),
                        u16::try_from(index).unwrap(),
                    ))
                    .await
                    .unwrap(),
            )
        });
    }
    let mut idle = Vec::new();
    let mut hot = None;
    while let Some(opened) = opening.join_next().await {
        let (index, stream) = opened.unwrap();
        if index == 1 {
            hot = Some(stream);
        } else {
            idle.push(stream);
        }
    }
    let mut stream = hot.unwrap();
    let bytes = vec![0x5a; warm + measured];
    let started = Instant::now();
    stream.write_all(&bytes).await.unwrap();
    let warmed = warm_done.await.unwrap();
    let finished = finished.await.unwrap();
    let elapsed = finished
        .duration_since(if warm == 0 { started } else { warmed })
        .as_secs_f64();
    println!("mux_driver production={production} streams={streams} rtt_ms={rtt_ms} warm_bytes={warm} measured_bytes={measured} seconds={elapsed:.6} mbps={:.3}", f64::from(u32::try_from(measured).unwrap()) * 8.0 / elapsed / 1_000_000.0);
    stream.shutdown().await.unwrap();
    receiving.await.unwrap();
    drop((stream, idle));
    client_owner.shutdown().await;
    server_owner.shutdown().await;
    for task in links {
        task.abort();
        let _ = task.await;
    }
}

#[tokio::test]
#[ignore = "explicit serial release-mode driver/startup/warmed diagnostic"]
async fn measure_driver_startup_and_idle_stream_scaling() {
    for (rtt, streams, production, warm, measured) in [
        (100, 1, false, 0, 8),
        (100, 1, true, 0, 8),
        (100, 1, true, 32, 16),
        (0, 1, true, 8, 16),
        (0, 32, true, 8, 16),
        (0, 128, true, 8, 16),
    ] {
        tokio::time::timeout(
            Duration::from_secs(30),
            measure(
                rtt,
                streams,
                production,
                warm * 1024 * 1024,
                measured * 1024 * 1024,
            ),
        )
        .await
        .unwrap();
    }
}
