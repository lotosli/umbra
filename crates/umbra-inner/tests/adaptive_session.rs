//! Bidirectional proof with asymmetric receiver policy and shared budget owners.
use tokio::io::DuplexStream;
use umbra_inner::{
    budget::BudgetPool,
    mux::{MuxEvent, MuxRole, MuxSession},
    padding::PadScheme,
};
use umbra_proto::{addr::TargetAddr, flow::FlowSettings};

fn session(
    io: DuplexStream,
    role: MuxRole,
    pool: &BudgetPool,
    group: usize,
    window: u32,
) -> MuxSession<DuplexStream> {
    let limits = FlowSettings {
        stream: window,
        connection: window * 2,
        max_stream: 512 * 1024,
        max_connection: 1024 * 1024,
    };
    MuxSession::adaptive(
        io,
        role,
        &PadScheme::none(),
        limits,
        pool.reserve(group, limits.connection as usize).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn asymmetric_limits_grow_and_preserve_both_directions() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let pool = BudgetPool::new(4 * 1024 * 1024, 2 * 1024 * 1024).unwrap();
        let (left, right) = tokio::io::duplex(65_536);
        let mut client = session(left, MuxRole::Client, &pool, 0, 16_384);
        let mut server = session(right, MuxRole::Server, &pool, 1, 131_072);
        let (done, completed) = tokio::sync::oneshot::channel();
        let receiving = tokio::spawn(async move {
            let (mut stream, _) = server.accept().await.unwrap();
            let mut total = 0;
            loop {
                match server.receive_next().await.unwrap() {
                    MuxEvent::Data { stream_id, payload } => {
                        assert!(payload.iter().all(|byte| *byte == 0x42));
                        total += payload.len();
                        server
                            .send_window_update(stream_id, u32::try_from(payload.len()).unwrap())
                            .await
                            .unwrap();
                    }
                    MuxEvent::Fin { .. } => break,
                    _ => {}
                }
            }
            assert_eq!(total, 65_536);
            server
                .send_data_wait_window(&mut stream, &vec![0x24; 524_288])
                .await
                .unwrap();
            server.finish_stream(stream.stream_id).await.unwrap();
            completed.await.unwrap();
        });
        let mut stream = client
            .open(&TargetAddr::domain("asymmetric.invalid", 443).unwrap())
            .await
            .unwrap();
        client
            .send_data_wait_window(&mut stream, &vec![0x42; 65_536])
            .await
            .unwrap();
        client.finish_stream(stream.stream_id).await.unwrap();
        let mut total = 0;
        loop {
            match client.receive_next().await.unwrap() {
                MuxEvent::Data { stream_id, payload } => {
                    assert!(payload.iter().all(|byte| *byte == 0x24));
                    total += payload.len();
                    client
                        .send_window_update(stream_id, u32::try_from(payload.len()).unwrap())
                        .await
                        .unwrap();
                }
                MuxEvent::Fin { .. } => break,
                _ => {}
            }
        }
        assert_eq!(total, 524_288);
        assert!(client.flow_snapshot().unwrap().receive_window > 32_768);
        assert!(pool.committed() <= 4 * 1024 * 1024);
        done.send(()).unwrap();
        receiving.await.unwrap();
        drop(client);
        assert_eq!(pool.committed(), 0);
    })
    .await
    .expect("asymmetric transfer completes");
}

#[tokio::test]
async fn adaptive_peer_cannot_acknowledge_stream_before_settings() {
    use tokio::io::AsyncWriteExt;
    use umbra_proto::frame::{MuxCommand, MuxFrame};
    let pool = BudgetPool::new(4 * 1024 * 1024, 2 * 1024 * 1024).unwrap();
    let (io, mut peer) = tokio::io::duplex(4096);
    let mut client = session(io, MuxRole::Client, &pool, 0, 16_384);
    let stream = client
        .begin_open(&TargetAddr::domain("invalid.test", 443).unwrap())
        .unwrap();
    peer.write_all(
        &MuxFrame::new(MuxCommand::SynAck, stream.stream_id, Vec::new())
            .unwrap()
            .encode()
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(client.receive_next().await.is_err());
    assert_eq!(pool.committed(), 0);
}
