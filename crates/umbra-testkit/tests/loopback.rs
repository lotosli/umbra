//! Tests for reusable process-local loopback fixtures.

use std::time::Duration;

use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use umbra_core::dispatch::{dispatch_with_connector, DispatchOutcome, FallbackReason};
use umbra_crypto::x25519;
use umbra_inner::{
    mux::{MuxEvent, MuxSession},
    padding::PadScheme,
};
use umbra_reality::replay::ReplayCache;
use umbra_testkit::{
    loopback_dispatch_cfg, malformed_client_hello_record, sample_dest_profile, sample_target,
    LOOPBACK_NOW,
};

#[tokio::test]
async fn scenario_testkit_authenticated_inner_mux_roundtrip() {
    let (client_io, server_io) = io::duplex(8192);
    let target = sample_target();

    let client_task = tokio::spawn({
        let target = target.clone();
        async move {
            let mut mux =
                MuxSession::client(client_io, &PadScheme::none()).expect("client mux starts");
            let mut stream = mux.open(&target).await.expect("open target stream");
            mux.send_data_wait_window(&mut stream, b"ping")
                .await
                .expect("send request");
            assert_eq!(
                mux.receive_next().await.expect("receive response"),
                MuxEvent::Data {
                    stream_id: stream.stream_id,
                    payload: b"pong".to_vec(),
                }
            );
        }
    });

    let server_task = tokio::spawn(async move {
        let mut mux = MuxSession::server(server_io, &PadScheme::none()).expect("server mux starts");
        let (mut stream, observed_target) = mux.accept().await.expect("accept stream");
        assert_eq!(observed_target, target);
        assert_eq!(
            mux.receive_next().await.expect("receive request"),
            MuxEvent::Data {
                stream_id: stream.stream_id,
                payload: b"ping".to_vec(),
            }
        );
        mux.send_data_wait_window(&mut stream, b"pong")
            .await
            .expect("send response");
    });

    timeout(Duration::from_secs(1), client_task)
        .await
        .expect("client completes")
        .expect("client task");
    timeout(Duration::from_secs(1), server_task)
        .await
        .expect("server completes")
        .expect("server task");
}

#[tokio::test]
async fn scenario_testkit_fallback_loopback_forwards_dest_bytes() {
    let cfg = loopback_dispatch_cfg(x25519::generate_keypair());
    let profile = sample_dest_profile();
    let replay = ReplayCache::new(16, 120).expect("replay cache");
    let malformed = malformed_client_hello_record();
    let (mut client, server) = io::duplex(65_536);
    let (dest_stream, mut dest_peer) = io::duplex(65_536);
    let dispatch_task = tokio::spawn(async move {
        dispatch_with_connector(
            server,
            &cfg,
            &profile,
            &replay,
            LOOPBACK_NOW,
            move |dest| async move {
                assert_eq!(dest, "dest.example:443");
                Ok::<io::DuplexStream, std::io::Error>(dest_stream)
            },
        )
        .await
    });

    client.write_all(&malformed).await.expect("write malformed");
    client.write_all(b"tail").await.expect("write tail");
    client.shutdown().await.expect("shutdown client write");

    let mut forwarded = vec![0_u8; malformed.len() + b"tail".len()];
    timeout(Duration::from_secs(1), dest_peer.read_exact(&mut forwarded))
        .await
        .expect("dest receives bytes")
        .expect("read forwarded bytes");
    assert_eq!(&forwarded[..malformed.len()], malformed.as_slice());
    assert_eq!(&forwarded[malformed.len()..], b"tail");

    dest_peer.write_all(b"dest").await.expect("dest response");
    dest_peer.shutdown().await.expect("shutdown dest");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read response");
    assert_eq!(response, b"dest");

    assert_eq!(
        timeout(Duration::from_secs(1), dispatch_task)
            .await
            .expect("dispatch completes")
            .expect("dispatch task")
            .expect("fallback succeeds"),
        DispatchOutcome::Forwarded {
            reason: FallbackReason::MalformedClientHello,
            client_to_dest: 4,
            dest_to_client: 4,
        }
    );
}
