//! Process-local end-to-end loopback coverage for authenticated inner traffic
//! and unauthenticated destination fallback.

use std::time::Duration;

use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use umbra_core::dispatch::{
    dispatch_with_connector, DispatchOutcome, FallbackReason, HelloReadLimits, ServerCfg,
};
use umbra_crypto::{secret::Secret, x25519};
use umbra_inner::{
    mux::{MuxEvent, MuxSession},
    padding::PadScheme,
};
use umbra_proto::addr::TargetAddr;
use umbra_reality::{
    prebuild::{CertTemplate, DestProfile},
    replay::ReplayCache,
};

const NOW: u64 = 1_765_000_000;

/// Scenario: authenticated inner mux can carry target data in both directions.
#[tokio::test]
#[ignore = "architecture marks e2e loopback as ignored; CI runs ignored tests explicitly"]
async fn e2e_authenticated_mux_roundtrip() {
    let (client_io, server_io) = io::duplex(8192);
    let target = TargetAddr::domain("target.example", 443).expect("target address");

    let client_task = tokio::spawn({
        let target = target.clone();
        async move {
            let mut mux =
                MuxSession::client(client_io, &PadScheme::none()).expect("client mux starts");
            let mut stream = mux.open(&target).await.expect("open target stream");
            mux.send_data_wait_window(&mut stream, b"ping")
                .await
                .expect("send request");
            let event = mux.receive_next().await.expect("receive response");
            assert_eq!(
                event,
                MuxEvent::Data {
                    stream_id: stream.stream_id,
                    payload: b"pong".to_vec(),
                }
            );
            mux.finish_stream(stream.stream_id)
                .await
                .expect("finish stream");
        }
    });

    let server_task = tokio::spawn(async move {
        let mut mux = MuxSession::server(server_io, &PadScheme::none()).expect("server mux starts");
        let (mut stream, observed_target) = mux.accept().await.expect("accept stream");
        assert_eq!(observed_target, target);
        let event = mux.receive_next().await.expect("receive request");
        assert_eq!(
            event,
            MuxEvent::Data {
                stream_id: stream.stream_id,
                payload: b"ping".to_vec(),
            }
        );
        mux.send_data_wait_window(&mut stream, b"pong")
            .await
            .expect("send response");
        let event = mux.receive_next().await.expect("receive stream finish");
        assert_eq!(
            event,
            MuxEvent::Fin {
                stream_id: stream.stream_id,
            }
        );
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

/// Scenario: unauthenticated or malformed handshakes are forwarded to dest.
#[tokio::test]
#[ignore = "architecture marks e2e loopback as ignored; CI runs ignored tests explicitly"]
async fn e2e_unauthenticated_falls_back_to_dest() {
    let server_key = x25519::generate_keypair();
    let cfg = ServerCfg {
        private_key: server_key.private,
        short_ids: vec![b"short".to_vec()],
        server_names: vec!["server.example".to_owned()],
        dest: "dest.example:443".to_owned(),
        max_time_diff: 120,
        mldsa_seed: Secret::new([7_u8; 32]),
        hello_limits: HelloReadLimits::default(),
    };
    let profile = sample_dest_profile();
    let replay = ReplayCache::new(16, 120).expect("replay cache");
    let malformed = malformed_client_hello_record();

    let (mut client, server) = io::duplex(65_536);
    let (dest_stream, mut dest_peer) = io::duplex(65_536);
    let mut dispatch = Box::pin(dispatch_with_connector(
        server,
        &cfg,
        &profile,
        &replay,
        NOW,
        move |dest| async move {
            assert_eq!(dest, "dest.example:443");
            Ok::<io::DuplexStream, std::io::Error>(dest_stream)
        },
    ));

    client
        .write_all(&malformed)
        .await
        .expect("write malformed ClientHello");
    client
        .write_all(b"probe-tail")
        .await
        .expect("write post-hello bytes");
    client.shutdown().await.expect("shutdown client write half");

    let mut forwarded = vec![0_u8; malformed.len() + b"probe-tail".len()];
    {
        let mut read_forwarded = Box::pin(dest_peer.read_exact(&mut forwarded));
        timeout(Duration::from_secs(1), async {
            tokio::select! {
                read = &mut read_forwarded => read.expect("dest receives forwarded bytes"),
                outcome = &mut dispatch => panic!("dispatch finished before dest observed fallback bytes: {outcome:?}"),
            }
        })
        .await
        .expect("dest receives forwarded bytes before timeout");
    }
    assert_eq!(&forwarded[..malformed.len()], malformed.as_slice());
    assert_eq!(&forwarded[malformed.len()..], b"probe-tail");

    dest_peer
        .write_all(b"dest-response")
        .await
        .expect("write dest response");
    dest_peer
        .shutdown()
        .await
        .expect("shutdown dest write half");

    let mut dispatch_outcome = None;
    let mut response = Vec::new();
    {
        let mut read_response = Box::pin(client.read_to_end(&mut response));
        timeout(Duration::from_secs(1), async {
            tokio::select! {
                read = &mut read_response => {
                    read.expect("read dest response");
                },
                outcome = &mut dispatch => {
                    dispatch_outcome = Some(outcome.expect("fallback succeeds"));
                },
            }
        })
        .await
        .expect("client receives destination response before timeout");
    }
    if dispatch_outcome.is_some() && response.is_empty() {
        client
            .read_to_end(&mut response)
            .await
            .expect("read buffered destination response");
    }
    assert_eq!(response, b"dest-response");

    let outcome = match dispatch_outcome {
        Some(outcome) => outcome,
        None => timeout(Duration::from_secs(1), &mut dispatch)
            .await
            .expect("dispatch completes")
            .expect("fallback succeeds"),
    };
    assert_eq!(
        outcome,
        DispatchOutcome::Forwarded {
            reason: FallbackReason::MalformedClientHello,
            client_to_dest: u64::try_from(b"probe-tail".len()).expect("len fits"),
            dest_to_client: u64::try_from(b"dest-response".len()).expect("len fits"),
        }
    );
}

fn malformed_client_hello_record() -> Vec<u8> {
    vec![0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00]
}

fn sample_dest_profile() -> DestProfile {
    DestProfile {
        dest: "template.example:443".to_owned(),
        tls_ver: 0x0304,
        cipher: 0x1301,
        group: 0x001d,
        alpn: vec![b"h2".to_vec()],
        ee_exts: vec![0x0010],
        leaf_template: CertTemplate {
            subject: "CN=template.example".to_owned(),
            issuer: "CN=Template CA".to_owned(),
            not_before_unix: 1_700_000_000,
            not_after_unix: 1_800_000_000,
            san_dns: vec!["template.example".to_owned()],
            sct: Vec::new(),
            signature_algorithm: "ecdsa-with-SHA256".to_owned(),
            leaf_der: Vec::new(),
        },
        ocsp: None,
        rtt: Duration::from_millis(40),
    }
}
