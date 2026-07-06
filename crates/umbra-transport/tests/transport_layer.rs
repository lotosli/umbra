//! Integration tests for TCP outer transport, TCP evasion, and QUIC surfaces.

use tokio::{
    io::{self, AsyncReadExt},
    net::TcpStream,
    sync::oneshot,
};
use umbra_crypto::x25519;
use umbra_fingerprint::load_profile;
use umbra_proto::addr::TargetAddr;
use umbra_tls::parse::parse_client_hello;
use umbra_transport::{
    evasion::{
        fallback_plan_on_recoverable_error, parse_tcp_evasion, plan_client_hello_writes,
        EvasionPlan, RecoverableBeforeSend, TcpEvasionPolicy,
    },
    quic::{
        build_quic_client_hello_surface, open_target_stream, quic_dispatch_bad_auth,
        quic_fingerprint_from_profile, recover_quic_auth_token, QuicDispatchDecision,
    },
    tcp::{
        accept_once_with_dispatch, bind_listener, build_tcp_client_hello, send_client_hello,
        tcp_connect_and_send, TcpClientHelloConfig,
    },
};

#[test]
fn scenario_segment_strategy_parses_and_unknown_is_rejected() {
    assert_eq!(
        parse_tcp_evasion("segment").expect("segment parses"),
        TcpEvasionPolicy::Segment {
            threshold: 64,
            first_segment_len: 32,
        }
    );
    assert_eq!(
        parse_tcp_evasion("segment:threshold=10,first=4").expect("explicit segment parses"),
        TcpEvasionPolicy::Segment {
            threshold: 10,
            first_segment_len: 4,
        }
    );
    assert_eq!(
        parse_tcp_evasion("geneva:fragment{tcp}").expect("geneva parses"),
        TcpEvasionPolicy::Geneva("fragment{tcp}".to_owned())
    );
    assert!(parse_tcp_evasion("unknown").is_err());
}

#[test]
fn scenario_clienthello_is_split_and_fallback_preserves_bytes() {
    let hello = (0_u8..100).collect::<Vec<_>>();
    let policy = TcpEvasionPolicy::Segment {
        threshold: 20,
        first_segment_len: 7,
    };
    let chunks = plan_client_hello_writes(&hello, &policy).expect("plan segment writes");

    assert!(chunks.len() > 1);
    assert_eq!(chunks.concat(), hello);
    assert_eq!(
        fallback_plan_on_recoverable_error(&hello, Ok(chunks.clone())),
        EvasionPlan::Evasion(chunks)
    );
    assert_eq!(
        fallback_plan_on_recoverable_error(&hello, Err(RecoverableBeforeSend)),
        EvasionPlan::Ordinary(hello)
    );
}

#[tokio::test]
async fn scenario_evasion_off_writes_once() {
    let (mut writer, mut reader) = io::duplex(128);
    let hello = b"clienthello bytes";
    let report = send_client_hello(&mut writer, hello, &TcpEvasionPolicy::Off)
        .await
        .expect("send ordinary ClientHello");

    assert_eq!(report.writes, 1);
    assert_eq!(report.bytes, hello.len());
    let mut received = vec![0_u8; hello.len()];
    reader
        .read_exact(&mut received)
        .await
        .expect("read ClientHello");
    assert_eq!(received, hello);
}

#[tokio::test]
async fn scenario_tcp_connect_sends_profile_shaped_clienthello() {
    let client_hello = sample_tcp_client_hello("server.example");
    let listener = bind_listener("127.0.0.1:0".parse().expect("socket addr"))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let server_addr = addr.to_string();

    let client = tcp_connect_and_send(&server_addr, &client_hello, &TcpEvasionPolicy::Off);
    let server = async {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        let mut received = vec![0_u8; client_hello.len()];
        stream
            .read_exact(&mut received)
            .await
            .expect("read ClientHello");
        received
    };
    let (client_result, received) = tokio::join!(client, server);
    let (_stream, report) = client_result.expect("client connected");

    assert_eq!(report.writes, 1);
    assert_eq!(received, client_hello);
    let parsed = parse_client_hello(&received).expect("parse ClientHello");
    assert_eq!(parsed.sni.as_deref(), Some("server.example"));
}

#[tokio::test]
async fn scenario_accepted_tcp_stream_is_dispatched() {
    let listener = bind_listener("127.0.0.1:0".parse().expect("socket addr"))
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let (tx, rx) = oneshot::channel();

    let accept = accept_once_with_dispatch(&listener, move |_stream, peer| async move {
        tx.send(peer).expect("send peer addr");
        Ok(())
    });
    let connect = TcpStream::connect(addr);
    let (accept_result, connect_result) = tokio::join!(accept, connect);

    accept_result.expect("accepted stream dispatched");
    connect_result.expect("client connected");
    let peer = rx.await.expect("peer sent");
    assert_eq!(
        peer.ip(),
        "127.0.0.1".parse::<std::net::IpAddr>().expect("ip")
    );
}

#[test]
fn scenario_quic_alpn_is_h3_and_token_carrier_recovers() {
    let profile = load_profile("chrome-latest").expect("load profile");
    let fp = quic_fingerprint_from_profile(&profile);
    let token = [0x5a_u8; 32];

    assert_eq!(fp.alpn, "h3");
    let surface = build_quic_client_hello_surface(&token, &fp).expect("build QUIC surface");
    assert_eq!(surface.alpn, "h3");
    assert_eq!(
        recover_quic_auth_token(&surface, &fp).expect("recover token"),
        token
    );

    let mut split_fp = fp;
    split_fp.grease_value_capacity = 8;
    let split = build_quic_client_hello_surface(&token, &split_fp).expect("build split carrier");
    assert_eq!(&split.scid[..8], &token[..8]);
    assert_eq!(
        recover_quic_auth_token(&split, &split_fp).expect("recover split token"),
        token
    );
}

#[test]
fn scenario_bad_quic_auth_is_forwarded_and_stream_carries_target() {
    let datagram = b"bad initial";
    assert_eq!(
        quic_dispatch_bad_auth(datagram),
        QuicDispatchDecision::ForwardToDest {
            datagram: datagram.to_vec(),
        }
    );

    let target = TargetAddr::domain("target.example", 443).expect("target");
    let stream = open_target_stream(&target, b"payload").expect("target stream");
    let (decoded, consumed) = TargetAddr::decode_from(&stream.bytes).expect("decode target");

    assert_eq!(decoded, target);
    assert_eq!(&stream.bytes[consumed..], b"payload");
}

fn sample_tcp_client_hello(sni: &str) -> Vec<u8> {
    let profile = load_profile("chrome-latest").expect("load profile");
    let keypair = x25519::generate_keypair();
    build_tcp_client_hello(TcpClientHelloConfig {
        sni: sni.to_owned(),
        session_id: [0x11_u8; 32],
        x25519_priv: *keypair.private.expose_secret(),
        x25519_pub: *keypair.public.as_bytes(),
        mlkem_key_exchange: vec![0x42; 32],
        profile,
        random: [0x22_u8; 32],
    })
    .expect("build TCP ClientHello")
}
