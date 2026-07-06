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
        build_quic_client_hello_surface, open_target_stream, parse_quic_initial_header,
        quic_dispatch_bad_auth, quic_fingerprint_from_profile, recover_quic_auth_token,
        QuicDispatchDecision,
    },
    tcp::{
        accept_once_with_dispatch, bind_listener, build_tcp_client_hello, send_client_hello,
        tcp_connect_and_send, TcpClientHelloConfig,
    },
};

#[test]
fn scenario_segment_strategy_parses_and_unknown_is_rejected() {
    assert!(TcpEvasionPolicy::Off.is_off());
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
    assert!(parse_tcp_evasion("geneva:").is_err());
    assert!(parse_tcp_evasion("segment:threshold=x,first=4").is_err());
    assert!(parse_tcp_evasion("segment:threshold=10,extra=4").is_err());
    assert!(parse_tcp_evasion("segment:first=4").is_err());
    assert!(parse_tcp_evasion("segment:threshold=10").is_err());
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
    assert_eq!(
        plan_client_hello_writes(
            b"short",
            &TcpEvasionPolicy::Segment {
                threshold: 64,
                first_segment_len: 16,
            },
        )
        .expect("short ClientHello stays single write"),
        vec![b"short".to_vec()]
    );
    assert!(plan_client_hello_writes(
        b"hello",
        &TcpEvasionPolicy::Segment {
            threshold: 0,
            first_segment_len: 16,
        },
    )
    .is_err());
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

#[test]
fn scenario_quic_carrier_rejects_invalid_profile_surface() {
    let profile = load_profile("chrome-latest").expect("load profile");
    let mut fp = quic_fingerprint_from_profile(&profile);
    let token = [0x33_u8; 32];

    fp.alpn = "h2".to_owned();
    assert!(build_quic_client_hello_surface(&token, &fp).is_err());

    fp.alpn = "h3".to_owned();
    fp.scid_len = 4;
    assert!(build_quic_client_hello_surface(&token, &fp).is_err());

    fp.scid_len = 8;
    fp.grease_value_capacity = 8;
    let mut surface = build_quic_client_hello_surface(&token, &fp).expect("split carrier");
    surface.transport_parameters.clear();
    assert!(recover_quic_auth_token(&surface, &fp).is_err());

    surface
        .transport_parameters
        .push(umbra_transport::quic::QuicTransportParameter {
            id: fp.grease_parameter,
            value: vec![0xaa; 8],
        });
    assert!(recover_quic_auth_token(&surface, &fp).is_err());
}

#[test]
fn scenario_quic_initial_header_exposes_scid_for_dispatch() {
    let datagram = sample_quic_initial();
    let header = parse_quic_initial_header(&datagram).expect("Initial header parses");

    assert_eq!(header.version, 1);
    assert_eq!(header.dcid, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        header.scid,
        vec![0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7]
    );
    assert_eq!(header.token, vec![0xbb, 0xcc]);
    assert_eq!(header.payload_len, 4);
    assert_eq!(header.packet_number_offset, 27);
    assert_eq!(header.packet_len, 31);
}

#[test]
fn scenario_quic_initial_header_rejects_malformed_datagrams() {
    assert!(parse_quic_initial_header(b"short").is_err());

    let mut short_header = sample_quic_initial();
    short_header[0] = 0x40;
    assert!(parse_quic_initial_header(&short_header).is_err());

    let mut fixed_bit_missing = sample_quic_initial();
    fixed_bit_missing[0] = 0x80;
    assert!(parse_quic_initial_header(&fixed_bit_missing).is_err());

    let mut zero_rtt = sample_quic_initial();
    zero_rtt[0] = 0xd0;
    assert!(parse_quic_initial_header(&zero_rtt).is_err());

    let mut cid_too_large = sample_quic_initial();
    cid_too_large[5] = 21;
    assert!(parse_quic_initial_header(&cid_too_large).is_err());

    let mut truncated_payload = sample_quic_initial();
    truncated_payload.pop();
    assert!(parse_quic_initial_header(&truncated_payload).is_err());
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

fn sample_quic_initial() -> Vec<u8> {
    let mut datagram = Vec::new();
    datagram.push(0xc0);
    datagram.extend_from_slice(&1_u32.to_be_bytes());
    datagram.push(8);
    datagram.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    datagram.push(8);
    datagram.extend_from_slice(&[0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7]);
    datagram.push(2);
    datagram.extend_from_slice(&[0xbb, 0xcc]);
    datagram.push(4);
    datagram.extend_from_slice(&[0, 0, 0, 1]);
    datagram
}
