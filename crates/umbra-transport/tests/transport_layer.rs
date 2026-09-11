//! Integration tests for TCP outer transport, TCP evasion, and QUIC surfaces.

use bytes::BytesMut;
use tokio::{
    io::{self, AsyncReadExt},
    net::TcpStream,
    sync::oneshot,
};
use umbra_crypto::x25519;
use umbra_fingerprint::load_profile;
use umbra_proto::addr::TargetAddr;
use umbra_tls::quic::QuicTrafficSecrets;
use umbra_tls::{
    clienthello::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
    parse::parse_client_hello,
};
use umbra_transport::{
    evasion::{
        fallback_plan_on_recoverable_error, parse_tcp_evasion, plan_client_hello_writes,
        EvasionPlan, RecoverableBeforeSend, TcpEvasionPolicy,
    },
    quic::{
        build_quic_client_hello_surface, derive_quic_packet_protection, derive_quinn_packet_keys,
        open_target_stream, parse_quic_initial_header, parse_target_stream_payload,
        quic_dispatch_bad_auth, quic_fingerprint_from_profile, read_target_stream,
        recover_quic_auth_token, write_target_stream, QuicDispatchDecision,
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
        parse_tcp_evasion(" off ").expect("off parses"),
        TcpEvasionPolicy::Off
    );
    for strategy in [
        "geneva:",
        "geneva:fragment{tcp}",
        " geneva:SYNTHETIC_SECRET ",
    ] {
        let error = parse_tcp_evasion(strategy).expect_err("Geneva sender unavailable");
        assert!(matches!(
            error,
            umbra_transport::TransportError::InvalidEvasionStrategy(_)
        ));
        assert_eq!(
            error.to_string(),
            "invalid TCP evasion strategy: unsupported Geneva strategy: sender unavailable"
        );
        assert!(!format!("{error:?}").contains("SYNTHETIC_SECRET"));
    }
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
async fn scenario_evasion_geneva_direct_sender_fails_without_touching_writer() {
    for hello in [&b"clienthello bytes"[..], &b""[..]] {
        let mut writer = EvasionWriter::default();
        let policy = TcpEvasionPolicy::Geneva("SYNTHETIC_SECRET".to_owned());
        let error = send_client_hello(&mut writer, hello, &policy)
            .await
            .expect_err("Geneva cannot silently become Off");
        assert!(matches!(
            error,
            umbra_transport::TransportError::InvalidEvasionStrategy(_)
        ));
        assert!(!format!("{error} {error:?}").contains("SYNTHETIC_SECRET"));
        assert!(writer.attempts.is_empty());
        assert!(writer.bytes.is_empty());
        assert_eq!(writer.flushes, 0);
    }
}

#[tokio::test]
async fn scenario_evasion_segment_preserves_order_at_threshold_and_split_boundaries() {
    for len in [0, 1, 20, 21, 100] {
        let hello = (0_u8..len).collect::<Vec<_>>();
        for first_segment_len in [1, 7, 1000] {
            let policy = TcpEvasionPolicy::Segment {
                threshold: 20,
                first_segment_len,
            };
            let mut writer = EvasionWriter::default();
            let report = send_client_hello(&mut writer, &hello, &policy)
                .await
                .expect("ordered segmentation");
            assert_eq!(writer.bytes, hello);
            assert_eq!(writer.attempts.concat(), hello);
            assert_eq!(report.bytes, hello.len());
            assert_eq!(writer.flushes, 1);
            if len > 20 {
                let split = first_segment_len.min(hello.len() - 1);
                assert_eq!(
                    writer.attempts,
                    vec![hello[..split].to_vec(), hello[split..].to_vec()]
                );
                assert_eq!(report.writes, 2);
            } else {
                // An empty write_all need not poll the writer.
                assert_eq!(writer.attempts.len(), usize::from(len != 0));
                assert_eq!(report.writes, 1);
            }
        }
    }
}

#[tokio::test]
async fn scenario_evasion_partial_write_is_not_replayed() {
    let hello = (0_u8..100).collect::<Vec<_>>();
    for policy in [
        TcpEvasionPolicy::Off,
        TcpEvasionPolicy::Segment {
            threshold: 20,
            first_segment_len: 7,
        },
    ] {
        // Include a zero-byte I/O error: it is not a recoverable setup failure.
        for fail_after in [0, 1, 7, 9, 99] {
            let mut writer = EvasionWriter {
                remaining_before_failure: Some(fail_after),
                ..Default::default()
            };
            let error = send_client_hello(&mut writer, &hello, &policy)
                .await
                .expect_err("write failure terminates the send");
            assert!(matches!(error, umbra_transport::TransportError::Io(_)));
            assert_eq!(writer.bytes, hello[..fail_after]);
            // The error is one-shot: any retry would be recorded and could succeed.
            assert_eq!(
                writer.attempts.last().expect("failing write")[0],
                hello[fail_after]
            );
            assert_eq!(writer.flushes, 0);
        }
    }
}

#[tokio::test]
async fn scenario_evasion_invalid_segment_is_not_a_recoverable_setup_failure() {
    for policy in [
        TcpEvasionPolicy::Segment {
            threshold: 0,
            first_segment_len: 7,
        },
        TcpEvasionPolicy::Segment {
            threshold: 20,
            first_segment_len: 0,
        },
    ] {
        let mut writer = EvasionWriter::default();
        let error = send_client_hello(&mut writer, b"clienthello", &policy)
            .await
            .expect_err("invalid policy is not recoverable");
        assert!(matches!(
            error,
            umbra_transport::TransportError::InvalidEvasionStrategy(_)
        ));
        assert!(writer.attempts.is_empty());
        assert_eq!(writer.flushes, 0);
    }
}

#[tokio::test]
async fn scenario_evasion_recoverable_setup_fallback_sends_ordinary_bytes_once() {
    let hello = b"clienthello bytes";
    let mut writer = EvasionWriter::default();
    let EvasionPlan::Ordinary(bytes) =
        fallback_plan_on_recoverable_error(hello, Err(RecoverableBeforeSend))
    else {
        panic!("recoverable setup failure should fall back")
    };
    assert!(writer.attempts.is_empty());
    let report = send_client_hello(&mut writer, &bytes, &TcpEvasionPolicy::Off)
        .await
        .expect("ordinary fallback send");
    assert_eq!(report.writes, 1);
    assert_eq!(report.bytes, hello.len());
    assert_eq!(writer.attempts, vec![hello.to_vec()]);
    assert_eq!(writer.bytes, hello);
}

#[derive(Default)]
struct EvasionWriter {
    attempts: Vec<Vec<u8>>,
    bytes: Vec<u8>,
    remaining_before_failure: Option<usize>,
    flushes: usize,
}

impl tokio::io::AsyncWrite for EvasionWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        self.attempts.push(buf.to_vec());
        let len = match self.remaining_before_failure {
            Some(0) => {
                self.remaining_before_failure = None;
                return std::task::Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected write failure",
                )));
            }
            Some(remaining) => {
                let len = buf.len().min(remaining);
                self.remaining_before_failure = Some(remaining - len);
                len
            }
            None => buf.len(),
        };
        self.bytes.extend_from_slice(&buf[..len]);
        std::task::Poll::Ready(Ok(len))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.flushes += 1;
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
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

    let (decoded, payload) =
        parse_target_stream_payload(&stream.bytes).expect("parse target stream payload");
    assert_eq!(decoded, target);
    assert_eq!(payload, b"payload");
}

#[tokio::test]
async fn scenario_quic_target_stream_helpers_write_and_read_prefix() {
    let (mut client, mut server) = tokio::io::duplex(128);
    let target = TargetAddr::domain("stream.example", 8443).expect("target");
    let expected = target.clone();
    let write = tokio::spawn(async move {
        write_target_stream(&mut client, &target, b"first bytes")
            .await
            .expect("write target stream");
    });

    let decoded = read_target_stream(&mut server)
        .await
        .expect("read target prefix");
    assert_eq!(decoded, expected);
    let mut payload = vec![0_u8; 11];
    tokio::io::AsyncReadExt::read_exact(&mut server, &mut payload)
        .await
        .expect("read remaining stream payload");
    assert_eq!(payload, b"first bytes");
    write.await.expect("writer task");
}

#[test]
fn scenario_quic_packet_protection_round_trips_supported_cipher_suites() {
    for cipher_suite in [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ] {
        let secret = match cipher_suite {
            TLS_AES_256_GCM_SHA384 => vec![0x33_u8; 48],
            _ => vec![0x33_u8; 32],
        };
        let sealer = derive_quic_packet_protection(cipher_suite, &secret).expect("derive sealer");
        let opener = derive_quic_packet_protection(cipher_suite, &secret).expect("derive opener");
        let header = b"\x40\x00\x00\x00\x01";
        let mut payload = b"protected payload".to_vec();
        let tag = sealer
            .seal_packet_payload(7, header, &mut payload)
            .expect("seal payload");
        payload.extend_from_slice(&tag);

        let plaintext = opener
            .open_packet_payload(7, header, &mut payload)
            .expect("open payload");
        assert_eq!(plaintext, b"protected payload");

        let sample = [0x44_u8; 16];
        let mut first = 0x41;
        let mut packet_number = [0_u8, 0_u8, 0_u8, 7_u8];
        let original_first = first;
        let original_packet_number = packet_number;
        sealer
            .apply_header_protection(&sample, &mut first, &mut packet_number)
            .expect("apply header protection");
        assert_ne!(
            (first, packet_number),
            (original_first, original_packet_number)
        );
        opener
            .remove_header_protection(&sample, &mut first, &mut packet_number)
            .expect("remove header protection");
        assert_eq!(first, original_first);
        assert_eq!(packet_number, original_packet_number);

        let secrets = QuicTrafficSecrets {
            cipher_suite,
            client: secret,
            server: match cipher_suite {
                TLS_AES_256_GCM_SHA384 => vec![0x44_u8; 48],
                _ => vec![0x44_u8; 32],
            },
        };
        let client_keys =
            derive_quinn_packet_keys(&secrets, quinn::Side::Client).expect("derive client keys");
        let server_keys =
            derive_quinn_packet_keys(&secrets, quinn::Side::Server).expect("derive server keys");
        assert_eq!(client_keys.packet.local.tag_len(), 16);
        assert_eq!(client_keys.header.local.sample_size(), 16);
        assert_eq!(
            client_keys.packet.local.confidentiality_limit(),
            expected_quic_confidentiality_limit(cipher_suite)
        );
        assert_eq!(
            client_keys.packet.local.integrity_limit(),
            expected_quic_integrity_limit(cipher_suite)
        );

        let header_len = 5;
        let mut quinn_packet = b"\x40\x00\x00\x00\x07quinn payload".to_vec();
        quinn_packet.resize(
            quinn_packet.len() + client_keys.packet.local.tag_len(),
            0_u8,
        );
        client_keys
            .packet
            .local
            .encrypt(7, &mut quinn_packet, header_len);
        let header = quinn_packet[..header_len].to_vec();
        let mut payload = BytesMut::from(&quinn_packet[header_len..]);
        server_keys
            .packet
            .remote
            .decrypt(7, &header, &mut payload)
            .expect("server remote key decrypts client local packet");
        assert_eq!(payload.as_ref(), b"quinn payload");

        let mut header_packet = vec![0x41, 0x00, 0x00, 0x00, 0x07];
        header_packet.extend_from_slice(&[0x55_u8; 20]);
        let original_header = header_packet[..5].to_vec();
        client_keys.header.local.encrypt(1, &mut header_packet);
        assert_ne!(&header_packet[..5], original_header.as_slice());
        server_keys.header.remote.decrypt(1, &mut header_packet);
        assert_eq!(&header_packet[..5], original_header.as_slice());
    }
}

fn expected_quic_confidentiality_limit(cipher_suite: u16) -> u64 {
    match cipher_suite {
        TLS_AES_128_GCM_SHA256 | TLS_AES_256_GCM_SHA384 => 1_u64 << 23,
        TLS_CHACHA20_POLY1305_SHA256 => u64::MAX,
        _ => 0,
    }
}

fn expected_quic_integrity_limit(cipher_suite: u16) -> u64 {
    match cipher_suite {
        TLS_AES_128_GCM_SHA256 | TLS_AES_256_GCM_SHA384 => 1_u64 << 52,
        TLS_CHACHA20_POLY1305_SHA256 => 1_u64 << 36,
        _ => 0,
    }
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
