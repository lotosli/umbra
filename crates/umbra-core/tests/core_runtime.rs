//! Integration tests for configuration, SOCKS5, runtime orchestration, and probe resistance.

use std::{
    fs,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use proptest::prelude::*;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
    time::timeout,
};
use umbra_core::{
    config::{ClientCfg, ClientConfigOverrides, ServerCfg, ServerConfigOverrides, TransportKind},
    dispatch::{
        classify_client_hello, classify_quic_initial, read_client_hello_raw, DispatchContext,
        DispatchDecision, FallbackReason, QuicDispatchDecision,
    },
    probe::{
        FallbackRelayPolicy, ProbeResistancePolicy, TimingAlignment, UselessRecordAction,
        UselessRecordPolicy,
    },
    relay::relay_bidirectional,
    runtime::{
        build_quic_client_initial, client_session_from_config, client_session_with_outer,
        open_outer_from_config, run_realsite_spider, ClientConnectPlan, ClientInnerMode,
        ClientRuntime, QuicRuntimeOutcome, ServerRuntime,
    },
    socks::{
        accept_connect, decode_udp_packet, encode_udp_packet, encode_udp_response_packets,
        negotiate_no_auth, read_request, SocksRequest, SocksUdpPacket, SocksUdpReassembler,
    },
    CoreError,
};
use umbra_crypto::{mldsa::mldsa_keygen_from_seed, mlkem::mlkem_keygen, secret::Secret, x25519};
use umbra_fingerprint::load_profile;
use umbra_inner::mux::{MuxEvent, MuxSession};
use umbra_proto::addr::TargetAddr;
use umbra_reality::{
    auth::try_seal_session_id,
    prebuild::{CertTemplate, DestProfile},
    replay::ReplayCache,
};
use umbra_tls::{
    clienthello::{
        build_client_hello_handshake, quic_hello0, ClientHelloParams, ClientQuicTransportParameter,
        MlkemShare, EXT_QUIC_TRANSPORT_PARAMETERS,
    },
    parse::parse_client_hello,
};
use umbra_transport::quic::{build_quic_initial_crypto_packet, parse_quic_initial_header};

#[test]
fn scenario_complete_server_config_loads() {
    let cfg = ServerCfg::from_toml_str(&server_toml()).expect("server config loads");

    assert_eq!(cfg.listen.to_string(), "127.0.0.1:0");
    assert_eq!(
        cfg.udp_listen.expect("udp listen configured").to_string(),
        "127.0.0.1:0"
    );
    assert_eq!(cfg.private_key.expose_secret(), &[1_u8; 32]);
    assert_eq!(
        cfg.short_ids,
        vec![Vec::<u8>::new(), vec![1, 35, 69, 103, 137, 171, 205, 239]]
    );
    assert_eq!(cfg.dest, "www.microsoft.com:443");
    assert_eq!(cfg.server_names, vec!["www.microsoft.com"]);
    assert_eq!(cfg.max_time_diff, Duration::from_mins(2));
    assert!(cfg.prebuild);
    assert!(format!("{cfg:?}").contains("<redacted>"));
    assert!(!format!("{cfg:?}").contains(&b64(1)));
}

#[test]
fn scenario_complete_client_config_loads() {
    let cfg = ClientCfg::from_toml_str(&client_toml()).expect("client config loads");

    assert_eq!(cfg.server, "203.0.113.10:443");
    assert_eq!(cfg.transport, TransportKind::Tcp);
    assert_eq!(cfg.public_key.as_bytes(), &[3_u8; 32]);
    assert_eq!(cfg.short_id, vec![1, 35, 69, 103, 137, 171, 205, 239]);
    assert_eq!(cfg.server_name, "www.microsoft.com");
    assert_eq!(cfg.fingerprint, "chrome-latest");
    assert_eq!(cfg.mldsa_verify, vec![4_u8; 32]);
    assert_eq!(cfg.spider_path, "/client-a");
    assert!(cfg.mux);
    assert!(!format!("{cfg:?}").contains(&b64(3)));
}

#[test]
fn scenario_invalid_key_is_rejected() {
    let bad = server_toml().replace(&b64(1), "not-base64");
    let err = ServerCfg::from_toml_str(&bad).expect_err("invalid key rejected");

    assert!(matches!(err, CoreError::InvalidConfig(_)));
}

#[test]
fn scenario_cli_listen_overrides_file() {
    let cfg = ServerCfg::from_toml_str_with_overrides(
        &server_toml(),
        ServerConfigOverrides {
            listen: Some("127.0.0.1:9443".to_owned()),
            ..ServerConfigOverrides::default()
        },
    )
    .expect("override config loads");

    assert_eq!(cfg.listen.to_string(), "127.0.0.1:9443");
}

#[test]
fn scenario_client_cli_transport_override_is_validated() {
    let err = ClientCfg::from_toml_str_with_overrides(
        &client_toml(),
        ClientConfigOverrides {
            transport: Some("invalid".to_owned()),
            ..ClientConfigOverrides::default()
        },
    )
    .expect_err("invalid override rejected");

    assert!(matches!(err, CoreError::InvalidConfig(_)));
}

#[test]
fn scenario_config_file_load_and_all_overrides_apply() {
    let path = std::env::temp_dir().join(format!("umbra-core-config-{}.toml", std::process::id()));
    fs::write(&path, server_toml()).expect("write temp config");

    let cfg = ServerCfg::from_file_with_overrides(
        &path,
        ServerConfigOverrides {
            listen: Some("127.0.0.1:9443".to_owned()),
            udp_listen: Some("127.0.0.1:9444".to_owned()),
            private_key: Some(b64(8)),
            short_ids: Some(vec!["aa".to_owned()]),
            dest: Some("override.example:443".to_owned()),
            server_names: Some(vec!["override.example".to_owned()]),
            max_time_diff: Some("2m".to_owned()),
            mldsa_seed: Some(b64(9)),
            prebuild: Some(false),
            padding_scheme: Some("default".to_owned()),
            tcp_evasion: Some("segment:threshold=128,first=64".to_owned()),
        },
    )
    .expect("file config with overrides loads");
    fs::remove_file(&path).expect("remove temp config");

    assert_eq!(cfg.listen.to_string(), "127.0.0.1:9443");
    assert_eq!(cfg.udp_listen.expect("udp").to_string(), "127.0.0.1:9444");
    assert_eq!(cfg.private_key.expose_secret(), &[8_u8; 32]);
    assert_eq!(cfg.short_ids, vec![vec![0xaa]]);
    assert_eq!(cfg.dest, "override.example:443");
    assert_eq!(cfg.server_names, vec!["override.example"]);
    assert_eq!(cfg.max_time_diff, Duration::from_mins(2));
    assert!(!cfg.prebuild);
}

#[test]
fn scenario_client_all_overrides_apply() {
    let cfg = ClientCfg::from_toml_str_with_overrides(
        &client_toml(),
        ClientConfigOverrides {
            server: Some("198.51.100.7:8443".to_owned()),
            transport: Some("quic".to_owned()),
            public_key: Some(b64(10)),
            short_id: Some(String::new()),
            server_name: Some("alt.example".to_owned()),
            fingerprint: Some("chrome-latest".to_owned()),
            mldsa_verify: Some(b64(11)),
            spider_path: Some("/alt".to_owned()),
            socks_listen: Some("127.0.0.1:2080".to_owned()),
            mux: Some(false),
            padding_scheme: Some("default".to_owned()),
            tcp_evasion: Some("geneva:fragment{tcp:flags:PA}".to_owned()),
        },
    )
    .expect("client overrides load");

    assert_eq!(cfg.server, "198.51.100.7:8443");
    assert_eq!(cfg.transport, TransportKind::Quic);
    assert_eq!(cfg.public_key.as_bytes(), &[10_u8; 32]);
    assert!(cfg.short_id.is_empty());
    assert_eq!(cfg.server_name, "alt.example");
    assert_eq!(cfg.spider_path, "/alt");
    assert_eq!(cfg.socks_listen.to_string(), "127.0.0.1:2080");
    assert!(!cfg.mux);
}

#[test]
fn scenario_config_validation_rejects_bad_values() {
    assert!(matches!(
        ServerCfg::from_toml_str(&server_toml().replace("120s", "0s")),
        Err(CoreError::InvalidConfig(_))
    ));
    assert!(matches!(
        ServerCfg::from_toml_str(&server_toml().replace("www.microsoft.com", "bad name")),
        Err(CoreError::InvalidConfig(_))
    ));
    assert!(matches!(
        ServerCfg::from_toml_str(&server_toml().replace("0123456789abcdef", "abc")),
        Err(CoreError::InvalidConfig(_))
    ));
    assert!(matches!(
        ClientCfg::from_toml_str(&client_toml().replace("/client-a", "relative")),
        Err(CoreError::InvalidConfig(_))
    ));
    assert!(matches!(
        ClientCfg::from_toml_str(&client_toml().replace("203.0.113.10:443", "missing-port")),
        Err(CoreError::InvalidConfig(_))
    ));
}

proptest! {
    #[test]
    fn prop_client_config_accepts_valid_overrides(
        label in "[a-z][a-z0-9]{0,12}",
        server_port in 1_u16..=u16::MAX,
        socks_port in 1_u16..=u16::MAX,
        spider_tail in "[a-z0-9/_-]{0,16}",
    ) {
        let server_name = format!("{label}.example");
        let cfg = ClientCfg::from_toml_str_with_overrides(
            &client_toml(),
            ClientConfigOverrides {
                server: Some(format!("{server_name}:{server_port}")),
                server_name: Some(server_name.clone()),
                socks_listen: Some(format!("127.0.0.1:{socks_port}")),
                spider_path: Some(format!("/{spider_tail}")),
                ..ClientConfigOverrides::default()
            },
        )
        .expect("valid generated client config");

        prop_assert_eq!(&cfg.server_name, &server_name);
        prop_assert_eq!(cfg.server, format!("{server_name}:{server_port}"));
        prop_assert_eq!(cfg.socks_listen.port(), socks_port);
    }

    #[test]
    fn prop_server_config_accepts_positive_time_diff(seconds in 1_u64..=86_400) {
        let cfg = ServerCfg::from_toml_str_with_overrides(
            &server_toml(),
            ServerConfigOverrides {
                max_time_diff: Some(format!("{seconds}s")),
                ..ServerConfigOverrides::default()
            },
        )
        .expect("valid generated server config");

        prop_assert_eq!(cfg.max_time_diff, Duration::from_secs(seconds));
    }

    #[test]
    fn prop_config_rejects_whitespace_server_names(
        left in "[a-z]{1,8}",
        right in "[a-z]{1,8}",
    ) {
        let rejected = ClientCfg::from_toml_str_with_overrides(
            &client_toml(),
            ClientConfigOverrides {
                server_name: Some(format!("{left} {right}.example")),
                ..ClientConfigOverrides::default()
            },
        );

        prop_assert!(rejected.is_err());
    }
}

#[test]
fn scenario_dispatch_config_conversion_preserves_runtime_values() {
    let cfg = ServerCfg::from_toml_str(&server_toml()).expect("server config loads");
    let dispatch_cfg = cfg.into_dispatch_cfg();

    assert_eq!(dispatch_cfg.dest, "www.microsoft.com:443");
    assert_eq!(dispatch_cfg.max_time_diff, 120);
    assert_eq!(dispatch_cfg.server_names, vec!["www.microsoft.com"]);
    assert_eq!(dispatch_cfg.short_ids.len(), 2);
}

#[test]
fn scenario_config_defaults_file_loading_and_debug_paths() {
    let server = format!(
        r#"
listen = "127.0.0.1:0"
private_key = "{}"
short_ids = ["aa"]
dest = "default.example:443"
server_names = ["default.example"]
max_time_diff = "1h"
mldsa_seed = "{}"
"#,
        b64(12),
        b64(13)
    );
    let cfg = ServerCfg::from_toml_str(&server).expect("server defaults load");
    assert!(cfg.udp_listen.is_none());
    assert!(cfg.prebuild);
    assert_eq!(cfg.max_time_diff, Duration::from_hours(1));

    let path = std::env::temp_dir().join(format!("umbra-core-client-{}.toml", std::process::id()));
    fs::write(&path, client_toml()).expect("write client config");
    let cfg = ClientCfg::from_file_with_overrides(
        &path,
        ClientConfigOverrides {
            socks_listen: Some("127.0.0.1:2081".to_owned()),
            ..ClientConfigOverrides::default()
        },
    )
    .expect("client file loads");
    fs::remove_file(&path).expect("remove client config");
    assert_eq!(cfg.socks_listen.to_string(), "127.0.0.1:2081");

    let err = ServerCfg::from_toml_str("unknown = true").expect_err("unknown field rejected");
    assert!(matches!(err, CoreError::ConfigParse(_)));

    let server_overrides = ServerConfigOverrides {
        private_key: Some(b64(1)),
        short_ids: Some(vec!["aa".to_owned(), "bb".to_owned()]),
        dest: Some("secret.example:443".to_owned()),
        mldsa_seed: Some(b64(2)),
        ..ServerConfigOverrides::default()
    };
    let debug = format!("{server_overrides:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("secret.example"));

    let client_overrides = ClientConfigOverrides {
        server: Some("secret.example:443".to_owned()),
        public_key: Some(b64(3)),
        short_id: Some("aa".to_owned()),
        mldsa_verify: Some(b64(4)),
        ..ClientConfigOverrides::default()
    };
    let debug = format!("{client_overrides:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("secret.example"));
}

#[tokio::test]
async fn scenario_no_auth_method_selected() {
    let (mut client, mut server) = io::duplex(64);

    client
        .write_all(&[0x05, 0x02, 0x02, 0x00])
        .await
        .expect("write negotiation");
    negotiate_no_auth(&mut server)
        .await
        .expect("no-auth selected");

    let mut reply = [0_u8; 2];
    client.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(reply, [0x05, 0x00]);
}

#[tokio::test]
async fn scenario_domain_connect_creates_target_address() {
    let (mut client, mut server) = io::duplex(128);
    client
        .write_all(&socks_connect_domain("example.com", 443, 0x01))
        .await
        .expect("write connect");

    let connect = accept_connect(&mut server)
        .await
        .expect("domain connect accepted");

    assert_eq!(
        connect.target,
        TargetAddr::domain("example.com", 443).expect("valid domain")
    );
    let mut replies = [0_u8; 12];
    client.read_exact(&mut replies).await.expect("read replies");
    assert_eq!(&replies[..2], &[0x05, 0x00]);
    assert_eq!(&replies[2..4], &[0x05, 0x00]);
}

#[tokio::test]
async fn scenario_udp_associate_request_is_parsed() {
    let (mut client, mut server) = io::duplex(128);
    client
        .write_all(&socks_connect_domain("example.com", 443, 0x03))
        .await
        .expect("write associate");

    negotiate_no_auth(&mut server)
        .await
        .expect("no-auth selected");
    let request = read_request(&mut server)
        .await
        .expect("UDP associate parses");

    let SocksRequest::UdpAssociate(associate) = request else {
        panic!("expected UDP associate");
    };
    assert_eq!(
        associate.client_addr,
        TargetAddr::domain("example.com", 443).expect("valid domain")
    );
    let mut method_reply = [0_u8; 2];
    client
        .read_exact(&mut method_reply)
        .await
        .expect("read method reply");
    assert_eq!(method_reply, [0x05, 0x00]);
}

#[tokio::test]
async fn scenario_bind_command_is_rejected() {
    let (mut client, mut server) = io::duplex(128);
    client
        .write_all(&socks_connect_domain("example.com", 443, 0x02))
        .await
        .expect("write bind");

    let err = accept_connect(&mut server)
        .await
        .expect_err("BIND rejected");

    assert!(matches!(err, CoreError::Socks("unsupported SOCKS command")));
    let mut replies = [0_u8; 12];
    client.read_exact(&mut replies).await.expect("read replies");
    assert_eq!(&replies[..2], &[0x05, 0x00]);
    assert_eq!(&replies[2..4], &[0x05, 0x07]);
}

#[tokio::test]
async fn scenario_socks_ipv4_and_ipv6_connect_requests_parse() {
    let (mut client4, mut server4) = io::duplex(128);
    client4
        .write_all(&[
            0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 192, 0, 2, 1, 0x01, 0xbb,
        ])
        .await
        .expect("write ipv4 request");
    let ipv4 = accept_connect(&mut server4).await.expect("ipv4 accepted");
    assert_eq!(
        ipv4.target,
        TargetAddr::Ipv4(std::net::Ipv4Addr::new(192, 0, 2, 1), 443)
    );

    let (mut client6, mut server6) = io::duplex(128);
    let mut request = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x04];
    request.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
    request.extend_from_slice(&443_u16.to_be_bytes());
    client6
        .write_all(&request)
        .await
        .expect("write ipv6 request");
    let ipv6 = accept_connect(&mut server6).await.expect("ipv6 accepted");
    assert_eq!(
        ipv6.target,
        TargetAddr::Ipv6(std::net::Ipv6Addr::LOCALHOST, 443)
    );
}

#[test]
fn scenario_socks_udp_domain_packet_round_trips() {
    let target = TargetAddr::domain("dns.example", 53).expect("target");
    let packet = SocksUdpPacket {
        frag: 0,
        target: target.clone(),
        payload: b"query".to_vec(),
    };
    let encoded = encode_udp_packet(&packet).expect("packet encodes");
    let decoded = decode_udp_packet(&encoded).expect("packet decodes");

    assert_eq!(decoded.frag, 0);
    assert_eq!(decoded.target, target);
    assert_eq!(decoded.payload, b"query");
}

#[test]
fn scenario_socks_udp_fragmented_request_is_reassembled() {
    let target = TargetAddr::domain("frag.example", 53).expect("target");
    let mut reassembler = SocksUdpReassembler::default();
    let now = Instant::now();

    assert!(reassembler
        .process(
            SocksUdpPacket {
                frag: 1,
                target: target.clone(),
                payload: b"abc".to_vec(),
            },
            now,
        )
        .expect("first fragment")
        .is_none());
    assert!(reassembler
        .process(
            SocksUdpPacket {
                frag: 2,
                target: target.clone(),
                payload: b"def".to_vec(),
            },
            now,
        )
        .expect("second fragment")
        .is_none());
    let complete = reassembler
        .process(
            SocksUdpPacket {
                frag: 0x83,
                target: target.clone(),
                payload: b"ghi".to_vec(),
            },
            now,
        )
        .expect("last fragment")
        .expect("sequence completes");

    assert_eq!(complete.target, target);
    assert_eq!(complete.payload, b"abcdefghi");
}

#[test]
fn scenario_socks_udp_fragment_timer_and_lower_fragment_reset_queue() {
    let target = TargetAddr::domain("reset.example", 53).expect("target");
    let mut reassembler = SocksUdpReassembler::new(4, 1024, Duration::from_secs(5));
    let now = Instant::now();

    assert!(reassembler
        .process(
            SocksUdpPacket {
                frag: 1,
                target: target.clone(),
                payload: b"old".to_vec(),
            },
            now,
        )
        .expect("old fragment")
        .is_none());
    assert!(reassembler
        .process(
            SocksUdpPacket {
                frag: 0x82,
                target: target.clone(),
                payload: b"ignored".to_vec(),
            },
            now + Duration::from_secs(6),
        )
        .expect("expired final fragment")
        .is_none());
    assert!(reassembler
        .process(
            SocksUdpPacket {
                frag: 2,
                target: target.clone(),
                payload: b"gap".to_vec(),
            },
            now + Duration::from_secs(7),
        )
        .expect("gap fragment")
        .is_none());
    assert!(reassembler
        .process(
            SocksUdpPacket {
                frag: 1,
                target,
                payload: b"reset".to_vec(),
            },
            now + Duration::from_secs(8),
        )
        .expect("lower fragment resets")
        .is_none());
}

#[test]
fn scenario_socks_udp_fragment_state_is_bounded() {
    let target = TargetAddr::domain("bounded.example", 53).expect("target");
    let other_target = TargetAddr::domain("overflow.example", 53).expect("target");
    let mut reassembler = SocksUdpReassembler::new(1, 3, Duration::from_secs(5));
    let now = Instant::now();

    assert!(reassembler
        .process(
            SocksUdpPacket {
                frag: 1,
                target: target.clone(),
                payload: b"abc".to_vec(),
            },
            now,
        )
        .expect("first queue fragment")
        .is_none());
    assert!(reassembler
        .process(
            SocksUdpPacket {
                frag: 1,
                target: other_target,
                payload: b"new".to_vec(),
            },
            now,
        )
        .expect("queue limit drops additional target")
        .is_none());
    assert!(reassembler
        .process(
            SocksUdpPacket {
                frag: 2,
                target: target.clone(),
                payload: b"d".to_vec(),
            },
            now,
        )
        .expect("byte limit drops partial queue")
        .is_none());
    assert!(reassembler
        .process(
            SocksUdpPacket {
                frag: 0x82,
                target,
                payload: Vec::new(),
            },
            now,
        )
        .expect("dropped queue is not completed")
        .is_none());
}

#[test]
fn scenario_socks_udp_large_reply_is_fragmented() {
    let target = TargetAddr::domain("reply.example", 53).expect("target");
    let packets = encode_udp_response_packets(&target, b"abcdefgh", 3).expect("response fragments");
    let decoded: Vec<_> = packets
        .iter()
        .map(|packet| decode_udp_packet(packet).expect("fragment decodes"))
        .collect();
    let payload = decoded
        .iter()
        .flat_map(|packet| packet.payload.iter().copied())
        .collect::<Vec<_>>();

    assert_eq!(decoded.len(), 3);
    assert_eq!(decoded[0].frag, 1);
    assert_eq!(decoded[1].frag, 2);
    assert_eq!(decoded[2].frag, 0x83);
    assert_eq!(payload, b"abcdefgh");
}

proptest! {
    #[test]
    fn prop_socks_udp_packet_round_trip(
        label in "[a-z0-9][a-z0-9-]{0,20}",
        port in any::<u16>(),
        frag in any::<u8>(),
        payload in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let packet = SocksUdpPacket {
            frag,
            target: TargetAddr::domain(format!("{label}.example"), port)?,
            payload,
        };
        let encoded = encode_udp_packet(&packet)?;
        let decoded = decode_udp_packet(&encoded)?;

        prop_assert_eq!(decoded, packet);
    }

    #[test]
    fn prop_socks_udp_fragment_sequence_reassembles(
        label in "[a-z0-9][a-z0-9-]{0,20}",
        port in any::<u16>(),
        chunks in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..32),
            1..16,
        ),
    ) {
        let target = TargetAddr::domain(format!("{label}.example"), port)?;
        let mut reassembler = SocksUdpReassembler::new(4, 4096, Duration::from_secs(5));
        let now = Instant::now();
        let mut expected = Vec::new();

        for (index, chunk) in chunks.iter().enumerate() {
            expected.extend_from_slice(chunk);
            let position = u8::try_from(index + 1).expect("bounded fragment position");
            let frag = if index + 1 == chunks.len() {
                0x80 | position
            } else {
                position
            };
            let result = reassembler.process(
                SocksUdpPacket {
                    frag,
                    target: target.clone(),
                    payload: chunk.clone(),
                },
                now,
            )?;
            if index + 1 == chunks.len() {
                let complete = result.expect("final fragment completes");
                prop_assert_eq!(complete.target, target.clone());
                prop_assert_eq!(complete.payload, expected.clone());
            } else {
                prop_assert!(result.is_none());
            }
        }
    }
}

#[tokio::test]
async fn scenario_socks_negotiation_failures_are_explicit() {
    let (mut client, mut server) = io::duplex(64);
    client
        .write_all(&[0x05, 0x01, 0x02])
        .await
        .expect("write methods");
    let err = negotiate_no_auth(&mut server)
        .await
        .expect_err("missing no-auth rejected");
    assert!(matches!(
        err,
        CoreError::Socks("SOCKS no-auth method missing")
    ));
    let mut reply = [0_u8; 2];
    client.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(reply, [0x05, 0xff]);

    let (mut client, mut server) = io::duplex(64);
    client
        .write_all(&[0x04, 0x01, 0x00])
        .await
        .expect("write bad version");
    assert!(matches!(
        negotiate_no_auth(&mut server).await,
        Err(CoreError::Socks("unsupported SOCKS version"))
    ));
}

#[tokio::test]
async fn scenario_socks_request_failures_are_explicit() {
    let (mut client, mut server) = io::duplex(64);
    client
        .write_all(&[0x05, 0x00])
        .await
        .expect("write empty methods");
    assert!(matches!(
        negotiate_no_auth(&mut server).await,
        Err(CoreError::Socks("no SOCKS auth methods offered"))
    ));
    let mut reply = [0_u8; 2];
    client.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(reply, [0x05, 0xff]);

    let (mut client, mut server) = io::duplex(128);
    client
        .write_all(&[0x05, 0x01, 0x00, 0x05, 0x01, 0x01, 0x01])
        .await
        .expect("write bad reserved byte");
    let err = accept_connect(&mut server)
        .await
        .expect_err("reserved byte rejected");
    assert!(matches!(
        err,
        CoreError::Socks("SOCKS reserved byte is invalid")
    ));

    let (mut client, mut server) = io::duplex(128);
    client
        .write_all(&[0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x09])
        .await
        .expect("write unsupported address type");
    let err = accept_connect(&mut server)
        .await
        .expect_err("unsupported atyp rejected");
    assert!(matches!(
        err,
        CoreError::Socks("unsupported SOCKS address type")
    ));

    let (mut client, mut server) = io::duplex(128);
    client
        .write_all(&[0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x00])
        .await
        .expect("write empty domain");
    let err = accept_connect(&mut server)
        .await
        .expect_err("empty domain rejected");
    assert!(matches!(err, CoreError::Socks("SOCKS domain is empty")));
}

#[tokio::test]
async fn scenario_server_starts_configured_listeners() {
    let cfg = ServerCfg::from_toml_str(&server_toml()).expect("server config loads");
    let runtime = ServerRuntime::bind_with_profile(
        cfg,
        sample_dest_profile(),
        ProbeResistancePolicy::default(),
    )
    .await
    .expect("runtime binds");

    assert_eq!(runtime.listener_count(), 2);
    assert!(runtime.prebuild_enabled());
    assert!(matches!(
        runtime.tcp_evasion(),
        umbra_transport::evasion::TcpEvasionPolicy::Off
    ));
    assert_eq!(
        runtime.padding_scheme(),
        &umbra_inner::padding::PadScheme::none()
    );
    assert_ne!(runtime.local_addr().expect("tcp addr").port(), 0);
    assert_ne!(
        runtime
            .udp_local_addr()
            .expect("udp addr")
            .expect("udp bound")
            .port(),
        0
    );
}

#[tokio::test]
async fn scenario_socks_request_opens_selected_tcp_mux_stream() {
    let cfg = ClientCfg::from_toml_str(&client_toml()).expect("client config loads");
    let (mut socks_client, mut socks_server) = io::duplex(4096);
    let (outer_client, outer_server) = io::duplex(4096);
    let observed_plan = Arc::new(Mutex::new(None));
    let plan_slot = Arc::clone(&observed_plan);
    let server_task = tokio::spawn(async move {
        let mut mux = MuxSession::server(outer_server, &umbra_inner::padding::PadScheme::none())
            .expect("server mux");
        let (mut stream, target) = mux.accept().await.expect("server accepts mux stream");
        let payload = loop {
            if let MuxEvent::Data { stream_id, payload } =
                mux.receive_next().await.expect("server receives data")
            {
                assert_eq!(stream_id, stream.stream_id);
                break payload;
            }
        };
        assert_eq!(payload, b"ping");
        mux.send_window_update(
            stream.stream_id,
            u32::try_from(payload.len()).expect("payload length fits u32"),
        )
        .await
        .expect("window update");
        mux.send_data_wait_window(&mut stream, b"pong")
            .await
            .expect("server sends response");
        mux.finish_stream(stream.stream_id)
            .await
            .expect("server sends fin");
        target
    });

    socks_client
        .write_all(&socks_connect_domain("target.example", 8443, 0x01))
        .await
        .expect("write SOCKS request");
    let session_task = tokio::spawn(async move {
        Box::pin(client_session_with_outer(
            &cfg,
            &mut socks_server,
            move |plan| {
                *plan_slot.lock().expect("plan mutex") = Some(plan.clone());
                async move { Ok::<_, CoreError>(outer_client) }
            },
        ))
        .await
    });
    let mut replies = [0_u8; 12];
    socks_client
        .read_exact(&mut replies)
        .await
        .expect("read SOCKS replies");
    assert_eq!(&replies[..2], &[0x05, 0x00]);
    assert_eq!(&replies[2..4], &[0x05, 0x00]);
    socks_client
        .write_all(b"ping")
        .await
        .expect("write payload");
    socks_client
        .shutdown()
        .await
        .expect("close socks write side");
    let mut response = [0_u8; 4];
    socks_client
        .read_exact(&mut response)
        .await
        .expect("read mux response");
    assert_eq!(&response, b"pong");
    let session = timeout(Duration::from_secs(1), session_task)
        .await
        .expect("client session completes")
        .expect("session task")
        .expect("client session opens mux");
    assert_eq!(session.transport, TransportKind::Tcp);
    assert_eq!(session.mode, ClientInnerMode::Mux);
    assert_eq!(
        session.target,
        TargetAddr::domain("target.example", 8443).expect("valid target")
    );
    assert_eq!(
        observed_plan
            .lock()
            .expect("plan mutex")
            .as_ref()
            .expect("plan")
            .mode,
        ClientInnerMode::Mux
    );
    assert_eq!(
        server_task.await.expect("server task"),
        TargetAddr::domain("target.example", 8443).expect("valid target")
    );
}

#[tokio::test]
async fn scenario_socks_udp_associate_relays_over_tcp_mux_datagram() {
    let cfg = ClientCfg::from_toml_str(&client_toml()).expect("client config loads");
    let (mut socks_client, mut socks_server) = io::duplex(4096);
    let (outer_client, outer_server) = io::duplex(4096);
    let server_task = tokio::spawn(async move {
        let mut mux = MuxSession::server(outer_server, &umbra_inner::padding::PadScheme::none())
            .expect("server mux");
        let target = TargetAddr::domain("udp.example", 5353).expect("valid target");
        mux.send_udp_datagram(&target, b"early")
            .await
            .expect("server sends early UDP reply");
        let event = mux.receive_next().await.expect("server receives UDP");
        let MuxEvent::UdpDatagram { target, payload } = event else {
            panic!("expected UDP datagram");
        };
        assert_eq!(
            target,
            TargetAddr::domain("udp.example", 5353).expect("valid target")
        );
        assert_eq!(payload, b"question");
        mux.send_udp_datagram(&target, b"answer")
            .await
            .expect("server sends UDP reply");
    });

    socks_client
        .write_all(&socks_connect_domain("0.0.0.0", 0, 0x03))
        .await
        .expect("write UDP associate");
    let session_task = tokio::spawn(async move {
        Box::pin(client_session_with_outer(
            &cfg,
            &mut socks_server,
            |_plan| async move { Ok::<_, CoreError>(outer_client) },
        ))
        .await
    });

    let mut replies = [0_u8; 12];
    socks_client
        .read_exact(&mut replies)
        .await
        .expect("read UDP associate replies");
    assert_eq!(&replies[..2], &[0x05, 0x00]);
    assert_eq!(&replies[2..6], &[0x05, 0x00, 0x00, 0x01]);
    let bound = std::net::SocketAddr::from((
        std::net::Ipv4Addr::new(replies[6], replies[7], replies[8], replies[9]),
        u16::from_be_bytes([replies[10], replies[11]]),
    ));
    assert_ne!(bound.port(), 0);

    let udp_client = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind local UDP client");
    let attacker = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind second UDP peer");
    attacker
        .send_to(&[0, 0, 0, 0xff], bound)
        .await
        .expect("send malformed UDP packet");
    let request = encode_udp_packet(&SocksUdpPacket {
        frag: 0,
        target: TargetAddr::domain("udp.example", 5353).expect("valid target"),
        payload: b"question".to_vec(),
    })
    .expect("UDP packet encodes");
    udp_client
        .send_to(&request, bound)
        .await
        .expect("send UDP packet");
    attacker
        .send_to(&request, bound)
        .await
        .expect("send ignored UDP packet from second peer");
    let mut response = vec![0_u8; 256];
    let read = udp_client
        .recv(&mut response)
        .await
        .expect("receive UDP response");
    let response = decode_udp_packet(&response[..read]).expect("response decodes");
    assert_eq!(
        response.target,
        TargetAddr::domain("udp.example", 5353).expect("valid target")
    );
    assert_eq!(response.payload, b"answer");

    socks_client.shutdown().await.expect("close UDP control");
    let session = timeout(Duration::from_secs(1), session_task)
        .await
        .expect("UDP session completes")
        .expect("session task")
        .expect("UDP session succeeds");
    assert_eq!(session.transport, TransportKind::Tcp);
    assert_eq!(session.mode, ClientInnerMode::Mux);
    server_task.await.expect("server task");
}

#[tokio::test]
async fn scenario_udp_associate_rejects_generic_quic_outer() {
    let cfg = ClientCfg::from_toml_str_with_overrides(
        &client_toml(),
        ClientConfigOverrides {
            transport: Some("quic".to_owned()),
            ..ClientConfigOverrides::default()
        },
    )
    .expect("client config loads");
    let (mut socks_client, mut socks_server) = io::duplex(256);
    let (outer_client, _outer_server) = io::duplex(64);
    socks_client
        .write_all(&socks_connect_domain("0.0.0.0", 0, 0x03))
        .await
        .expect("write UDP associate");
    let session_task = tokio::spawn(async move {
        Box::pin(client_session_with_outer(
            &cfg,
            &mut socks_server,
            |_plan| async move { Ok::<_, CoreError>(outer_client) },
        ))
        .await
    });

    let mut method_reply = [0_u8; 2];
    socks_client
        .read_exact(&mut method_reply)
        .await
        .expect("read method reply");
    assert_eq!(method_reply, [0x05, 0x00]);

    let err = session_task
        .await
        .expect("session task")
        .expect_err("generic QUIC UDP association rejected");
    assert!(matches!(
        err,
        CoreError::InvalidConfig("QUIC UDP association requires configured QUIC runtime")
    ));
}

#[tokio::test]
async fn scenario_socks_request_opens_solo_vision_preface() {
    let cfg = ClientCfg::from_toml_str_with_overrides(
        &client_toml(),
        ClientConfigOverrides {
            mux: Some(false),
            ..ClientConfigOverrides::default()
        },
    )
    .expect("client config loads");
    let (mut socks_client, mut socks_server) = io::duplex(4096);
    let (outer_client, mut outer_server) = io::duplex(4096);
    socks_client
        .write_all(&socks_connect_domain("solo.example", 443, 0x01))
        .await
        .expect("write SOCKS request");

    let session_task = tokio::spawn(async move {
        Box::pin(client_session_with_outer(
            &cfg,
            &mut socks_server,
            |_plan| async move { Ok::<_, CoreError>(outer_client) },
        ))
        .await
    });
    let mut replies = [0_u8; 12];
    socks_client
        .read_exact(&mut replies)
        .await
        .expect("read SOCKS replies");
    assert_eq!(&replies[..2], &[0x05, 0x00]);
    assert_eq!(&replies[2..4], &[0x05, 0x00]);
    let mut preface = [0_u8; 16];
    outer_server
        .read_exact(&mut preface)
        .await
        .expect("read solo preface");
    assert_eq!(preface[0], 0x03);
    socks_client
        .write_all(b"solo")
        .await
        .expect("write solo data");
    socks_client
        .shutdown()
        .await
        .expect("close solo socks side");
    let mut observed = [0_u8; 4];
    outer_server
        .read_exact(&mut observed)
        .await
        .expect("outer receives solo data");
    assert_eq!(&observed, b"solo");
    outer_server
        .write_all(b"done")
        .await
        .expect("write response");
    outer_server.shutdown().await.expect("close outer side");
    let mut response = [0_u8; 4];
    socks_client
        .read_exact(&mut response)
        .await
        .expect("socks receives response");
    assert_eq!(&response, b"done");
    let session = timeout(Duration::from_secs(1), session_task)
        .await
        .expect("solo session completes")
        .expect("session task")
        .expect("client session opens solo");
    assert_eq!(session.mode, ClientInnerMode::VisionSolo);
}

#[tokio::test]
async fn scenario_server_runtime_accepts_and_dispatches_fallback() {
    let cfg = ServerCfg::from_toml_str(&server_toml()).expect("server config loads");
    let runtime = ServerRuntime::bind_with_profile(
        cfg,
        sample_dest_profile(),
        ProbeResistancePolicy::default(),
    )
    .await
    .expect("runtime binds");
    let addr = runtime.local_addr().expect("runtime addr");
    let (dest_stream, mut dest_peer) = io::duplex(4096);
    let accept_task = tokio::spawn(async move {
        runtime
            .accept_one_with_connector(
                move |_dest| async move { Ok::<_, std::io::Error>(dest_stream) },
            )
            .await
    });
    let mut client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect runtime");
    let malformed = malformed_client_hello_record();
    client
        .write_all(&malformed)
        .await
        .expect("write malformed ClientHello");
    client.write_all(b"tail").await.expect("write tail");
    client.shutdown().await.expect("shutdown client");

    let mut forwarded = vec![0_u8; malformed.len() + 4];
    dest_peer
        .read_exact(&mut forwarded)
        .await
        .expect("dest receives fallback bytes");
    assert_eq!(&forwarded[..malformed.len()], malformed.as_slice());
    assert_eq!(&forwarded[malformed.len()..], b"tail");
    dest_peer.shutdown().await.expect("close dest");

    let accepted = timeout(Duration::from_secs(1), accept_task)
        .await
        .expect("accept completes")
        .expect("accept task")
        .expect("fallback dispatch succeeds");
    assert!(matches!(
        accepted.outcome,
        umbra_core::dispatch::DispatchOutcome::Forwarded { .. }
    ));
}

#[tokio::test]
async fn scenario_server_runtime_quic_fallback_relays_datagram_flow() {
    let dest = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind dest UDP");
    let cfg = ServerCfg::from_toml_str_with_overrides(
        &server_toml(),
        ServerConfigOverrides {
            dest: Some(dest.local_addr().expect("dest addr").to_string()),
            ..ServerConfigOverrides::default()
        },
    )
    .expect("server config loads");
    let runtime = ServerRuntime::bind_with_profile(
        cfg,
        sample_dest_profile(),
        ProbeResistancePolicy::default(),
    )
    .await
    .expect("runtime binds");
    let quic_addr = runtime
        .udp_local_addr()
        .expect("udp addr")
        .expect("udp configured");
    let accept_task = tokio::spawn(async move {
        runtime
            .accept_one_quic_with_idle_timeout(Duration::from_millis(25))
            .await
    });

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client UDP");
    client.connect(quic_addr).await.expect("connect client UDP");
    client.send(b"bad initial").await.expect("send bad initial");

    let mut dest_buf = [0_u8; 64];
    let (read, upstream_peer) = dest.recv_from(&mut dest_buf).await.expect("dest receives");
    assert_eq!(&dest_buf[..read], b"bad initial");

    client.send(b"second").await.expect("send second datagram");
    let (read, second_peer) = dest
        .recv_from(&mut dest_buf)
        .await
        .expect("dest receives second");
    assert_eq!(second_peer, upstream_peer);
    assert_eq!(&dest_buf[..read], b"second");

    dest.send_to(b"reply", upstream_peer)
        .await
        .expect("dest replies");
    let mut client_buf = [0_u8; 64];
    let read = client
        .recv(&mut client_buf)
        .await
        .expect("client receives reply");
    assert_eq!(&client_buf[..read], b"reply");

    let accepted = timeout(Duration::from_secs(1), accept_task)
        .await
        .expect("QUIC accept completes")
        .expect("accept task")
        .expect("QUIC fallback succeeds");
    assert_eq!(
        accepted.peer.ip(),
        client.local_addr().expect("client addr").ip()
    );
    assert_eq!(
        accepted.outcome,
        QuicRuntimeOutcome::Forwarded {
            reason: FallbackReason::MalformedClientHello,
            client_to_dest: u64::try_from(b"bad initial".len() + b"second".len())
                .expect("length fits"),
            dest_to_client: u64::try_from(b"reply".len()).expect("length fits"),
        }
    );
}

#[tokio::test]
async fn scenario_runtime_shutdown_returns_without_accepting() {
    let cfg = ServerCfg::from_toml_str(&server_toml()).expect("server config loads");
    let runtime = ServerRuntime::bind_with_profile(
        cfg,
        sample_dest_profile(),
        ProbeResistancePolicy::default(),
    )
    .await
    .expect("runtime binds");

    Box::pin(runtime.run_until_shutdown(async {}))
        .await
        .expect("server shutdown completes");

    let cfg = ClientCfg::from_toml_str(&client_toml()).expect("client config loads");
    let client = ClientRuntime::bind(cfg)
        .await
        .expect("client runtime binds");
    Box::pin(client.run_until_shutdown(async {}))
        .await
        .expect("client shutdown completes");
}

#[tokio::test]
async fn scenario_server_runtime_survives_early_client_disconnect() {
    let cfg = ServerCfg::from_toml_str(&server_toml()).expect("server config loads");
    let runtime = ServerRuntime::bind_with_profile(
        cfg,
        sample_dest_profile(),
        ProbeResistancePolicy::default(),
    )
    .await
    .expect("runtime binds");
    let addr = runtime.local_addr().expect("runtime addr");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        Box::pin(runtime.run_until_shutdown(async {
            let _ = shutdown_rx.await;
        }))
        .await
    });

    let client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect runtime");
    drop(client);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !task.is_finished(),
        "server must keep accepting after early EOF"
    );

    shutdown_tx.send(()).expect("send shutdown");
    timeout(Duration::from_secs(1), task)
        .await
        .expect("server shuts down")
        .expect("join server task")
        .expect("server loop returns ok");
}

#[tokio::test]
async fn scenario_tcp_outer_sends_profile_shaped_clienthello() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind capture listener");
    let addr = listener.local_addr().expect("listener addr");
    let server_key = x25519::generate_keypair();
    let mldsa_seed = Secret::new([44_u8; 32]);
    let mldsa = mldsa_keygen_from_seed(mldsa_seed.expose_secret());
    let cfg = ClientCfg::from_toml_str_with_overrides(
        &client_toml(),
        ClientConfigOverrides {
            server: Some(addr.to_string()),
            public_key: Some(b64_bytes(server_key.public.as_bytes())),
            mldsa_verify: Some(b64_bytes(&mldsa.verifying_key)),
            ..ClientConfigOverrides::default()
        },
    )
    .expect("client config loads");
    let plan = ClientConnectPlan {
        target: TargetAddr::domain("target.example", 443).expect("target"),
        server: cfg.server.clone(),
        transport: TransportKind::Tcp,
        mode: ClientInnerMode::Mux,
        server_name: cfg.server_name.clone(),
    };
    let capture = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept outer");
        let chello_raw = read_client_hello_raw(
            &mut stream,
            umbra_core::dispatch::HelloReadLimits::default(),
        )
        .await
        .expect("read ClientHello");
        let replay = ReplayCache::new(16, 180).expect("replay cache");
        let dispatch_cfg = umbra_core::dispatch::ServerCfg {
            private_key: server_key.private,
            short_ids: vec![vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]],
            server_names: vec!["www.microsoft.com".to_owned()],
            dest: "www.microsoft.com:443".to_owned(),
            max_time_diff: 120,
            mldsa_seed,
            hello_limits: umbra_core::dispatch::HelloReadLimits::default(),
        };
        let decision = classify_client_hello(
            chello_raw.clone(),
            DispatchContext {
                cfg: &dispatch_cfg,
                profile: &sample_dest_profile(),
                replay: &replay,
                now_unix: current_test_unix_time(),
            },
        )
        .expect("classify ClientHello");
        let DispatchDecision::Authenticated(mut authenticated) = decision else {
            panic!("ClientHello must authenticate");
        };
        stream
            .write_all(&authenticated.server_flight)
            .await
            .expect("write server flight");
        let client_finished = loop {
            let record = umbra_core::tls_io::read_tls_record(&mut stream)
                .await
                .expect("read client Finished")
                .expect("client Finished record");
            if record.as_slice() != umbra_tls::handshake::Tls13Client::dummy_change_cipher_spec() {
                break record;
            }
        };
        authenticated
            .tls_server
            .drive(&client_finished)
            .expect("server accepts client Finished");
        chello_raw
    });

    let stream = open_outer_from_config(&cfg, &plan)
        .await
        .expect("open tcp outer");
    drop(stream);
    let record = capture.await.expect("capture task");
    let parsed = parse_client_hello(&record[5..]).expect("parse captured ClientHello");
    assert_eq!(parsed.sni.as_deref(), Some("www.microsoft.com"));
}

#[tokio::test]
async fn scenario_quic_network_runtime_relays_direct_stream() {
    let server_key = x25519::generate_keypair();
    let mldsa_seed = [0x6d_u8; 32];
    let mldsa = mldsa_keygen_from_seed(&mldsa_seed);
    let runtime = ServerRuntime::bind_with_profile(
        quic_runtime_server_cfg(&server_key, &mldsa_seed),
        sample_dest_profile(),
        ProbeResistancePolicy::default(),
    )
    .await
    .expect("server runtime binds");
    let quic_addr = runtime
        .udp_local_addr()
        .expect("udp local addr")
        .expect("udp listener");

    let (target_addr, target_task) = spawn_ping_pong_target().await;
    let server_task = tokio::spawn(async move {
        runtime
            .accept_one_quic_with_idle_timeout(Duration::from_secs(1))
            .await
    });
    let cfg = quic_runtime_client_cfg(quic_addr, &server_key.public, &mldsa.verifying_key);
    let (mut socks_client, mut socks_server) = io::duplex(4096);
    let client_task =
        tokio::spawn(async move { client_session_from_config(&cfg, &mut socks_server).await });

    socks_client
        .write_all(&socks_connect_domain("127.0.0.1", target_addr.port(), 0x01))
        .await
        .expect("write SOCKS request");
    let mut replies = [0_u8; 12];
    socks_client
        .read_exact(&mut replies)
        .await
        .expect("read SOCKS replies");
    assert_eq!(&replies[..2], &[0x05, 0x00]);
    assert_eq!(&replies[2..4], &[0x05, 0x00]);
    socks_client
        .write_all(b"ping")
        .await
        .expect("write request");
    socks_client.shutdown().await.expect("close socks write");
    let mut response = [0_u8; 4];
    socks_client
        .read_exact(&mut response)
        .await
        .expect("read response");
    assert_eq!(&response, b"pong");

    let client_outcome = timeout(Duration::from_secs(5), client_task)
        .await
        .expect("client completes")
        .expect("client task")
        .expect("client session succeeds");
    assert_eq!(client_outcome.transport, TransportKind::Quic);
    assert_eq!(client_outcome.mode, ClientInnerMode::QuicStream);

    let server_outcome = timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server completes")
        .expect("server task")
        .expect("server QUIC accepts");
    assert!(matches!(
        server_outcome.outcome,
        QuicRuntimeOutcome::Authenticated { .. }
    ));
    target_task.await.expect("target task");
}

#[tokio::test]
async fn scenario_tcp_network_runtime_relays_udp_association() {
    let server_key = x25519::generate_keypair();
    let mldsa_seed = [0x72_u8; 32];
    let mldsa = mldsa_keygen_from_seed(&mldsa_seed);
    let runtime = ServerRuntime::bind_with_profile(
        quic_runtime_server_cfg(&server_key, &mldsa_seed),
        sample_dest_profile(),
        ProbeResistancePolicy::default(),
    )
    .await
    .expect("server runtime binds");
    let server_addr = runtime.local_addr().expect("tcp addr");
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind UDP target");
    let target_addr = target.local_addr().expect("target addr");
    let target_task = tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        let (read, peer) = target.recv_from(&mut buf).await.expect("target receives");
        assert_eq!(&buf[..read], b"question");
        target
            .send_to(b"answer", peer)
            .await
            .expect("target replies");
    });
    let server_task = tokio::spawn(async move {
        runtime
            .accept_one_with_connector(tokio::net::TcpStream::connect)
            .await
    });
    let cfg = tcp_runtime_client_cfg(server_addr, &server_key.public, &mldsa.verifying_key);
    let (mut socks_client, mut socks_server) = io::duplex(4096);
    let client_task =
        tokio::spawn(async move { client_session_from_config(&cfg, &mut socks_server).await });

    socks_client
        .write_all(&socks_connect_domain("0.0.0.0", 0, 0x03))
        .await
        .expect("write UDP associate");
    let mut replies = [0_u8; 12];
    socks_client
        .read_exact(&mut replies)
        .await
        .expect("read UDP associate replies");
    let bound = std::net::SocketAddr::from((
        std::net::Ipv4Addr::new(replies[6], replies[7], replies[8], replies[9]),
        u16::from_be_bytes([replies[10], replies[11]]),
    ));
    let udp_client = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind UDP client");
    let request = encode_udp_packet(&SocksUdpPacket {
        frag: 0,
        target: TargetAddr::domain("127.0.0.1", target_addr.port()).expect("target"),
        payload: b"question".to_vec(),
    })
    .expect("UDP packet encodes");
    udp_client
        .send_to(&request, bound)
        .await
        .expect("send UDP request");
    let mut response = vec![0_u8; 256];
    let read = udp_client
        .recv(&mut response)
        .await
        .expect("receive UDP response");
    let response = decode_udp_packet(&response[..read]).expect("response decodes");
    assert_eq!(response.payload, b"answer");

    socks_client.shutdown().await.expect("close control");
    let client_outcome = timeout(Duration::from_secs(5), client_task)
        .await
        .expect("client completes")
        .expect("client task")
        .expect("client session succeeds");
    assert_eq!(client_outcome.transport, TransportKind::Tcp);
    assert_eq!(client_outcome.mode, ClientInnerMode::Mux);
    let server_outcome = timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server completes")
        .expect("server task")
        .expect("server accepts");
    assert!(matches!(
        server_outcome.outcome,
        umbra_core::dispatch::DispatchOutcome::Authenticated { .. }
    ));
    target_task.await.expect("target task");
}

#[tokio::test]
async fn scenario_quic_network_runtime_relays_udp_association() {
    let server_key = x25519::generate_keypair();
    let mldsa_seed = [0x71_u8; 32];
    let mldsa = mldsa_keygen_from_seed(&mldsa_seed);
    let runtime = ServerRuntime::bind_with_profile(
        quic_runtime_server_cfg(&server_key, &mldsa_seed),
        sample_dest_profile(),
        ProbeResistancePolicy::default(),
    )
    .await
    .expect("server runtime binds");
    let quic_addr = runtime
        .udp_local_addr()
        .expect("udp local addr")
        .expect("udp listener");
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind UDP target");
    let target_addr = target.local_addr().expect("target addr");
    let target_task = tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        let (read, peer) = target.recv_from(&mut buf).await.expect("target receives");
        assert_eq!(&buf[..read], b"question");
        target
            .send_to(b"answer", peer)
            .await
            .expect("target replies");
    });
    let server_task = tokio::spawn(async move {
        runtime
            .accept_one_quic_with_idle_timeout(Duration::from_secs(2))
            .await
    });
    let cfg = quic_runtime_client_cfg(quic_addr, &server_key.public, &mldsa.verifying_key);
    let (mut socks_client, mut socks_server) = io::duplex(4096);
    let client_task =
        tokio::spawn(async move { client_session_from_config(&cfg, &mut socks_server).await });

    socks_client
        .write_all(&socks_connect_domain("0.0.0.0", 0, 0x03))
        .await
        .expect("write UDP associate");
    let mut replies = [0_u8; 12];
    socks_client
        .read_exact(&mut replies)
        .await
        .expect("read UDP associate replies");
    assert_eq!(&replies[..2], &[0x05, 0x00]);
    assert_eq!(&replies[2..6], &[0x05, 0x00, 0x00, 0x01]);
    let bound = std::net::SocketAddr::from((
        std::net::Ipv4Addr::new(replies[6], replies[7], replies[8], replies[9]),
        u16::from_be_bytes([replies[10], replies[11]]),
    ));

    let udp_client = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind UDP client");
    let request = encode_udp_packet(&SocksUdpPacket {
        frag: 0,
        target: TargetAddr::domain("127.0.0.1", target_addr.port()).expect("target"),
        payload: b"question".to_vec(),
    })
    .expect("UDP packet encodes");
    udp_client
        .send_to(&request, bound)
        .await
        .expect("send UDP request");
    let mut response = vec![0_u8; 256];
    let read = udp_client
        .recv(&mut response)
        .await
        .expect("receive UDP response");
    let response = decode_udp_packet(&response[..read]).expect("response decodes");
    assert_eq!(response.payload, b"answer");

    socks_client.shutdown().await.expect("close control");
    let client_outcome = timeout(Duration::from_secs(5), client_task)
        .await
        .expect("client completes")
        .expect("client task")
        .expect("client session succeeds");
    assert_eq!(client_outcome.transport, TransportKind::Quic);
    assert_eq!(client_outcome.mode, ClientInnerMode::QuicStream);
    let server_outcome = timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server completes")
        .expect("server task")
        .expect("server accepts");
    assert!(matches!(
        server_outcome.outcome,
        QuicRuntimeOutcome::Authenticated { .. }
    ));
    target_task.await.expect("target task");
}

#[test]
fn scenario_quic_initial_dispatch_authenticates_and_rejects_bad_auth() {
    let server_key = x25519::generate_keypair();
    let server_public = server_key.public;
    let client_key = x25519::generate_keypair();
    let short_id = vec![1, 35, 69, 103, 137, 171, 205, 239];
    let now = current_test_unix_time();
    let dispatch_cfg = umbra_core::dispatch::ServerCfg {
        private_key: server_key.private,
        short_ids: vec![short_id.clone()],
        server_names: vec!["www.microsoft.com".to_owned()],
        dest: "www.microsoft.com:443".to_owned(),
        max_time_diff: 120,
        mldsa_seed: Secret::new([7_u8; 32]),
        hello_limits: umbra_core::dispatch::HelloReadLimits::default(),
    };
    let replay = ReplayCache::new(64, 120).expect("replay cache");
    let (datagram, token, handshake) =
        quic_initial_for_dispatch(&server_public, &client_key, &short_id, now, None);

    let decision = classify_quic_initial(
        datagram,
        DispatchContext {
            cfg: &dispatch_cfg,
            profile: &sample_dest_profile(),
            replay: &replay,
            now_unix: now,
        },
    )
    .expect("QUIC Initial classifies");
    let QuicDispatchDecision::Authenticated(authenticated) = decision else {
        panic!("QUIC Initial should authenticate");
    };
    assert_eq!(authenticated.sni, "www.microsoft.com");
    assert_eq!(authenticated.session_id, token);
    assert_eq!(authenticated.client_hello, handshake);

    let bad_replay = ReplayCache::new(64, 120).expect("replay cache");
    let bad = quic_initial_for_dispatch(
        &server_public,
        &client_key,
        &short_id,
        now,
        Some([0x55; 32]),
    )
    .0;
    let rejected = classify_quic_initial(
        bad.clone(),
        DispatchContext {
            cfg: &dispatch_cfg,
            profile: &sample_dest_profile(),
            replay: &bad_replay,
            now_unix: now,
        },
    )
    .expect("bad QUIC Initial classifies");
    assert!(matches!(
        rejected,
        QuicDispatchDecision::Fallback {
            reason: FallbackReason::AuthenticationRejected,
            datagram
        } if datagram == bad
    ));
}

#[test]
fn scenario_quic_client_initial_from_config_authenticates_against_dispatch() {
    let server_key = x25519::generate_keypair();
    let server_public = server_key.public;
    let cfg = ClientCfg::from_toml_str_with_overrides(
        &client_toml(),
        ClientConfigOverrides {
            transport: Some("quic".to_owned()),
            public_key: Some(b64_bytes(server_public.as_bytes())),
            ..ClientConfigOverrides::default()
        },
    )
    .expect("client config loads");
    let initial = build_quic_client_initial(&cfg).expect("QUIC Initial builds from config");
    let header = parse_quic_initial_header(&initial.datagram).expect("Initial header parses");
    assert_eq!(header.dcid, initial.dcid);
    assert_eq!(header.scid, initial.scid);
    assert_eq!(header.scid.len(), 8);
    assert!(initial.datagram.len() >= 1200);
    let parsed = parse_client_hello(&initial.client_hello).expect("ClientHello parses");
    assert_eq!(parsed.sni.as_deref(), Some("www.microsoft.com"));
    assert!(parsed.session_id.is_empty());

    let now = current_test_unix_time();
    let dispatch_cfg = umbra_core::dispatch::ServerCfg {
        private_key: server_key.private,
        short_ids: vec![cfg.short_id.clone()],
        server_names: vec![cfg.server_name.clone()],
        dest: "www.microsoft.com:443".to_owned(),
        max_time_diff: 120,
        mldsa_seed: Secret::new([7_u8; 32]),
        hello_limits: umbra_core::dispatch::HelloReadLimits::default(),
    };
    let replay = ReplayCache::new(64, 120).expect("replay cache");
    let decision = classify_quic_initial(
        initial.datagram,
        DispatchContext {
            cfg: &dispatch_cfg,
            profile: &sample_dest_profile(),
            replay: &replay,
            now_unix: now,
        },
    )
    .expect("QUIC Initial classifies");
    let QuicDispatchDecision::Authenticated(authenticated) = decision else {
        panic!("configured QUIC Initial should authenticate");
    };
    assert_eq!(authenticated.sni, cfg.server_name);
    assert_eq!(authenticated.session_id, initial.auth_token);
    assert_eq!(authenticated.client_hello, initial.client_hello);
}

#[tokio::test]
async fn scenario_client_runtime_binds_socks_listener() {
    let cfg = ClientCfg::from_toml_str(&client_toml()).expect("client config loads");
    let runtime = ClientRuntime::bind(cfg)
        .await
        .expect("client runtime binds");

    assert_ne!(runtime.local_addr().expect("socks addr").port(), 0);
}

#[tokio::test]
async fn scenario_client_runtime_accept_one_uses_injected_outer() {
    let cfg = ClientCfg::from_toml_str(&client_toml()).expect("client config loads");
    let runtime = ClientRuntime::bind(cfg)
        .await
        .expect("client runtime binds");
    let addr = runtime.local_addr().expect("runtime addr");
    let (outer_client, outer_server) = io::duplex(4096);
    let server_task = tokio::spawn(async move {
        let mut mux = MuxSession::server(outer_server, &umbra_inner::padding::PadScheme::none())
            .expect("server mux");
        let (mut stream, target) = mux.accept().await.expect("server accepts");
        let payload = loop {
            if let MuxEvent::Data { stream_id, payload } =
                mux.receive_next().await.expect("server receives data")
            {
                assert_eq!(stream_id, stream.stream_id);
                break payload;
            }
        };
        assert_eq!(payload, b"runtime");
        mux.send_window_update(
            stream.stream_id,
            u32::try_from(payload.len()).expect("payload length fits u32"),
        )
        .await
        .expect("window update");
        mux.send_data_wait_window(&mut stream, b"reply")
            .await
            .expect("server sends reply");
        mux.finish_stream(stream.stream_id)
            .await
            .expect("server sends fin");
        target
    });
    let accept_task = tokio::spawn(async move {
        Box::pin(
            runtime.accept_one_with_outer(|_plan| async move { Ok::<_, CoreError>(outer_client) }),
        )
        .await
    });
    let mut socks = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect socks runtime");
    socks
        .write_all(&socks_connect_domain("runtime.example", 443, 0x01))
        .await
        .expect("write request");
    let mut replies = [0_u8; 12];
    socks.read_exact(&mut replies).await.expect("read replies");
    assert_eq!(&replies[..2], &[0x05, 0x00]);
    assert_eq!(&replies[2..4], &[0x05, 0x00]);
    socks.write_all(b"runtime").await.expect("write payload");
    socks.shutdown().await.expect("close socks write side");
    let mut response = [0_u8; 5];
    socks
        .read_exact(&mut response)
        .await
        .expect("read response");
    assert_eq!(&response, b"reply");
    let outcome = timeout(Duration::from_secs(1), accept_task)
        .await
        .expect("accept completes")
        .expect("accept task")
        .expect("accept succeeds");
    assert_eq!(outcome.mode, ClientInnerMode::Mux);
    assert_eq!(
        server_task.await.expect("server task"),
        TargetAddr::domain("runtime.example", 443).expect("target")
    );
}

#[tokio::test]
async fn scenario_eof_closes_peer_direction() {
    let (mut left_writer, mut left_relay) = io::duplex(64);
    let (mut right_relay, mut right_peer) = io::duplex(64);
    let mut relay = Box::pin(relay_bidirectional(&mut left_relay, &mut right_relay));

    left_writer
        .write_all(b"hello")
        .await
        .expect("write left bytes");
    left_writer.shutdown().await.expect("left half-close");

    let mut observed = [0_u8; 5];
    {
        let mut read_right = Box::pin(right_peer.read_exact(&mut observed));
        timeout(Duration::from_secs(1), async {
            tokio::select! {
                read = &mut read_right => read.expect("right receives bytes"),
                outcome = &mut relay => panic!("relay finished too early: {outcome:?}"),
            }
        })
        .await
        .expect("right read completes");
    }
    assert_eq!(&observed, b"hello");
    right_peer.shutdown().await.expect("right half-close");

    let outcome = timeout(Duration::from_secs(1), &mut relay)
        .await
        .expect("relay finishes")
        .expect("relay succeeds");
    assert_eq!(outcome.left_to_right, 5);
}

#[test]
fn scenario_auth_path_waits_for_profile_rtt() {
    let timing = TimingAlignment::enabled(Duration::from_millis(2));

    assert_eq!(
        timing.delay_for(Duration::from_millis(40), Duration::from_millis(10)),
        Duration::from_millis(30)
    );
    assert_eq!(
        timing.delay_for(Duration::from_millis(40), Duration::from_millis(39)),
        Duration::ZERO
    );
}

#[test]
fn scenario_useless_flood_follows_fallback_policy() {
    let policy = UselessRecordPolicy {
        max_useless_records: 2,
        action: UselessRecordAction::ForwardToDest,
    };

    assert_eq!(policy.action_for(2), None);
    assert_eq!(
        policy.action_for(3),
        Some(UselessRecordAction::ForwardToDest)
    );
}

#[test]
fn scenario_forwarded_bytes_use_ordinary_relay_policy() {
    assert!(FallbackRelayPolicy::ordinary().is_probe_resistant());
    assert!(!FallbackRelayPolicy {
        rate_limited: true,
        early_close_on_garbage: false
    }
    .is_probe_resistant());
}

#[test]
fn scenario_probe_policy_validation_rejects_distinguishable_fallback() {
    assert_eq!(
        TimingAlignment::disabled().delay_for(Duration::from_secs(1), Duration::ZERO),
        Duration::ZERO
    );
    assert!(UselessRecordPolicy {
        max_useless_records: 1,
        action: UselessRecordAction::Close,
    }
    .validate()
    .is_ok());
    assert!(UselessRecordPolicy {
        max_useless_records: 0,
        action: UselessRecordAction::Close,
    }
    .validate()
    .is_err());
    assert!(ProbeResistancePolicy {
        fallback: FallbackRelayPolicy {
            rate_limited: false,
            early_close_on_garbage: true,
        },
        ..ProbeResistancePolicy::default()
    }
    .validate()
    .is_err());
}

#[tokio::test]
async fn scenario_realsite_triggers_spider_path() {
    let (client, mut site) = io::duplex(4096);
    let spider = tokio::spawn(run_realsite_spider(client, "/spider"));

    let mut request = vec![0_u8; 256];
    let read = site.read(&mut request).await.expect("read spider request");
    assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /spider HTTP/1.1"));
    site.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        .await
        .expect("write response");
    site.shutdown().await.expect("close site");

    spider
        .await
        .expect("spider task")
        .expect("spider completes");
}

fn quic_runtime_server_cfg(server_key: &x25519::Keypair, mldsa_seed: &[u8; 32]) -> ServerCfg {
    ServerCfg::from_toml_str(&format!(
        r#"
listen = "127.0.0.1:0"
udp_listen = "127.0.0.1:0"
private_key = "{}"
short_ids = ["0123456789abcdef"]
dest = "www.microsoft.com:443"
server_names = ["www.microsoft.com"]
max_time_diff = "120s"
mldsa_seed = "{}"
prebuild = true
padding_scheme = "none"
tcp_evasion = "off"
"#,
        b64_bytes(server_key.private.expose_secret()),
        b64_bytes(mldsa_seed)
    ))
    .expect("server config loads")
}

fn quic_runtime_client_cfg(
    quic_addr: std::net::SocketAddr,
    server_public: &x25519::PublicKeyBytes,
    mldsa_verify: &[u8],
) -> ClientCfg {
    ClientCfg::from_toml_str_with_overrides(
        &client_toml(),
        ClientConfigOverrides {
            server: Some(quic_addr.to_string()),
            transport: Some("quic".to_owned()),
            public_key: Some(b64_bytes(server_public.as_bytes())),
            mldsa_verify: Some(b64_bytes(mldsa_verify)),
            ..ClientConfigOverrides::default()
        },
    )
    .expect("client config loads")
}

fn tcp_runtime_client_cfg(
    server_addr: std::net::SocketAddr,
    server_public: &x25519::PublicKeyBytes,
    mldsa_verify: &[u8],
) -> ClientCfg {
    ClientCfg::from_toml_str_with_overrides(
        &client_toml(),
        ClientConfigOverrides {
            server: Some(server_addr.to_string()),
            transport: Some("tcp".to_owned()),
            public_key: Some(b64_bytes(server_public.as_bytes())),
            mldsa_verify: Some(b64_bytes(mldsa_verify)),
            ..ClientConfigOverrides::default()
        },
    )
    .expect("client config loads")
}

async fn spawn_ping_pong_target() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind target");
    let target_addr = target_listener.local_addr().expect("target addr");
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.expect("accept target");
        let mut request = [0_u8; 4];
        stream
            .read_exact(&mut request)
            .await
            .expect("target reads request");
        assert_eq!(&request, b"ping");
        stream
            .write_all(b"pong")
            .await
            .expect("target writes reply");
        stream.shutdown().await.expect("target closes");
    });
    (target_addr, target_task)
}

fn server_toml() -> String {
    format!(
        r#"
listen = "127.0.0.1:0"
udp_listen = "127.0.0.1:0"
private_key = "{}"
short_ids = ["", "0123456789abcdef"]
dest = "www.microsoft.com:443"
server_names = ["www.microsoft.com"]
max_time_diff = "120s"
mldsa_seed = "{}"
prebuild = true
padding_scheme = "none"
tcp_evasion = "off"
"#,
        b64(1),
        b64(2)
    )
}

#[tokio::test]
async fn scenario_client_runtime_accepts_concurrent_socks_sessions() {
    let outer_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind outer listener");
    let outer_addr = outer_listener.local_addr().expect("outer addr");
    let cfg = ClientCfg::from_toml_str_with_overrides(
        &client_toml(),
        ClientConfigOverrides {
            server: Some(outer_addr.to_string()),
            ..ClientConfigOverrides::default()
        },
    )
    .expect("client config loads");
    let runtime = ClientRuntime::bind(cfg)
        .await
        .expect("client runtime binds");
    let socks_addr = runtime.local_addr().expect("socks addr");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let runtime_task = tokio::spawn(async move {
        Box::pin(runtime.run_until_shutdown(async {
            let _ = shutdown_rx.await;
        }))
        .await
    });

    let first_socks = open_socks_connect(socks_addr, "first.example").await;
    let (first_outer, _) = timeout(Duration::from_secs(1), outer_listener.accept())
        .await
        .expect("first outer connection is not blocked")
        .expect("accept first outer");

    let second_socks = open_socks_connect(socks_addr, "second.example").await;
    let (second_outer, _) = timeout(Duration::from_secs(1), outer_listener.accept())
        .await
        .expect("second outer connection is accepted concurrently")
        .expect("accept second outer");

    drop(first_socks);
    drop(second_socks);
    drop(first_outer);
    drop(second_outer);
    shutdown_tx.send(()).expect("send shutdown");
    timeout(Duration::from_secs(1), runtime_task)
        .await
        .expect("runtime shuts down")
        .expect("join runtime")
        .expect("runtime returns ok");
}

async fn open_socks_connect(
    socks_addr: std::net::SocketAddr,
    domain: &str,
) -> tokio::net::TcpStream {
    let mut socks = tokio::net::TcpStream::connect(socks_addr)
        .await
        .expect("connect socks runtime");
    socks
        .write_all(&socks_connect_domain(domain, 443, 0x01))
        .await
        .expect("write socks connect");
    socks
}

fn client_toml() -> String {
    format!(
        r#"
server = "203.0.113.10:443"
transport = "tcp"
public_key = "{}"
short_id = "0123456789abcdef"
server_name = "www.microsoft.com"
fingerprint = "chrome-latest"
mldsa_verify = "{}"
spider_path = "/client-a"
socks_listen = "127.0.0.1:0"
mux = true
padding_scheme = "none"
tcp_evasion = "off"
"#,
        b64(3),
        b64(4)
    )
}

fn b64(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}

fn b64_bytes(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn current_test_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is valid")
        .as_secs()
}

fn quic_initial_for_dispatch(
    server_public: &x25519::PublicKeyBytes,
    client_key: &x25519::Keypair,
    short_id: &[u8],
    now: u64,
    token_override: Option<[u8; 32]>,
) -> (Vec<u8>, [u8; 32], Vec<u8>) {
    let mut profile = load_profile("chrome-latest").expect("profile loads");
    profile.alpn = vec!["h3".to_owned()];
    if !profile
        .extension_order
        .contains(&EXT_QUIC_TRANSPORT_PARAMETERS)
    {
        let insert_at = profile
            .extension_order
            .iter()
            .position(|ext| *ext == 0x0015)
            .unwrap_or(profile.extension_order.len());
        profile
            .extension_order
            .insert(insert_at, EXT_QUIC_TRANSPORT_PARAMETERS);
    }
    let grease = profile.quic.grease_parameter;
    let mlkem_key_exchange = hybrid_mlkem_key_exchange(client_key.public.as_bytes());
    let zero_handshake = build_client_hello_handshake(&ClientHelloParams {
        sni: "www.microsoft.com".to_owned(),
        session_id: Vec::new(),
        x25519_priv: *client_key.private.expose_secret(),
        x25519_pub: *client_key.public.as_bytes(),
        mlkem: MlkemShare::x25519_mlkem768(mlkem_key_exchange.clone()),
        profile: profile.clone(),
        random: [0x33; 32],
        quic_transport_parameters: vec![ClientQuicTransportParameter {
            id: grease,
            value: vec![0; 32],
        }],
    })
    .expect("zero QUIC ClientHello builds");
    let aad = quic_hello0(&zero_handshake, grease).expect("QUIC AAD builds");
    let shared =
        x25519::agree(&client_key.private, server_public.as_bytes()).expect("X25519 agrees");
    let token = token_override.unwrap_or_else(|| {
        try_seal_session_id(shared.expose_secret(), short_id, &aad, now)
            .expect("QUIC REALITY token seals")
    });
    let handshake = build_client_hello_handshake(&ClientHelloParams {
        sni: "www.microsoft.com".to_owned(),
        session_id: Vec::new(),
        x25519_priv: *client_key.private.expose_secret(),
        x25519_pub: *client_key.public.as_bytes(),
        mlkem: MlkemShare::x25519_mlkem768(mlkem_key_exchange),
        profile,
        random: [0x33; 32],
        quic_transport_parameters: vec![ClientQuicTransportParameter {
            id: grease,
            value: token.to_vec(),
        }],
    })
    .expect("auth QUIC ClientHello builds");
    assert_eq!(
        quic_hello0(&handshake, grease).expect("auth QUIC AAD builds"),
        aad
    );
    let datagram = build_quic_initial_crypto_packet(
        &handshake,
        &[1_u8, 2, 3, 4, 5, 6, 7, 8],
        &[0xa0_u8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7],
        &[],
    )
    .expect("QUIC Initial builds");
    (datagram, token, handshake)
}

fn hybrid_mlkem_key_exchange(x25519_public: &[u8; 32]) -> Vec<u8> {
    let mlkem = mlkem_keygen();
    let mut key_exchange = Vec::with_capacity(x25519_public.len() + mlkem.encapsulation_key.len());
    key_exchange.extend_from_slice(x25519_public);
    key_exchange.extend_from_slice(&mlkem.encapsulation_key);
    key_exchange
}

fn socks_connect_domain(domain: &str, port: u16, command: u8) -> Vec<u8> {
    let mut out = vec![0x05, 0x01, 0x00, 0x05, command, 0x00, 0x03];
    out.push(u8::try_from(domain.len()).expect("domain length fits"));
    out.extend_from_slice(domain.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out
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
