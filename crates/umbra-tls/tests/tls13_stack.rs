//! Integration tests for component A: TLS 1.3 uTLS stack.

use proptest::prelude::*;
use umbra_crypto::x25519;
use umbra_fingerprint::{load_profile, FingerprintProfile};
use umbra_tls::{
    clienthello::{
        build_client_hello, hello0, ClientHelloParams, MlkemShare, EXT_QUIC_TRANSPORT_PARAMETERS,
        TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
    },
    handshake::{CertVerify, PeerKind, Tls13Client},
    keyschedule::{
        derive_secret, derive_secret_with_hash, derive_traffic_keys, empty_hash, finished_key,
        hkdf_extract, transcript_hash,
    },
    parse::parse_client_hello,
    records::{
        open_record, seal_record, RecordLayer, CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA,
        CONTENT_TYPE_HANDSHAKE,
    },
    server::{DestProfile, ForgedCert, Tls13Server},
    TlsError,
};

#[test]
fn scenario_session_id_and_key_share_are_caller_controlled() {
    let params = client_hello_params();
    let session_id = params.session_id;
    let public_key = params.x25519_pub;
    let record = build_client_hello(&params).expect("ClientHello should build");
    let parsed = parse_client_hello(&record).expect("ClientHello should parse");

    assert_eq!(parsed.session_id, session_id);
    assert_eq!(parsed.x25519_key_share, Some(public_key));
    assert_eq!(parsed.sni.as_deref(), Some("server.example"));
    assert_eq!(
        hello0(&record).expect("HELLO0 should build")[44..76],
        [0_u8; 32]
    );
}

#[test]
fn scenario_extension_order_follows_profile() {
    let params = client_hello_params();
    let record = build_client_hello(&params).expect("ClientHello should build");
    let parsed = parse_client_hello(&record).expect("ClientHello should parse");

    assert_eq!(parsed.extensions, params.profile.extension_order);
}

#[test]
fn scenario_quic_carrier_and_large_varints_are_parsed() {
    let mut params = client_hello_params();
    let padding_pos = params
        .profile
        .extension_order
        .iter()
        .position(|ext| *ext == 0x0015)
        .expect("profile has padding");
    params
        .profile
        .extension_order
        .insert(padding_pos, EXT_QUIC_TRANSPORT_PARAMETERS);
    params.profile.quic.transport_parameters = vec![
        params.profile.quic.grease_parameter,
        63,
        64,
        16_383,
        16_384,
        1_073_741_823,
        1_073_741_824,
    ];

    let record = build_client_hello(&params).expect("ClientHello should build");
    let parsed = parse_client_hello(&record).expect("ClientHello should parse");

    assert_eq!(
        parsed
            .quic_transport_parameters
            .iter()
            .map(|param| param.id)
            .collect::<Vec<_>>(),
        params.profile.quic.transport_parameters
    );
    assert_eq!(parsed.quic_auth_carriers, vec![Vec::<u8>::new()]);
}

#[test]
fn scenario_clienthello_fail_fast_errors() {
    let mut params = client_hello_params();
    let rendered = format!("{params:?}");
    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains("a5a5"));

    params.sni.clear();
    assert_eq!(
        build_client_hello(&params).expect_err("empty SNI must fail"),
        TlsError::InvalidInput("SNI is empty")
    );

    assert_eq!(
        hello0(&[0x16, 0x03, 0x03, 0x00]).expect_err("short record must fail"),
        TlsError::InvalidInput("short TLS record")
    );

    let mut raw = vec![0x01, 0x00, 0x00, 0x26, 0x03, 0x03];
    raw.extend_from_slice(&[0_u8; 32]);
    raw.push(0);
    assert_eq!(
        hello0(&raw).expect_err("short session id must fail"),
        TlsError::InvalidInput("session id is not 32 bytes")
    );
}

#[test]
fn scenario_rfc8448_key_schedule_vector() {
    let zeros = [0_u8; 32];
    let early_secret = hkdf_extract(&zeros, &zeros);
    assert_eq!(
        early_secret,
        hex_32(
            "33ad0a1c607ec03b09e6cd9893680ce2\
                10adf300aa1f2660e1b22e10f170f92a"
        )
    );

    let derived_for_handshake =
        derive_secret_with_hash(&early_secret, "derived", &empty_hash()).expect("derive");
    assert_eq!(
        derived_for_handshake,
        hex_32(
            "6f2615a108c702c5678f54fc9dbab697\
                16c076189c48250cebeac3576c3611ba"
        )
    );

    let ecdhe = hex_32(
        "8bd4054fb55b9d63fdfbacf9f04b9f0d\
                        35e6d63f537563efd46272900f89492d",
    );
    let handshake_secret = hkdf_extract(&derived_for_handshake, &ecdhe);
    assert_eq!(
        handshake_secret,
        hex_32(
            "1dc826e93606aa6fdc0aadc12f741b01\
                046aa6b99f691ed221a9f0ca043fbeac"
        )
    );

    let handshake_hash = hex_32(
        "860c06edc07858ee8e78f0e7428c58ed\
                                 d6b43f2ca3e6e95f02ed063cf0e1cad8",
    );
    let client_hs = derive_secret_with_hash(&handshake_secret, "c hs traffic", &handshake_hash)
        .expect("derive client hs");
    let server_hs = derive_secret_with_hash(&handshake_secret, "s hs traffic", &handshake_hash)
        .expect("derive server hs");

    assert_eq!(
        client_hs,
        hex_32(
            "b3eddb126e067f35a780b3abf45e2d8f\
                3b1a950738f52e9600746a0e27a55a21"
        )
    );
    assert_eq!(
        server_hs,
        hex_32(
            "b67b7d690cc16c4e75e54213cb2d37b4\
                e9c912bcded9105d42befd59d391ad38"
        )
    );

    let server_keys =
        derive_traffic_keys(TLS_AES_128_GCM_SHA256, &server_hs).expect("derive traffic keys");
    assert_eq!(server_keys.key, hex("3fce516009c21727d0f2e4e86ee403bc"));
    assert_eq!(server_keys.iv, hex_12("5d313eb2671276ee13000b30"));

    assert_eq!(
        derive_secret(&handshake_secret, "c hs traffic", b"transcript").expect("derive raw"),
        derive_secret_with_hash(
            &handshake_secret,
            "c hs traffic",
            &transcript_hash(b"transcript")
        )
        .expect("derive hash")
    );
    assert!(finished_key(&server_hs).is_ok());
    assert_eq!(
        derive_traffic_keys(0x9999, &server_hs).expect_err("unsupported suite must fail"),
        TlsError::UnsupportedCipherSuite(0x9999)
    );
}

#[test]
fn scenario_record_round_trip_all_supported_algorithms() {
    for cipher_suite in [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ] {
        let key = vec![0x41; key_len(cipher_suite)];
        let iv = [0x24_u8; 12];
        let record = seal_record(
            cipher_suite,
            &key,
            &iv,
            7,
            CONTENT_TYPE_HANDSHAKE,
            b"handshake bytes",
        )
        .expect("record should seal");
        let opened = open_record(cipher_suite, &key, &iv, 7, &record).expect("record should open");

        assert_eq!(opened.content_type, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(opened.plaintext, b"handshake bytes");
        assert_eq!(record[0], CONTENT_TYPE_APPLICATION_DATA);
    }
}

#[test]
fn scenario_record_layer_sequences_and_errors() {
    let key = vec![0x12; 16];
    let iv = [0x34_u8; 12];
    let mut write = RecordLayer::new(TLS_AES_128_GCM_SHA256, key.clone(), iv);
    let mut read = RecordLayer::new(TLS_AES_128_GCM_SHA256, key, iv);

    assert_eq!(write.sequence(), 0);
    let first = write
        .seal(CONTENT_TYPE_APPLICATION_DATA, b"first")
        .expect("seal first");
    assert_eq!(write.sequence(), 1);
    assert_eq!(read.open(&first).expect("open first").plaintext, b"first");
    assert_eq!(read.sequence(), 1);

    assert_eq!(
        open_record(TLS_AES_128_GCM_SHA256, &[0x12; 16], &iv, 0, &[0x16])
            .expect_err("short record must fail"),
        TlsError::InvalidInput("short TLS record")
    );
    assert_eq!(
        open_record(
            TLS_AES_128_GCM_SHA256,
            &[0x12; 16],
            &iv,
            0,
            &[0x16, 0x03, 0x03, 0x00, 0x00],
        )
        .expect_err("wrong type must fail"),
        TlsError::InvalidInput("protected record has bad type")
    );
    assert_eq!(
        open_record(
            TLS_AES_128_GCM_SHA256,
            &[0x12; 16],
            &iv,
            0,
            &[0x17, 0x03, 0x03, 0x00, 0x02, 0x00],
        )
        .expect_err("length mismatch must fail"),
        TlsError::InvalidInput("record length mismatch")
    );
}

#[test]
fn scenario_tampered_record_is_rejected() {
    let key = vec![0x55; 16];
    let iv = [0x66_u8; 12];
    let mut record = seal_record(
        TLS_AES_128_GCM_SHA256,
        &key,
        &iv,
        0,
        CONTENT_TYPE_ALERT,
        b"alert",
    )
    .expect("record should seal");
    let last = record.last_mut().expect("record has tag");
    *last ^= 0x01;

    assert_eq!(
        open_record(TLS_AES_128_GCM_SHA256, &key, &iv, 0, &record).expect_err("tamper must fail"),
        TlsError::AuthenticationFailed
    );
}

#[test]
fn scenario_server_echoes_compatibility_session_id() {
    let params = client_hello_params();
    let record = build_client_hello(&params).expect("ClientHello should build");
    let profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
    let (_server, outbound) =
        Tls13Server::accept(&record, forged_cert(), &profile).expect("server should accept");
    let (server_hello, _) = split_first_record_for_test(&outbound);
    let parsed = umbra_tls::handshake::parse_server_hello_record(server_hello)
        .expect("ServerHello should parse");

    assert_eq!(parsed.session_id, params.session_id);
}

#[test]
fn scenario_server_accept_requires_classic_x25519_key_share() {
    let mut params = client_hello_params();
    params.profile.supported_groups = vec![0x0a0a];
    let record = build_client_hello(&params).expect("ClientHello should build");
    let profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);

    let Err(err) = Tls13Server::accept(&record, forged_cert(), &profile) else {
        panic!("missing X25519 must fail");
    };
    assert_eq!(
        err,
        TlsError::InvalidInput("missing client X25519 key_share")
    );
}

#[test]
fn scenario_client_handshake_completes_against_test_server() {
    let params = client_hello_params();
    let profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
    let (mut client, chello) = Tls13Client::start(params).expect("client should start");
    let (mut server, server_flight) =
        Tls13Server::accept(&chello, forged_cert(), &profile).expect("server should accept");
    let client_out = client
        .drive(&server_flight, &AcceptAll)
        .expect("client should complete");
    let server_out = server
        .drive(&client_out.outbound)
        .expect("server should complete");

    assert!(client_out.complete);
    assert!(server_out.complete);
    assert!(server_out.outbound.is_empty());

    let request = client.app_seal(b"GET / HTTP/1.1").expect("app seal");
    assert_eq!(
        server.app_open(&request).expect("server app open"),
        b"GET / HTTP/1.1"
    );
    let response = server.app_seal(b"HTTP/1.1 200 OK").expect("app seal");
    assert_eq!(
        client.app_open(&response).expect("client app open"),
        b"HTTP/1.1 200 OK"
    );

    assert_eq!(
        Tls13Client::dummy_change_cipher_spec(),
        [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
    );
    assert_eq!(client.client_hello_record(), chello);
    assert_eq!(
        client
            .drive(&server_flight, &AcceptAll)
            .expect_err("second client drive must fail"),
        TlsError::InvalidInput("client handshake already complete")
    );
    assert_eq!(
        server
            .drive(&client_out.outbound)
            .expect_err("second server drive must fail"),
        TlsError::InvalidInput("server handshake already complete")
    );
}

#[test]
fn scenario_certificate_callback_can_reject_peer() {
    let params = client_hello_params();
    let profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
    let (mut client, chello) = Tls13Client::start(params).expect("client should start");
    let (_server, server_flight) =
        Tls13Server::accept(&chello, forged_cert(), &profile).expect("server should accept");

    assert_eq!(
        client
            .drive(&server_flight, &RejectAll)
            .expect_err("peer should be rejected"),
        TlsError::PeerRejected
    );
}

#[test]
fn scenario_certificate_verify_signature_is_checked() {
    let params = client_hello_params();
    let profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
    let (mut client, chello) = Tls13Client::start(params).expect("client should start");
    let (_server, server_flight) = Tls13Server::accept(
        &chello,
        forged_cert_with_mismatched_certificate_verify_key(),
        &profile,
    )
    .expect("server should sign with mismatched key");

    assert_eq!(
        client
            .drive(&server_flight, &AcceptAll)
            .expect_err("mismatched CertificateVerify key must fail"),
        TlsError::AuthenticationFailed
    );
}

#[test]
fn scenario_state_machines_fail_fast_before_connected_and_on_tamper() {
    let params = client_hello_params();
    let profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
    let (mut client, chello) = Tls13Client::start(params).expect("client should start");
    assert_eq!(
        client
            .app_seal(b"too early")
            .expect_err("client app before handshake must fail"),
        TlsError::InvalidInput("client is not connected")
    );

    let (mut server, server_flight) =
        Tls13Server::accept(&chello, forged_cert(), &profile).expect("server should accept");
    assert_eq!(
        server
            .app_seal(b"too early")
            .expect_err("server app before handshake must fail"),
        TlsError::InvalidInput("server is not connected")
    );

    let mut client_out = client
        .drive(&server_flight, &AcceptAll)
        .expect("client should complete")
        .outbound;
    *client_out
        .last_mut()
        .expect("client Finished record has tag") ^= 0x01;
    assert_eq!(
        server
            .drive(&client_out)
            .expect_err("tampered Finished must fail"),
        TlsError::AuthenticationFailed
    );
}

proptest! {
    #[test]
    fn scenario_arbitrary_bytes_do_not_panic(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = parse_client_hello(&input);
    }
}

struct AcceptAll;

impl CertVerify for AcceptAll {
    fn verify(&self, leaf_der: &[u8], chain: &[Vec<u8>]) -> PeerKind {
        assert!(!leaf_der.is_empty());
        assert!(chain.is_empty());
        PeerKind::UmbraTrusted
    }
}

struct RejectAll;

impl CertVerify for RejectAll {
    fn verify(&self, _leaf_der: &[u8], _chain: &[Vec<u8>]) -> PeerKind {
        PeerKind::Invalid
    }
}

fn client_hello_params() -> ClientHelloParams {
    let profile = load_profile("chrome-latest").expect("profile should load");
    params_with_profile(profile)
}

fn params_with_profile(profile: FingerprintProfile) -> ClientHelloParams {
    let keypair = x25519::generate_keypair();
    let x25519::Keypair { private, public } = keypair;
    ClientHelloParams {
        sni: "server.example".to_owned(),
        session_id: [0xa5; 32],
        x25519_priv: private.into_inner(),
        x25519_pub: public.into_bytes(),
        mlkem: MlkemShare::x25519_mlkem768(vec![0x42; 32]),
        profile,
        random: [0x11; 32],
    }
}

fn forged_cert() -> ForgedCert {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(["server.example".to_owned()])
            .expect("test certificate should generate");
    ForgedCert {
        leaf_der: cert.der().as_ref().to_vec(),
        chain_der: Vec::new(),
        certificate_verify_key_der: key_pair.serialize_der(),
    }
}

fn forged_cert_with_mismatched_certificate_verify_key() -> ForgedCert {
    let cert = forged_cert();
    let rcgen::CertifiedKey { key_pair, .. } =
        rcgen::generate_simple_self_signed(["server.example".to_owned()])
            .expect("test certificate should generate");
    ForgedCert {
        certificate_verify_key_der: key_pair.serialize_der(),
        ..cert
    }
}

fn split_first_record_for_test(input: &[u8]) -> (&[u8], &[u8]) {
    let len = usize::from(u16::from_be_bytes([input[3], input[4]]));
    input.split_at(5 + len)
}

fn key_len(cipher_suite: u16) -> usize {
    match cipher_suite {
        TLS_AES_128_GCM_SHA256 => 16,
        TLS_AES_256_GCM_SHA384 | TLS_CHACHA20_POLY1305_SHA256 => 32,
        _ => unreachable!("test only uses supported suites"),
    }
}

fn hex(input: &str) -> Vec<u8> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(compact.len() % 2, 0, "hex length must be even");
    (0..compact.len())
        .step_by(2)
        .map(|idx| {
            u8::from_str_radix(&compact[idx..idx + 2], 16).expect("test vector hex should parse")
        })
        .collect()
}

fn hex_32(input: &str) -> [u8; 32] {
    hex(input)
        .try_into()
        .expect("test vector should be 32 bytes")
}

fn hex_12(input: &str) -> [u8; 12] {
    hex(input)
        .try_into()
        .expect("test vector should be 12 bytes")
}
