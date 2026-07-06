//! Integration tests for server dispatch and probe fallback.

use std::time::Duration;

use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use umbra_core::{
    dispatch::{
        classify_client_hello, dispatch_with_connector, read_client_hello_raw, relay_prefixed,
        write_fallback_prefix, DispatchContext, DispatchDecision, DispatchOutcome, FallbackReason,
        HelloReadLimits, ServerCfg,
    },
    prefixed::PrefixedStream,
    CoreError,
};
use umbra_crypto::{mlkem::mlkem_keygen, secret::Secret, x25519};
use umbra_fingerprint::{load_profile, FingerprintProfile};
use umbra_reality::{
    auth::try_seal_session_id,
    prebuild::{CertTemplate, DestProfile},
    replay::ReplayCache,
};
use umbra_tls::clienthello::{build_client_hello, hello0, ClientHelloParams, MlkemShare};

const NOW: u64 = 1_765_000_000;
const SESSION_ID_START: usize = 44;

#[tokio::test]
async fn scenario_partial_clienthello_does_not_complete_before_response() {
    let fixture = authenticated_fixture();
    let (mut client, mut server) = io::duplex(4096);
    let mut pending = Box::pin(read_client_hello_raw(
        &mut server,
        HelloReadLimits::default(),
    ));

    client
        .write_all(&fixture.client_hello[..10])
        .await
        .expect("write partial ClientHello");

    assert!(
        timeout(Duration::from_millis(50), &mut pending)
            .await
            .is_err(),
        "ClientHello reader must wait for the full declared handshake"
    );
}

#[tokio::test]
async fn scenario_fragmented_clienthello_is_read_as_original_records() {
    let fixture = authenticated_fixture();
    let fragmented = fragmented_records(&fixture.client_hello);
    let (mut client, mut server) = io::duplex(4096);

    client
        .write_all(&fragmented)
        .await
        .expect("write fragmented ClientHello");
    drop(client);

    let raw = read_client_hello_raw(&mut server, HelloReadLimits::default())
        .await
        .expect("read complete fragmented ClientHello");

    assert_eq!(raw, fragmented);
}

#[tokio::test]
async fn scenario_read_limits_fail_fast_before_buffer_growth() {
    let fixture = authenticated_fixture();
    let (mut client, mut server) = io::duplex(4096);

    client
        .write_all(&fixture.client_hello)
        .await
        .expect("write ClientHello");

    let err = read_client_hello_raw(
        &mut server,
        HelloReadLimits {
            max_bytes: 16,
            ..HelloReadLimits::default()
        },
    )
    .await
    .expect_err("oversized ClientHello must fail");

    assert!(matches!(err, CoreError::ClientHelloTooLarge));
}

#[test]
fn scenario_valid_reality_token_enters_local_tls_path() {
    let fixture = authenticated_fixture();
    let decision = classify_client_hello(
        fixture.client_hello.clone(),
        DispatchContext {
            cfg: &fixture.cfg,
            profile: &fixture.dest_profile,
            replay: &fixture.replay,
            now_unix: fixture.now,
        },
    )
    .expect("dispatch classification");

    let DispatchDecision::Authenticated(authenticated) = decision else {
        panic!("valid REALITY token must select authenticated dispatch");
    };

    assert_eq!(authenticated.sni, "server.example");
    assert_eq!(authenticated.session_id, fixture.session_id);
    assert_eq!(authenticated.shared_secret.expose_secret(), &fixture.shared);
    assert!(!authenticated.server_flight.is_empty());
    assert_eq!(authenticated.server_flight[0], 0x16);
}

#[tokio::test]
async fn scenario_dispatch_authenticated_writes_server_flight() {
    let fixture = authenticated_fixture();
    let (mut client, server) = io::duplex(65_536);
    let mut dispatch = Box::pin(dispatch_with_connector(
        server,
        &fixture.cfg,
        &fixture.dest_profile,
        &fixture.replay,
        fixture.now,
        |_dest| async {
            Err::<io::DuplexStream, std::io::Error>(std::io::Error::other(
                "unexpected destination connect",
            ))
        },
    ));

    client
        .write_all(&fixture.client_hello)
        .await
        .expect("write ClientHello");

    let outcome = timeout(Duration::from_secs(1), &mut dispatch)
        .await
        .expect("dispatch completes")
        .expect("authenticated dispatch succeeds");

    let DispatchOutcome::Authenticated {
        sni,
        server_flight_len,
    } = outcome
    else {
        panic!("valid token must not connect to fallback destination");
    };
    assert_eq!(sni, "server.example");
    assert!(server_flight_len > 0);

    let mut server_flight = vec![0_u8; server_flight_len];
    client
        .read_exact(&mut server_flight)
        .await
        .expect("read server flight");
    assert_eq!(server_flight[0], 0x16);
}

#[tokio::test]
async fn scenario_bad_token_falls_back_and_forwards_exact_clienthello() {
    let fixture = authenticated_fixture();
    let mut tampered = fixture.client_hello.clone();
    tampered[SESSION_ID_START] ^= 0x80;

    let decision = classify_client_hello(
        tampered.clone(),
        DispatchContext {
            cfg: &fixture.cfg,
            profile: &fixture.dest_profile,
            replay: &fixture.replay,
            now_unix: fixture.now,
        },
    )
    .expect("dispatch classification");

    let DispatchDecision::Fallback { reason, chello_raw } = decision else {
        panic!("bad token must fall back to destination forwarding");
    };
    assert_eq!(reason, FallbackReason::AuthenticationRejected);
    assert_eq!(chello_raw, tampered);

    let (mut dest, mut dest_peer) = io::duplex(4096);
    write_fallback_prefix(&mut dest, &chello_raw)
        .await
        .expect("write fallback prefix");

    let mut forwarded = vec![0_u8; chello_raw.len()];
    dest_peer
        .read_exact(&mut forwarded)
        .await
        .expect("read forwarded ClientHello");
    assert_eq!(forwarded, chello_raw);
}

#[tokio::test]
async fn scenario_dispatch_fallback_relays_after_forwarded_clienthello() {
    let fixture = authenticated_fixture();
    let mut tampered = fixture.client_hello.clone();
    tampered[SESSION_ID_START] ^= 0x80;
    let (mut client, server) = io::duplex(65_536);
    let (dest_stream, mut dest_peer) = io::duplex(65_536);
    let mut dispatch = Box::pin(dispatch_with_connector(
        server,
        &fixture.cfg,
        &fixture.dest_profile,
        &fixture.replay,
        fixture.now,
        move |dest| async move {
            assert_eq!(dest, "dest.example:443");
            Ok::<io::DuplexStream, std::io::Error>(dest_stream)
        },
    ));

    client
        .write_all(&tampered)
        .await
        .expect("write tampered ClientHello");
    client.write_all(b"after").await.expect("write relay bytes");
    client.shutdown().await.expect("shutdown client write half");

    let mut forwarded = vec![0_u8; tampered.len() + b"after".len()];
    {
        let mut read_forwarded = Box::pin(dest_peer.read_exact(&mut forwarded));
        timeout(Duration::from_secs(1), async {
            tokio::select! {
                read = &mut read_forwarded => read.expect("read forwarded bytes"),
                outcome = &mut dispatch => panic!("dispatch finished before destination observed prefix: {outcome:?}"),
            }
        })
        .await
        .expect("destination receives prefix and relayed bytes");
    }
    assert_eq!(&forwarded[..tampered.len()], tampered.as_slice());
    assert_eq!(&forwarded[tampered.len()..], b"after");

    dest_peer
        .write_all(b"response")
        .await
        .expect("write destination response");
    dest_peer
        .shutdown()
        .await
        .expect("shutdown destination write half");

    let outcome = timeout(Duration::from_secs(1), &mut dispatch)
        .await
        .expect("dispatch finishes")
        .expect("fallback dispatch succeeds");
    assert_eq!(
        outcome,
        DispatchOutcome::Forwarded {
            reason: FallbackReason::AuthenticationRejected,
            client_to_dest: u64::try_from(b"after".len()).expect("len fits"),
            dest_to_client: u64::try_from(b"response".len()).expect("len fits"),
        }
    );

    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read destination response");
    assert_eq!(response, b"response");
}

#[test]
fn scenario_invalid_dispatch_config_fails_fast() {
    let mut fixture = authenticated_fixture();
    fixture.cfg.short_ids.clear();

    let result = classify_client_hello(
        fixture.client_hello.clone(),
        DispatchContext {
            cfg: &fixture.cfg,
            profile: &fixture.dest_profile,
            replay: &fixture.replay,
            now_unix: fixture.now,
        },
    );
    let Err(err) = result else {
        panic!("empty short id list must fail before fallback classification");
    };

    assert!(matches!(err, CoreError::InvalidConfig(_)));
}

#[tokio::test]
async fn scenario_prefixed_stream_replays_prefix_before_inner_bytes() {
    let (mut writer, inner) = io::duplex(64);
    writer.write_all(b"inner").await.expect("write inner bytes");
    drop(writer);

    let mut stream = PrefixedStream::new(b"prefix-".to_vec(), inner);
    let mut out = Vec::new();
    stream
        .read_to_end(&mut out)
        .await
        .expect("read prefixed stream");

    assert_eq!(out, b"prefix-inner");
}

#[tokio::test]
async fn scenario_relay_prefixed_copies_prefix_and_both_directions() {
    let (mut client_writer, client_stream) = io::duplex(64);
    let (dest_stream, mut dest_peer) = io::duplex(64);
    let mut relay = Box::pin(relay_prefixed(
        client_stream,
        dest_stream,
        b"prefix-".to_vec(),
    ));

    client_writer
        .write_all(b"client")
        .await
        .expect("write client bytes");
    client_writer
        .shutdown()
        .await
        .expect("shutdown client write half");

    let mut dest_received = vec![0_u8; b"prefix-client".len()];
    {
        let mut read_dest = Box::pin(dest_peer.read_exact(&mut dest_received));
        timeout(Duration::from_secs(1), async {
            tokio::select! {
                read = &mut read_dest => read.expect("read prefix and client bytes"),
                outcome = &mut relay => panic!("relay finished before destination read: {outcome:?}"),
            }
        })
        .await
        .expect("destination receives prefixed bytes");
    }
    assert_eq!(dest_received, b"prefix-client");

    dest_peer
        .write_all(b"dest")
        .await
        .expect("write destination bytes");
    dest_peer.shutdown().await.expect("shutdown destination");

    let copied = timeout(Duration::from_secs(1), &mut relay)
        .await
        .expect("relay finishes")
        .expect("relay succeeds");
    assert_eq!(
        copied,
        (
            u64::try_from(b"prefix-client".len()).expect("len fits"),
            u64::try_from(b"dest".len()).expect("len fits"),
        )
    );

    let mut response = Vec::new();
    client_writer
        .read_to_end(&mut response)
        .await
        .expect("read destination bytes");
    assert_eq!(response, b"dest");
}

struct Fixture {
    client_hello: Vec<u8>,
    cfg: ServerCfg,
    dest_profile: DestProfile,
    replay: ReplayCache,
    session_id: [u8; 32],
    shared: [u8; 32],
    now: u64,
}

fn authenticated_fixture() -> Fixture {
    let profile = load_profile("chrome-latest").expect("load fingerprint profile");
    let server_key = x25519::generate_keypair();
    let client_key = x25519::generate_keypair();
    let shared = x25519::agree(&client_key.private, server_key.public.as_bytes())
        .expect("derive shared secret")
        .into_inner();

    let zero_session = [0_u8; 32];
    let mlkem_key_exchange = hybrid_mlkem_key_exchange(client_key.public.as_bytes());
    let zero_hello = client_hello(&profile, &client_key, zero_session, &mlkem_key_exchange);
    let aad = hello0(&zero_hello).expect("derive HELLO0");
    let session_id = try_seal_session_id(&shared, b"short", &aad, NOW).expect("seal REALITY token");
    let client_hello = client_hello(&profile, &client_key, session_id, &mlkem_key_exchange);

    Fixture {
        client_hello,
        cfg: ServerCfg {
            private_key: server_key.private,
            short_ids: vec![b"short".to_vec()],
            server_names: vec!["server.example".to_owned()],
            dest: "dest.example:443".to_owned(),
            max_time_diff: 120,
            mldsa_seed: Secret::new([7_u8; 32]),
            hello_limits: HelloReadLimits::default(),
        },
        dest_profile: sample_dest_profile(),
        replay: ReplayCache::new(16, 120).expect("replay cache"),
        session_id,
        shared,
        now: NOW,
    }
}

fn client_hello(
    profile: &FingerprintProfile,
    keypair: &x25519::Keypair,
    session_id: [u8; 32],
    mlkem_key_exchange: &[u8],
) -> Vec<u8> {
    let x25519_pub = *keypair.public.as_bytes();
    build_client_hello(&ClientHelloParams {
        sni: "server.example".to_owned(),
        session_id: session_id.to_vec(),
        x25519_priv: *keypair.private.expose_secret(),
        x25519_pub,
        mlkem: MlkemShare::x25519_mlkem768(mlkem_key_exchange.to_vec()),
        profile: profile.clone(),
        random: [0xa5_u8; 32],
        quic_transport_parameters: Vec::new(),
    })
    .expect("build ClientHello")
}

fn hybrid_mlkem_key_exchange(x25519_public: &[u8; 32]) -> Vec<u8> {
    let mlkem = mlkem_keygen();
    let mut key_exchange = Vec::with_capacity(x25519_public.len() + mlkem.encapsulation_key.len());
    key_exchange.extend_from_slice(x25519_public);
    key_exchange.extend_from_slice(&mlkem.encapsulation_key);
    key_exchange
}

fn fragmented_records(record: &[u8]) -> Vec<u8> {
    assert_eq!(record[0], 0x16);
    let payload = &record[5..];
    let mid = payload.len() / 2;
    let mut out = tls_handshake_record(&payload[..mid]);
    out.extend_from_slice(&tls_handshake_record(&payload[mid..]));
    out
}

fn tls_handshake_record(payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(payload.len()).expect("payload fits TLS record");
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0x16);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
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
