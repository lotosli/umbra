//! RFC 10024 interoperability against rustls/AWS-LC, forcing the hybrid group.
//!
//! These tests exchange real Finished messages and application ciphertext with
//! an independent TLS implementation. A classic X25519 handshake cannot pass.

use std::{
    io::{Cursor, Read, Write},
    sync::Arc,
};

use rustls::{crypto::aws_lc_rs, NamedGroup};
use umbra_crypto::{mlkem::mlkem_keygen, x25519};
use umbra_fingerprint::load_profile;
use umbra_tls::{
    clienthello::{
        ClientHelloParams, ClientQuicTransportParameter, MlkemShare, EXT_QUIC_TRANSPORT_PARAMETERS,
        GROUP_X25519_MLKEM768, TLS_AES_128_GCM_SHA256,
    },
    handshake::{parse_server_hello_record, CertVerify, PeerKind, Tls13Client},
    keyschedule::hkdf_expand_label_for_suite,
    parse::parse_client_hello,
    quic::{QuicTlsClient, QuicTlsServer, QuicTrafficSecrets},
    server::{DestProfile, ForgedCert, Tls13Server},
};

struct PinnedLeaf(Vec<u8>);

impl CertVerify for PinnedLeaf {
    fn verify(&self, leaf: &[u8], _chain: &[Vec<u8>]) -> PeerKind {
        if leaf == self.0 {
            PeerKind::UmbraTrusted
        } else {
            PeerKind::Invalid
        }
    }
}

fn certificate() -> ForgedCert {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["server.example".to_owned()]).unwrap();
    ForgedCert {
        leaf_der: cert.der().to_vec(),
        chain_der: vec![],
        certificate_verify_key_der: key_pair.serialize_der(),
    }
}

fn provider(include_classic_offer: bool) -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = aws_lc_rs::default_provider();
    provider.cipher_suites = vec![aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
    if include_classic_offer {
        // rustls reuses its hybrid X25519 component for the companion share.
        // Umbra authenticates that classic share; the server is forced to hybrid.
        provider.kx_groups.push(aws_lc_rs::kx_group::X25519);
    }
    Arc::new(provider)
}

fn server_config(cert: &ForgedCert, alpn: &[u8]) -> Arc<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder_with_provider(provider(false))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.leaf_der.clone().into()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.certificate_verify_key_der.clone())
                .into(),
        )
        .unwrap();
    config.alpn_protocols = vec![alpn.to_vec()];
    config.send_tls13_tickets = 0;
    Arc::new(config)
}

fn client_config(cert: &ForgedCert, alpn: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.leaf_der.clone().into()).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    Arc::new(config)
}

fn params(quic: bool) -> ClientHelloParams {
    let keypair = x25519::generate_keypair();
    let mlkem = mlkem_keygen();
    let mut share = mlkem.encapsulation_key;
    share.extend_from_slice(keypair.public.as_bytes());
    let mut profile = load_profile("chrome-latest").unwrap();
    assert!(profile.extension_order.contains(&0xfe0d));
    if quic {
        profile.alpn = vec!["h3".to_owned()];
        profile.supported_versions = vec![0x2a2a, 0x0304];
        profile.extension_order.push(EXT_QUIC_TRANSPORT_PARAMETERS);
    }
    ClientHelloParams {
        sni: "server.example".to_owned(),
        session_id: if quic { vec![] } else { vec![0x42; 32] },
        x25519_priv: *keypair.private.expose_secret(),
        x25519_pub: *keypair.public.as_bytes(),
        mlkem: MlkemShare::x25519_mlkem768_with_decapsulation_key(share, mlkem.decapsulation_key),
        profile,
        random: [0x24; 32],
        quic_transport_parameters: if quic {
            vec![ClientQuicTransportParameter {
                id: 4,
                value: vec![0x40, 0x40],
            }]
        } else {
            vec![]
        },
    }
}

fn assert_hybrid(peer: &rustls::CommonState) {
    assert!(!peer.is_handshaking());
    assert_eq!(
        peer.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::X25519MLKEM768,
    );
}

fn client_finished_record(flight: &[u8]) -> &[u8] {
    // A standard TCP client can emit its optional compatibility CCS first.
    let record = if flight.starts_with(&Tls13Client::dummy_change_cipher_spec()) {
        &flight[6..]
    } else {
        flight
    };
    assert_eq!(record[0], 23);
    assert_eq!(
        usize::from(u16::from_be_bytes([record[3], record[4]])) + 5,
        record.len()
    );
    record
}

#[test]
fn scenario_umbra_client_completes_forced_hybrid_with_standard_tls_server() {
    let cert = certificate();
    let verifier = PinnedLeaf(cert.leaf_der.clone());
    let mut peer = rustls::ServerConnection::new(server_config(&cert, b"h2")).unwrap();
    let (mut client, hello) = Tls13Client::start(params(false)).unwrap();
    peer.read_tls(&mut Cursor::new(hello)).unwrap();
    peer.process_new_packets().unwrap();
    let mut flight = vec![];
    peer.write_tls(&mut flight).unwrap();
    assert_eq!(
        parse_server_hello_record(
            &flight[..5 + usize::from(u16::from_be_bytes([flight[3], flight[4]]))]
        )
        .unwrap()
        .key_share_group,
        GROUP_X25519_MLKEM768
    );
    let mut finished = vec![];
    let mut complete = false;
    for fragment in flight.chunks(7) {
        let out = client.drive(fragment, &verifier).unwrap();
        complete |= out.complete;
        finished.extend_from_slice(&out.outbound);
    }
    assert!(complete);
    peer.read_tls(&mut Cursor::new(finished)).unwrap();
    peer.process_new_packets().unwrap();
    assert_hybrid(&peer);
    peer.read_tls(&mut Cursor::new(
        client.app_seal(b"hybrid request").unwrap(),
    ))
    .unwrap();
    peer.process_new_packets().unwrap();
    let mut request = [0; 14];
    peer.reader().read_exact(&mut request).unwrap();
    assert_eq!(&request, b"hybrid request");
    peer.writer().write_all(b"hybrid response").unwrap();
    let mut response = vec![];
    peer.write_tls(&mut response).unwrap();
    assert_eq!(client.app_open(&response).unwrap(), b"hybrid response");
}

#[test]
fn scenario_umbra_server_completes_forced_hybrid_with_standard_tls_client() {
    let cert = certificate();
    let mut peer = rustls::ClientConnection::new(
        client_config(&cert, b"h2"),
        "server.example".try_into().unwrap(),
    )
    .unwrap();
    let mut hello = vec![];
    peer.write_tls(&mut hello).unwrap();
    let parsed = parse_client_hello(&hello).unwrap();
    let hybrid = parsed
        .key_shares
        .iter()
        .find(|share| share.group == GROUP_X25519_MLKEM768)
        .unwrap();
    assert_eq!(
        &hybrid.key_exchange[1184..],
        parsed.x25519_key_share.unwrap()
    );
    let profile =
        DestProfile::from_fingerprint("server.example".to_owned(), &params(false).profile);
    let (mut server, flight) = Tls13Server::accept(&hello, cert, &profile).unwrap();
    assert_eq!(
        parse_server_hello_record(
            &flight[..5 + usize::from(u16::from_be_bytes([flight[3], flight[4]]))]
        )
        .unwrap()
        .key_share_group,
        GROUP_X25519_MLKEM768
    );
    peer.read_tls(&mut Cursor::new(flight)).unwrap();
    peer.process_new_packets().unwrap();
    assert_hybrid(&peer);
    let mut finished = vec![];
    peer.write_tls(&mut finished).unwrap();
    assert!(
        server
            .drive(client_finished_record(&finished))
            .unwrap()
            .complete
    );
    peer.writer().write_all(b"hybrid request").unwrap();
    let mut request = vec![];
    peer.write_tls(&mut request).unwrap();
    assert_eq!(server.app_open(&request).unwrap(), b"hybrid request");
    peer.read_tls(&mut Cursor::new(
        server.app_seal(b"hybrid response").unwrap(),
    ))
    .unwrap();
    peer.process_new_packets().unwrap();
    let mut response = [0; 15];
    peer.reader().read_exact(&mut response).unwrap();
    assert_eq!(&response, b"hybrid response");
}

fn one_rtt(change: Option<rustls::quic::KeyChange>) -> rustls::quic::Keys {
    match change.unwrap() {
        rustls::quic::KeyChange::OneRtt { keys, .. } => keys,
        rustls::quic::KeyChange::Handshake { .. } => panic!("expected 1-RTT keys"),
    }
}

fn ring_packet_key(secret: &[u8]) -> (ring::aead::LessSafeKey, [u8; 12]) {
    let key =
        hkdf_expand_label_for_suite(TLS_AES_128_GCM_SHA256, secret, "quic key", &[], 16).unwrap();
    let iv =
        hkdf_expand_label_for_suite(TLS_AES_128_GCM_SHA256, secret, "quic iv", &[], 12).unwrap();
    let key = ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &key).unwrap();
    (ring::aead::LessSafeKey::new(key), iv.try_into().unwrap())
}

fn quic_application_data(
    secrets: &QuicTrafficSecrets,
    peer: &rustls::quic::Keys,
    umbra_client: bool,
) {
    assert_eq!(secrets.cipher_suite, TLS_AES_128_GCM_SHA256);
    let (local, remote) = if umbra_client {
        (&secrets.client, &secrets.server)
    } else {
        (&secrets.server, &secrets.client)
    };
    // Packet number zero uses the IV unchanged; the same nonempty header is AAD.
    let header = b"\x40\x00";
    let (key, iv) = ring_packet_key(local);
    let mut request = b"hybrid QUIC request".to_vec();
    key.seal_in_place_append_tag(
        ring::aead::Nonce::assume_unique_for_key(iv),
        ring::aead::Aad::from(header),
        &mut request,
    )
    .unwrap();
    assert_eq!(
        peer.remote
            .packet
            .decrypt_in_place(0, header, &mut request)
            .unwrap(),
        b"hybrid QUIC request"
    );
    let mut response = b"hybrid QUIC response".to_vec();
    let tag = peer
        .local
        .packet
        .encrypt_in_place(0, header, &mut response)
        .unwrap();
    response.extend_from_slice(tag.as_ref());
    let (key, iv) = ring_packet_key(remote);
    assert_eq!(
        key.open_in_place(
            ring::aead::Nonce::assume_unique_for_key(iv),
            ring::aead::Aad::from(header),
            &mut response
        )
        .unwrap(),
        b"hybrid QUIC response"
    );
}

#[test]
fn scenario_umbra_quic_client_completes_forced_hybrid_with_standard_peer() {
    let cert = certificate();
    let verifier = PinnedLeaf(cert.leaf_der.clone());
    let mut peer = rustls::quic::ServerConnection::new(
        server_config(&cert, b"h3"),
        rustls::quic::Version::V1,
        vec![4, 2, 0x40, 0x80],
    )
    .unwrap();
    let (mut client, hello) = QuicTlsClient::start(&params(true)).unwrap();
    peer.read_hs(&hello).unwrap();
    let mut server_hello = vec![];
    assert!(matches!(
        peer.write_hs(&mut server_hello),
        Some(rustls::quic::KeyChange::Handshake { .. })
    ));
    client.read_server_hello(&server_hello).unwrap();
    let mut flight = vec![];
    let keys = one_rtt(peer.write_hs(&mut flight));
    let finished = client.read_server_flight(&flight, &verifier).unwrap();
    peer.read_hs(&finished.finished).unwrap();
    assert_hybrid(&peer);
    assert_eq!(finished.peer_transport_parameters, [4, 2, 0x40, 0x80]);
    assert_eq!(
        peer.quic_transport_parameters(),
        Some([4, 2, 0x40, 0x40].as_slice())
    );
    quic_application_data(&finished.application_secrets, &keys, true);
}

#[test]
fn scenario_umbra_quic_server_completes_forced_hybrid_with_standard_peer() {
    let cert = certificate();
    let mut peer = rustls::quic::ClientConnection::new(
        client_config(&cert, b"h3"),
        rustls::quic::Version::V1,
        "server.example".try_into().unwrap(),
        vec![4, 2, 0x40, 0x40],
    )
    .unwrap();
    let mut hello = vec![];
    assert!(peer.write_hs(&mut hello).is_none());
    let profile = DestProfile::from_fingerprint("server.example".to_owned(), &params(true).profile);
    let mut accepted = QuicTlsServer::accept_with_transport_parameters(
        &hello,
        cert,
        &profile,
        &[4, 2, 0x40, 0x80],
    )
    .unwrap();
    peer.read_hs(&accepted.server_hello).unwrap();
    assert!(matches!(
        peer.write_hs(&mut vec![]),
        Some(rustls::quic::KeyChange::Handshake { .. })
    ));
    peer.read_hs(&accepted.server_flight).unwrap();
    let mut finished = vec![];
    let keys = one_rtt(peer.write_hs(&mut finished));
    let secrets = accepted.server.read_client_finished(&finished).unwrap();
    assert_hybrid(&peer);
    assert_eq!(accepted.peer_transport_parameters, [4, 2, 0x40, 0x40]);
    assert_eq!(
        peer.quic_transport_parameters(),
        Some([4, 2, 0x40, 0x80].as_slice())
    );
    quic_application_data(&secrets, &keys, false);
}
