//! Integration tests for component A: TLS 1.3 uTLS stack.

use proptest::prelude::*;
use umbra_crypto::{mlkem::mlkem_keygen, x25519};
use umbra_fingerprint::{load_profile, FingerprintProfile};
use umbra_tls::{
    clienthello::{
        build_client_hello, build_client_hello_handshake, hello0, quic_hello0, ClientHelloParams,
        ClientQuicTransportParameter, MlkemShare, EXT_QUIC_TRANSPORT_PARAMETERS,
        TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
    },
    handshake::{CertVerify, PeerKind, Tls13Client},
    keyschedule::{
        derive_secret, derive_secret_with_hash, derive_tls13_secrets,
        derive_tls13_secrets_for_suite, derive_traffic_keys, empty_hash, finished_key,
        finished_verify_data, finished_verify_data_for_suite, hkdf_extract, transcript_hash,
        transcript_hash_for_suite,
    },
    parse::parse_client_hello,
    quic::{QuicTlsClient, QuicTlsServer},
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
    let session_id = params.session_id.clone();
    let public_key = params.x25519_pub;
    let record = build_client_hello(&params).expect("ClientHello should build");
    let parsed = parse_client_hello(&record).expect("ClientHello should parse");

    assert_eq!(parsed.session_id, session_id);
    assert_eq!(parsed.x25519_key_share, Some(public_key));
    assert_eq!(parsed.sni.as_deref(), Some("server.example"));
    assert_eq!(
        hello0(&record).expect("HELLO0 should build")[39..71],
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
fn scenario_supported_versions_follow_profile() {
    let params = client_hello_params();
    let record = build_client_hello(&params).expect("ClientHello should build");

    assert_eq!(
        supported_versions_from_record(&record),
        params.profile.supported_versions
    );
}

#[test]
fn scenario_quic_carrier_and_large_varints_are_parsed() {
    let mut params = client_hello_params();
    let padding_pos = quic_extension_insert_pos(&params.profile);
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
    params.quic_transport_parameters = params
        .profile
        .quic
        .transport_parameters
        .iter()
        .map(|id| ClientQuicTransportParameter {
            id: *id,
            value: Vec::new(),
        })
        .collect();

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
fn scenario_quic_transport_parameter_values_are_serialized() {
    let mut params = client_hello_params();
    params.session_id = Vec::new();
    params.profile.alpn = vec!["h3".to_owned()];
    let padding_pos = quic_extension_insert_pos(&params.profile);
    params
        .profile
        .extension_order
        .insert(padding_pos, EXT_QUIC_TRANSPORT_PARAMETERS);
    let grease = params.profile.quic.grease_parameter;
    params.quic_transport_parameters = vec![
        ClientQuicTransportParameter {
            id: grease,
            value: vec![0x11; 32],
        },
        ClientQuicTransportParameter {
            id: 0x1f,
            value: vec![0x22, 0x33],
        },
    ];

    let handshake = build_client_hello_handshake(&params).expect("raw ClientHello should build");
    let record = build_client_hello(&params).expect("ClientHello should build");
    assert_eq!(&record[5..], handshake.as_slice());
    let parsed = parse_client_hello(&record).expect("ClientHello should parse");

    assert!(parsed.session_id.is_empty());
    assert_eq!(
        parsed
            .quic_transport_parameters
            .iter()
            .find(|param| param.id == grease)
            .expect("grease parameter")
            .value,
        vec![0x11; 32]
    );
    assert_eq!(
        parsed
            .quic_transport_parameters
            .iter()
            .find(|param| param.id == 0x1f)
            .expect("extra parameter")
            .value,
        vec![0x22, 0x33]
    );

    let aad = quic_hello0(&handshake, grease).expect("QUIC AAD clears carrier");
    let aad_parsed = parse_client_hello(&aad).expect("QUIC AAD remains a ClientHello");
    assert_eq!(
        aad_parsed
            .quic_transport_parameters
            .iter()
            .find(|param| param.id == grease)
            .expect("grease parameter")
            .value,
        vec![0; 32]
    );
    assert_eq!(
        aad_parsed
            .quic_transport_parameters
            .iter()
            .find(|param| param.id == 0x1f)
            .expect("extra parameter")
            .value,
        vec![0x22, 0x33]
    );
    let record_aad = quic_hello0(&record, grease).expect("record-shaped QUIC AAD clears carrier");
    assert_eq!(&record_aad[..5], &record[..5]);
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

    let mut params = client_hello_params();
    params.session_id.clear();
    let raw = build_client_hello_handshake(&params).expect("empty session id is valid TLS");
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
fn scenario_full_schedule_matches_rfc8448_and_independent_sha384_reference() {
    // RFC 8448 section 3: CH, SH, EE, Certificate, CV, server Finished, client Finished.
    let transcript = hex(concat!(
        "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001",
        "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304",
        "080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000",
        "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000",
        "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3",
        "140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718",
        "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61",
    ));
    assert_eq!(transcript.len(), 979);
    let shared = hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    let published = [
        "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5",
        "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643",
        "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50",
        "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c",
    ];
    // SHA-384 values: independent Python hashlib/hmac RFC 8446 reference over the
    // same RFC bytes (not a published RFC 8448 SHA-384 handshake). HKDF output is
    // HMAC(PRK, uint16(HashLen)||uint8(LabelLen)||Label||uint8(HashLen)||Hash(T)||01).
    let sha384_reference = [
        "bbafec3b0ca7533f456f73d389ef910ec44f2c6fa5dc2e112a4414b6752a1d00ddf6d0ce9b6dd4b111e191562ed967be",
        "9aabfb28a3106d6af28555d12ee08fb6b233680580a2a2b7df5cce8742aeba5f8cc14daf944fa21ab06a713deaf829a7",
        "b496a8cef4fbd4a75ad8209682639a7278810704c35f3457c6775104d3ca14eb74045acf4d9a30446e4f164a7cf3d42c",
        "39419dc4397778d9772a6a75429fdc3fc3f12b28ddda960fd2e717d0c1a710e97dd9ccc5437cd864ff8b4f9e3d66ae6d",
    ];
    for suite in [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ] {
        let actual = derive_tls13_secrets_for_suite(
            suite,
            &shared,
            &transcript[..286],
            &transcript[..943],
            &transcript,
        )
        .unwrap();
        let expected = if suite == TLS_AES_256_GCM_SHA384 {
            sha384_reference
        } else {
            published
        };
        for (secret, value) in [
            &actual.client_application_traffic_secret,
            &actual.server_application_traffic_secret,
            &actual.exporter_master_secret,
            &actual.resumption_master_secret,
        ]
        .into_iter()
        .zip(expected)
        {
            assert_eq!(*secret, hex(value));
        }
        let changed = derive_tls13_secrets_for_suite(
            suite,
            &shared,
            &transcript[..286],
            &transcript[..943],
            b"different client Finished",
        )
        .unwrap();
        assert_eq!(
            actual.client_application_traffic_secret,
            changed.client_application_traffic_secret
        );
        assert_eq!(
            actual.exporter_master_secret,
            changed.exporter_master_secret
        );
        assert_ne!(
            actual.resumption_master_secret,
            changed.resumption_master_secret
        );
    }
    let actual =
        derive_tls13_secrets(&shared, &transcript[..286], &transcript[..943], &transcript).unwrap();
    assert_eq!(
        actual.client_handshake_traffic_secret,
        hex_32("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    );
    assert_eq!(
        actual.master_secret,
        hex_32("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
    );
    assert_eq!(
        actual.client_application_traffic_secret,
        hex_32(published[0])
    );
    assert_eq!(actual.resumption_master_secret, hex_32(published[3]));
}

#[test]
fn scenario_sha256_legacy_key_schedule_matches_suite_aware_schedule() {
    let ecdhe = [0x42_u8; 32];
    let handshake_transcript = b"client hello || server hello";
    let application_transcript = b"server flight || client finished";

    let legacy = derive_tls13_secrets(
        &ecdhe,
        handshake_transcript,
        b"through server finished",
        application_transcript,
    )
    .expect("legacy SHA-256 schedule");
    let suite = derive_tls13_secrets_for_suite(
        TLS_AES_128_GCM_SHA256,
        &ecdhe,
        handshake_transcript,
        b"through server finished",
        application_transcript,
    )
    .expect("suite-aware SHA-256 schedule");

    assert_eq!(suite.early_secret, legacy.early_secret);
    assert_eq!(suite.handshake_secret, legacy.handshake_secret);
    assert_eq!(
        suite.client_handshake_traffic_secret,
        legacy.client_handshake_traffic_secret
    );
    assert_eq!(
        suite.server_handshake_traffic_secret,
        legacy.server_handshake_traffic_secret
    );
    assert_eq!(suite.master_secret, legacy.master_secret);
    assert_eq!(
        suite.client_application_traffic_secret,
        legacy.client_application_traffic_secret
    );
    assert_eq!(
        suite.server_application_traffic_secret,
        legacy.server_application_traffic_secret
    );
    assert_eq!(suite.exporter_master_secret, legacy.exporter_master_secret);
    assert_eq!(
        suite.resumption_master_secret,
        legacy.resumption_master_secret
    );

    let legacy_finished = finished_verify_data(
        &legacy.server_handshake_traffic_secret,
        &transcript_hash(application_transcript),
    )
    .expect("legacy Finished verify data");
    let suite_finished = finished_verify_data_for_suite(
        TLS_AES_128_GCM_SHA256,
        &suite.server_handshake_traffic_secret,
        &transcript_hash_for_suite(TLS_AES_128_GCM_SHA256, application_transcript)
            .expect("suite transcript hash"),
    )
    .expect("suite Finished verify data");
    assert_eq!(suite_finished, legacy_finished);

    let sha384 = derive_tls13_secrets_for_suite(
        TLS_AES_256_GCM_SHA384,
        &ecdhe,
        handshake_transcript,
        b"through server finished",
        application_transcript,
    )
    .expect("SHA-384 schedule");
    let sha384_finished = finished_verify_data_for_suite(
        TLS_AES_256_GCM_SHA384,
        &sha384.server_handshake_traffic_secret,
        &transcript_hash_for_suite(TLS_AES_256_GCM_SHA384, application_transcript)
            .expect("SHA-384 transcript hash"),
    )
    .expect("SHA-384 Finished verify data");
    assert_eq!(sha384.server_handshake_traffic_secret.len(), 48);
    assert_eq!(sha384_finished.len(), 48);
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
    assert_eq!(client_out.peer_kind, Some(PeerKind::UmbraTrusted));
    assert!(server_out.complete);
    assert_eq!(server_out.peer_kind, None);
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
fn scenario_negotiated_alpn_is_published_only_after_verified_handshake() {
    for (selected, offer_alpn) in [
        (Some("http/1.1"), true),
        (Some("h2"), true),
        (None, true),
        (None, false),
    ] {
        let mut params = client_hello_params();
        params.profile.alpn = vec!["h2".into(), "http/1.1".into()];
        if !offer_alpn {
            params.profile.extension_order.retain(|id| *id != 0x0010);
        }
        let mut profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
        profile.alpn = selected.map(str::to_owned);
        let (mut client, hello) = Tls13Client::start(params).unwrap();
        assert_eq!(client.negotiated_alpn(), None);
        let (mut server, flight) = Tls13Server::accept(&hello, forged_cert(), &profile).unwrap();
        let last = flight.len() - 1;
        assert!(
            !client
                .drive(&flight[..last], &RealSiteVerifier)
                .unwrap()
                .complete
        );
        assert_eq!(client.negotiated_alpn(), None);
        assert!(client.app_seal(b"not authenticated").is_err());
        let out = client.drive(&flight[last..], &RealSiteVerifier).unwrap();
        assert!(out.complete);
        assert_eq!(out.peer_kind, Some(PeerKind::RealSite));
        assert_eq!(client.negotiated_alpn(), selected.map(str::as_bytes));
        assert!(server.drive(&out.outbound).unwrap().complete);
    }
}

#[test]
fn scenario_unoffered_empty_and_duplicate_alpn_are_rejected() {
    for (selected, offer_alpn, extension_ids, error) in [
        ("h3", true, vec![16], "unoffered ALPN protocol"),
        ("H2", true, vec![16], "unoffered ALPN protocol"),
        ("h2", false, vec![16], "unoffered ALPN protocol"),
        (
            "",
            true,
            vec![16],
            "ALPN must select exactly one nonempty protocol",
        ),
        (
            "h2",
            true,
            vec![16, 16],
            "duplicate EncryptedExtensions extension",
        ),
    ] {
        let mut params = client_hello_params();
        params.profile.alpn = vec!["h2".into(), "http/1.1".into()];
        if !offer_alpn {
            params.profile.extension_order.retain(|id| *id != 16);
        }
        let mut profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
        profile.alpn = Some(selected.into());
        profile.encrypted_extensions = extension_ids;
        let (mut client, hello) = Tls13Client::start(params).unwrap();
        let (_server, flight) = Tls13Server::accept(&hello, forged_cert(), &profile).unwrap();
        assert_eq!(
            client.drive(&flight, &AcceptAll),
            Err(TlsError::InvalidInput(error))
        );
        assert_eq!(client.negotiated_alpn(), None);
        assert!(client.app_seal(b"rejected").is_err());
        assert!(client.drive(&[], &AcceptAll).is_err());
        assert_eq!(client.negotiated_alpn(), None);
    }
}

#[test]
fn scenario_truncated_alpn_and_invalid_finished_never_publish_selection() {
    for truncate_alpn in [true, false] {
        let params = client_hello_params();
        let private = umbra_crypto::secret::Secret::new(params.x25519_priv);
        let mut profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
        profile.cipher_suite = TLS_AES_128_GCM_SHA256;
        profile.key_share_group = 0x001d;
        profile.alpn = Some("h2".into());
        let (mut client, hello) = Tls13Client::start(params).unwrap();
        let (_server, flight) = Tls13Server::accept(&hello, forged_cert(), &profile).unwrap();
        let (server_hello, encrypted) = split_first_record_for_test(&flight);
        let parsed = umbra_tls::handshake::parse_server_hello_record(server_hello).unwrap();
        let shared = x25519::agree(&private, &parsed.x25519_key_share).unwrap();
        let transcript = [&hello[5..], &server_hello[5..]].concat();
        let secrets = derive_tls13_secrets_for_suite(
            profile.cipher_suite,
            shared.expose_secret(),
            &transcript,
            &[],
            &[],
        )
        .unwrap();
        let keys = derive_traffic_keys(
            profile.cipher_suite,
            &secrets.server_handshake_traffic_secret,
        )
        .unwrap();
        let mut plaintext = open_record(profile.cipher_suite, &keys.key, &keys.iv, 0, encrypted)
            .unwrap()
            .plaintext;
        let expected = if truncate_alpn {
            // EE selects h2: make its name length exceed the ALPN payload without
            // changing the enclosing message lengths or the record authentication.
            assert_eq!(&plaintext[..13], &[8, 0, 0, 11, 0, 9, 0, 16, 0, 5, 0, 3, 2]);
            plaintext[12] = 3;
            TlsError::InvalidInput("ALPN must select exactly one nonempty protocol")
        } else {
            // Leave CertificateVerify valid but corrupt Finished inside a valid AEAD record.
            *plaintext.last_mut().unwrap() ^= 1;
            TlsError::AuthenticationFailed
        };
        let mut writer = RecordLayer::from_traffic_keys(profile.cipher_suite, keys);
        let before_finished = plaintext.len() - 36;
        let prefix = writer
            .seal(CONTENT_TYPE_HANDSHAKE, &plaintext[..before_finished])
            .unwrap();
        assert!(!client.drive(server_hello, &AcceptAll).unwrap().complete);
        assert!(!client.drive(&prefix, &AcceptAll).unwrap().complete);
        assert_eq!(client.negotiated_alpn(), None);
        let last = writer
            .seal(CONTENT_TYPE_HANDSHAKE, &plaintext[before_finished..])
            .unwrap();
        assert_eq!(client.drive(&last, &AcceptAll), Err(expected));
        assert_eq!(client.negotiated_alpn(), None);
        assert!(client.app_seal(b"unauthenticated").is_err());
    }
}

#[test]
fn scenario_quic_tls_raw_handshake_derives_matching_secrets() {
    let mut params = client_hello_params();
    params.session_id = Vec::new();
    params.profile.alpn = vec!["h3".into()];
    params.profile.supported_versions = vec![0x2a2a, 0x0304];
    params
        .profile
        .extension_order
        .push(EXT_QUIC_TRANSPORT_PARAMETERS);
    params.quic_transport_parameters = vec![ClientQuicTransportParameter {
        id: 0x1f,
        value: vec![0x01],
    }];
    let profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
    let (mut client, chello) = QuicTlsClient::start(&params).expect("QUIC client should start");

    assert_eq!(chello[0], 0x01);
    let server_transport_parameters = vec![0x04, 0x01, 0x40];
    let mut accepted = QuicTlsServer::accept_with_transport_parameters(
        &chello,
        forged_cert(),
        &profile,
        &server_transport_parameters,
    )
    .expect("QUIC server accepts");
    assert_eq!(accepted.server_hello[0], 0x02);
    assert_eq!(accepted.peer_transport_parameters, vec![0x1f, 0x01, 0x01]);
    let client_hs = client
        .read_server_hello(&accepted.server_hello)
        .expect("client reads ServerHello");
    assert_eq!(
        client_hs.cipher_suite,
        accepted.handshake_secrets.cipher_suite
    );
    assert_eq!(client_hs.client, accepted.handshake_secrets.client);
    assert_eq!(client_hs.server, accepted.handshake_secrets.server);

    let client_finished = client
        .read_server_flight(&accepted.server_flight, &AcceptAll)
        .expect("client reads server flight");
    assert_eq!(client_finished.peer_kind, PeerKind::UmbraTrusted);
    assert_eq!(
        client_finished.peer_transport_parameters,
        server_transport_parameters
    );
    assert_eq!(client_finished.finished[0], 0x14);
    let server_app = accepted
        .server
        .read_client_finished(&client_finished.finished)
        .expect("server reads client Finished");
    assert_eq!(
        server_app.cipher_suite,
        client_finished.application_secrets.cipher_suite
    );
    assert_eq!(
        server_app.client,
        client_finished.application_secrets.client
    );
    assert_eq!(
        server_app.server,
        client_finished.application_secrets.server
    );
}

#[test]
fn scenario_quic_tls_rejects_unoffered_alpn() {
    let mut params = client_hello_params();
    params.session_id.clear();
    params.profile.alpn = vec!["h3".into()];
    params.profile.supported_versions = vec![0x2a2a, 0x0304];
    let mut profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
    profile.alpn = Some("h2".into());
    let (mut client, hello) = QuicTlsClient::start(&params).unwrap();
    let accepted = QuicTlsServer::accept_with_transport_parameters(
        &hello,
        forged_cert(),
        &profile,
        &[4, 1, 64],
    )
    .unwrap();
    client.read_server_hello(&accepted.server_hello).unwrap();
    assert_eq!(
        client
            .read_server_flight(&accepted.server_flight, &AcceptAll)
            .err(),
        Some(TlsError::InvalidInput("unoffered ALPN protocol"))
    );
}

#[test]
fn scenario_quic_tls_rejects_invalid_version_offers_without_mutating_hello() {
    for versions in [
        vec![0x0303, 0x0304],
        vec![0x0303],
        vec![0x2a2a],
        vec![],
        vec![0x0304, 0x0305],
    ] {
        let mut params = client_hello_params();
        params.session_id.clear();
        params.profile.supported_versions = versions;
        let before = build_client_hello_handshake(&params).unwrap();
        assert_eq!(
            QuicTlsClient::start(&params).err(),
            Some(TlsError::InvalidInput(
                "QUIC supported_versions must contain only TLS 1.3 and GREASE"
            ))
        );
        assert_eq!(build_client_hello_handshake(&params).unwrap(), before);
    }
    let mut params = client_hello_params();
    params.session_id.clear();
    params.profile.supported_versions = vec![0x0a0a, 0x0304, 0xfafa];
    let before = build_client_hello_handshake(&params).unwrap();
    let (_, hello) = QuicTlsClient::start(&params).unwrap();
    assert_eq!(hello, before);
}

#[test]
fn scenario_standard_hybrid_wire_layout_and_invalid_classic_binding() {
    use umbra_tls::clienthello::GROUP_X25519_MLKEM768;
    use umbra_tls::handshake::parse_server_hello_record;
    let mut params = client_hello_params();
    let hello = build_client_hello(&params).unwrap();
    let parsed = parse_client_hello(&hello).unwrap();
    let hybrid = parsed
        .key_shares
        .iter()
        .find(|share| share.group == GROUP_X25519_MLKEM768)
        .unwrap();
    assert_eq!(hybrid.key_exchange.len(), 1216);
    assert_eq!(&hybrid.key_exchange[1184..], params.x25519_pub);
    let profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
    let (_, flight) = Tls13Server::accept(&hello, forged_cert(), &profile).unwrap();
    let server_hello = parse_server_hello_record(
        &flight[..5 + usize::from(u16::from_be_bytes([flight[3], flight[4]]))],
    )
    .unwrap();
    assert_eq!(server_hello.key_share_group, GROUP_X25519_MLKEM768);
    assert_eq!(server_hello.key_share.len(), 1120);
    assert_eq!(
        &server_hello.key_share[1088..],
        server_hello.x25519_key_share
    );

    params.mlkem.key_exchange[1184] ^= 1;
    let mismatched = build_client_hello(&params).unwrap();
    assert_eq!(
        Tls13Server::accept(&mismatched, forged_cert(), &profile).err(),
        Some(TlsError::InvalidInput(
            "hybrid and classic X25519 key_shares differ"
        ))
    );
    params.mlkem.key_exchange[1184] ^= 1;
    params.mlkem.key_exchange.rotate_right(32);
    let legacy = build_client_hello(&params).unwrap();
    assert!(Tls13Server::accept(&legacy, forged_cert(), &profile).is_err());
}

#[test]
fn scenario_client_rejects_legacy_server_hybrid_order_before_application_data() {
    use umbra_tls::handshake::parse_server_hello_record;
    let params = client_hello_params();
    let profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
    let (mut client, hello) = Tls13Client::start(params).unwrap();
    let (_, mut flight) = Tls13Server::accept(&hello, forged_cert(), &profile).unwrap();
    let record_len = 5 + usize::from(u16::from_be_bytes([flight[3], flight[4]]));
    let server_hello = parse_server_hello_record(&flight[..record_len]).unwrap();
    let share = server_hello.key_share;
    let start = flight[..record_len]
        .windows(share.len())
        .position(|bytes| bytes == share)
        .unwrap();
    flight[start..start + share.len()].rotate_right(32);
    assert!(client.drive(&flight, &AcceptAll).is_err());
    assert!(client.app_seal(b"must remain unavailable").is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn arbitrary_non_exact_hybrid_client_shares_fail_without_panic(bytes in prop::collection::vec(any::<u8>(), 0..2400)) {
        prop_assume!(bytes.len() != 1216);
        let mut params = client_hello_params();
        params.mlkem.key_exchange = bytes;
        let profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
        let hello = build_client_hello(&params).unwrap();
        prop_assert_eq!(Tls13Server::accept(&hello, forged_cert(), &profile).err(), Some(TlsError::InvalidInput(
            "invalid client hybrid key_share length"
        )));
    }
}

#[test]
fn scenario_quic_tls_rejects_compatibility_session_id() {
    let params = client_hello_params();

    let Err(err) = QuicTlsClient::start(&params) else {
        panic!("non-empty QUIC session id must fail");
    };
    assert_eq!(
        err,
        TlsError::InvalidInput("QUIC ClientHello legacy_session_id must be empty")
    );
}

#[test]
fn scenario_realsite_peer_kind_is_returned_to_runtime() {
    let params = client_hello_params();
    let profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
    let (mut client, chello) = Tls13Client::start(params).expect("client should start");
    let (_server, server_flight) =
        Tls13Server::accept(&chello, forged_cert(), &profile).expect("server should accept");

    let out = client
        .drive(&server_flight, &RealSiteVerifier)
        .expect("RealSite certificate still completes TLS");

    assert!(out.complete);
    assert_eq!(out.peer_kind, Some(PeerKind::RealSite));
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
    assert_eq!(client.negotiated_alpn(), None);
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
    assert_eq!(client.negotiated_alpn(), None);
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

#[test]
fn scenario_hello0_is_record_independent_and_compression_encoding_is_rfc8879() {
    let params = client_hello_params();
    let raw = build_client_hello_handshake(&params).unwrap();
    let record = build_client_hello(&params).unwrap();
    let expected = hello0(&raw).unwrap();
    assert_eq!(hello0(&record).unwrap(), expected);
    assert_eq!(expected.len(), raw.len());
    assert_eq!(extension_data_from_record(&record, 27), [2, 0, 2]);
    for size in [1, 3, 17, 64, raw.len() - 1] {
        let mut reframed = Vec::new();
        for chunk in raw.chunks(size) {
            reframed.extend_from_slice(&[22, 3, 1]);
            reframed.extend_from_slice(&u16::try_from(chunk.len()).unwrap().to_be_bytes());
            reframed.extend_from_slice(chunk);
        }
        assert_eq!(hello0(&reframed).unwrap(), expected);
    }
    for len in 0..raw.len() {
        assert!(hello0(&raw[..len]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(hello0(&trailing).is_err());
    let mut changed = raw;
    changed[6] ^= 1;
    assert_ne!(hello0(&changed).unwrap(), expected);
}

#[test]
fn scenario_standard_rustls_peer_interoperates_with_fragmentation_and_brotli() {
    for suite in [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ] {
        for algorithm in [
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P384_SHA384,
            &rcgen::PKCS_ED25519,
        ] {
            for compressed in [false, true] {
                rustls_interop(suite, algorithm, compressed);
            }
        }
    }
}

fn rustls_interop(suite: u16, algorithm: &'static rcgen::SignatureAlgorithm, compressed: bool) {
    use std::{
        io::{Cursor, Read, Write},
        sync::Arc,
    };
    let key = rcgen::KeyPair::generate_for(algorithm).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["server.example".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|candidate| u16::from(candidate.suite()) == suite);
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
    config.max_fragment_size = Some(64);
    config.send_tls13_tickets = 0;
    config.alpn_protocols = vec![b"h2".to_vec()];
    if !compressed {
        config.cert_compressors.clear();
    }
    let mut peer = rustls::ServerConnection::new(Arc::new(config)).unwrap();
    let mut params = client_hello_params();
    params.profile.signature_algorithms.push(0x0807);
    assert!(params.profile.extension_order.contains(&0xfe0d));
    let (mut client, mut hello) = Tls13Client::start(params).unwrap();
    hello.extend_from_slice(&Tls13Client::dummy_change_cipher_spec());
    peer.read_tls(&mut Cursor::new(hello)).unwrap();
    peer.process_new_packets().unwrap();
    let mut flight = Vec::new();
    peer.write_tls(&mut flight).unwrap();
    let mut outbound = Vec::new();
    let mut completed = false;
    for chunk in flight.chunks(7) {
        let out = client.drive(chunk, &RealSiteVerifier).unwrap();
        if out.complete {
            completed = true;
            assert_eq!(out.peer_kind, Some(PeerKind::RealSite));
        } else {
            assert_eq!(client.negotiated_alpn(), None);
        }
        outbound.extend_from_slice(&out.outbound);
    }
    assert!(completed);
    assert_eq!(client.negotiated_alpn(), Some(b"h2".as_slice()));
    assert!(client.take_pending_input().is_empty());
    peer.read_tls(&mut Cursor::new(outbound)).unwrap();
    peer.process_new_packets().unwrap();
    assert!(!peer.is_handshaking());
    let request = client.app_seal(b"standard-peer request").unwrap();
    peer.read_tls(&mut Cursor::new(request)).unwrap();
    peer.process_new_packets().unwrap();
    let mut actual = vec![0; b"standard-peer request".len()];
    peer.reader().read_exact(&mut actual).unwrap();
    assert_eq!(actual, b"standard-peer request");
    peer.writer().write_all(b"standard-peer response").unwrap();
    let mut response = Vec::new();
    peer.write_tls(&mut response).unwrap();
    assert_eq!(
        client.app_open(&response).unwrap(),
        b"standard-peer response"
    );
}

#[test]
fn scenario_streamed_client_rejects_invalid_ccs_and_bounds() {
    for invalid in [
        vec![20, 3, 3, 0, 1, 2],
        vec![20, 3, 3, 0, 2, 1, 1],
        vec![23, 3, 3, 0xff, 0xff],
    ] {
        let (mut client, _) = Tls13Client::start(client_hello_params()).unwrap();
        assert!(client.drive(&invalid, &AcceptAll).is_err());
        assert!(client.drive(&[], &AcceptAll).is_err());
        assert!(client.app_seal(b"not connected").is_err());
    }
    let (mut client, _) = Tls13Client::start(client_hello_params()).unwrap();
    assert!(client.drive(&vec![0; 1024 * 1024 + 1], &AcceptAll).is_err());
}

#[test]
fn scenario_fragmented_server_hello_large_chain_and_pending_input() {
    let params = client_hello_params();
    let profile = DestProfile::from_fingerprint("server.example".into(), &params.profile);
    let (mut client, hello) = Tls13Client::start(params).unwrap();
    let mut cert = forged_cert();
    cert.chain_der = vec![cert.leaf_der.clone(); 64];
    let (mut server, flight) = Tls13Server::accept(&hello, cert, &profile).unwrap();
    let (server_hello, encrypted) = split_first_record_for_test(&flight);
    assert!(encrypted.len() > 16384);
    let mut reframed = Vec::new();
    for fragment in server_hello[5..].chunks(3) {
        reframed.extend_from_slice(&[22, 3, 3]);
        reframed.extend_from_slice(&u16::try_from(fragment.len()).unwrap().to_be_bytes());
        reframed.extend_from_slice(fragment);
        reframed.extend_from_slice(&Tls13Client::dummy_change_cipher_spec());
    }
    reframed.extend_from_slice(encrypted);
    for chunk in reframed[..reframed.len() - 1].chunks(31) {
        assert!(!client.drive(chunk, &RealSiteVerifier).unwrap().complete);
    }
    assert!(client.take_pending_input().is_empty());
    let pending = [23, 3, 3, 0, 17, 0];
    let last = [&reframed[reframed.len() - 1..], pending.as_slice()].concat();
    let finished = client.drive(&last, &RealSiteVerifier).unwrap();
    assert!(finished.complete);
    assert_eq!(client.take_pending_input(), pending);
    assert!(client.take_pending_input().is_empty());
    assert!(server.drive(&finished.outbound).unwrap().complete);
    let response = server.app_seal(b"fragmented handshake succeeded").unwrap();
    assert_eq!(
        client.app_open(&response).unwrap(),
        b"fragmented handshake succeeded"
    );
}

#[test]
fn scenario_secret_holders_are_zeroizing_and_debug_is_redacted() {
    use zeroize::{Zeroize, ZeroizeOnDrop};
    fn drops_zeroized<T: ZeroizeOnDrop>() {}
    drops_zeroized::<umbra_tls::keyschedule::SuiteSecrets>();
    drops_zeroized::<umbra_tls::keyschedule::Tls13Secrets>();
    drops_zeroized::<umbra_tls::keyschedule::TrafficKeys>();
    drops_zeroized::<umbra_tls::quic::QuicTrafficSecrets>();
    drops_zeroized::<RecordLayer>();
    drops_zeroized::<ForgedCert>();
    let mut secrets = derive_tls13_secrets(&[42; 32], b"hs", b"sf", b"cf").unwrap();
    assert_eq!(format!("{secrets:?}"), "Tls13Secrets(<redacted>)");
    secrets.zeroize();
    assert_eq!(secrets.master_secret, [0; 32]);
    assert_eq!(secrets.client_application_traffic_secret, [0; 32]);
    let mut keys = derive_traffic_keys(TLS_AES_128_GCM_SHA256, &[42; 32]).unwrap();
    assert_eq!(format!("{keys:?}"), "TrafficKeys(<redacted>)");
    keys.zeroize();
    assert!(keys.key.is_empty());
    assert_eq!(keys.iv, [0; 12]);
    let mut cert = forged_cert();
    assert!(format!("{cert:?}").contains("<redacted>"));
    cert.zeroize();
    assert!(cert.certificate_verify_key_der.is_empty());
}

proptest! {
    #[test]
    fn scenario_arbitrary_bytes_do_not_panic(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = parse_client_hello(&input);
        let _ = hello0(&input);
        let _ = umbra_tls::handshake::parse_server_hello_record(&input);
        let _ = umbra_tls::handshake::parse_server_hello_handshake(&input);
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

struct RealSiteVerifier;

impl CertVerify for RealSiteVerifier {
    fn verify(&self, _leaf_der: &[u8], _chain: &[Vec<u8>]) -> PeerKind {
        PeerKind::RealSite
    }
}

fn client_hello_params() -> ClientHelloParams {
    let profile = load_profile("chrome-latest").expect("profile should load");
    params_with_profile(profile)
}

fn quic_extension_insert_pos(profile: &FingerprintProfile) -> usize {
    profile
        .extension_order
        .iter()
        .position(|ext| *ext == 0x0015)
        .unwrap_or(profile.extension_order.len())
}

fn supported_versions_from_record(record: &[u8]) -> Vec<u16> {
    let data = extension_data_from_record(record, 0x002b);
    let Some((&len, versions)) = data.split_first() else {
        return Vec::new();
    };
    assert_eq!(usize::from(len), versions.len());
    versions
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect()
}

fn extension_data_from_record(record: &[u8], target: u16) -> Vec<u8> {
    assert_eq!(record.first().copied(), Some(0x16));
    let record_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    let handshake = &record[5..5 + record_len];
    assert_eq!(handshake.first().copied(), Some(0x01));
    let handshake_len = (usize::from(handshake[1]) << 16)
        | (usize::from(handshake[2]) << 8)
        | usize::from(handshake[3]);
    let body = &handshake[4..4 + handshake_len];
    let mut offset = 2 + 32;
    let session_len = usize::from(body[offset]);
    offset += 1 + session_len;
    let cipher_len = usize::from(u16::from_be_bytes([body[offset], body[offset + 1]]));
    offset += 2 + cipher_len;
    let compression_len = usize::from(body[offset]);
    offset += 1 + compression_len;
    let extensions_len = usize::from(u16::from_be_bytes([body[offset], body[offset + 1]]));
    offset += 2;
    let extensions_end = offset + extensions_len;
    while offset < extensions_end {
        let ext = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let len = usize::from(u16::from_be_bytes([body[offset + 2], body[offset + 3]]));
        offset += 4;
        let data = &body[offset..offset + len];
        if ext == target {
            return data.to_vec();
        }
        offset += len;
    }
    Vec::new()
}

fn params_with_profile(profile: FingerprintProfile) -> ClientHelloParams {
    let keypair = x25519::generate_keypair();
    let x25519::Keypair { private, public } = keypair;
    let x25519_pub = public.into_bytes();
    ClientHelloParams {
        sni: "server.example".to_owned(),
        session_id: vec![0xa5; 32],
        x25519_priv: private.into_inner(),
        x25519_pub,
        mlkem: hybrid_mlkem_share(&x25519_pub),
        profile,
        random: [0x11; 32],
        quic_transport_parameters: Vec::new(),
    }
}

fn hybrid_mlkem_share(x25519_public: &[u8; 32]) -> MlkemShare {
    let mlkem = mlkem_keygen();
    let mut key_exchange = Vec::with_capacity(x25519_public.len() + mlkem.encapsulation_key.len());
    key_exchange.extend_from_slice(&mlkem.encapsulation_key);
    key_exchange.extend_from_slice(x25519_public);
    MlkemShare::x25519_mlkem768_with_decapsulation_key(key_exchange, mlkem.decapsulation_key)
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
    let mut cert = forged_cert();
    let rcgen::CertifiedKey { key_pair, .. } =
        rcgen::generate_simple_self_signed(["server.example".to_owned()])
            .expect("test certificate should generate");
    zeroize::Zeroize::zeroize(&mut cert);
    cert.certificate_verify_key_der = key_pair.serialize_der();
    cert
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
