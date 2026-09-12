//! Integration tests for fingerprint profile loading and self-checks.

use umbra_fingerprint::{
    grease::{is_grease, without_grease},
    ja3::{build_profile_fixture, ja3_ja4, parse_client_hello},
    ja3_ja4_with_transport, load_profile,
    profile::FingerprintError,
    ClientHelloFingerprint, EvidenceStatus, FingerprintProfile, Ja4Transport,
};

#[test]
fn scenario_known_profile_loads() {
    let profile = load_profile("chrome-latest").expect("profile should load");

    assert_eq!(profile.name, "chrome-latest");
    assert_eq!(
        profile.chrome_version,
        "Google Chrome 150.0.7871.47 macOS local capture 2026-07-08"
    );
    assert!(!profile.ciphers.is_empty());
    assert!(!profile.extension_order.is_empty());
    assert!(!profile.grease_extension_slots.is_empty());
    assert_eq!(profile.supported_versions, [10794, 772, 771]);
    assert!(!profile.supported_groups.is_empty());
    assert!(!profile.signature_algorithms.is_empty());
    assert_eq!(profile.alpn, ["h2", "http/1.1"]);
    assert_eq!(profile.padding_target, 1757);
}

#[test]
fn scenario_versioned_local_chrome_profile_loads() {
    let profile = load_profile("chrome-150-macos").expect("profile should load");

    assert_eq!(profile.name, "chrome-150-macos");
    assert_eq!(
        profile.chrome_version,
        "Google Chrome 150.0.7871.47 macOS local capture 2026-07-08"
    );
    assert_eq!(
        profile.ciphers,
        [
            43690, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156,
            157, 47, 53
        ]
    );
    assert_eq!(profile.grease_extension_slots, [0, 17]);
    assert_eq!(profile.supported_versions, [10794, 772, 771]);
    assert_eq!(profile.supported_groups, [43690, 4588, 29, 23, 24]);
    assert_eq!(profile.alpn, ["h2", "http/1.1"]);
    assert_eq!(profile.alps, ["h2"]);
    assert_eq!(profile.padding_target, 1757);
}

#[test]
fn scenario_latest_profile_tracks_versioned_capture() {
    let latest = load_profile("chrome-latest").expect("latest profile should load");
    let versioned = load_profile("chrome-150-macos").expect("versioned profile should load");

    assert_eq!(latest.chrome_version, versioned.chrome_version);
    assert_eq!(latest.ciphers, versioned.ciphers);
    assert_eq!(latest.extension_order, versioned.extension_order);
    assert_eq!(
        latest.grease_extension_slots,
        versioned.grease_extension_slots
    );
    assert_eq!(latest.supported_versions, versioned.supported_versions);
    assert_eq!(latest.supported_groups, versioned.supported_groups);
    assert_eq!(latest.signature_algorithms, versioned.signature_algorithms);
    assert_eq!(latest.alpn, versioned.alpn);
    assert_eq!(latest.alps, versioned.alps);
    assert_eq!(latest.padding_target, versioned.padding_target);
    assert_eq!(latest.expected_ja3, versioned.expected_ja3);
    assert_eq!(latest.expected_ja4, versioned.expected_ja4);
    assert_eq!(latest.evidence, versioned.evidence);
    assert_eq!(latest.quic, versioned.quic);
}

#[test]
fn scenario_unknown_profile_is_rejected() {
    assert!(matches!(
        load_profile("missing-profile"),
        Err(FingerprintError::NotFound(name)) if name == "missing-profile"
    ));
}

#[test]
fn scenario_generated_hello_matches_profile_identifiers() {
    let profile = load_profile("chrome-150-macos").expect("profile should load");
    let fixture = build_profile_fixture(&profile).expect("fixture should build");
    let parsed = parse_client_hello(&fixture).expect("fixture should parse");
    let (ja3, ja4) = ja3_ja4(&fixture).expect("fixture should fingerprint");

    assert_eq!(parsed.ciphers, profile.ciphers);
    assert_eq!(parsed.extensions, profile.extension_order);
    assert_eq!(parsed.supported_groups, profile.supported_groups);
    assert_eq!(parsed.supported_versions, profile.supported_versions);
    assert!(parsed.has_sni);
    assert_eq!(parsed.signature_algorithms, profile.signature_algorithms);
    assert_eq!(parsed.alpn, [b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert_eq!(ja3, profile.expected_ja3);
    assert_eq!(ja3, "fc513d165de2da9e593e11eddc48906e");
    assert_eq!(ja4, profile.expected_ja4);
    // Independently hashed with Python hashlib from the canonical strings in capture.md.
    assert_eq!(ja4, "t13d1516h2_8daaf6152771_806a8c22fdea");
}

#[test]
fn scenario_quic_profile_preserves_parameter_order() {
    let profile = load_profile("chrome-latest").expect("profile should load");

    assert_eq!(profile.quic.alpn, "h3");
    assert_eq!(profile.quic.scid_len, 8);
    assert_eq!(
        profile.quic.transport_parameters[0],
        profile.quic.grease_parameter
    );
    assert_eq!(
        profile.quic.transport_parameters,
        vec![10794, 1, 3, 4, 5, 6, 7, 8, 9, 11, 15]
    );
}

#[test]
fn scenario_grease_values_are_filtered_for_ja3() {
    assert!(is_grease(0x0a0a));
    assert!(is_grease(0x2a2a));
    assert!(!is_grease(0x1301));
    assert_eq!(without_grease(&[0x0a0a, 0x1301, 0x2a2a]), vec![0x1301]);
}

#[test]
fn scenario_malformed_clienthello_is_rejected() {
    assert!(matches!(
        parse_client_hello(&[0x16, 0x03, 0x01, 0x00]),
        Err(FingerprintError::InvalidClientHello)
    ));
    assert!(matches!(
        parse_client_hello(&[0x02, 0x00, 0x00, 0x00]),
        Err(FingerprintError::InvalidClientHello)
    ));
}

// Published wire fields and expected hash, not generated by Umbra's profile builder:
// https://github.com/FoxIO-LLC/ja4/blob/d3dedafd6d3ac27a37107183533fc7274c5f4ea9/technical_details/JA4.md#example
const PUBLISHED_JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";
const PUBLISHED_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];

// Minimal synthetic framing of the published inputs, not a browser capture.
fn wire_hello(ciphers: &[u16], extensions: Option<&[(u16, &[u8])]>) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.push(0); // session ID
    body.extend_from_slice(&u16::try_from(ciphers.len() * 2).unwrap().to_be_bytes());
    for cipher in ciphers {
        body.extend_from_slice(&cipher.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]); // compression
    if let Some(extensions) = extensions {
        let mut bytes = Vec::new();
        for (id, data) in extensions {
            bytes.extend_from_slice(&id.to_be_bytes());
            bytes.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(data);
        }
        body.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&bytes);
    }
    let mut hello = vec![1];
    hello.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    hello.extend_from_slice(&body);
    hello
}

fn published_wire_hello() -> Vec<u8> {
    wire_hello(
        PUBLISHED_CIPHERS,
        Some(&[
            (0x001b, &[]),
            (0x0000, &[0, 4, 0, 0, 1, b'a']),
            (0x0033, &[]),
            (0x0010, &[0, 3, 2, b'h', b'2']),
            (0x4469, &[]),
            (0x0017, &[]),
            (0x002d, &[]),
            (
                0x000d,
                &[0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1],
            ),
            (0x0005, &[]),
            (0x0023, &[]),
            (0x0012, &[]),
            (0x002b, &[4, 3, 4, 3, 3]),
            (0xff01, &[]),
            (0x000b, &[1, 0]),
            (0x000a, &[0, 2, 0, 29]),
            (0x0015, &[]),
        ]),
    )
}

fn published_fields() -> ClientHelloFingerprint {
    parse_client_hello(&published_wire_hello()).unwrap()
}

#[test]
fn scenario_ja4_matches_published_foxio_example() {
    let parsed = published_fields();
    assert_eq!(parsed.ja4(), PUBLISHED_JA4);
    assert_eq!(ja3_ja4(&published_wire_hello()).unwrap().1, PUBLISHED_JA4);
    // The definition separately publishes this hash without signatures.
    let mut no_signatures = parsed;
    no_signatures.signature_algorithms.clear();
    assert_eq!(no_signatures.ja4(), "t13d1516h2_8daaf6152771_6d807ffa2a79");
}

#[test]
fn scenario_ja4_transport_is_explicit_not_inferred_from_framing() {
    let handshake = published_wire_hello();
    let mut record = vec![0x16, 3, 1];
    record.extend_from_slice(&u16::try_from(handshake.len()).unwrap().to_be_bytes());
    record.extend_from_slice(&handshake);
    for input in [&handshake, &record] {
        assert_eq!(ja3_ja4(input).unwrap().1, PUBLISHED_JA4);
        let (ja3, ja4) = ja3_ja4_with_transport(input, Ja4Transport::Quic).unwrap();
        assert_eq!(ja3, published_fields().ja3_hash());
        assert_eq!(ja4, "q13d1516h2_8daaf6152771_e5627efa2ab1");
    }
}

#[test]
fn scenario_ja4_ignores_grease_and_sorts_only_ciphers_and_extensions() {
    let mut parsed = published_fields();
    let ja3 = parsed.ja3_hash();
    parsed.ciphers.extend([0x0a0a, 0xfafa]);
    parsed.extensions.extend([0x1a1a, 0xeaea]);
    parsed.supported_versions.extend([0x2a2a, 0xdada]);
    parsed.signature_algorithms.insert(1, 0x3a3a);
    parsed.supported_groups.push(0x4a4a);
    assert_eq!(parsed.ja4(), PUBLISHED_JA4);
    assert_eq!(parsed.ja3_hash(), ja3);
    parsed.ciphers.reverse();
    parsed.extensions.reverse();
    parsed.supported_versions.reverse();
    assert_eq!(parsed.ja4(), PUBLISHED_JA4);
    assert_ne!(parsed.ja3_hash(), ja3); // JA3 wire-order semantics are unchanged.
    parsed.signature_algorithms.reverse();
    assert_ne!(parsed.ja4(), PUBLISHED_JA4);
    assert_eq!(parsed.ja4().split('_').nth(1), Some("8daaf6152771"));
}

#[test]
fn scenario_ja4_caps_counts_but_hashes_all_values_and_includes_scsv() {
    let mut parsed = published_fields();
    parsed.ciphers = vec![0xfe00, 0x5600, 0x1301, 0x00ff, 0x0a0a];
    // Independent hashlib SHA-256 of "00ff,1301,5600,fe00".
    assert_eq!(parsed.ja4(), "t13d0416h2_130ea533afe5_e5627efa2ab1");
    parsed.ciphers = vec![0x1301; 100];
    parsed.extensions = (100..200).collect();
    assert!(parsed.ja4().starts_with("t12d9999h2_"));
    let before = parsed.ja4();
    parsed.ciphers.push(0x1302);
    parsed.extensions.push(200);
    let after = parsed.ja4();
    let before: Vec<_> = before.split('_').collect();
    let after: Vec<_> = after.split('_').collect();
    assert_eq!(before[0], after[0]);
    assert_ne!(before[1], after[1]);
    assert_ne!(before[2], after[2]);
}

#[test]
fn scenario_ja4_alpn_uses_first_protocol_endpoint_bytes() {
    let cases: &[(&[u8], &str)] = &[
        (b"h2", "h2"),
        (b"http/1.1", "h1"),
        (b"h3", "h3"),
        (b"X", "XX"),
        (b"", "00"),
        (&[0xab], "ab"),
        (&[0x20], "20"),
        (&[0xab, 0xcd], "ad"),
        (&[0x20, 0x61], "21"),
        (&[0x30, 0xab], "3b"),
        (&[0x61, 0x20], "60"),
        (&[0x30, 0x31, 0xab, 0xcd], "3d"),
        (&[0x30, 0xab, 0xcd, 0x31], "01"),
    ];
    for (protocol, expected) in cases {
        let mut parsed = published_fields();
        parsed.alpn = vec![protocol.to_vec(), b"ignored".to_vec()];
        assert_eq!(
            parsed.ja4(),
            format!("t13d1516{expected}_8daaf6152771_e5627efa2ab1")
        );
    }
    let mut parsed = published_fields();
    parsed.alpn.clear();
    assert_eq!(parsed.ja4(), "t13d151600_8daaf6152771_e5627efa2ab1");
}

#[test]
fn scenario_ja4_version_mapping_and_absent_or_grease_only_versions() {
    let mut parsed = published_fields();
    for (version, expected) in [
        (0x0304, "13"),
        (0x0303, "12"),
        (0x0302, "11"),
        (0x0301, "10"),
        (0x0300, "s3"),
        (0x0002, "s2"),
        (0xfeff, "d1"),
        (0xfefd, "d2"),
        (0xfefc, "d3"),
        (0x0000, "00"),
        (0xffff, "00"),
    ] {
        parsed.supported_versions = vec![0x0a0a, version];
        assert!(parsed.ja4().starts_with(&format!("t{expected}d1516h2_")));
    }
    parsed.supported_versions = vec![0x0303, 0xffff, 0x0304];
    assert!(parsed.ja4().starts_with("t00")); // highest unknown is not ignored
    parsed.supported_versions = vec![0x0a0a, 0xfafa];
    assert!(parsed.ja4().starts_with("t00"));
    parsed.extensions.retain(|extension| *extension != 0x002b);
    assert!(parsed.ja4().starts_with("t12")); // ClientHello, not record version
}

#[test]
fn scenario_ja4_missing_fields_and_empty_hashes() {
    let hello = wire_hello(&[0x0a0a], None);
    let mut parsed = parse_client_hello(&hello).unwrap();
    assert_eq!(parsed.ja4(), "t12i000000_000000000000_000000000000");
    parsed.ciphers.clear();
    assert_eq!(parsed.ja4(), "t12i000000_000000000000_000000000000");
    parsed.extensions = vec![0, 16, 0x0a0a];
    parsed.has_sni = true;
    parsed.alpn = vec![b"h2".to_vec()];
    assert_eq!(parsed.ja4(), "t12d0002h2_000000000000_000000000000");
    parsed.extensions = vec![13];
    parsed.signature_algorithms = vec![0x0a0a];
    assert!(parsed.ja4().ends_with("_06540eb5c95f")); // SHA-256("000d"), no underscore
    parsed.signature_algorithms.push(0x0403);
    assert!(parsed.ja4().ends_with("_79c50902419d")); // SHA-256("000d_0403")
}

#[test]
fn scenario_sni_and_alpn_are_counted_but_excluded_from_extension_hash() {
    let mut parsed = published_fields();
    parsed
        .extensions
        .retain(|extension| !matches!(extension, 0 | 16));
    parsed.has_sni = false;
    parsed.alpn.clear();
    assert_eq!(parsed.ja4(), "t13i151400_8daaf6152771_e5627efa2ab1");
}

#[test]
fn scenario_parser_retains_opaque_alpn_and_ordered_signature_bytes() {
    let hello = wire_hello(
        &[0x1301],
        Some(&[
            (16, &[0, 6, 2, 0xab, 0xcd, 2, b'h', b'2']),
            (13, &[0, 6, 8, 4, 0x0a, 0x0a, 4, 3]),
            (43, &[6, 3, 3, 0x0a, 0x0a, 3, 4]),
        ]),
    );
    let parsed = parse_client_hello(&hello).unwrap();
    assert_eq!(parsed.alpn, [vec![0xab, 0xcd], b"h2".to_vec()]);
    assert_eq!(parsed.signature_algorithms, [0x0804, 0x0a0a, 0x0403]);
    assert_eq!(parsed.supported_versions, [0x0303, 0x0a0a, 0x0304]);
    assert!(parsed.ja4().starts_with("t13i0103ad_"));
}

#[test]
fn scenario_parser_rejects_malformed_ja4_extension_vectors() {
    let cases: &[(u16, &[u8])] = &[
        (43, &[]),
        (43, &[0]),
        (43, &[1, 3]),
        (43, &[2, 3]),
        (43, &[2, 3, 4, 0]),
        (13, &[]),
        (13, &[0]),
        (13, &[0, 0]),
        (13, &[0, 1, 4]),
        (13, &[0, 2, 4]),
        (13, &[0, 2, 4, 3, 0]),
        (16, &[]),
        (16, &[0, 0]),
        (16, &[0, 1, 0]),
        (16, &[0, 2, 2, b'h']),
        (16, &[0, 3, 2, b'h', b'2', 0]),
        (16, &[0, 4, 2, b'h', b'2', 1]),
        (0, &[]),
        (0, &[0, 0]),
        (0, &[0, 3, 0, 0, 0]),
        (0, &[0, 4, 0, 0, 2, b'a']),
        (0, &[0, 4, 1, 0, 1, b'a']),
        (0, &[0, 4, 0, 0, 1, b'a', 0]),
        (0, &[0, 8, 0, 0, 1, b'a', 0, 0, 1, b'b']),
        (10, &[]),
        (10, &[0, 1, 0]),
        (11, &[]),
        (11, &[0]),
        (11, &[2, 0]),
    ];
    for (id, data) in cases {
        let hello = wire_hello(&[0x1301], Some(&[(*id, data)]));
        assert!(
            parse_client_hello(&hello).is_err(),
            "extension {id}: {data:?}"
        );
    }
    let duplicate = wire_hello(&[0x1301], Some(&[(13, &[0, 2, 4, 3]), (13, &[0, 2, 8, 4])]));
    assert!(parse_client_hello(&duplicate).is_err());
}

#[test]
fn scenario_parser_rejects_truncated_hello_and_extension_boundary_mismatch() {
    let hello = published_wire_hello();
    for len in 0..hello.len() {
        assert!(
            parse_client_hello(&hello[..len]).is_err(),
            "truncation at {len}"
        );
    }
    // One-cipher, empty-session framing gives an extension-length offset of 45.
    let mut hello = wire_hello(&[0x1301], Some(&[(1234, &[])]));
    hello[45..47].copy_from_slice(&3_u16.to_be_bytes());
    assert!(parse_client_hello(&hello).is_err()); // trailing data outside extension block
    hello[45..47].copy_from_slice(&5_u16.to_be_bytes());
    assert!(parse_client_hello(&hello).is_err()); // block beyond handshake
    assert!(parse_client_hello(&wire_hello(&[], None)).is_err());
    let mut hello = wire_hello(&[0x1301], None);
    hello[38] = 33; // session ID over protocol maximum
    assert!(parse_client_hello(&hello).is_err());
    let mut hello = wire_hello(&[0x1301], None);
    hello[40] = 1; // odd cipher vector length
    assert!(parse_client_hello(&hello).is_err());
    let mut hello = wire_hello(&[0x1301], None);
    hello[43] = 0; // empty compression vector
    assert!(parse_client_hello(&hello).is_err());
}

#[test]
fn scenario_missing_capture_evidence_is_not_promoted_by_fixture_checks() {
    for name in ["chrome-latest", "chrome-150-macos"] {
        let profile = load_profile(name).unwrap();
        assert_eq!(profile.evidence.parsed_tls, EvidenceStatus::Recorded);
        assert_eq!(
            profile.evidence.full_tls_payload,
            EvidenceStatus::Unverified
        );
        assert_eq!(profile.evidence.quic, EvidenceStatus::Unverified);
        let before = profile.evidence.clone();
        let fixture = build_profile_fixture(&profile).unwrap();
        assert_eq!(ja3_ja4(&fixture).unwrap().1, profile.expected_ja4);
        assert_eq!(profile.evidence, before);
    }
}

#[test]
fn scenario_profile_evidence_is_required_and_typed() {
    let text = include_str!("../../../fingerprints/chrome-150-macos.toml");
    let parsed: FingerprintProfile = toml::from_str(text).unwrap();
    assert_eq!(parsed.evidence.parsed_tls, EvidenceStatus::Recorded);
    for field in [
        "parsed_tls = \"recorded\"\n",
        "full_tls_payload = \"unverified\"\n",
        "quic = \"unverified\"\n",
    ] {
        assert!(toml::from_str::<FingerprintProfile>(&text.replace(field, "")).is_err());
    }
    assert!(toml::from_str::<FingerprintProfile>(&text.replace("recorded", "assumed")).is_err());
}

#[test]
fn scenario_fixture_rejects_unencodable_lengths() {
    let mut profile = load_profile("chrome-latest").unwrap();
    profile.supported_versions = vec![0x0304; 128];
    assert!(build_profile_fixture(&profile).is_err());
    profile.supported_versions = vec![0x0304];
    profile.alpn = vec!["a".repeat(256)];
    assert!(build_profile_fixture(&profile).is_err());
    profile.alpn = vec!["h2".into()];
    profile.signature_algorithms = vec![0x0403; 32768];
    assert!(build_profile_fixture(&profile).is_err());
}
