//! Integration tests for fingerprint profile loading and self-checks.

use umbra_fingerprint::{
    grease::{is_grease, without_grease},
    ja3::{build_profile_fixture, ja3_ja4, parse_client_hello},
    load_profile,
    profile::FingerprintError,
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
    assert_eq!(ja3, profile.expected_ja3);
    assert_eq!(ja4, profile.expected_ja4);
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
