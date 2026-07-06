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
    assert!(!profile.ciphers.is_empty());
    assert!(!profile.extension_order.is_empty());
    assert!(!profile.grease_extension_slots.is_empty());
    assert!(!profile.supported_groups.is_empty());
    assert!(!profile.signature_algorithms.is_empty());
    assert_eq!(profile.alpn, ["h2", "http/1.1"]);
    assert_eq!(profile.padding_target, 512);
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
    let profile = load_profile("chrome-latest").expect("profile should load");
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
