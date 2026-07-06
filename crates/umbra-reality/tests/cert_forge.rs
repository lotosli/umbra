//! Integration tests for component E: forged certificate binding.

use std::time::Duration;

use umbra_crypto::{mldsa::mldsa_keygen_from_seed, secret::Secret};
use umbra_reality::{
    cert::{classify_peer_certificate, forge_leaf_certificate, PeerKind},
    prebuild::{CertTemplate, DestProfile},
};
use x509_parser::{extensions::ParsedExtension, prelude::*};

#[test]
fn scenario_san_mirrors_server_name_and_valid_binding_verifies() {
    let profile = sample_profile();
    let seed = Secret::new([7_u8; 32]);
    let mldsa = mldsa_keygen_from_seed(seed.expose_secret());
    let shared = [9_u8; 32];
    let session_id = [3_u8; 32];

    let forged = forge_leaf_certificate(&profile, "front.example", &shared, &session_id, &seed)
        .expect("forged leaf");
    let (_, cert) = X509Certificate::from_der(&forged.tls_cert.leaf_der).expect("parse leaf");

    assert!(!forged.tls_cert.chain_der.is_empty());
    assert!(!forged.leaf_private_key_der.is_empty());
    assert_eq!(cert.validity().not_before.timestamp(), 1_700_000_000);
    assert_eq!(cert.validity().not_after.timestamp(), 1_800_000_000);
    assert!(cert.subject().to_string().contains("CN=front.example"));
    assert!(cert.issuer().to_string().contains("CN=Template CA"));
    assert!(leaf_dns_names(&cert).contains(&"front.example".to_owned()));
    assert!(has_oid(&cert, "1.3.6.1.4.1.62397.1"));
    assert!(has_oid(&cert, "1.3.6.1.4.1.62397.2"));

    assert_eq!(
        classify_peer_certificate(
            &forged.tls_cert.leaf_der,
            &shared,
            &session_id,
            &mldsa.verifying_key,
            true,
        ),
        PeerKind::UmbraTrusted
    );
}

#[test]
fn scenario_wrong_shared_secret_does_not_verify() {
    let profile = sample_profile();
    let seed = Secret::new([7_u8; 32]);
    let mldsa = mldsa_keygen_from_seed(seed.expose_secret());
    let session_id = [3_u8; 32];
    let forged = forge_leaf_certificate(&profile, "front.example", &[9_u8; 32], &session_id, &seed)
        .expect("forged leaf");

    assert_eq!(
        classify_peer_certificate(
            &forged.tls_cert.leaf_der,
            &[8_u8; 32],
            &session_id,
            &mldsa.verifying_key,
            true,
        ),
        PeerKind::RealSite
    );
}

#[test]
fn scenario_tampered_pq_signature_is_rejected() {
    let profile = sample_profile();
    let seed = Secret::new([7_u8; 32]);
    let mldsa = mldsa_keygen_from_seed(seed.expose_secret());
    let shared = [9_u8; 32];
    let session_id = [3_u8; 32];
    let forged = forge_leaf_certificate(&profile, "front.example", &shared, &session_id, &seed)
        .expect("forged leaf");
    let mut tampered = forged.tls_cert.leaf_der.clone();
    let sig_pos = find_subslice(&tampered, &forged.mldsa_signature).expect("signature in DER");
    tampered[sig_pos] ^= 0x01;

    assert_eq!(
        classify_peer_certificate(&tampered, &shared, &session_id, &mldsa.verifying_key, true),
        PeerKind::RealSite
    );
}

#[test]
fn scenario_real_certificate_without_extensions_is_not_umbra_trusted() {
    let seed = Secret::new([7_u8; 32]);
    let mldsa = mldsa_keygen_from_seed(seed.expose_secret());
    let rcgen::CertifiedKey { cert, .. } =
        rcgen::generate_simple_self_signed(["front.example".to_owned()]).expect("real certificate");

    assert_eq!(
        classify_peer_certificate(
            cert.der().as_ref(),
            &[9_u8; 32],
            &[3_u8; 32],
            &mldsa.verifying_key,
            true,
        ),
        PeerKind::RealSite
    );
}

#[test]
fn scenario_tls_invalid_or_malformed_certificate_is_invalid() {
    let profile = sample_profile();
    let seed = Secret::new([7_u8; 32]);
    let mldsa = mldsa_keygen_from_seed(seed.expose_secret());
    let forged = forge_leaf_certificate(&profile, "front.example", &[9_u8; 32], &[3_u8; 32], &seed)
        .expect("forged leaf");

    assert_eq!(
        classify_peer_certificate(
            &forged.tls_cert.leaf_der,
            &[9_u8; 32],
            &[3_u8; 32],
            &mldsa.verifying_key,
            false,
        ),
        PeerKind::Invalid
    );
    assert_eq!(
        classify_peer_certificate(
            b"not der",
            &[9_u8; 32],
            &[3_u8; 32],
            &mldsa.verifying_key,
            true,
        ),
        PeerKind::Invalid
    );
}

fn leaf_dns_names(cert: &X509Certificate<'_>) -> Vec<String> {
    cert.extensions()
        .iter()
        .find_map(|extension| {
            if let ParsedExtension::SubjectAlternativeName(names) = extension.parsed_extension() {
                Some(
                    names
                        .general_names
                        .iter()
                        .filter_map(|name| {
                            if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                                Some((*dns).to_owned())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>(),
                )
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn has_oid(cert: &X509Certificate<'_>, oid: &str) -> bool {
    cert.extensions()
        .iter()
        .any(|extension| extension.oid.to_id_string() == oid)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn sample_profile() -> DestProfile {
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
