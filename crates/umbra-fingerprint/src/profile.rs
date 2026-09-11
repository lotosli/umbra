//! Fingerprint profile loading.

use std::{fs, path::PathBuf};

use serde::Deserialize;
use thiserror::Error;

const BUILTIN_PROFILES: &[(&str, &str)] = &[
    (
        "chrome-latest",
        include_str!("../../../fingerprints/chrome-latest.toml"),
    ),
    (
        "chrome-150-macos",
        include_str!("../../../fingerprints/chrome-150-macos.toml"),
    ),
];

/// Errors returned while loading or validating fingerprint profiles.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FingerprintError {
    /// Profile file could not be read.
    #[error("profile not found: {0}")]
    NotFound(String),
    /// Profile TOML could not be parsed.
    #[error("invalid profile TOML: {0}")]
    InvalidToml(#[from] toml::de::Error),
    /// Profile is missing required data.
    #[error("invalid profile: {0}")]
    InvalidProfile(&'static str),
    /// ClientHello bytes could not be parsed.
    #[error("invalid ClientHello")]
    InvalidClientHello,
}

/// Data-driven Chrome TLS fingerprint profile.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct FingerprintProfile {
    /// Profile name such as `chrome-latest`.
    pub name: String,
    /// Human-readable Chrome version or capture label.
    pub chrome_version: String,
    /// TLS cipher suite order, including GREASE values.
    pub ciphers: Vec<u16>,
    /// TLS extension order, including GREASE values.
    pub extension_order: Vec<u16>,
    /// Extension indexes where GREASE is expected.
    pub grease_extension_slots: Vec<usize>,
    /// Supported TLS versions in wire order, including GREASE values.
    pub supported_versions: Vec<u16>,
    /// Supported group order, including hybrid and GREASE groups.
    pub supported_groups: Vec<u16>,
    /// Signature algorithm order.
    pub signature_algorithms: Vec<u16>,
    /// ALPN protocol order.
    pub alpn: Vec<String>,
    /// ALPS/application_settings protocol order.
    pub alps: Vec<String>,
    /// ClientHello padding target length used by the TLS builder.
    pub padding_target: usize,
    /// Expected JA3 hash for the profile fixture.
    pub expected_ja3: String,
    /// Expected standard TCP JA4 for the recorded fields, not full-payload proof.
    pub expected_ja4: String,
    /// Required provenance: synthetic fixture self-checks do not upgrade evidence.
    pub evidence: CaptureEvidence,
    /// QUIC fingerprint data paired with this TLS profile.
    pub quic: QuicFingerprint,
}

/// Verification status of a specific kind of browser fingerprint evidence.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    /// A historical parsed-field transcription exists, but cannot be re-decoded.
    Recorded,
    /// Reviewed raw capture evidence supports this specific claim.
    Verified,
    /// Matching capture evidence is unavailable; generated fixtures are not proof.
    Unverified,
}

/// Separate evidence claims for parsed TLS fields, complete payloads, and QUIC.
///
/// These required declarations describe provenance, not a runtime verification
/// result. In particular, TLS identifier matches cannot verify payload or QUIC parity.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct CaptureEvidence {
    /// Provenance of the parsed TLS fields used by JA3/JA4 and order checks.
    pub parsed_tls: EvidenceStatus,
    /// Verification of complete TLS extension payloads against a raw capture.
    pub full_tls_payload: EvidenceStatus,
    /// Verification against a decoded browser QUIC Initial capture.
    pub quic: EvidenceStatus,
}

/// QUIC-visible Chrome fingerprint parameters.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct QuicFingerprint {
    /// QUIC versions offered by the client.
    pub versions: Vec<u32>,
    /// QUIC transport parameter identifiers in wire order.
    pub transport_parameters: Vec<u64>,
    /// GREASE transport parameter identifier used for auth carrier tests.
    pub grease_parameter: u64,
    /// QUIC ALPN, normally `h3`.
    pub alpn: String,
    /// Source connection ID length.
    pub scid_len: usize,
    /// HTTP/3 setting identifiers in wire order.
    pub h3_settings: Vec<u64>,
}

/// Load a named fingerprint profile.
///
/// Built-in profiles are embedded into release binaries from the repository
/// `fingerprints/` directory at compile time. Non-built-in names fall back to a
/// filesystem lookup in the same repository directory for local experiments.
pub fn load_profile(name: &str) -> Result<FingerprintProfile, FingerprintError> {
    if let Some((_, text)) = BUILTIN_PROFILES
        .iter()
        .find(|(profile_name, _)| *profile_name == name)
    {
        return parse_profile(text);
    }

    let path = profile_path(name);
    let text = fs::read_to_string(&path).map_err(|_| FingerprintError::NotFound(name.into()))?;
    parse_profile(&text)
}

fn parse_profile(text: &str) -> Result<FingerprintProfile, FingerprintError> {
    let profile: FingerprintProfile = toml::from_str(text)?;
    validate_profile(&profile)?;
    Ok(profile)
}

fn profile_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fingerprints")
        .join(format!("{name}.toml"))
}

fn validate_profile(profile: &FingerprintProfile) -> Result<(), FingerprintError> {
    if profile.name.is_empty() {
        return Err(FingerprintError::InvalidProfile("name is empty"));
    }
    if profile.ciphers.is_empty() {
        return Err(FingerprintError::InvalidProfile("ciphers are empty"));
    }
    if profile.extension_order.is_empty() {
        return Err(FingerprintError::InvalidProfile("extensions are empty"));
    }
    if profile.supported_versions.is_empty() {
        return Err(FingerprintError::InvalidProfile(
            "supported versions are empty",
        ));
    }
    if profile.supported_groups.is_empty() {
        return Err(FingerprintError::InvalidProfile(
            "supported groups are empty",
        ));
    }
    if profile.signature_algorithms.is_empty() {
        return Err(FingerprintError::InvalidProfile(
            "signature algorithms are empty",
        ));
    }
    if profile.alpn.is_empty() {
        return Err(FingerprintError::InvalidProfile("ALPN is empty"));
    }
    if profile.padding_target == 0 {
        return Err(FingerprintError::InvalidProfile("padding target is zero"));
    }
    if profile.quic.transport_parameters.is_empty() {
        return Err(FingerprintError::InvalidProfile(
            "QUIC transport parameters are empty",
        ));
    }
    if profile.quic.alpn != "h3" {
        return Err(FingerprintError::InvalidProfile("QUIC ALPN must be h3"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_validation_keeps_existing_required_fields() {
        type ProfileMutation = fn(&mut FingerprintProfile);
        let valid = load_profile("chrome-latest").unwrap();
        let cases: &[(&str, ProfileMutation)] = &[
            ("name is empty", |profile| profile.name.clear()),
            ("ciphers are empty", |profile| profile.ciphers.clear()),
            ("extensions are empty", |profile| {
                profile.extension_order.clear();
            }),
            ("supported versions are empty", |profile| {
                profile.supported_versions.clear();
            }),
            ("supported groups are empty", |profile| {
                profile.supported_groups.clear();
            }),
            ("signature algorithms are empty", |profile| {
                profile.signature_algorithms.clear();
            }),
            ("ALPN is empty", |profile| profile.alpn.clear()),
            ("padding target is zero", |profile| {
                profile.padding_target = 0;
            }),
            ("QUIC transport parameters are empty", |profile| {
                profile.quic.transport_parameters.clear();
            }),
            ("QUIC ALPN must be h3", |profile| {
                profile.quic.alpn = "h2".into();
            }),
        ];
        for (expected, mutate) in cases {
            let mut profile = valid.clone();
            mutate(&mut profile);
            let error = validate_profile(&profile).unwrap_err();
            assert!(
                matches!(error, FingerprintError::InvalidProfile(message) if message == *expected)
            );
            assert_eq!(error.to_string(), format!("invalid profile: {expected}"));
        }
    }

    #[test]
    fn invalid_profile_toml_and_missing_provenance_are_errors() {
        for text in ["not toml", "name = 'missing-fields'"] {
            let error = parse_profile(text).unwrap_err();
            assert!(matches!(error, FingerprintError::InvalidToml(_)));
            assert!(error.to_string().starts_with("invalid profile TOML:"));
        }
        let text = BUILTIN_PROFILES[0].1;
        let missing_evidence = text.replace("[evidence]", "[unrelated]");
        assert!(matches!(
            parse_profile(&missing_evidence),
            Err(FingerprintError::InvalidToml(_))
        ));
    }

    #[test]
    fn evidence_states_remain_distinct_declarations() {
        let evidence: CaptureEvidence = toml::from_str(
            "parsed_tls = 'recorded'\nfull_tls_payload = 'verified'\nquic = 'unverified'",
        )
        .unwrap();
        assert_eq!(evidence.parsed_tls, EvidenceStatus::Recorded);
        assert_eq!(evidence.full_tls_payload, EvidenceStatus::Verified);
        assert_eq!(evidence.quic, EvidenceStatus::Unverified);
        assert_ne!(evidence.parsed_tls, evidence.full_tls_payload);
        assert_ne!(evidence.full_tls_payload, evidence.quic);
    }
}
