//! Forged REALITY certificate generation and client-side classification.

use std::{collections::BTreeSet, sync::Arc};

use ::time::OffsetDateTime;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::{
    client::{danger::ServerCertVerifier, WebPkiServerVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    RootCertStore,
};
use subtle::ConstantTimeEq;
use umbra_crypto::{
    kdf::hkdf_sha256,
    mac::hmac_sha256,
    mldsa::{mldsa_sign, mldsa_verify},
    secret::{Secret, SecretBytes},
};
use umbra_tls::server::ForgedCert;
use x509_parser::prelude::*;

use crate::{prebuild::DestProfile, RealityError};

/// Private extension carrying `HMAC-SHA256(cert_key, leaf_SPKI_DER)`.
pub const CERT_MAC_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1];
/// Private extension carrying `ML-DSA-65_Sign(mldsa_sk, leaf_SPKI_DER)`.
pub const CERT_MLDSA_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 2];

const CERT_MAC_OID_STR: &str = "1.3.6.1.4.1.62397.1";
const CERT_MLDSA_OID_STR: &str = "1.3.6.1.4.1.62397.2";
const CERT_KEY_SALT: &[u8] = b"umbra-cert-v1";

/// Certificate classification used by the REALITY client.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PeerKind {
    /// The peer leaf contains valid Umbra MAC and ML-DSA private extensions.
    UmbraTrusted,
    /// The peer presented an otherwise valid borrowed-site certificate.
    RealSite,
    /// The peer certificate was not TLS-valid or could not be parsed.
    Invalid,
}

/// A freshly generated forged leaf plus its signing key material.
#[derive(Debug)]
pub struct ForgedLeaf {
    /// TLS server certificate payload consumed by component A.
    pub tls_cert: ForgedCert,
    /// Leaf SubjectPublicKeyInfo DER authenticated by the private extensions.
    pub leaf_spki_der: Vec<u8>,
    /// Computed private MAC extension payload.
    pub cert_mac: [u8; 32],
    /// Computed ML-DSA extension payload.
    pub mldsa_signature: Vec<u8>,
}

/// Derive the certificate binding key.
pub fn cert_key(shared: &[u8], session_id: &[u8]) -> Result<[u8; 32], RealityError> {
    let key = SecretBytes::new(
        hkdf_sha256(CERT_KEY_SALT, shared, session_id, 32)
            .map_err(|_| RealityError::CertificateBindingInvalid("cert key derivation failed"))?,
    );
    key.expose_secret()
        .try_into()
        .map_err(|_| RealityError::CertificateBindingInvalid("cert key has wrong length"))
}

/// Compute the REALITY certificate MAC.
pub fn cert_mac(
    shared: &[u8],
    session_id: &[u8],
    leaf_spki_der: &[u8],
) -> Result<[u8; 32], RealityError> {
    let key = Secret::new(cert_key(shared, session_id)?);
    hmac_sha256(key.expose_secret(), leaf_spki_der)
        .map_err(|_| RealityError::CertificateBindingInvalid("cert MAC failed"))
}

/// Generate an ephemeral forged leaf from the destination profile template.
pub fn forge_leaf_certificate(
    profile: &DestProfile,
    server_name: &str,
    shared: &[u8],
    session_id: &[u8],
    mldsa_seed: &Secret<32>,
) -> Result<ForgedLeaf, RealityError> {
    if server_name.is_empty() {
        return Err(RealityError::CertificateForgeFailed("server name is empty"));
    }

    let leaf_key = KeyPair::generate()
        .map_err(|_| RealityError::CertificateForgeFailed("leaf key generation failed"))?;
    let leaf_spki_der = leaf_key.public_key_der();
    let cert_mac = cert_mac(shared, session_id, &leaf_spki_der)?;
    let mldsa_signature = mldsa_sign(mldsa_seed, &leaf_spki_der);

    let issuer_key = KeyPair::generate()
        .map_err(|_| RealityError::CertificateForgeFailed("issuer key generation failed"))?;
    let issuer_cert = issuer_params(profile)?
        .self_signed(&issuer_key)
        .map_err(|_| {
            RealityError::CertificateForgeFailed("issuer certificate generation failed")
        })?;
    let leaf_cert = leaf_params(profile, server_name, cert_mac, &mldsa_signature)?
        .signed_by(&leaf_key, &issuer_cert, &issuer_key)
        .map_err(|_| RealityError::CertificateForgeFailed("leaf certificate signing failed"))?;
    let leaf_private_key_der = leaf_key.serialize_der();

    Ok(ForgedLeaf {
        tls_cert: ForgedCert {
            leaf_der: leaf_cert.der().as_ref().to_vec(),
            chain_der: vec![issuer_cert.der().as_ref().to_vec()],
            certificate_verify_key_der: leaf_private_key_der,
        },
        leaf_spki_der,
        cert_mac,
        mldsa_signature,
    })
}

/// Classify a peer leaf certificate according to REALITY private extensions.
#[must_use]
pub fn classify_peer_certificate(
    leaf_der: &[u8],
    shared: &[u8],
    session_id: &[u8],
    mldsa_verifying_key: &[u8],
    tls_valid: bool,
) -> PeerKind {
    if !tls_valid {
        return PeerKind::Invalid;
    }
    let Ok((_, cert)) = X509Certificate::from_der(leaf_der) else {
        return PeerKind::Invalid;
    };
    let spki_der = cert.public_key().raw;
    let Ok(expected_mac) = cert_mac(shared, session_id, spki_der) else {
        return PeerKind::Invalid;
    };
    let extensions = extract_umbra_extensions(&cert);
    let Some(mac) = extensions.cert_mac else {
        return PeerKind::RealSite;
    };
    let Some(signature) = extensions.mldsa_signature else {
        return PeerKind::RealSite;
    };
    if mac.len() != 32 || !bool::from(expected_mac.as_slice().ct_eq(mac.as_slice())) {
        return PeerKind::RealSite;
    }
    if !mldsa_verify(mldsa_verifying_key, spki_der, &signature) {
        return PeerKind::RealSite;
    }
    PeerKind::UmbraTrusted
}

/// Verify an ordinary peer's chain, server name, and validity against public roots.
#[must_use]
pub fn verify_site_certificate(leaf_der: &[u8], chain: &[Vec<u8>], server_name: &str) -> bool {
    verify_site_certificate_with_roots(
        leaf_der,
        chain,
        server_name,
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
        UnixTime::now(),
    )
}

fn verify_site_certificate_with_roots(
    leaf_der: &[u8],
    chain: &[Vec<u8>],
    server_name: &str,
    roots: RootCertStore,
    now: UnixTime,
) -> bool {
    let Ok(name) = ServerName::try_from(server_name) else {
        return false;
    };
    let Ok(verifier) = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build() else {
        return false;
    };
    let intermediates = chain
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect::<Vec<_>>();
    verifier
        .verify_server_cert(
            &CertificateDer::from(leaf_der),
            &intermediates,
            &name,
            &[],
            now,
        )
        .is_ok()
}

fn leaf_params(
    profile: &DestProfile,
    server_name: &str,
    mac: [u8; 32],
    mldsa_signature: &[u8],
) -> Result<CertificateParams, RealityError> {
    let mut names = BTreeSet::new();
    names.insert(server_name.to_owned());
    names.extend(profile.leaf_template.san_dns.iter().cloned());
    let mut params = CertificateParams::new(names.into_iter().collect::<Vec<_>>())
        .map_err(|_| RealityError::CertificateForgeFailed("SAN set is invalid"))?;
    params.distinguished_name = dn_with_common_name(server_name);
    params.not_before = unix_time(profile.leaf_template.not_before_unix)?;
    params.not_after = unix_time(profile.leaf_template.not_after_unix)?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            CERT_MAC_OID,
            der_octet_string(&mac),
        ));
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            CERT_MLDSA_OID,
            der_octet_string(mldsa_signature),
        ));
    Ok(params)
}

fn issuer_params(profile: &DestProfile) -> Result<CertificateParams, RealityError> {
    let mut params = CertificateParams::default();
    params.distinguished_name = dn_with_common_name(&issuer_common_name(profile));
    params.not_before = unix_time(profile.leaf_template.not_before_unix)?;
    params.not_after = unix_time(profile.leaf_template.not_after_unix)?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    Ok(params)
}

fn issuer_common_name(profile: &DestProfile) -> String {
    common_name_from_dn_string(&profile.leaf_template.issuer)
        .or_else(|| common_name_from_dn_string(&profile.leaf_template.subject))
        .unwrap_or_else(|| profile.dest.clone())
}

fn common_name_from_dn_string(input: &str) -> Option<String> {
    input.split(',').find_map(|part| {
        let trimmed = part.trim();
        trimmed
            .strip_prefix("CN=")
            .or_else(|| trimmed.strip_prefix("commonName="))
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn dn_with_common_name(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

fn unix_time(value: u64) -> Result<OffsetDateTime, RealityError> {
    let timestamp = i64::try_from(value)
        .map_err(|_| RealityError::CertificateForgeFailed("certificate time is too large"))?;
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|_| RealityError::CertificateForgeFailed("certificate time is invalid"))
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
struct UmbraExtensions {
    cert_mac: Option<Vec<u8>>,
    mldsa_signature: Option<Vec<u8>>,
}

fn extract_umbra_extensions(cert: &X509Certificate<'_>) -> UmbraExtensions {
    let mut out = UmbraExtensions::default();
    for extension in cert.extensions() {
        match extension.oid.to_id_string().as_str() {
            CERT_MAC_OID_STR => out.cert_mac = parse_der_octet_string(extension.value),
            CERT_MLDSA_OID_STR => out.mldsa_signature = parse_der_octet_string(extension.value),
            _ => {}
        }
    }
    out
}

fn der_octet_string(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + der_len_len(input.len()) + input.len());
    out.push(0x04);
    push_der_len(input.len(), &mut out);
    out.extend_from_slice(input);
    out
}

fn parse_der_octet_string(input: &[u8]) -> Option<Vec<u8>> {
    if input.first() != Some(&0x04) {
        return None;
    }
    let (len, header_len) = parse_der_len(&input[1..])?;
    let start = 1_usize.checked_add(header_len)?;
    let end = start.checked_add(len)?;
    if end == input.len() {
        Some(input[start..end].to_vec())
    } else {
        None
    }
}

fn der_len_len(len: usize) -> usize {
    if len < 128 {
        1
    } else {
        len.to_be_bytes()
            .into_iter()
            .skip_while(|byte| *byte == 0)
            .count()
            + 1
    }
}

fn push_der_len(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        if let Ok(short_len) = u8::try_from(len) {
            out.push(short_len);
        }
        return;
    }
    let bytes: Vec<u8> = len
        .to_be_bytes()
        .into_iter()
        .skip_while(|byte| *byte == 0)
        .collect();
    let Ok(octet_count) = u8::try_from(bytes.len()) else {
        return;
    };
    out.push(0x80 | octet_count);
    out.extend_from_slice(&bytes);
}

fn parse_der_len(input: &[u8]) -> Option<(usize, usize)> {
    let first = *input.first()?;
    if first & 0x80 == 0 {
        return Some((usize::from(first), 1));
    }
    let octets = usize::from(first & 0x7f);
    if octets == 0 || octets > std::mem::size_of::<usize>() || input.len() < 1 + octets {
        return None;
    }
    let mut len = 0_usize;
    for byte in &input[1..=octets] {
        len = len.checked_shl(8)?.checked_add(usize::from(*byte))?;
    }
    Some((len, 1 + octets))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn scenario_ordinary_certificate_requires_trusted_root_name_and_time() {
        let root_key = KeyPair::generate().expect("root key");
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root = root_params.self_signed(&root_key).expect("root cert");
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(vec!["site.example".to_owned()]).expect("SAN");
        params.not_before = unix_time(1_700_000_000).expect("not before");
        params.not_after = unix_time(1_800_000_000).expect("not after");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &root, &root_key).expect("leaf cert");
        let mut roots = RootCertStore::empty();
        roots.add(root.der().clone()).expect("trusted root");
        let now = UnixTime::since_unix_epoch(Duration::from_secs(1_750_000_000));
        assert!(verify_site_certificate_with_roots(
            cert.der(),
            &[],
            "site.example",
            roots.clone(),
            now,
        ));
        for name in ["other.example", "not a dns name"] {
            assert!(!verify_site_certificate_with_roots(
                cert.der(),
                &[],
                name,
                roots.clone(),
                now,
            ));
        }
        for timestamp in [1_600_000_000, 1_900_000_000] {
            assert!(!verify_site_certificate_with_roots(
                cert.der(),
                &[],
                "site.example",
                roots.clone(),
                UnixTime::since_unix_epoch(Duration::from_secs(timestamp)),
            ));
        }
        assert!(!verify_site_certificate_with_roots(
            cert.der(),
            &[],
            "site.example",
            RootCertStore::empty(),
            now,
        ));
        assert!(!verify_site_certificate_with_roots(
            b"invalid DER",
            &[],
            "site.example",
            roots,
            now,
        ));
        assert!(!verify_site_certificate(cert.der(), &[], "site.example"));
    }

    #[test]
    fn scenario_ordinary_certificate_verifies_intermediate_chain() {
        let root_key = KeyPair::generate().expect("root key");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.distinguished_name = dn_with_common_name("Test root");
        let root = params.self_signed(&root_key).expect("root");
        let intermediate_key = KeyPair::generate().expect("intermediate key");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.distinguished_name = dn_with_common_name("Test intermediate");
        let intermediate = params
            .signed_by(&intermediate_key, &root, &root_key)
            .expect("intermediate");
        let key = KeyPair::generate().expect("leaf key");
        let cert = CertificateParams::new(vec!["site.example".to_owned()])
            .expect("SAN")
            .signed_by(&key, &intermediate, &intermediate_key)
            .expect("leaf");
        let mut roots = RootCertStore::empty();
        roots.add(root.der().clone()).expect("root trust");
        let now = UnixTime::since_unix_epoch(Duration::from_secs(1_750_000_000));
        assert!(!verify_site_certificate_with_roots(
            cert.der(),
            &[],
            "site.example",
            roots.clone(),
            now,
        ));
        assert!(verify_site_certificate_with_roots(
            cert.der(),
            &[intermediate.der().to_vec()],
            "site.example",
            roots,
            now,
        ));
    }
}
