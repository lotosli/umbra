//! RFC 8446 TLS 1.3 key-schedule helpers.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

use crate::{
    clienthello::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
    TlsError,
};

/// SHA-256 output length used by Umbra's TLS 1.3 profile.
pub const HASH_LEN: usize = 32;
/// TLS 1.3 AEAD nonce length.
pub const TLS13_IV_LEN: usize = 12;

const TLS13_LABEL_PREFIX: &[u8] = b"tls13 ";

/// Traffic secrets and master-level secrets derived from one TLS 1.3 schedule.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Tls13Secrets {
    /// Early secret.
    pub early_secret: [u8; HASH_LEN],
    /// Handshake secret.
    pub handshake_secret: [u8; HASH_LEN],
    /// Client handshake traffic secret.
    pub client_handshake_traffic_secret: [u8; HASH_LEN],
    /// Server handshake traffic secret.
    pub server_handshake_traffic_secret: [u8; HASH_LEN],
    /// Master secret.
    pub master_secret: [u8; HASH_LEN],
    /// Client application traffic secret.
    pub client_application_traffic_secret: [u8; HASH_LEN],
    /// Server application traffic secret.
    pub server_application_traffic_secret: [u8; HASH_LEN],
    /// Exporter master secret.
    pub exporter_master_secret: [u8; HASH_LEN],
    /// Resumption master secret.
    pub resumption_master_secret: [u8; HASH_LEN],
}

/// Traffic secrets and master-level secrets for a negotiated TLS 1.3 cipher suite.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SuiteSecrets {
    /// Early secret.
    pub early_secret: Vec<u8>,
    /// Handshake secret.
    pub handshake_secret: Vec<u8>,
    /// Client handshake traffic secret.
    pub client_handshake_traffic_secret: Vec<u8>,
    /// Server handshake traffic secret.
    pub server_handshake_traffic_secret: Vec<u8>,
    /// Master secret.
    pub master_secret: Vec<u8>,
    /// Client application traffic secret.
    pub client_application_traffic_secret: Vec<u8>,
    /// Server application traffic secret.
    pub server_application_traffic_secret: Vec<u8>,
    /// Exporter master secret.
    pub exporter_master_secret: Vec<u8>,
    /// Resumption master secret.
    pub resumption_master_secret: Vec<u8>,
}

/// AEAD key and IV derived from a TLS traffic secret.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TrafficKeys {
    /// AEAD key.
    pub key: Vec<u8>,
    /// Static IV used with sequence-number nonce XOR.
    pub iv: [u8; TLS13_IV_LEN],
}

/// SHA-256 transcript hash.
#[must_use]
pub fn transcript_hash(messages: &[u8]) -> [u8; HASH_LEN] {
    let digest = Sha256::digest(messages);
    digest.into()
}

/// SHA-256 hash of an empty transcript.
#[must_use]
pub fn empty_hash() -> [u8; HASH_LEN] {
    transcript_hash(&[])
}

/// HKDF-Extract with SHA-256.
#[must_use]
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0_u8; HASH_LEN];
    out.copy_from_slice(&prk);
    out
}

/// RFC 8446 `HKDF-Expand-Label`.
pub fn hkdf_expand_label(
    secret: &[u8],
    label: &str,
    context: &[u8],
    len: usize,
) -> Result<Vec<u8>, TlsError> {
    let info = hkdf_label(label, context, len)?;
    let hkdf =
        Hkdf::<Sha256>::from_prk(secret).map_err(|_| TlsError::InvalidInput("bad HKDF PRK"))?;
    let mut out = vec![0_u8; len];
    hkdf.expand(&info, &mut out)
        .map_err(|_| TlsError::LengthOutOfRange)?;
    Ok(out)
}

/// Cipher-suite aware `HKDF-Expand-Label`.
pub fn hkdf_expand_label_for_suite(
    cipher_suite: u16,
    secret: &[u8],
    label: &str,
    context: &[u8],
    len: usize,
) -> Result<Vec<u8>, TlsError> {
    let info = hkdf_label(label, context, len)?;
    let mut out = vec![0_u8; len];
    match hash_algorithm(cipher_suite)? {
        HashAlgorithm::Sha256 => Hkdf::<Sha256>::from_prk(secret)
            .map_err(|_| TlsError::InvalidInput("bad HKDF PRK"))?
            .expand(&info, &mut out)
            .map_err(|_| TlsError::LengthOutOfRange)?,
        HashAlgorithm::Sha384 => Hkdf::<Sha384>::from_prk(secret)
            .map_err(|_| TlsError::InvalidInput("bad HKDF PRK"))?
            .expand(&info, &mut out)
            .map_err(|_| TlsError::LengthOutOfRange)?,
    }
    Ok(out)
}

/// RFC 8446 `Derive-Secret` using raw transcript messages.
pub fn derive_secret(
    secret: &[u8],
    label: &str,
    transcript_messages: &[u8],
) -> Result<[u8; HASH_LEN], TlsError> {
    derive_secret_with_hash(secret, label, &transcript_hash(transcript_messages))
}

/// RFC 8446 `Derive-Secret` using a precomputed transcript hash.
pub fn derive_secret_with_hash(
    secret: &[u8],
    label: &str,
    transcript_hash: &[u8; HASH_LEN],
) -> Result<[u8; HASH_LEN], TlsError> {
    let out = hkdf_expand_label(secret, label, transcript_hash, HASH_LEN)?;
    array32(&out)
}

/// Derive the full TLS 1.3 secret tree for SHA-256 cipher suites.
pub fn derive_tls13_secrets(
    ecdhe_secret: &[u8],
    handshake_transcript: &[u8],
    application_transcript: &[u8],
) -> Result<Tls13Secrets, TlsError> {
    let zeros = [0_u8; HASH_LEN];
    let early_secret = hkdf_extract(&zeros, &zeros);
    let derived_for_handshake = derive_secret_with_hash(&early_secret, "derived", &empty_hash())?;
    let handshake_secret = hkdf_extract(&derived_for_handshake, ecdhe_secret);

    let handshake_hash = transcript_hash(handshake_transcript);
    let client_handshake_traffic_secret =
        derive_secret_with_hash(&handshake_secret, "c hs traffic", &handshake_hash)?;
    let server_handshake_traffic_secret =
        derive_secret_with_hash(&handshake_secret, "s hs traffic", &handshake_hash)?;

    let derived_for_master = derive_secret_with_hash(&handshake_secret, "derived", &empty_hash())?;
    let master_secret = hkdf_extract(&derived_for_master, &zeros);

    let application_hash = transcript_hash(application_transcript);
    let client_application_traffic_secret =
        derive_secret_with_hash(&master_secret, "c ap traffic", &application_hash)?;
    let server_application_traffic_secret =
        derive_secret_with_hash(&master_secret, "s ap traffic", &application_hash)?;
    let exporter_master_secret =
        derive_secret_with_hash(&master_secret, "exp master", &application_hash)?;
    let resumption_master_secret =
        derive_secret_with_hash(&master_secret, "res master", &application_hash)?;

    Ok(Tls13Secrets {
        early_secret,
        handshake_secret,
        client_handshake_traffic_secret,
        server_handshake_traffic_secret,
        master_secret,
        client_application_traffic_secret,
        server_application_traffic_secret,
        exporter_master_secret,
        resumption_master_secret,
    })
}

/// Derive the full TLS 1.3 secret tree for the negotiated cipher suite.
pub fn derive_tls13_secrets_for_suite(
    cipher_suite: u16,
    ecdhe_secret: &[u8],
    handshake_transcript: &[u8],
    application_transcript: &[u8],
) -> Result<SuiteSecrets, TlsError> {
    let hash_len = hash_len_for_suite(cipher_suite)?;
    let zeros = vec![0_u8; hash_len];
    let early_secret = hkdf_extract_for_suite(cipher_suite, &zeros, &zeros)?;
    let empty_hash = empty_hash_for_suite(cipher_suite)?;
    let derived_for_handshake =
        derive_secret_with_hash_for_suite(cipher_suite, &early_secret, "derived", &empty_hash)?;
    let handshake_secret =
        hkdf_extract_for_suite(cipher_suite, &derived_for_handshake, ecdhe_secret)?;

    let handshake_hash = transcript_hash_for_suite(cipher_suite, handshake_transcript)?;
    let client_handshake_traffic_secret = derive_secret_with_hash_for_suite(
        cipher_suite,
        &handshake_secret,
        "c hs traffic",
        &handshake_hash,
    )?;
    let server_handshake_traffic_secret = derive_secret_with_hash_for_suite(
        cipher_suite,
        &handshake_secret,
        "s hs traffic",
        &handshake_hash,
    )?;

    let derived_for_master =
        derive_secret_with_hash_for_suite(cipher_suite, &handshake_secret, "derived", &empty_hash)?;
    let master_secret = hkdf_extract_for_suite(cipher_suite, &derived_for_master, &zeros)?;

    let application_hash = transcript_hash_for_suite(cipher_suite, application_transcript)?;
    let client_application_traffic_secret = derive_secret_with_hash_for_suite(
        cipher_suite,
        &master_secret,
        "c ap traffic",
        &application_hash,
    )?;
    let server_application_traffic_secret = derive_secret_with_hash_for_suite(
        cipher_suite,
        &master_secret,
        "s ap traffic",
        &application_hash,
    )?;
    let exporter_master_secret = derive_secret_with_hash_for_suite(
        cipher_suite,
        &master_secret,
        "exp master",
        &application_hash,
    )?;
    let resumption_master_secret = derive_secret_with_hash_for_suite(
        cipher_suite,
        &master_secret,
        "res master",
        &application_hash,
    )?;

    Ok(SuiteSecrets {
        early_secret,
        handshake_secret,
        client_handshake_traffic_secret,
        server_handshake_traffic_secret,
        master_secret,
        client_application_traffic_secret,
        server_application_traffic_secret,
        exporter_master_secret,
        resumption_master_secret,
    })
}

/// Derive an AEAD key and static IV from a traffic secret.
pub fn derive_traffic_keys(
    cipher_suite: u16,
    traffic_secret: &[u8],
) -> Result<TrafficKeys, TlsError> {
    let key_len = match cipher_suite {
        TLS_AES_128_GCM_SHA256 => 16,
        TLS_AES_256_GCM_SHA384 | TLS_CHACHA20_POLY1305_SHA256 => 32,
        other => return Err(TlsError::UnsupportedCipherSuite(other)),
    };
    let key = hkdf_expand_label_for_suite(cipher_suite, traffic_secret, "key", &[], key_len)?;
    let iv = array12(&hkdf_expand_label_for_suite(
        cipher_suite,
        traffic_secret,
        "iv",
        &[],
        TLS13_IV_LEN,
    )?)?;
    Ok(TrafficKeys { key, iv })
}

/// Derive the TLS 1.3 Finished key from a traffic secret.
pub fn finished_key(traffic_secret: &[u8]) -> Result<[u8; HASH_LEN], TlsError> {
    array32(&hkdf_expand_label(
        traffic_secret,
        "finished",
        &[],
        HASH_LEN,
    )?)
}

/// Compute TLS 1.3 Finished verify_data.
pub fn finished_verify_data(
    traffic_secret: &[u8],
    transcript_hash: &[u8; HASH_LEN],
) -> Result<[u8; HASH_LEN], TlsError> {
    let key = finished_key(traffic_secret)?;
    umbra_crypto::mac::hmac_sha256(&key, transcript_hash)
        .map_err(|_| TlsError::InvalidInput("bad finished key"))
}

/// Hash transcript messages with the negotiated cipher-suite hash.
pub fn transcript_hash_for_suite(cipher_suite: u16, messages: &[u8]) -> Result<Vec<u8>, TlsError> {
    match hash_algorithm(cipher_suite)? {
        HashAlgorithm::Sha256 => Ok(Sha256::digest(messages).to_vec()),
        HashAlgorithm::Sha384 => Ok(Sha384::digest(messages).to_vec()),
    }
}

/// Hash an empty transcript with the negotiated cipher-suite hash.
pub fn empty_hash_for_suite(cipher_suite: u16) -> Result<Vec<u8>, TlsError> {
    transcript_hash_for_suite(cipher_suite, &[])
}

/// Derive a TLS 1.3 secret from a precomputed cipher-suite transcript hash.
pub fn derive_secret_with_hash_for_suite(
    cipher_suite: u16,
    secret: &[u8],
    label: &str,
    transcript_hash: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let hash_len = hash_len_for_suite(cipher_suite)?;
    hkdf_expand_label_for_suite(cipher_suite, secret, label, transcript_hash, hash_len)
}

/// Derive the TLS 1.3 Finished key for the negotiated cipher suite.
pub fn finished_key_for_suite(
    cipher_suite: u16,
    traffic_secret: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let hash_len = hash_len_for_suite(cipher_suite)?;
    hkdf_expand_label_for_suite(cipher_suite, traffic_secret, "finished", &[], hash_len)
}

/// Compute TLS 1.3 Finished verify_data for the negotiated cipher suite.
pub fn finished_verify_data_for_suite(
    cipher_suite: u16,
    traffic_secret: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let key = finished_key_for_suite(cipher_suite, traffic_secret)?;
    match hash_algorithm(cipher_suite)? {
        HashAlgorithm::Sha256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key)
                .map_err(|_| TlsError::InvalidInput("bad finished key"))?;
            mac.update(transcript_hash);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        HashAlgorithm::Sha384 => {
            let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(&key)
                .map_err(|_| TlsError::InvalidInput("bad finished key"))?;
            mac.update(transcript_hash);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

fn hkdf_extract_for_suite(cipher_suite: u16, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, TlsError> {
    match hash_algorithm(cipher_suite)? {
        HashAlgorithm::Sha256 => {
            let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
            Ok(prk.to_vec())
        }
        HashAlgorithm::Sha384 => {
            let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
            Ok(prk.to_vec())
        }
    }
}

fn hash_len_for_suite(cipher_suite: u16) -> Result<usize, TlsError> {
    Ok(match hash_algorithm(cipher_suite)? {
        HashAlgorithm::Sha256 => 32,
        HashAlgorithm::Sha384 => 48,
    })
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum HashAlgorithm {
    Sha256,
    Sha384,
}

fn hash_algorithm(cipher_suite: u16) -> Result<HashAlgorithm, TlsError> {
    match cipher_suite {
        TLS_AES_128_GCM_SHA256 | TLS_CHACHA20_POLY1305_SHA256 => Ok(HashAlgorithm::Sha256),
        TLS_AES_256_GCM_SHA384 => Ok(HashAlgorithm::Sha384),
        other => Err(TlsError::UnsupportedCipherSuite(other)),
    }
}

fn hkdf_label(label: &str, context: &[u8], len: usize) -> Result<Vec<u8>, TlsError> {
    let len_u16 = u16::try_from(len).map_err(|_| TlsError::LengthOutOfRange)?;
    let full_label_len = TLS13_LABEL_PREFIX
        .len()
        .checked_add(label.len())
        .ok_or(TlsError::LengthOutOfRange)?;
    let label_len = u8::try_from(full_label_len).map_err(|_| TlsError::LengthOutOfRange)?;
    let context_len = u8::try_from(context.len()).map_err(|_| TlsError::LengthOutOfRange)?;

    let mut out = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    out.extend_from_slice(&len_u16.to_be_bytes());
    out.push(label_len);
    out.extend_from_slice(TLS13_LABEL_PREFIX);
    out.extend_from_slice(label.as_bytes());
    out.push(context_len);
    out.extend_from_slice(context);
    Ok(out)
}

fn array32(input: &[u8]) -> Result<[u8; HASH_LEN], TlsError> {
    input
        .try_into()
        .map_err(|_| TlsError::InvalidInput("expected 32 bytes"))
}

fn array12(input: &[u8]) -> Result<[u8; TLS13_IV_LEN], TlsError> {
    input
        .try_into()
        .map_err(|_| TlsError::InvalidInput("expected 12 bytes"))
}
