//! TLS 1.3 record protection.

use umbra_crypto::aead::{self, AeadAlgorithm};

use crate::{
    clienthello::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
    keyschedule::TLS13_IV_LEN,
    TlsError,
};

/// TLS handshake content type.
pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
/// TLS application-data content type.
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
/// TLS alert content type.
pub const CONTENT_TYPE_ALERT: u8 = 0x15;

const TLS13_RECORD_VERSION: u16 = 0x0303;

/// Stateful TLS 1.3 record layer for one direction.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RecordLayer {
    cipher_suite: u16,
    key: Vec<u8>,
    iv: [u8; TLS13_IV_LEN],
    sequence: u64,
}

/// Opened TLS inner plaintext.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OpenRecord {
    /// Inner content type.
    pub content_type: u8,
    /// Inner plaintext bytes.
    pub plaintext: Vec<u8>,
}

impl RecordLayer {
    /// Construct a record layer from an AEAD key and static IV.
    #[must_use]
    pub fn new(cipher_suite: u16, key: Vec<u8>, iv: [u8; TLS13_IV_LEN]) -> Self {
        Self {
            cipher_suite,
            key,
            iv,
            sequence: 0,
        }
    }

    /// Return the next sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Seal one record and advance the sequence number.
    pub fn seal(&mut self, content_type: u8, plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        let out = seal_record(
            self.cipher_suite,
            &self.key,
            &self.iv,
            self.sequence,
            content_type,
            plaintext,
        )?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(TlsError::InvalidInput("record sequence overflow"))?;
        Ok(out)
    }

    /// Open one record and advance the sequence number.
    pub fn open(&mut self, record: &[u8]) -> Result<OpenRecord, TlsError> {
        let out = open_record(
            self.cipher_suite,
            &self.key,
            &self.iv,
            self.sequence,
            record,
        )?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(TlsError::InvalidInput("record sequence overflow"))?;
        Ok(out)
    }
}

/// Seal one TLS 1.3 protected record for an explicit sequence number.
pub fn seal_record(
    cipher_suite: u16,
    key: &[u8],
    iv: &[u8; TLS13_IV_LEN],
    sequence: u64,
    content_type: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let algorithm = algorithm(cipher_suite)?;
    let mut inner = Vec::with_capacity(plaintext.len() + 1);
    inner.extend_from_slice(plaintext);
    inner.push(content_type);

    let length = inner
        .len()
        .checked_add(16)
        .ok_or(TlsError::LengthOutOfRange)?;
    let mut header = record_header(length)?;
    let nonce = sequence_nonce(iv, sequence);
    let ciphertext = aead::seal(algorithm, key, &nonce, &inner, &header)
        .map_err(|_| TlsError::AuthenticationFailed)?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

/// Open one TLS 1.3 protected record for an explicit sequence number.
pub fn open_record(
    cipher_suite: u16,
    key: &[u8],
    iv: &[u8; TLS13_IV_LEN],
    sequence: u64,
    record: &[u8],
) -> Result<OpenRecord, TlsError> {
    let algorithm = algorithm(cipher_suite)?;
    if record.len() < 5 {
        return Err(TlsError::InvalidInput("short TLS record"));
    }
    if record[0] != CONTENT_TYPE_APPLICATION_DATA {
        return Err(TlsError::InvalidInput("protected record has bad type"));
    }
    let declared = usize::from(u16::from_be_bytes([record[3], record[4]]));
    if record.len() != 5 + declared {
        return Err(TlsError::InvalidInput("record length mismatch"));
    }
    let nonce = sequence_nonce(iv, sequence);
    let inner = aead::open(algorithm, key, &nonce, &record[5..], &record[..5])
        .map_err(|_| TlsError::AuthenticationFailed)?;
    split_inner_plaintext(&inner)
}

fn record_header(ciphertext_len: usize) -> Result<Vec<u8>, TlsError> {
    let len = u16::try_from(ciphertext_len).map_err(|_| TlsError::LengthOutOfRange)?;
    let mut out = Vec::with_capacity(5);
    out.push(CONTENT_TYPE_APPLICATION_DATA);
    out.extend_from_slice(&TLS13_RECORD_VERSION.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    Ok(out)
}

fn split_inner_plaintext(inner: &[u8]) -> Result<OpenRecord, TlsError> {
    let Some(type_index) = inner.iter().rposition(|byte| *byte != 0) else {
        return Err(TlsError::InvalidInput("missing TLS inner content type"));
    };
    Ok(OpenRecord {
        content_type: inner[type_index],
        plaintext: inner[..type_index].to_vec(),
    })
}

fn sequence_nonce(iv: &[u8; TLS13_IV_LEN], sequence: u64) -> [u8; TLS13_IV_LEN] {
    let mut nonce = *iv;
    let seq = sequence.to_be_bytes();
    for (dst, src) in nonce[4..].iter_mut().zip(seq) {
        *dst ^= src;
    }
    nonce
}

fn algorithm(cipher_suite: u16) -> Result<AeadAlgorithm, TlsError> {
    match cipher_suite {
        TLS_AES_128_GCM_SHA256 => Ok(AeadAlgorithm::Aes128Gcm),
        TLS_AES_256_GCM_SHA384 => Ok(AeadAlgorithm::Aes256Gcm),
        TLS_CHACHA20_POLY1305_SHA256 => Ok(AeadAlgorithm::ChaCha20Poly1305),
        other => Err(TlsError::UnsupportedCipherSuite(other)),
    }
}
