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
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
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

impl core::fmt::Debug for RecordLayer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecordLayer")
            .field("cipher_suite", &self.cipher_suite)
            .field("sequence", &self.sequence)
            .field("keys", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl RecordLayer {
    /// Transfer derived keys into a record layer without duplicating the key allocation.
    #[must_use]
    pub fn from_traffic_keys(cipher_suite: u16, mut keys: crate::keyschedule::TrafficKeys) -> Self {
        Self::new(cipher_suite, core::mem::take(&mut keys.key), keys.iv)
    }

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
    if plaintext.len() > 16384 {
        return Err(TlsError::LengthOutOfRange);
    }
    let header = record_header(plaintext.len() + 17)?;
    let mut output = zeroize::Zeroizing::new(Vec::with_capacity(plaintext.len() + 22));
    output.extend_from_slice(&header);
    output.extend_from_slice(plaintext);
    output.push(content_type);
    let nonce = sequence_nonce(iv, sequence);
    let tag = aead::seal_in_place(algorithm, key, &nonce, &mut output[5..], &header)
        .map_err(|_| TlsError::AuthenticationFailed)?;
    output.extend_from_slice(&tag);
    Ok(core::mem::take(&mut output))
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
    if record[1..3] != TLS13_RECORD_VERSION.to_be_bytes() {
        return Err(TlsError::InvalidInput("protected record has bad version"));
    }
    let declared = usize::from(u16::from_be_bytes([record[3], record[4]]));
    if declared > 16384 + 256 {
        return Err(TlsError::LengthOutOfRange);
    }
    if record.len() != 5 + declared {
        return Err(TlsError::InvalidInput("record length mismatch"));
    }
    let nonce = sequence_nonce(iv, sequence);
    let mut inner = zeroize::Zeroizing::new(record[5..].to_vec());
    aead::open_in_place(algorithm, key, &nonce, &mut inner, &record[..5])
        .map_err(|_| TlsError::AuthenticationFailed)?;
    let Some(type_index) = inner.iter().rposition(|byte| *byte != 0) else {
        return Err(TlsError::InvalidInput("missing TLS inner content type"));
    };
    let content_type = inner[type_index];
    inner.truncate(type_index);
    Ok(OpenRecord {
        content_type,
        plaintext: core::mem::take(&mut inner),
    })
}

fn record_header(ciphertext_len: usize) -> Result<[u8; 5], TlsError> {
    let len = u16::try_from(ciphertext_len)
        .map_err(|_| TlsError::LengthOutOfRange)?
        .to_be_bytes();
    Ok([CONTENT_TYPE_APPLICATION_DATA, 3, 3, len[0], len[1]])
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
