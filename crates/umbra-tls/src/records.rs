//! TLS 1.3 record protection.

use umbra_crypto::aead::{AeadAlgorithm, AeadContext};
use zeroize::Zeroize;

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
    context: Option<AeadContext>,
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
            context: None,
        }
    }

    /// Return the next sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    fn context(&mut self) -> Result<&AeadContext, TlsError> {
        if self.context.is_none() {
            let context = AeadContext::new(algorithm(self.cipher_suite)?, &self.key)
                .map_err(|_| TlsError::AuthenticationFailed)?;
            self.key.zeroize();
            self.key.clear();
            self.context = Some(context);
        }
        self.context.as_ref().ok_or(TlsError::AuthenticationFailed)
    }

    /// Seal one record and advance the sequence number.
    pub fn seal(&mut self, content_type: u8, plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        let mut output = Vec::new();
        self.seal_into(content_type, plaintext, &mut output)?;
        Ok(output)
    }

    /// Seal into reusable output storage. An error clears the output and does
    /// not advance the sequence; an exhausted sequence never exposes ciphertext.
    pub fn seal_into(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), TlsError> {
        self.seal_parts_into(content_type, &[plaintext], output)
    }

    /// Encode borrowed plaintext parts directly into their final protected record.
    pub fn seal_parts_into(
        &mut self,
        content_type: u8,
        parts: &[&[u8]],
        output: &mut Vec<u8>,
    ) -> Result<(), TlsError> {
        let result = (|| {
            let next = self
                .sequence
                .checked_add(1)
                .ok_or(TlsError::InvalidInput("record sequence overflow"))?;
            let nonce = sequence_nonce(&self.iv, self.sequence);
            seal_with_context(self.context()?, &nonce, content_type, parts, output)?;
            self.sequence = next;
            Ok(())
        })();
        if result.is_err() {
            output.zeroize();
            output.clear();
        }
        result
    }

    /// Authenticate/decrypt in place. On success the original five-byte header
    /// is retained and plaintext follows it; the tag, inner type and padding
    /// are removed. Any error clears the complete caller buffer.
    pub fn open_in_place(&mut self, record: &mut Vec<u8>) -> Result<u8, TlsError> {
        let result = (|| {
            let next = self
                .sequence
                .checked_add(1)
                .ok_or(TlsError::InvalidInput("record sequence overflow"))?;
            let nonce = sequence_nonce(&self.iv, self.sequence);
            let kind = open_with_context(self.context()?, &nonce, record)?;
            self.sequence = next;
            Ok(kind)
        })();
        if result.is_err() {
            record.zeroize();
            record.clear();
        }
        result
    }

    /// Open only application data, clearing output for unexpected inner types.
    pub fn open_application_in_place(&mut self, record: &mut Vec<u8>) -> Result<(), TlsError> {
        if self.open_in_place(record)? != CONTENT_TYPE_APPLICATION_DATA {
            record.zeroize();
            record.clear();
            return Err(TlsError::InvalidInput("not application data"));
        }
        Ok(())
    }

    /// Open one borrowed record, returning independently owned plaintext.
    pub fn open(&mut self, record: &[u8]) -> Result<OpenRecord, TlsError> {
        let next = self
            .sequence
            .checked_add(1)
            .ok_or(TlsError::InvalidInput("record sequence overflow"))?;
        let nonce = sequence_nonce(&self.iv, self.sequence);
        let output = open_borrowed(self.context()?, &nonce, record)?;
        self.sequence = next;
        Ok(output)
    }
}

/// Application receive/send key owners transferred out of a completed handshake.
/// Both fields destroy their raw and expanded key state when dropped.
#[derive(Debug)]
pub struct ApplicationRecords {
    /// Peer-to-local protected records.
    pub read: RecordLayer,
    /// Local-to-peer protected records.
    pub write: RecordLayer,
}

/// Validate a protected header and return the complete ciphertext record length.
/// Header-only callers can reject oversized declarations before allocating a body.
pub fn protected_record_length(header: &[u8]) -> Result<usize, TlsError> {
    if header.len() < 5 {
        return Err(TlsError::InvalidInput("short TLS record"));
    }
    if header[0] != CONTENT_TYPE_APPLICATION_DATA {
        return Err(TlsError::InvalidInput("protected record has bad type"));
    }
    if header[1..3] != TLS13_RECORD_VERSION.to_be_bytes() {
        return Err(TlsError::InvalidInput("protected record has bad version"));
    }
    let declared = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if declared > 16384 + 256 {
        return Err(TlsError::LengthOutOfRange);
    }
    Ok(5 + declared)
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
    let context = AeadContext::new(algorithm(cipher_suite)?, key)
        .map_err(|_| TlsError::AuthenticationFailed)?;
    let mut output = zeroize::Zeroizing::new(Vec::new());
    seal_with_context(
        &context,
        &sequence_nonce(iv, sequence),
        content_type,
        &[plaintext],
        &mut output,
    )?;
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
    let context = AeadContext::new(algorithm(cipher_suite)?, key)
        .map_err(|_| TlsError::AuthenticationFailed)?;
    open_borrowed(&context, &sequence_nonce(iv, sequence), record)
}

fn seal_with_context(
    context: &AeadContext,
    nonce: &[u8; 12],
    content_type: u8,
    parts: &[&[u8]],
    output: &mut Vec<u8>,
) -> Result<(), TlsError> {
    let length = parts.iter().try_fold(0_usize, |n, part| {
        n.checked_add(part.len()).ok_or(TlsError::LengthOutOfRange)
    })?;
    if length > 16384 {
        return Err(TlsError::LengthOutOfRange);
    }
    let header = record_header(length + 17)?;
    output.clear();
    output.reserve(length + 22);
    output.extend_from_slice(&header);
    for part in parts {
        output.extend_from_slice(part);
    }
    output.push(content_type);
    let tag = context
        .seal_in_place(nonce, &mut output[5..], &header)
        .map_err(|_| TlsError::AuthenticationFailed)?;
    output.extend_from_slice(&tag);
    Ok(())
}

fn validate_record(record: &[u8]) -> Result<[u8; 5], TlsError> {
    if record.len() != protected_record_length(record)? {
        return Err(TlsError::InvalidInput("record length mismatch"));
    }
    if record.len() < 22 {
        return Err(TlsError::AuthenticationFailed);
    }
    let mut header = [0; 5];
    header.copy_from_slice(&record[..5]);
    Ok(header)
}

fn open_payload(
    context: &AeadContext,
    nonce: &[u8; 12],
    header: [u8; 5],
    payload: &mut [u8],
) -> Result<(u8, usize), TlsError> {
    let end = payload
        .len()
        .checked_sub(16)
        .ok_or(TlsError::AuthenticationFailed)?;
    let mut tag = [0; 16];
    tag.copy_from_slice(&payload[end..]);
    context
        .open_in_place_detached(nonce, &mut payload[..end], &header, &tag)
        .map_err(|_| TlsError::AuthenticationFailed)?;
    if end > 16_385 {
        return Err(TlsError::LengthOutOfRange);
    }
    let type_index = payload[..end]
        .iter()
        .rposition(|byte| *byte != 0)
        .ok_or(TlsError::InvalidInput("missing TLS inner content type"))?;
    Ok((payload[type_index], type_index))
}

fn open_with_context(
    context: &AeadContext,
    nonce: &[u8; 12],
    record: &mut Vec<u8>,
) -> Result<u8, TlsError> {
    let header = validate_record(record)?;
    let (content_type, length) = open_payload(context, nonce, header, &mut record[5..])?;
    record.truncate(5 + length);
    Ok(content_type)
}

fn open_borrowed(
    context: &AeadContext,
    nonce: &[u8; 12],
    record: &[u8],
) -> Result<OpenRecord, TlsError> {
    let header = validate_record(record)?;
    let mut output = zeroize::Zeroizing::new(record[5..].to_vec());
    let (content_type, length) = open_payload(context, nonce, header, &mut output)?;
    output.truncate(length);
    Ok(OpenRecord {
        content_type,
        plaintext: core::mem::take(&mut output),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_sequences_never_publish_or_reuse_output() {
        let mut layer = RecordLayer::new(TLS_AES_128_GCM_SHA256, vec![0x42; 16], [0; 12]);
        layer.sequence = u64::MAX;
        let mut output = vec![0xa5; 32];
        assert!(layer
            .seal_into(CONTENT_TYPE_APPLICATION_DATA, b"private", &mut output)
            .is_err());
        assert!(output.is_empty());
        let mut record = seal_record(
            TLS_AES_128_GCM_SHA256,
            &[0x42; 16],
            &[0; 12],
            u64::MAX,
            CONTENT_TYPE_APPLICATION_DATA,
            b"private",
        )
        .unwrap();
        assert!(layer.open_in_place(&mut record).is_err());
        assert!(record.is_empty());
        assert_eq!(layer.sequence(), u64::MAX);
    }
}
