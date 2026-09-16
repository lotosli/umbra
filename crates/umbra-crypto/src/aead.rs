//! AEAD helpers and reusable, zeroizing cipher contexts.

use aes_gcm::{AeadInOut, Aes128Gcm, Aes256Gcm, KeyInit};
use chacha20poly1305::KeyInit as _;
use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;

/// Supported AEAD algorithms.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AeadAlgorithm {
    /// AES-128-GCM with a 16-byte key and 12-byte nonce.
    Aes128Gcm,
    /// AES-256-GCM with a 32-byte key and 12-byte nonce.
    Aes256Gcm,
    /// ChaCha20-Poly1305 with a 32-byte key and 12-byte nonce.
    ChaCha20Poly1305,
}

impl AeadAlgorithm {
    /// Required key length in bytes.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Required nonce length in bytes.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        12
    }
}

// Boxing the expanded AES schedules keeps record-owner futures small. These
// allocations occur once per traffic key, never once per protected record.
enum Cipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(ChaCha20Poly1305),
}

/// A validated key's reusable expanded AEAD state.
///
/// Callers MUST supply a unique nonce for every encryption under this key.
/// Clearing the context is terminal. No key bytes are retained separately or
/// exposed by formatting. Every cipher implements upstream `ZeroizeOnDrop`.
pub struct AeadContext {
    cipher: Option<Cipher>,
}

impl core::fmt::Debug for AeadContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AeadContext(<redacted>)")
    }
}

impl AeadContext {
    /// Validate and expand one traffic key.
    pub fn new(algorithm: AeadAlgorithm, key: &[u8]) -> Result<Self, CryptoError> {
        // Compile-time bounds prevent dependency feature changes from silently
        // removing destruction of expanded AES, GHASH or ChaCha key material.
        fn zeroizing<T: ZeroizeOnDrop>(value: T) -> T {
            value
        }
        if key.len() != algorithm.key_len() {
            return Err(CryptoError::InvalidKeyLength);
        }
        let cipher = match algorithm {
            AeadAlgorithm::Aes128Gcm => Cipher::Aes128(Box::new(zeroizing(
                Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?,
            ))),
            AeadAlgorithm::Aes256Gcm => Cipher::Aes256(Box::new(zeroizing(
                Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?,
            ))),
            AeadAlgorithm::ChaCha20Poly1305 => Cipher::ChaCha(zeroizing(
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?,
            )),
        };
        Ok(Self {
            cipher: Some(cipher),
        })
    }

    /// Encrypt the caller's payload and return the detached 16-byte tag.
    pub fn seal_in_place(
        &self,
        nonce: &[u8],
        buffer: &mut [u8],
        aad: &[u8],
    ) -> Result<[u8; 16], CryptoError> {
        let nonce: &[u8; 12] = nonce
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceLength)?;
        match self.cipher.as_ref().ok_or(CryptoError::ContextCleared)? {
            Cipher::Aes128(cipher) => cipher
                .encrypt_inout_detached(&(*nonce).into(), aad, buffer.into())
                .map(Into::into)
                .map_err(|_| CryptoError::AuthenticationFailed),
            Cipher::Aes256(cipher) => cipher
                .encrypt_inout_detached(&(*nonce).into(), aad, buffer.into())
                .map(Into::into)
                .map_err(|_| CryptoError::AuthenticationFailed),
            Cipher::ChaCha(cipher) => cipher
                .encrypt_in_place_detached(chacha20poly1305::Nonce::from_slice(nonce), aad, buffer)
                .map(Into::into)
                .map_err(|_| CryptoError::AuthenticationFailed),
        }
    }

    /// Authenticate a detached tag and decrypt the caller's payload.
    /// Any error clears the entire payload slice.
    pub fn open_in_place_detached(
        &self,
        nonce: &[u8],
        buffer: &mut [u8],
        aad: &[u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        let result = self.open_detached(nonce, buffer, aad, tag);
        if result.is_err() {
            buffer.zeroize();
        }
        result
    }

    fn open_detached(
        &self,
        nonce: &[u8],
        buffer: &mut [u8],
        aad: &[u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        let nonce: &[u8; 12] = nonce
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceLength)?;
        match self.cipher.as_ref().ok_or(CryptoError::ContextCleared)? {
            Cipher::Aes128(cipher) => cipher
                .decrypt_inout_detached(&(*nonce).into(), aad, buffer.into(), &(*tag).into())
                .map_err(|_| CryptoError::AuthenticationFailed),
            Cipher::Aes256(cipher) => cipher
                .decrypt_inout_detached(&(*nonce).into(), aad, buffer.into(), &(*tag).into())
                .map_err(|_| CryptoError::AuthenticationFailed),
            Cipher::ChaCha(cipher) => cipher
                .decrypt_in_place_detached(
                    chacha20poly1305::Nonce::from_slice(nonce),
                    aad,
                    buffer,
                    chacha20poly1305::Tag::from_slice(tag),
                )
                .map_err(|_| CryptoError::AuthenticationFailed),
        }
    }

    /// Open a ciphertext-plus-tag buffer, retaining its allocation on success.
    /// Any error clears both its storage and logical length.
    pub fn open_in_place(
        &self,
        nonce: &[u8],
        buffer: &mut Vec<u8>,
        aad: &[u8],
    ) -> Result<(), CryptoError> {
        if nonce.len() != 12 {
            buffer.zeroize();
            buffer.clear();
            return Err(CryptoError::InvalidNonceLength);
        }
        let result = match buffer.len().checked_sub(16) {
            Some(end) => {
                let mut tag = [0; 16];
                tag.copy_from_slice(&buffer[end..]);
                self.open_in_place_detached(nonce, &mut buffer[..end], aad, &tag)
                    .map(|()| buffer.truncate(end))
            }
            None => Err(CryptoError::AuthenticationFailed),
        };
        if result.is_err() {
            buffer.zeroize();
            buffer.clear();
        }
        result
    }
}

impl Zeroize for AeadContext {
    fn zeroize(&mut self) {
        // Dropping the active variant invokes the verified upstream destructors
        // before releasing its allocation; the empty context cannot be reused.
        self.cipher.take();
    }
}
impl Drop for AeadContext {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for AeadContext {}

/// Seal plaintext with the selected AEAD and associated data.
pub fn seal(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let context = AeadContext::new(algorithm, key)?;
    let mut output = zeroize::Zeroizing::new(Vec::with_capacity(plaintext.len() + 16));
    output.extend_from_slice(plaintext);
    let tag = context.seal_in_place(nonce, &mut output, aad)?;
    output.extend_from_slice(&tag);
    Ok(core::mem::take(&mut output))
}

/// Open ciphertext with the selected AEAD and associated data.
pub fn open(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let context = AeadContext::new(algorithm, key)?;
    let mut output = ciphertext.to_vec();
    context.open_in_place(nonce, &mut output, aad)?;
    Ok(output)
}

/// Encrypt a payload in place and return its detached tag.
pub fn seal_in_place(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    buffer: &mut [u8],
    aad: &[u8],
) -> Result<[u8; 16], CryptoError> {
    AeadContext::new(algorithm, key)?.seal_in_place(nonce, buffer, aad)
}

/// Authenticate and decrypt an owned ciphertext-plus-tag buffer in place.
pub fn open_in_place(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    buffer: &mut Vec<u8>,
    aad: &[u8],
) -> Result<(), CryptoError> {
    AeadContext::new(algorithm, key)?.open_in_place(nonce, buffer, aad)
}

#[cfg(test)]
mod in_place_tests {
    use super::*;

    #[test]
    fn in_place_matches_existing_aead_and_clears_failed_output() {
        for algorithm in [
            AeadAlgorithm::Aes128Gcm,
            AeadAlgorithm::Aes256Gcm,
            AeadAlgorithm::ChaCha20Poly1305,
        ] {
            let key = vec![0x42; algorithm.key_len()];
            let nonce = [0x24; 12];
            for length in [0, 1, 16_384] {
                let input = vec![0xa5; length];
                let reference =
                    seal(algorithm, &key, &nonce, &input, b"header").expect("reference encryption");
                let mut output = input.clone();
                let tag = seal_in_place(algorithm, &key, &nonce, &mut output, b"header")
                    .expect("in-place encryption");
                output.extend_from_slice(&tag);
                assert_eq!(output, reference);
                open_in_place(algorithm, &key, &nonce, &mut output, b"header").expect("decrypt");
                assert_eq!(output, input);
                let mut invalid = reference;
                assert!(
                    open_in_place(algorithm, &key, &nonce, &mut invalid, b"bad header").is_err()
                );
                assert!(invalid.is_empty());
            }
            assert!(seal_in_place(algorithm, &[], &nonce, &mut [], b"").is_err());
            assert!(open_in_place(algorithm, &key, &[], &mut Vec::new(), b"").is_err());
        }
    }
}
