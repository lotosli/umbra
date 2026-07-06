//! AEAD seal/open helpers used by REALITY and TLS record protection.

use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, Aes256Gcm, KeyInit, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;

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
    /// Return the required key length in bytes.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Return the required nonce length in bytes.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        12
    }
}

/// Seal plaintext with the selected AEAD and associated data.
pub fn seal(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    validate_key_nonce(algorithm, key, nonce)?;
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match algorithm {
        AeadAlgorithm::Aes128Gcm => Aes128Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength)?
            .encrypt(Nonce::from_slice(nonce), payload)
            .map_err(|_| CryptoError::AuthenticationFailed),
        AeadAlgorithm::Aes256Gcm => Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength)?
            .encrypt(Nonce::from_slice(nonce), payload)
            .map_err(|_| CryptoError::AuthenticationFailed),
        AeadAlgorithm::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength)?
            .encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
            .map_err(|_| CryptoError::AuthenticationFailed),
    }
}

/// Open ciphertext with the selected AEAD and associated data.
pub fn open(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    validate_key_nonce(algorithm, key, nonce)?;
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    match algorithm {
        AeadAlgorithm::Aes128Gcm => Aes128Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength)?
            .decrypt(Nonce::from_slice(nonce), payload)
            .map_err(|_| CryptoError::AuthenticationFailed),
        AeadAlgorithm::Aes256Gcm => Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength)?
            .decrypt(Nonce::from_slice(nonce), payload)
            .map_err(|_| CryptoError::AuthenticationFailed),
        AeadAlgorithm::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength)?
            .decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
            .map_err(|_| CryptoError::AuthenticationFailed),
    }
}

fn validate_key_nonce(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
) -> Result<(), CryptoError> {
    if key.len() != algorithm.key_len() {
        return Err(CryptoError::InvalidKeyLength);
    }
    if nonce.len() != algorithm.nonce_len() {
        return Err(CryptoError::InvalidNonceLength);
    }
    Ok(())
}
