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

/// Encrypt a payload in place and return its 16-byte authentication tag.
/// The caller owns the output buffer and supplies the unchanged associated data.
pub fn seal_in_place(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    buffer: &mut [u8],
    aad: &[u8],
) -> Result<[u8; 16], CryptoError> {
    use aes_gcm::aead::AeadInPlace;
    validate_key_nonce(algorithm, key, nonce)?;
    let tag = match algorithm {
        AeadAlgorithm::Aes128Gcm => Aes128Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength)?
            .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, buffer),
        AeadAlgorithm::Aes256Gcm => Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength)?
            .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, buffer),
        AeadAlgorithm::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength)?
            .encrypt_in_place_detached(chacha20poly1305::Nonce::from_slice(nonce), aad, buffer),
    }
    .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(tag.into())
}

/// Authenticate and decrypt an owned ciphertext-plus-tag buffer in place.
/// Authentication failure clears the buffer rather than exposing partial output.
pub fn open_in_place(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    buffer: &mut Vec<u8>,
    aad: &[u8],
) -> Result<(), CryptoError> {
    use aes_gcm::aead::AeadInPlace;
    use zeroize::Zeroize;
    validate_key_nonce(algorithm, key, nonce)?;
    let result = match algorithm {
        AeadAlgorithm::Aes128Gcm => Aes128Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength)?
            .decrypt_in_place(Nonce::from_slice(nonce), aad, buffer),
        AeadAlgorithm::Aes256Gcm => Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength)?
            .decrypt_in_place(Nonce::from_slice(nonce), aad, buffer),
        AeadAlgorithm::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength)?
            .decrypt_in_place(chacha20poly1305::Nonce::from_slice(nonce), aad, buffer),
    };
    if result.is_err() {
        buffer.zeroize();
        buffer.clear();
    }
    result.map_err(|_| CryptoError::AuthenticationFailed)
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
