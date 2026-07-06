//! X25519 key agreement helpers.

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{secret::Secret, CryptoError};

/// X25519 private key bytes.
pub type PrivateKey = Secret<32>;

/// X25519 public key bytes.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PublicKeyBytes([u8; 32]);

impl PublicKeyBytes {
    /// Wrap public key bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the raw public key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume and return raw public key bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// X25519 keypair.
pub struct Keypair {
    /// Private key bytes.
    pub private: PrivateKey,
    /// Public key bytes.
    pub public: PublicKeyBytes,
}

/// Generate a fresh X25519 keypair using the OS CSPRNG.
#[must_use]
pub fn generate_keypair() -> Keypair {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);
    Keypair {
        private: PrivateKey::new(private.to_bytes()),
        public: PublicKeyBytes::new(public.to_bytes()),
    }
}

/// Return the X25519 public key corresponding to a private key.
#[must_use]
pub fn public_from_private(private: &PrivateKey) -> PublicKeyBytes {
    let secret = StaticSecret::from(*private.expose_secret());
    PublicKeyBytes::new(PublicKey::from(&secret).to_bytes())
}

/// Compute X25519 agreement.
///
/// The returned value is the raw 32-byte shared secret. Callers derive keys
/// from it with HKDF before use.
pub fn agree(private: &PrivateKey, peer_public: &[u8]) -> Result<Secret<32>, CryptoError> {
    let peer = public_from_slice(peer_public)?;
    let secret = StaticSecret::from(*private.expose_secret());
    Ok(Secret::new(secret.diffie_hellman(&peer).to_bytes()))
}

/// Compute X25519 over fixed scalar and point bytes.
///
/// This is mainly useful for RFC 7748 known-answer tests.
pub fn agree_raw(scalar: [u8; 32], point: [u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(scalar);
    let public = PublicKey::from(point);
    secret.diffie_hellman(&public).to_bytes()
}

fn public_from_slice(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidInputLength)?;
    Ok(PublicKey::from(array))
}
