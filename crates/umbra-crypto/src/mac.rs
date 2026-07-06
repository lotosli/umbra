//! HMAC-SHA256 helpers with constant-time verification.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::CryptoError;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 over `message`.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    mac.update(message);
    let bytes = mac.finalize().into_bytes();
    let mut output = [0_u8; 32];
    output.copy_from_slice(&bytes);
    Ok(output)
}

/// Verify an HMAC-SHA256 tag in constant time.
#[must_use]
pub fn verify_hmac_sha256(key: &[u8], message: &[u8], tag: &[u8]) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(message);
    mac.verify_slice(tag).is_ok()
}
