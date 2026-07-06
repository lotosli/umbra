//! HKDF-SHA256 helpers.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::CryptoError;

/// Derive output keying material with HKDF-SHA256.
///
/// `salt` and `info` are passed directly to HKDF as defined by RFC 5869.
pub fn hkdf_sha256(
    salt: &[u8],
    input_keying_material: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), input_keying_material);
    let mut output = vec![0_u8; output_len];
    hkdf.expand(info, &mut output)
        .map_err(|_| CryptoError::InvalidOutputLength)?;
    Ok(output)
}

/// Derive output keying material into a caller-provided buffer.
pub fn hkdf_sha256_into(
    salt: &[u8],
    input_keying_material: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), input_keying_material);
    hkdf.expand(info, output)
        .map_err(|_| CryptoError::InvalidOutputLength)
}

/// Run HKDF-SHA256 extract and return the pseudorandom key bytes.
#[must_use]
pub fn hkdf_sha256_extract(salt: &[u8], input_keying_material: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), input_keying_material);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&prk);
    output
}
