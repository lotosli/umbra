//! ML-DSA-65 wrappers.

use ml_dsa::{
    signature::{Keypair, SignatureEncoding, Signer, Verifier},
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, SigningKey, VerifyingKey,
};
use rand::{rngs::OsRng, RngCore};

use crate::{
    secret::{Secret, SecretBytes},
    CryptoError,
};

/// Encoded ML-DSA-65 key material.
#[derive(Debug)]
pub struct MldsaKeypair {
    /// Public verification key bytes.
    pub verifying_key: Vec<u8>,
    /// 32-byte signing seed.
    pub signing_seed: Secret<32>,
}

/// Generate an ML-DSA-65 keypair from a random 32-byte seed.
#[must_use]
pub fn mldsa_keygen() -> MldsaKeypair {
    let mut seed = [0_u8; 32];
    OsRng.fill_bytes(&mut seed);
    mldsa_keygen_from_seed(&seed)
}

/// Generate an ML-DSA-65 keypair from a 32-byte seed.
#[must_use]
pub fn mldsa_keygen_from_seed(seed: &[u8; 32]) -> MldsaKeypair {
    let signing_seed = Secret::new(*seed);
    let signing_key = signing_key_from_seed(&signing_seed);
    MldsaKeypair {
        verifying_key: signing_key.verifying_key().encode().to_vec(),
        signing_seed,
    }
}

/// Sign a message with an ML-DSA-65 signing seed.
#[must_use]
pub fn mldsa_sign(signing_seed: &Secret<32>, message: &[u8]) -> Vec<u8> {
    let signing_key = signing_key_from_seed(signing_seed);
    signing_key.sign(message).to_bytes().to_vec()
}

/// Sign a message with a variable-length secret seed wrapper.
pub fn mldsa_sign_bytes(
    signing_seed: &SecretBytes,
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let seed: [u8; 32] = signing_seed
        .expose_secret()
        .try_into()
        .map_err(|_| CryptoError::InvalidInputLength)?;
    Ok(mldsa_sign(&Secret::new(seed), message))
}

/// Verify an ML-DSA-65 signature.
#[must_use]
pub fn mldsa_verify(verifying_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(encoded_key) = EncodedVerifyingKey::<MlDsa65>::try_from(verifying_key) else {
        return false;
    };
    let verifying_key = VerifyingKey::<MlDsa65>::decode(&encoded_key);
    let Ok(encoded_signature) = EncodedSignature::<MlDsa65>::try_from(signature) else {
        return false;
    };
    let Some(signature) = Signature::<MlDsa65>::decode(&encoded_signature) else {
        return false;
    };
    verifying_key.verify(message, &signature).is_ok()
}

fn signing_key_from_seed(seed: &Secret<32>) -> SigningKey<MlDsa65> {
    SigningKey::<MlDsa65>::from_seed(&(*seed.expose_secret()).into())
}
