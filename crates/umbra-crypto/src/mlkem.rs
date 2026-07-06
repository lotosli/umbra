//! ML-KEM-768 wrappers.

use kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;

use crate::{
    secret::{Secret, SecretBytes},
    CryptoError,
};

type DecapsulationKey = <MlKem768 as KemCore>::DecapsulationKey;
type EncapsulationKey = <MlKem768 as KemCore>::EncapsulationKey;
type Ciphertext = ml_kem::Ciphertext<MlKem768>;

/// Encoded ML-KEM-768 keypair.
#[derive(Debug)]
pub struct MlkemKeypair {
    /// Public encapsulation key bytes.
    pub encapsulation_key: Vec<u8>,
    /// Secret decapsulation key bytes.
    pub decapsulation_key: SecretBytes,
}

/// Encapsulation output.
#[derive(Debug)]
pub struct MlkemEncapsulation {
    /// Ciphertext to send to the decapsulating peer.
    pub ciphertext: Vec<u8>,
    /// Shared secret produced by encapsulation.
    pub shared_secret: Secret<32>,
}

/// Generate an ML-KEM-768 keypair.
#[must_use]
pub fn mlkem_keygen() -> MlkemKeypair {
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    MlkemKeypair {
        encapsulation_key: ek.as_bytes().to_vec(),
        decapsulation_key: SecretBytes::new(dk.as_bytes().to_vec()),
    }
}

/// Encapsulate a shared secret to an encoded ML-KEM-768 public key.
pub fn mlkem_encapsulate(encapsulation_key: &[u8]) -> Result<MlkemEncapsulation, CryptoError> {
    let ek = decode_encapsulation_key(encapsulation_key)?;
    let (ciphertext, shared_secret) = ek
        .encapsulate(&mut OsRng)
        .map_err(|()| CryptoError::AuthenticationFailed)?;
    Ok(MlkemEncapsulation {
        ciphertext: ciphertext.to_vec(),
        shared_secret: Secret::new(array_to_32(&shared_secret)?),
    })
}

/// Decapsulate an ML-KEM-768 ciphertext with an encoded secret key.
pub fn mlkem_decapsulate(
    decapsulation_key: &SecretBytes,
    ciphertext: &[u8],
) -> Result<Secret<32>, CryptoError> {
    let dk = decode_decapsulation_key(decapsulation_key.expose_secret())?;
    let ciphertext = decode_ciphertext(ciphertext)?;
    let shared_secret = dk
        .decapsulate(&ciphertext)
        .map_err(|()| CryptoError::AuthenticationFailed)?;
    Ok(Secret::new(array_to_32(&shared_secret)?))
}

fn decode_encapsulation_key(bytes: &[u8]) -> Result<EncapsulationKey, CryptoError> {
    let encoded = Encoded::<EncapsulationKey>::try_from(bytes)
        .map_err(|_| CryptoError::InvalidInputLength)?;
    Ok(EncapsulationKey::from_bytes(&encoded))
}

fn decode_decapsulation_key(bytes: &[u8]) -> Result<DecapsulationKey, CryptoError> {
    let encoded = Encoded::<DecapsulationKey>::try_from(bytes)
        .map_err(|_| CryptoError::InvalidInputLength)?;
    Ok(DecapsulationKey::from_bytes(&encoded))
}

fn decode_ciphertext(bytes: &[u8]) -> Result<Ciphertext, CryptoError> {
    Ciphertext::try_from(bytes).map_err(|_| CryptoError::InvalidInputLength)
}

fn array_to_32(bytes: &[u8]) -> Result<[u8; 32], CryptoError> {
    bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidInputLength)
}
