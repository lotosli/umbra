//! Integration tests for the `pq-primitives` capability.

use umbra_crypto::{
    mldsa, mlkem,
    secret::{Secret, SecretBytes},
    CryptoError,
};

#[test]
fn scenario_mlkem_encapsulation_shared_secret_matches_decapsulation() {
    let keypair = mlkem::mlkem_keygen();
    let encapsulated =
        mlkem::mlkem_encapsulate(&keypair.encapsulation_key).expect("encapsulation should work");
    let decapsulated =
        mlkem::mlkem_decapsulate(&keypair.decapsulation_key, &encapsulated.ciphertext)
            .expect("decapsulation should work");

    assert!(encapsulated.shared_secret.ct_eq(&decapsulated));
}

#[test]
fn scenario_mlkem_rejects_wrong_lengths() {
    assert_eq!(
        mlkem::mlkem_encapsulate(&[0_u8; 8]).expect_err("short public key should fail"),
        CryptoError::InvalidInputLength
    );

    let keypair = mlkem::mlkem_keygen();
    assert_eq!(
        mlkem::mlkem_decapsulate(&keypair.decapsulation_key, &[0_u8; 8])
            .expect_err("short ciphertext should fail"),
        CryptoError::InvalidInputLength
    );
}

#[test]
fn scenario_mldsa_valid_signature_verifies() {
    let seed = [7_u8; 32];
    let keypair = mldsa::mldsa_keygen_from_seed(&seed);
    let message = b"leaf SPKI bytes";
    let signature = mldsa::mldsa_sign(&keypair.signing_seed, message);

    assert!(mldsa::mldsa_verify(
        &keypair.verifying_key,
        message,
        &signature
    ));
}

#[test]
fn scenario_mldsa_random_keygen_outputs_parseable_keys() {
    let keypair = mldsa::mldsa_keygen();
    let message = b"generated key message";
    let signature = mldsa::mldsa_sign(&keypair.signing_seed, message);

    assert_eq!(keypair.signing_seed.expose_secret().len(), 32);
    assert!(mldsa::mldsa_verify(
        &keypair.verifying_key,
        message,
        &signature
    ));
    assert!(!mldsa::mldsa_verify(
        &keypair.verifying_key,
        message,
        &[0_u8; 8]
    ));
}

#[test]
fn scenario_mldsa_tampered_signature_is_rejected() {
    let seed = [9_u8; 32];
    let keypair = mldsa::mldsa_keygen_from_seed(&seed);
    let message = b"certificate binding message";
    let mut signature = mldsa::mldsa_sign(&keypair.signing_seed, message);
    signature[0] ^= 0x01;

    assert!(!mldsa::mldsa_verify(
        &keypair.verifying_key,
        message,
        &signature
    ));

    let valid_signature = mldsa::mldsa_sign(&keypair.signing_seed, message);
    assert!(!mldsa::mldsa_verify(
        &keypair.verifying_key,
        b"different message",
        &valid_signature
    ));
}

#[test]
fn scenario_mldsa_rejects_wrong_lengths() {
    let seed = SecretBytes::new(vec![1, 2, 3]);
    assert_eq!(
        mldsa::mldsa_sign_bytes(&seed, b"message").expect_err("short seed should fail"),
        CryptoError::InvalidInputLength
    );
    assert!(!mldsa::mldsa_verify(&[0_u8; 8], b"message", &[0_u8; 8]));
}

#[test]
fn scenario_pq_secret_debug_output_is_redacted() {
    let fixed = Secret::<32>::new([0xab; 32]);
    let variable = SecretBytes::new(vec![0xcd; 64]);

    let fixed_debug = format!("{fixed:?}");
    let variable_debug = format!("{variable:?}");

    assert!(fixed_debug.contains("redacted"));
    assert!(variable_debug.contains("redacted"));
    assert!(!fixed_debug.contains("ab"));
    assert!(!variable_debug.contains("cd"));
    assert_eq!(variable.len(), 64);
    assert!(!variable.is_empty());
}

#[test]
fn scenario_secret_bytes_into_inner() {
    let secret = SecretBytes::new(vec![1, 2, 3, 4]);

    assert_eq!(secret.into_inner(), vec![1, 2, 3, 4]);
}
