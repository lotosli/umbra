//! Integration tests for the `crypto-primitives` OpenSpec capability.

use proptest::prelude::*;
use umbra_crypto::{
    aead::{self, AeadAlgorithm},
    kdf, mac,
    secret::Secret,
    stream, x25519, CryptoError,
};

#[test]
fn scenario_x25519_shared_secret_is_symmetric() {
    let alice = x25519::generate_keypair();
    let bob = x25519::generate_keypair();

    let alice_shared =
        x25519::agree(&alice.private, bob.public.as_bytes()).expect("alice agreement should work");
    let bob_shared =
        x25519::agree(&bob.private, alice.public.as_bytes()).expect("bob agreement should work");

    assert!(alice_shared.ct_eq(&bob_shared));
    assert_eq!(alice_shared.expose_secret().len(), 32);
}

#[test]
fn scenario_x25519_rfc7748_vector() {
    let scalar = hex_32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let point = hex_32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let expected = hex_32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    assert_eq!(x25519::agree_raw(scalar, point), expected);
}

#[test]
fn scenario_x25519_public_from_private_and_invalid_peer() {
    let scalar = Secret::new(hex_32(
        "0900000000000000000000000000000000000000000000000000000000000000",
    ));
    let public = x25519::public_from_private(&scalar);
    let public_bytes = public.into_bytes();

    assert_eq!(
        public_bytes,
        hex_32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
    );
    assert_eq!(
        x25519::agree(&scalar, &[0_u8; 31]).expect_err("short peer key should fail"),
        CryptoError::InvalidInputLength
    );
}

#[test]
fn scenario_hkdf_rfc5869_vectors() {
    let ikm = vec![0x0b; 22];
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let expected = hex("3cb25f25faacd57a90434f64d0362f2a\
         2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865");

    let okm = kdf::hkdf_sha256(&salt, &ikm, &info, 42).expect("HKDF vector should derive");
    assert_eq!(okm, expected);
}

#[test]
fn scenario_hkdf_extract_and_expand_into() {
    let salt = hex("000102030405060708090a0b0c");
    let prk = kdf::hkdf_sha256_extract(&salt, &[0x0b; 22]);
    let expected_prk = hex_32("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    let mut okm = [0_u8; 42];

    kdf::hkdf_sha256_into(&salt, &[0x0b; 22], &hex("f0f1f2f3f4f5f6f7f8f9"), &mut okm)
        .expect("HKDF into should derive");

    assert_eq!(prk, expected_prk);
    assert_eq!(
        okm.to_vec(),
        hex("3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",)
    );
}

#[test]
fn scenario_hmac_reject_tampered_tag() {
    let key = b"verification key";
    let message = b"message to authenticate";
    let mut tag = mac::hmac_sha256(key, message).expect("HMAC should compute");
    tag[0] ^= 0x01;

    assert!(!mac::verify_hmac_sha256(key, message, &tag));
}

#[test]
fn scenario_hmac_accept_valid_tag() {
    let key = b"verification key";
    let message = b"message to authenticate";
    let tag = mac::hmac_sha256(key, message).expect("HMAC should compute");

    assert!(mac::verify_hmac_sha256(key, message, &tag));
}

#[test]
fn scenario_aead_round_trip_all_algorithms() {
    for algorithm in [
        AeadAlgorithm::Aes128Gcm,
        AeadAlgorithm::Aes256Gcm,
        AeadAlgorithm::ChaCha20Poly1305,
    ] {
        let key = vec![0x11; algorithm.key_len()];
        let nonce = vec![0x22; algorithm.nonce_len()];
        let aad = b"associated data";
        let plaintext = b"plaintext bytes";

        let ciphertext =
            aead::seal(algorithm, &key, &nonce, plaintext, aad).expect("seal should work");
        let opened =
            aead::open(algorithm, &key, &nonce, &ciphertext, aad).expect("open should work");

        assert_eq!(opened, plaintext);
        assert_ne!(ciphertext, plaintext);
    }
}

#[test]
fn scenario_aead_reject_wrong_associated_data() {
    let algorithm = AeadAlgorithm::Aes128Gcm;
    let key = vec![0x33; algorithm.key_len()];
    let nonce = vec![0x44; algorithm.nonce_len()];
    let ciphertext =
        aead::seal(algorithm, &key, &nonce, b"secret", b"aad").expect("seal should work");

    let err = aead::open(algorithm, &key, &nonce, &ciphertext, b"different aad")
        .expect_err("wrong AAD must fail");

    assert_eq!(err, CryptoError::AuthenticationFailed);
}

#[test]
fn scenario_aes_gcm_known_answer_vector() {
    let key = [0_u8; 16];
    let nonce = [0_u8; 12];
    let plaintext = [0_u8; 16];
    let expected = hex("0388dace60b6a392f328c2b971b2fe78\
         ab6e47d42cec13bdf53a67b21257bddf");

    let ciphertext = aead::seal(AeadAlgorithm::Aes128Gcm, &key, &nonce, &plaintext, &[])
        .expect("AES-GCM vector should seal");

    assert_eq!(ciphertext, expected);
}

#[test]
fn scenario_aead_reject_wrong_lengths() {
    let err = aead::seal(AeadAlgorithm::Aes256Gcm, &[0_u8; 16], &[0_u8; 12], b"", b"")
        .expect_err("wrong key length should fail");
    assert_eq!(err, CryptoError::InvalidKeyLength);

    let err = aead::open(
        AeadAlgorithm::ChaCha20Poly1305,
        &[0_u8; 32],
        &[0_u8; 8],
        b"",
        b"",
    )
    .expect_err("wrong nonce length should fail");
    assert_eq!(err, CryptoError::InvalidNonceLength);
}

#[test]
fn scenario_chacha20_rfc8439_vectors() {
    let key = hex_32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let nonce = hex_12("000000000000004a00000000");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = hex("6e2e359a2568f98041ba0728dd0d6981\
         e97e7aec1d4360c20a27afccfd9fae0b\
         f91b65c5524733ab8f593dabcd62b357\
         1639d624e65152ab8f530c359f0861d8\
         07ca0dbf500d6a6156a38e088a22b65e\
         52bc514d16ccf806818ce91ab7793736\
         5af90bbf74a35be6b40b8eedf2785e42\
         874d");

    let ciphertext = stream::chacha20_xor(&key, &nonce, 1, plaintext);

    assert_eq!(ciphertext, expected);
}

#[test]
fn scenario_secret_debug_does_not_leak() {
    let secret = Secret::<4>::new([0xde, 0xad, 0xbe, 0xef]);
    let rendered = format!("{secret:?}");

    assert!(rendered.contains("redacted"));
    assert!(!rendered.to_ascii_lowercase().contains("deadbeef"));
}

#[test]
fn scenario_secret_constant_time_eq_and_into_inner() {
    let left = Secret::<4>::new([1, 2, 3, 4]);
    let same = Secret::<4>::new([1, 2, 3, 4]);
    let different = Secret::<4>::new([1, 2, 3, 5]);

    assert!(left.ct_eq(&same));
    assert_eq!(left, same);
    assert!(!different.ct_eq(&same));
    assert_eq!(different.into_inner(), [1, 2, 3, 5]);
}

proptest! {
    #[test]
    fn prop_aead_round_trip(
        plaintext in proptest::collection::vec(any::<u8>(), 0..1024),
        aad in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        for algorithm in [
            AeadAlgorithm::Aes128Gcm,
            AeadAlgorithm::Aes256Gcm,
            AeadAlgorithm::ChaCha20Poly1305,
        ] {
            let key = vec![0x5a; algorithm.key_len()];
            let nonce = vec![0xa5; algorithm.nonce_len()];
            let ciphertext = aead::seal(algorithm, &key, &nonce, &plaintext, &aad)?;
            let opened = aead::open(algorithm, &key, &nonce, &ciphertext, &aad)?;
            prop_assert_eq!(opened, plaintext.clone());
        }
    }

    #[test]
    fn prop_hkdf_output_len(
        ikm in proptest::collection::vec(any::<u8>(), 0..128),
        salt in proptest::collection::vec(any::<u8>(), 0..64),
        info in proptest::collection::vec(any::<u8>(), 0..64),
        len in 0_usize..128,
    ) {
        let okm = kdf::hkdf_sha256(&salt, &ikm, &info, len)?;
        prop_assert_eq!(okm.len(), len);
    }
}

fn hex(input: &str) -> Vec<u8> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(compact.len() % 2, 0, "hex length must be even");
    (0..compact.len())
        .step_by(2)
        .map(|idx| {
            u8::from_str_radix(&compact[idx..idx + 2], 16).expect("test vector hex should parse")
        })
        .collect()
}

fn hex_32(input: &str) -> [u8; 32] {
    hex(input)
        .try_into()
        .expect("test vector should be 32 bytes")
}

fn hex_12(input: &str) -> [u8; 12] {
    hex(input)
        .try_into()
        .expect("test vector should be 12 bytes")
}
