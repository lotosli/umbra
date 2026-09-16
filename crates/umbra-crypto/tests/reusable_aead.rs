//! Reusable contexts preserve an independent implementation's authenticated bytes.

use umbra_crypto::{
    aead::{self, AeadAlgorithm, AeadContext},
    CryptoError,
};
use zeroize::Zeroize;

#[test]
fn scenario_reused_context_matches_independent_vectors() {
    for (algorithm, reference) in [
        (AeadAlgorithm::Aes128Gcm, &ring::aead::AES_128_GCM),
        (AeadAlgorithm::Aes256Gcm, &ring::aead::AES_256_GCM),
        (
            AeadAlgorithm::ChaCha20Poly1305,
            &ring::aead::CHACHA20_POLY1305,
        ),
    ] {
        let key = vec![0x42; algorithm.key_len()];
        let context = AeadContext::new(algorithm, &key).unwrap();
        let reference =
            ring::aead::LessSafeKey::new(ring::aead::UnboundKey::new(reference, &key).unwrap());
        for (sequence, length) in [0, 1, 15, 16, 17, 1024, 16_384].into_iter().enumerate() {
            let mut nonce = [0x12; 12];
            nonce[4..].copy_from_slice(&u64::try_from(sequence).unwrap().to_be_bytes());
            let input = vec![0xa5; length];
            let mut expected = input.clone();
            reference
                .seal_in_place_append_tag(
                    ring::aead::Nonce::assume_unique_for_key(nonce),
                    ring::aead::Aad::from(b"header"),
                    &mut expected,
                )
                .unwrap();
            let mut output = input.clone();
            let tag = context
                .seal_in_place(&nonce, &mut output, b"header")
                .unwrap();
            output.extend_from_slice(&tag);
            assert_eq!(output, expected);
            let capacity = output.capacity();
            context
                .open_in_place(&nonce, &mut output, b"header")
                .unwrap();
            assert_eq!(output, input);
            assert_eq!(output.capacity(), capacity);
            let mut failed = expected.clone();
            assert_eq!(
                context.open_in_place(&nonce, &mut failed, b"wrong"),
                Err(CryptoError::AuthenticationFailed)
            );
            assert!(failed.is_empty());
            let mut detached = expected[..length].to_vec();
            let mut wrong = tag;
            wrong[0] ^= 1;
            assert!(context
                .open_in_place_detached(&nonce, &mut detached, b"header", &wrong)
                .is_err());
            assert!(detached.iter().all(|byte| *byte == 0));
        }
    }
}

#[test]
fn scenario_explicitly_cleared_context_is_terminal() {
    for algorithm in [
        AeadAlgorithm::Aes128Gcm,
        AeadAlgorithm::Aes256Gcm,
        AeadAlgorithm::ChaCha20Poly1305,
    ] {
        assert!(AeadContext::new(algorithm, &[]).is_err());
        let mut context = AeadContext::new(algorithm, &vec![0x42; algorithm.key_len()]).unwrap();
        assert_eq!(format!("{context:?}"), "AeadContext(<redacted>)");
        assert_eq!(
            context.seal_in_place(&[], &mut [], b""),
            Err(CryptoError::InvalidNonceLength)
        );
        let mut short = vec![0xa5; 15];
        assert!(context.open_in_place(&[0; 12], &mut short, b"").is_err());
        assert!(short.is_empty());
        let mut invalid_nonce = vec![0xa5; 16];
        assert_eq!(
            context.open_in_place(&[], &mut invalid_nonce, b""),
            Err(CryptoError::InvalidNonceLength)
        );
        assert!(invalid_nonce.is_empty());
        context.zeroize();
        context.zeroize();
        assert_eq!(
            context.seal_in_place(&[0; 12], &mut [], b""),
            Err(CryptoError::ContextCleared)
        );
        let mut payload = [0xa5; 16];
        assert_eq!(
            context.open_in_place_detached(&[0; 12], &mut payload, b"", &[0; 16]),
            Err(CryptoError::ContextCleared)
        );
        assert_eq!(payload, [0; 16]);
    }
}

#[test]
#[ignore = "explicit serial release-mode context/buffer throughput diagnostic"]
fn measure_reusable_context_and_buffers() {
    for length in [1024, 16_384] {
        let count = 64 * 1024 * 1024 / length;
        let plaintext = vec![0xa5; length];
        for cached in [false, true] {
            let context = AeadContext::new(AeadAlgorithm::Aes128Gcm, &[0x42; 16]).unwrap();
            let mut output = Vec::with_capacity(length + 16);
            let started = std::time::Instant::now();
            for sequence in 0..count {
                let mut nonce = [0; 12];
                nonce[0] = u8::from(cached);
                nonce[4..].copy_from_slice(&u64::try_from(sequence).unwrap().to_be_bytes());
                if cached {
                    output.clear();
                    output.extend_from_slice(&plaintext);
                    let tag = context
                        .seal_in_place(&nonce, &mut output, b"header")
                        .unwrap();
                    output.extend_from_slice(&tag);
                } else {
                    output = aead::seal(
                        AeadAlgorithm::Aes128Gcm,
                        &[0x42; 16],
                        &nonce,
                        &plaintext,
                        b"header",
                    )
                    .unwrap();
                }
                assert_eq!(output.len(), length + 16);
                std::hint::black_box(&output);
            }
            let seconds = started.elapsed().as_secs_f64();
            println!("aead cached={cached} record_bytes={length} bytes=67108864 seconds={seconds:.6} mbps={:.3}", 536.870_912 / seconds);
        }
    }
}
