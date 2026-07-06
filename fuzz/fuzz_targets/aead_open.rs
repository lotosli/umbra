#![no_main]

use libfuzzer_sys::fuzz_target;
use umbra_crypto::aead::{self, AeadAlgorithm};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let algorithm = match data[0] % 3 {
        0 => AeadAlgorithm::Aes128Gcm,
        1 => AeadAlgorithm::Aes256Gcm,
        _ => AeadAlgorithm::ChaCha20Poly1305,
    };
    let key = vec![data[0]; algorithm.key_len()];
    let nonce = vec![data[1]; algorithm.nonce_len()];
    let split = 2 + usize::from(data[1]) % (data.len() - 1);
    let ciphertext = &data[2..split];
    let aad = &data[split..];

    let _ = aead::open(algorithm, &key, &nonce, ciphertext, aad);
});
