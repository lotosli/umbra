//! ChaCha20 stream-cipher helper.

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

/// XOR `input` with the ChaCha20 keystream using a 96-bit nonce and block counter.
#[must_use]
pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, input: &[u8]) -> Vec<u8> {
    let mut cipher = chacha20::ChaCha20::new(key.into(), nonce.into());
    cipher.seek(u64::from(counter) * 64);
    let mut output = input.to_vec();
    cipher.apply_keystream(&mut output);
    output
}
