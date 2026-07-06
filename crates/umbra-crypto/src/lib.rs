//! Cryptographic primitives used by Umbra protocol components.
//!
//! This crate is a small typed wrapper around audited RustCrypto and dalek
//! primitives. It does not invent algorithms; it centralizes error handling,
//! secret zeroization, constant-time verification, and vector-tested APIs used
//! by the TLS and REALITY layers.

pub mod aead;
pub mod error;
pub mod kdf;
pub mod mac;
pub mod mldsa;
pub mod mlkem;
pub mod secret;
pub mod stream;
pub mod x25519;

pub use error::CryptoError;
