//! Chrome fingerprint profiles and ClientHello self-check helpers.
//!
//! Profiles live under the repository-level `fingerprints/` directory and are
//! embedded into release binaries for built-in names. The TLS stack consumes
//! these data files instead of hard-coding Chrome extension and QUIC
//! transport-parameter tables.

pub mod grease;
pub mod ja3;
pub mod profile;

pub use ja3::{ja3_ja4, ClientHelloFingerprint};
pub use profile::{load_profile, FingerprintError, FingerprintProfile, QuicFingerprint};
