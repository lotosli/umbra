//! `umbra-testkit` shared fixtures for process-local protocol tests.
//!
//! The crate intentionally keeps helpers deterministic and in-memory so tests
//! can exercise fallback, dispatch, and inner relay behavior without external
//! network access.

use std::time::Duration;

use umbra_core::dispatch::{HelloReadLimits, ServerCfg};
use umbra_crypto::{secret::Secret, x25519};
use umbra_proto::addr::TargetAddr;
use umbra_reality::prebuild::{CertTemplate, DestProfile};

/// Fixed Unix timestamp used by deterministic loopback tests.
pub const LOOPBACK_NOW: u64 = 1_765_000_000;

/// Build a dispatch config suitable for loopback fallback tests.
#[must_use]
pub fn loopback_dispatch_cfg(server_key: x25519::Keypair) -> ServerCfg {
    ServerCfg {
        private_key: server_key.private,
        short_ids: vec![b"short".to_vec()],
        server_names: vec!["server.example".to_owned()],
        dest: "dest.example:443".to_owned(),
        max_time_diff: 120,
        mldsa_seed: Secret::new([7_u8; 32]),
        hello_limits: HelloReadLimits::default(),
    }
}

/// Return a malformed ClientHello record that should enter fallback dispatch.
#[must_use]
pub fn malformed_client_hello_record() -> Vec<u8> {
    vec![0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00]
}

/// Return a deterministic destination profile for forged-handshake tests.
#[must_use]
pub fn sample_dest_profile() -> DestProfile {
    DestProfile {
        dest: "template.example:443".to_owned(),
        tls_ver: 0x0304,
        cipher: 0x1301,
        group: 0x001d,
        alpn: vec![b"h2".to_vec()],
        ee_exts: vec![0x0010],
        leaf_template: CertTemplate {
            subject: "CN=template.example".to_owned(),
            issuer: "CN=Template CA".to_owned(),
            not_before_unix: 1_700_000_000,
            not_after_unix: 1_800_000_000,
            san_dns: vec!["template.example".to_owned()],
            sct: Vec::new(),
            signature_algorithm: "ecdsa-with-SHA256".to_owned(),
            leaf_der: Vec::new(),
        },
        ocsp: None,
        rtt: Duration::from_millis(40),
    }
}

/// Return the default target used by loopback inner relay tests.
#[must_use]
pub fn sample_target() -> TargetAddr {
    TargetAddr::Domain("target.example".to_owned(), 443)
}
