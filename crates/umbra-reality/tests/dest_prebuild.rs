//! Integration tests for component D: destination prebuild profiles.

use std::{cell::RefCell, time::Duration};

use umbra_reality::{
    prebuild::{
        probe_dest_with, CertTemplate, DestProfile, ProbeBackend, ProbeSample, ProfileStore,
    },
    RealityError,
};

#[test]
fn scenario_probe_captures_successful_profile() {
    let backend = StaticBackend::ok(sample_with_cipher(0x1301));
    let profile = probe_dest_with("example.com:443", &backend).expect("probe should pass");

    assert_eq!(profile.dest, "example.com:443");
    assert_eq!(profile.tls_ver, 0x0304);
    assert_eq!(profile.cipher, 0x1301);
    assert_eq!(profile.group, 0x001d);
    assert_eq!(profile.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert_eq!(profile.ee_exts, vec![0x000a, 0x0010]);
    assert!(profile.ocsp.is_some());
    assert_eq!(profile.rtt, Duration::from_millis(42));

    let tls_profile = profile.to_tls_server_profile();
    assert_eq!(tls_profile.server_name, "example.com");
    assert_eq!(tls_profile.cipher_suite, 0x1301);
    assert_eq!(tls_profile.alpn.as_deref(), Some("h2"));
    assert_eq!(tls_profile.rtt_millis, 42);
}

#[test]
fn scenario_refresh_replaces_stale_profile() {
    let store = ProfileStore::new();
    let backend = QueueBackend::new(vec![
        Ok(sample_with_cipher(0x1301)),
        Ok(sample_with_cipher(0x1303)),
    ]);

    let first = store
        .startup_refresh("example.com:443", &backend)
        .expect("startup profile");
    let second = store
        .refresh("example.com:443", &backend)
        .expect("refresh profile");

    assert_eq!(first.cipher, 0x1301);
    assert_eq!(second.cipher, 0x1303);
    assert_eq!(store.active().expect("active").cipher, 0x1303);
}

#[test]
fn scenario_failed_refresh_keeps_prior_profile() {
    let store = ProfileStore::new();
    let backend = QueueBackend::new(vec![
        Ok(sample_with_cipher(0x1301)),
        Err(RealityError::ProbeFailed("offline")),
    ]);

    store
        .startup_refresh("example.com:443", &backend)
        .expect("startup profile");
    let retained = store
        .refresh("example.com:443", &backend)
        .expect("failed refresh should retain active");

    assert_eq!(retained.cipher, 0x1301);
    assert_eq!(store.active().expect("active").cipher, 0x1301);
}

#[test]
fn scenario_startup_failure_without_prior_profile_is_explicit() {
    let store = ProfileStore::new();
    let backend = StaticBackend::err(RealityError::ProbeFailed("offline"));

    assert_eq!(
        store
            .startup_refresh("example.com:443", &backend)
            .expect_err("startup must fail without profile"),
        RealityError::ProbeFailed("offline")
    );
    assert_eq!(
        store.active().expect_err("no active profile"),
        RealityError::NoActiveProfile
    );
}

#[test]
fn scenario_profile_validation_fails_fast() {
    assert_eq!(
        DestProfile::from_sample("", sample_with_cipher(0x1301)).expect_err("empty dest must fail"),
        RealityError::InvalidDestProfile("destination is empty")
    );
    assert_eq!(
        DestProfile::from_sample("example.com", sample_with_cipher(0x1301))
            .expect_err("missing port must fail"),
        RealityError::InvalidDestProfile("destination must be host:port")
    );

    let mut bad_tls = sample_with_cipher(0x1301);
    bad_tls.tls_ver = 0x0303;
    assert_eq!(
        DestProfile::from_sample("example.com:443", bad_tls).expect_err("TLS 1.2 must fail"),
        RealityError::InvalidDestProfile("destination is not TLS 1.3")
    );

    let mut bad_validity = sample_with_cipher(0x1301);
    bad_validity.leaf_template.not_after_unix = bad_validity.leaf_template.not_before_unix;
    assert_eq!(
        DestProfile::from_sample("example.com:443", bad_validity)
            .expect_err("bad cert validity must fail"),
        RealityError::InvalidDestProfile("certificate validity range is invalid")
    );
}

struct StaticBackend {
    result: Result<ProbeSample, RealityError>,
}

impl StaticBackend {
    fn ok(sample: ProbeSample) -> Self {
        Self { result: Ok(sample) }
    }

    fn err(error: RealityError) -> Self {
        Self { result: Err(error) }
    }
}

impl ProbeBackend for StaticBackend {
    fn probe_dest(&self, dest: &str) -> Result<DestProfile, RealityError> {
        let sample = self.result.clone()?;
        DestProfile::from_sample(dest, sample)
    }
}

struct QueueBackend {
    results: RefCell<Vec<Result<ProbeSample, RealityError>>>,
}

impl QueueBackend {
    fn new(mut results: Vec<Result<ProbeSample, RealityError>>) -> Self {
        results.reverse();
        Self {
            results: RefCell::new(results),
        }
    }
}

impl ProbeBackend for QueueBackend {
    fn probe_dest(&self, dest: &str) -> Result<DestProfile, RealityError> {
        let result = self
            .results
            .borrow_mut()
            .pop()
            .ok_or(RealityError::ProbeFailed("empty queue"))?;
        DestProfile::from_sample(dest, result?)
    }
}

fn sample_with_cipher(cipher: u16) -> ProbeSample {
    ProbeSample {
        tls_ver: 0x0304,
        cipher,
        group: 0x001d,
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        ee_exts: vec![0x000a, 0x0010],
        leaf_template: CertTemplate {
            subject: "CN=example.com".to_owned(),
            issuer: "CN=Test CA".to_owned(),
            not_before_unix: 100,
            not_after_unix: 200,
            san_dns: vec!["example.com".to_owned()],
            sct: vec![b"sct".to_vec()],
            signature_algorithm: "ecdsa-with-SHA256".to_owned(),
            leaf_der: b"leaf".to_vec(),
        },
        ocsp: Some(b"ocsp".to_vec()),
        rtt: Duration::from_millis(42),
    }
}
