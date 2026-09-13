//! Integration tests for component B: REALITY session_id authentication.

use proptest::prelude::*;
use umbra_reality::{
    auth::{
        open_session_id, seal_session_id, seal_session_id_with_flags, try_seal_session_id,
        try_seal_session_id_with_version, validate_server_name, ShortId, AUTH_VERSION_V1,
        AUTH_VERSION_V2,
    },
    replay::ReplayCache,
    RealityError,
};

#[test]
fn scenario_sealed_token_opens_with_same_hello() {
    let shared = shared_secret();
    let hello0 = b"client hello with zero session id";
    let session_id =
        try_seal_session_id(&shared, b"client-a", hello0, 100).expect("session id should seal");
    let replay = ReplayCache::new(16, 180).expect("cache should build");
    let opened = open_session_id(
        &shared,
        &session_id,
        hello0,
        &[b"client-a".to_vec()],
        105,
        120,
        &replay,
    )
    .expect("session id should open");

    assert_eq!(opened.flags, 0);
    assert_eq!(opened.version, AUTH_VERSION_V1);
    assert_eq!(opened.timestamp, 100);
    assert!(opened
        .short_id
        .ct_eq(&ShortId::from_slice(b"client-a").expect("short id")));
    assert_eq!(replay.len().expect("cache len"), 1);
}

#[test]
fn scenario_aad_change_is_rejected() {
    let shared = shared_secret();
    let session_id =
        try_seal_session_id(&shared, b"sid", b"hello0", 100).expect("session id should seal");
    let replay = ReplayCache::new(4, 180).expect("cache should build");

    assert_eq!(
        open_session_id(
            &shared,
            &session_id,
            b"hello1",
            &[b"sid".to_vec()],
            100,
            120,
            &replay,
        )
        .expect_err("AAD change must fail"),
        RealityError::AuthenticationFailed
    );
}

#[test]
fn scenario_expired_token_is_rejected() {
    let shared = shared_secret();
    let session_id =
        try_seal_session_id(&shared, b"sid", b"hello0", 100).expect("session id should seal");
    let replay = ReplayCache::new(4, 180).expect("cache should build");

    assert_eq!(
        open_session_id(
            &shared,
            &session_id,
            b"hello0",
            &[b"sid".to_vec()],
            221,
            120,
            &replay,
        )
        .expect_err("expired token must fail"),
        RealityError::Expired
    );
}

#[test]
fn scenario_replayed_key_share_is_rejected() {
    let shared = shared_secret();
    let session_id =
        try_seal_session_id(&shared, b"sid", b"hello0", 100).expect("session id should seal");
    let replay = ReplayCache::new(4, 180).expect("cache should build");

    open_session_id(
        &shared,
        &session_id,
        b"hello0",
        &[b"sid".to_vec()],
        100,
        120,
        &replay,
    )
    .expect("first open should pass");
    assert_eq!(
        open_session_id(
            &shared,
            &session_id,
            b"hello0",
            &[b"sid".to_vec()],
            100,
            120,
            &replay,
        )
        .expect_err("second open must replay"),
        RealityError::Replay
    );
}

#[test]
fn scenario_future_token_remains_replay_protected_through_inclusive_deadline() {
    let shared = shared_secret();
    let allowed = [b"sid".to_vec()];
    let session_id = try_seal_session_id(&shared, b"sid", b"hello0", 220).expect("seal");
    let cache = ReplayCache::new(1, 120).expect("cache");

    assert_eq!(
        open_session_id(&shared, &session_id, b"hello0", &allowed, 99, 120, &cache),
        Err(RealityError::Expired)
    );
    assert!(cache
        .is_empty()
        .expect("invalid token must not reserve capacity"));
    let opened = open_session_id(&shared, &session_id, b"hello0", &allowed, 100, 120, &cache)
        .expect("future token accepted at lower inclusive boundary");
    assert_eq!(opened.timestamp, 220);

    for now in [100, 220, 221, 340] {
        assert_eq!(cache.cleanup(now).expect("cleanup"), 1);
        assert_eq!(
            open_session_id(&shared, &session_id, b"hello0", &allowed, now, 120, &cache),
            Err(RealityError::Replay),
            "token must remain replay-protected at {now}"
        );
    }

    assert_eq!(cache.cleanup(341).expect("expired cleanup"), 0);
    assert_eq!(
        open_session_id(&shared, &session_id, b"hello0", &allowed, 341, 120, &cache),
        Err(RealityError::Expired)
    );
    assert!(cache
        .is_empty()
        .expect("expired token cannot regain authentication"));
}

#[test]
fn scenario_expired_entry_can_be_accepted_again() {
    let cache = ReplayCache::new(2, 1).expect("cache should build");
    let key = [0x44; 32];

    cache.insert_or_reject(key, 10).expect("first insert");
    assert_eq!(
        cache
            .insert_or_reject(key, 10)
            .expect_err("active replay must fail"),
        RealityError::Replay
    );
    assert_eq!(cache.cleanup(12).expect("cleanup"), 0);
    cache
        .insert_or_reject(key, 12)
        .expect("expired key can be inserted again");
}

#[test]
fn scenario_replay_cache_is_capacity_bounded() {
    let cache = ReplayCache::new(2, 100).expect("cache should build");

    cache.insert_or_reject([1; 32], 1).expect("insert first");
    cache.insert_or_reject([2; 32], 2).expect("insert second");
    assert_eq!(
        cache.insert_or_reject([3; 32], 3),
        Err(RealityError::ReplayCacheFull)
    );

    assert_eq!(cache.len().expect("len"), 2);
    for key in [[1; 32], [2; 32]] {
        assert_eq!(cache.insert_or_reject(key, 4), Err(RealityError::Replay));
    }
    assert_eq!(cache.len().expect("len"), 2);
    cache
        .insert_or_reject([3; 32], 102)
        .expect("insertion reclaims expired capacity");
    assert_eq!(cache.len().expect("len"), 2);
    assert_eq!(
        cache.insert_or_reject([2; 32], 102),
        Err(RealityError::Replay)
    );
}

#[test]
fn scenario_out_of_order_deadlines_reclaim_only_expired_entries() {
    let cache = ReplayCache::new(2, 1).expect("cache");
    cache
        .insert_or_reject_until([1; 32], 100, 340)
        .expect("long deadline inserted first");
    cache
        .insert_or_reject_until([2; 32], 100, 220)
        .expect("short deadline inserted second");
    assert_eq!(cache.cleanup(220).expect("inclusive cleanup"), 2);
    assert_eq!(
        cache.insert_or_reject_until([3; 32], 220, 500),
        Err(RealityError::ReplayCacheFull)
    );

    cache
        .insert_or_reject_until([2; 32], 221, 500)
        .expect("expired key reclaimed and reinserted behind a live entry");
    assert_eq!(cache.len().expect("bounded len"), 2);
    assert_eq!(
        cache.insert_or_reject_until([1; 32], 221, 221),
        Err(RealityError::Replay)
    );
    assert_eq!(
        cache.cleanup(340).expect("original deadline not shortened"),
        2
    );
    assert_eq!(cache.cleanup(341).expect("only first key expired"), 1);
    assert_eq!(
        cache.insert_or_reject_until([2; 32], 500, 500),
        Err(RealityError::Replay)
    );
    assert_eq!(cache.cleanup(501).expect("all expired"), 0);
}

#[test]
fn scenario_full_cache_rejects_new_auth_without_forgetting_live_token() {
    let shared = shared_secret();
    let other_shared = [0x6b; 32];
    let allowed = [b"sid".to_vec()];
    let token = try_seal_session_id(&shared, b"sid", b"hello0", 220).expect("seal");
    let other = try_seal_session_id(&other_shared, b"sid", b"hello0", 221).expect("seal");
    let cache = ReplayCache::new(1, 120).expect("cache");
    open_session_id(&shared, &token, b"hello0", &allowed, 100, 120, &cache)
        .expect("first token accepted");

    for now in [220, 221, 340] {
        assert_eq!(
            open_session_id(&other_shared, &other, b"hello0", &allowed, now, 120, &cache),
            Err(RealityError::ReplayCacheFull)
        );
        assert_eq!(
            open_session_id(&shared, &token, b"hello0", &allowed, now, 120, &cache),
            Err(RealityError::Replay)
        );
        assert_eq!(cache.len().expect("bounded len"), 1);
    }

    let opened = open_session_id(&other_shared, &other, b"hello0", &allowed, 341, 120, &cache)
        .expect("new token accepted at upper inclusive boundary after expired cleanup");
    assert_eq!(opened.timestamp, 221);
    assert_eq!(cache.len().expect("bounded len"), 1);
    assert_eq!(
        open_session_id(&shared, &token, b"hello0", &allowed, 341, 120, &cache),
        Err(RealityError::Expired)
    );
}

#[test]
fn scenario_replay_deadlines_reject_overflow_and_expired_insertion() {
    let cache = ReplayCache::new(1, 1).expect("cache");
    assert_eq!(
        cache.insert_or_reject([1; 32], u64::MAX),
        Err(RealityError::ReplayExpiryOverflow)
    );
    assert_eq!(
        cache.insert_or_reject_until([1; 32], 221, 220),
        Err(RealityError::Expired)
    );
    assert!(cache
        .is_empty()
        .expect("invalid deadlines do not reserve capacity"));
    cache
        .insert_or_reject_until([1; 32], u64::MAX, u64::MAX)
        .expect("maximum inclusive deadline is representable");
    assert_eq!(cache.cleanup(u64::MAX).expect("inclusive cleanup"), 1);
    assert_eq!(
        cache.insert_or_reject_until([1; 32], u64::MAX, u64::MAX),
        Err(RealityError::Replay)
    );

    let zero_ttl = ReplayCache::new(1, 0).expect("zero TTL cache");
    zero_ttl
        .insert_or_reject([2; 32], 100)
        .expect("zero TTL retains current second");
    assert_eq!(zero_ttl.cleanup(100).expect("inclusive cleanup"), 1);
    assert_eq!(zero_ttl.cleanup(101).expect("expired cleanup"), 0);
}

#[test]
fn scenario_auth_expiry_overflow_is_rejected_without_cache_insertion() {
    let shared = shared_secret();
    let allowed = [b"sid".to_vec()];
    let token = try_seal_session_id(&shared, b"sid", b"hello0", 100).expect("seal");
    let cache = ReplayCache::new(1, u64::MAX).expect("cache");
    assert_eq!(
        open_session_id(&shared, &token, b"hello0", &allowed, 100, u64::MAX, &cache),
        Err(RealityError::ReplayExpiryOverflow)
    );
    assert!(cache
        .is_empty()
        .expect("overflow does not reserve capacity"));

    // The default cache TTL must not affect authentication's explicit deadline.
    open_session_id(
        &shared,
        &token,
        b"hello0",
        &allowed,
        100,
        u64::MAX - 100,
        &cache,
    )
    .expect("expiry exactly u64::MAX is valid");
    assert_eq!(cache.cleanup(u64::MAX).expect("inclusive cleanup"), 1);
    assert_eq!(
        open_session_id(
            &shared,
            &token,
            b"hello0",
            &allowed,
            u64::MAX,
            u64::MAX - 100,
            &cache
        ),
        Err(RealityError::Replay)
    );
}

#[test]
fn scenario_simultaneous_duplicate_authentication_admits_exactly_one() {
    let shared = shared_secret();
    let allowed = [b"sid".to_vec()];
    let token = try_seal_session_id(&shared, b"sid", b"hello0", 220).expect("seal");
    let cache = ReplayCache::new(1, 120).expect("cache");
    let barrier = std::sync::Barrier::new(16);
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..16)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    open_session_id(&shared, &token, b"hello0", &allowed, 100, 120, &cache)
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("worker must not panic"))
            .collect::<Vec<_>>()
    });

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(RealityError::Replay))
            .count(),
        15
    );
    assert_eq!(cache.len().expect("exactly one stored token"), 1);
}

#[test]
fn scenario_fail_fast_validation_errors() {
    assert_eq!(
        ReplayCache::new(0, 1).expect_err("zero capacity must fail"),
        RealityError::InvalidReplayCapacity
    );
    assert_eq!(
        ShortId::from_slice(&[0_u8; 9]).expect_err("long short id must fail"),
        RealityError::InvalidShortIdLength
    );
    assert_eq!(
        try_seal_session_id(&shared_secret(), &[0_u8; 9], b"hello0", 100)
            .expect_err("long short id must fail"),
        RealityError::InvalidShortIdLength
    );
    assert_eq!(
        try_seal_session_id(&shared_secret(), b"sid", b"hello0", u64::from(u32::MAX) + 1)
            .expect_err("large timestamp must fail"),
        RealityError::TimestampOutOfRange
    );

    let session_id =
        seal_session_id_with_flags(&shared_secret(), b"sid", b"hello0", 100, 7).expect("seal");
    let replay = ReplayCache::new(4, 100).expect("cache should build");
    assert_eq!(
        open_session_id(
            &shared_secret(),
            &session_id,
            b"hello0",
            &[b"other".to_vec()],
            100,
            120,
            &replay,
        )
        .expect_err("short id mismatch must fail"),
        RealityError::ShortIdRejected
    );
    assert_eq!(
        open_session_id(
            &shared_secret(),
            &session_id,
            b"hello0",
            &[b"sid".to_vec()],
            100,
            0,
            &replay,
        )
        .expect_err("zero time window must fail"),
        RealityError::InvalidTimeWindow
    );
    validate_server_name("server.example", &["server.example".to_owned()])
        .expect("configured server name should pass");
    assert_eq!(
        validate_server_name("probe.example", &["server.example".to_owned()])
            .expect_err("wrong SNI must fail"),
        RealityError::ServerNameRejected
    );
}

#[test]
fn scenario_infallible_protocol_seal_surface_matches_checked_output() {
    let checked = try_seal_session_id(&shared_secret(), b"sid", b"hello0", 100).expect("seal");
    let infallible = seal_session_id(&shared_secret(), b"sid", b"hello0", 100);
    let redacted = format!("{:?}", ShortId::from_slice(b"sid").expect("short id"));

    assert_eq!(checked, infallible);
    assert!(redacted.contains("redacted"));
    assert!(!redacted.contains("sid"));
}

#[test]
fn scenario_vision_authentication_preserves_layout_and_all_authentication_checks() {
    let shared = shared_secret();
    let hello = b"synthetic zeroed client hello";
    let token = try_seal_session_id_with_version(&shared, b"sid", hello, 100, AUTH_VERSION_V2)
        .expect("v2 seals");
    let key = umbra_crypto::kdf::hkdf_sha256(b"umbra-reality-v1", &shared, b"key", 16)
        .expect("original KDF key");
    let nonce = umbra_crypto::kdf::hkdf_sha256(b"umbra-reality-v1", &shared, b"nonce", 12)
        .expect("original KDF nonce");
    let clear = umbra_crypto::aead::open(
        umbra_crypto::aead::AeadAlgorithm::Aes128Gcm,
        &key,
        &nonce,
        &token,
        hello,
    )
    .expect("original cryptographic format opens v2");
    assert_eq!(
        clear,
        [2, 0, 0, 0, 0, 100, b's', b'i', b'd', 0, 0, 0, 0, 0, 0, 0]
    );
    // This is the old peer's strict discriminator: only version 1 is accepted.
    assert_ne!(clear[0], AUTH_VERSION_V1);
    let allowed = [b"sid".to_vec()];
    let cache = ReplayCache::new(1, 120).expect("cache");
    for (test_shared, aad, ids, now, skew, expected) in [
        (
            [0x33; 32],
            hello.as_slice(),
            allowed.as_slice(),
            100,
            120,
            RealityError::AuthenticationFailed,
        ),
        (
            shared,
            b"changed".as_slice(),
            allowed.as_slice(),
            100,
            120,
            RealityError::AuthenticationFailed,
        ),
        (
            shared,
            hello.as_slice(),
            [].as_slice(),
            100,
            120,
            RealityError::ShortIdRejected,
        ),
        (
            shared,
            hello.as_slice(),
            allowed.as_slice(),
            221,
            120,
            RealityError::Expired,
        ),
        (
            shared,
            hello.as_slice(),
            allowed.as_slice(),
            100,
            0,
            RealityError::InvalidTimeWindow,
        ),
    ] {
        assert_eq!(
            open_session_id(&test_shared, &token, aad, ids, now, skew, &cache),
            Err(expected)
        );
        assert!(cache
            .is_empty()
            .expect("failure never reserves replay capacity"));
    }
    let opened = open_session_id(&shared, &token, hello, &allowed, 100, 120, &cache)
        .expect("correct v2 authentication");
    assert_eq!(
        (opened.version, opened.flags, opened.timestamp),
        (AUTH_VERSION_V2, 0, 100)
    );
    assert_eq!(
        open_session_id(&shared, &token, hello, &allowed, 100, 120, &cache),
        Err(RealityError::Replay)
    );
}

#[test]
fn scenario_versioned_sealer_retains_legacy_bytes_and_rejects_invalid_inputs() {
    let shared = shared_secret();
    assert_eq!(
        try_seal_session_id_with_version(&shared, b"sid", b"hello", 100, AUTH_VERSION_V1),
        try_seal_session_id(&shared, b"sid", b"hello", 100),
    );
    for version in [0, 3, 255] {
        assert_eq!(
            try_seal_session_id_with_version(&shared, b"sid", b"hello", 100, version),
            Err(RealityError::InvalidVersion(version))
        );
    }
    assert_eq!(
        try_seal_session_id_with_version(&shared, &[0; 9], b"hello", 100, AUTH_VERSION_V2),
        Err(RealityError::InvalidShortIdLength)
    );
    assert_eq!(
        try_seal_session_id_with_version(
            &shared,
            b"sid",
            b"hello",
            u64::from(u32::MAX) + 1,
            AUTH_VERSION_V2
        ),
        Err(RealityError::TimestampOutOfRange)
    );
}

proptest! {
    #[test]
    fn prop_tampered_session_id_does_not_open(byte_index in 0_usize..32, bit in 0_u8..8, version in 1_u8..=2) {
        let shared = shared_secret();
        let mut session_id = try_seal_session_id_with_version(&shared, b"sid", b"hello0", 100, version)
            .expect("session id should seal");
        session_id[byte_index] ^= 1 << bit;
        let replay = ReplayCache::new(4, 100).expect("cache should build");

        let result = open_session_id(
            &shared,
            &session_id,
            b"hello0",
            &[b"sid".to_vec()],
            100,
            120,
            &replay,
        );

        prop_assert!(result.is_err());
    }
}

fn shared_secret() -> [u8; 32] {
    [0x5a; 32]
}
