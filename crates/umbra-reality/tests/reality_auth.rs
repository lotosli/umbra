//! Integration tests for component B: REALITY session_id authentication.

use proptest::prelude::*;
use umbra_reality::{
    auth::{
        open_session_id, seal_session_id, seal_session_id_with_flags, try_seal_session_id,
        validate_server_name, ShortId,
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
    cache.insert_or_reject([3; 32], 3).expect("insert third");

    assert_eq!(cache.len().expect("len"), 2);
    cache
        .insert_or_reject([1; 32], 4)
        .expect("oldest entry should be evicted");
    assert_eq!(cache.len().expect("len"), 2);
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

proptest! {
    #[test]
    fn prop_tampered_session_id_does_not_open(byte_index in 0_usize..32, bit in 0_u8..8) {
        let shared = shared_secret();
        let mut session_id = try_seal_session_id(&shared, b"sid", b"hello0", 100)
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
