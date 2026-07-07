#![no_main]
use libfuzzer_sys::fuzz_target;

// Invariant: arbitrary 32-byte session IDs and AAD never panic; invalid inputs
// return `Err`, which keeps dispatch on the fallback-to-destination path.
// Run: cargo +nightly fuzz run session_id_open
fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let mut session_id = [0_u8; 32];
    session_id.copy_from_slice(&data[..32]);
    let Ok(replay) = umbra_reality::replay::ReplayCache::new(64, 180) else {
        return;
    };
    let _ = umbra_reality::auth::open_session_id(
        &[0_u8; 32],
        &session_id,
        &data[32..],
        &[Vec::new()],
        0,
        120,
        &replay,
    );
});
