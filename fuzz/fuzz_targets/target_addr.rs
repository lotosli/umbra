#![no_main]
use libfuzzer_sys::fuzz_target;
use umbra_proto::addr::TargetAddr;

// Invariant: arbitrary target-address bytes never panic; malformed lengths,
// domains, and trailing bytes return structured errors.
// Run: cargo +nightly fuzz run target_addr
fuzz_target!(|data: &[u8]| {
    let _ = TargetAddr::decode(data);
    let _ = TargetAddr::decode_from(data);
});
