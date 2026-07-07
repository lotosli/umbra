#![no_main]
use libfuzzer_sys::fuzz_target;

// Invariant: arbitrary bytes never panic or read out of bounds; parsing returns
// either a structured ClientHello or a structured error.
// Run: cargo +nightly fuzz run clienthello_parse
fuzz_target!(|data: &[u8]| {
    let _ = umbra_tls::parse::parse_client_hello(data);
});
