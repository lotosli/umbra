#![no_main]
use std::time::Instant;

use libfuzzer_sys::fuzz_target;
use umbra_core::socks::{decode_udp_packet, encode_udp_packet, SocksUdpReassembler};

// Invariant: arbitrary SOCKS UDP packets never panic; valid packets re-encode and enter reassembly safely.
// Run: cargo +nightly fuzz run socks_udp
fuzz_target!(|data: &[u8]| {
    if let Ok(packet) = decode_udp_packet(data) {
        let _ = encode_udp_packet(&packet);
        let mut reassembler = SocksUdpReassembler::default();
        let _ = reassembler.process(packet, Instant::now());
    }
});
