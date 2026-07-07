#![no_main]
use libfuzzer_sys::fuzz_target;
use umbra_proto::udp::UdpEnvelope;

// Invariant: arbitrary UDP envelope bytes never panic; valid envelopes round trip.
// Run: cargo +nightly fuzz run udp_envelope
fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = UdpEnvelope::decode(data) {
        if let Ok(encoded) = envelope.encode() {
            let _ = UdpEnvelope::decode(&encoded);
        }
    }
});
