#![no_main]
use libfuzzer_sys::fuzz_target;
use umbra_proto::frame::{MuxFrame, MAX_FRAME_PAYLOAD_LEN};

// Invariant: arbitrary frame bytes never panic, length fields cannot trigger
// out-of-bounds reads, and unknown commands fail as structured errors.
// Run: cargo +nightly fuzz run mux_frame
fuzz_target!(|data: &[u8]| {
    let _ = MuxFrame::decode(data, MAX_FRAME_PAYLOAD_LEN);
    let _ = MuxFrame::decode_from(data, MAX_FRAME_PAYLOAD_LEN);
});
