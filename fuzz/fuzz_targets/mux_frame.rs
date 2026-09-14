#![no_main]
use libfuzzer_sys::fuzz_target;
use umbra_proto::frame::{MuxFrame, MAX_FRAME_PAYLOAD_LEN};

// Invariant: arbitrary frame bytes never panic, length fields cannot trigger
// out-of-bounds reads, and unknown commands fail as structured errors.
// Run: cargo +nightly fuzz run mux_frame
fuzz_target!(|data: &[u8]| {
    let _ = umbra_proto::flow::FlowSettings::decode(data);
    let _ = umbra_proto::flow::CreditUpdate::decode(data);
    if let Ok(frame) = MuxFrame::decode(data, MAX_FRAME_PAYLOAD_LEN) {
        let _ = umbra_proto::flow::FlowSettings::decode(&frame.payload);
        let _ = umbra_proto::flow::CreditUpdate::decode(&frame.payload);
    }
    let _ = MuxFrame::decode_from(data, MAX_FRAME_PAYLOAD_LEN);
});
