#![no_main]

use libfuzzer_sys::fuzz_target;
use umbra_proto::vision::Envelope;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = Envelope::decode(data) {
        assert_eq!(envelope.encode().expect("decoded envelope is valid"), data);
    }
});
