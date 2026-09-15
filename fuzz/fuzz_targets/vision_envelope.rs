#![no_main]

use libfuzzer_sys::fuzz_target;
use umbra_proto::vision::Envelope;

fuzz_target!(|data: &[u8]| {
    let expected = Envelope::decode(data).map(|envelope| envelope.message);
    let mut owned = data.to_vec();
    assert_eq!(Envelope::take_message(&mut owned), expected);
    if let Ok(envelope) = Envelope::decode(data) {
        assert_eq!(envelope.encode().expect("decoded envelope is valid"), data);
    }
});
