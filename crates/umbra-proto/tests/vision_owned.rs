//! Borrowed encoding and ownership transfer preserve the established wire codec.

use proptest::prelude::*;
use umbra_proto::vision::{Envelope, Message, VisionError, MAX_DATA_LEN};

proptest! {
    #[test]
    fn borrowed_data_and_owned_decode_match_existing_codec(payload in prop::collection::vec(any::<u8>(), 1..4096), padding in prop::collection::vec(any::<u8>(), 0..1400)) {
        let expected = Envelope::new(Message::Data(payload.clone()), padding.clone()).unwrap().encode().unwrap();
        let header = Envelope::data_header(payload.len(), padding.len()).unwrap();
        let mut encoded = [header.as_slice(), payload.as_slice(), padding.as_slice()].concat();
        prop_assert_eq!(&encoded, &expected);
        let pointer = encoded.as_ptr();
        let message = Envelope::take_message(&mut encoded).unwrap();
        prop_assert!(encoded.is_empty());
        let Message::Data(data) = message else { unreachable!() };
        prop_assert_eq!(data.as_ptr(), pointer);
        prop_assert_eq!(data, payload);
    }

    #[test]
    fn arbitrary_owned_decode_has_identical_validation(input in prop::collection::vec(any::<u8>(), 0..17000)) {
        let expected = Envelope::decode(&input).map(|envelope| envelope.message);
        let failed = expected.is_err();
        let mut owned = input.clone();
        prop_assert_eq!(Envelope::take_message(&mut owned), expected);
        if failed { prop_assert_eq!(owned, input); }
    }
}

#[test]
fn controls_retain_storage_and_empty_data_is_rejected() {
    let mut bytes = Envelope::new(Message::Fin { final_offset: 42 }, Vec::new())
        .unwrap()
        .encode()
        .unwrap();
    let pointer = bytes.as_ptr();
    assert_eq!(
        Envelope::take_message(&mut bytes).unwrap(),
        Message::Fin { final_offset: 42 }
    );
    assert_eq!(bytes.as_ptr(), pointer);
    assert!(bytes.is_empty());
    assert_eq!(Envelope::data_header(0, 0), Err(VisionError::Field));
    assert_eq!(
        Envelope::data_header(MAX_DATA_LEN + 1, 0),
        Err(VisionError::Field)
    );
    assert_eq!(
        Envelope::data_header(1, usize::MAX),
        Err(VisionError::Length)
    );
    let mut empty_data = vec![1, 0x10, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        Envelope::take_message(&mut empty_data),
        Err(VisionError::Field)
    );
    assert_eq!(empty_data.len(), 8);
}
