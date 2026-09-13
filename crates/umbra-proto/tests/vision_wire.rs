//! Golden, negative, and property checks for authenticated solo envelopes.

use proptest::prelude::*;
use umbra_proto::vision::{
    Boundaries, Envelope, Message, VisionError, MAX_DATA_LEN, MAX_ENVELOPE_LEN,
};

fn hex(input: &str) -> Vec<u8> {
    input
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).expect("fixture hex"))
        .collect()
}

fn boundaries() -> Boundaries {
    Boundaries {
        switch_id: 1,
        c2s_boundary: 256,
        s2c_boundary: 512,
    }
}

fn golden() -> Vec<(Message, Vec<u8>, &'static str)> {
    vec![
        (Message::Hello { min_raw_ver: 1, max_raw_ver: 1, features: 1 }, vec![], "01 01 00 00 00 04 00 00 01 01 00 01"),
        (Message::HelloAck { selected_raw_ver: 1, target_result: 0, features: 1 }, vec![], "01 02 00 00 00 04 00 00 01 00 00 01"),
        (Message::HelloAck { selected_raw_ver: 0, target_result: 0, features: 0 }, vec![], "01 02 00 00 00 04 00 00 00 00 00 00"),
        (Message::Data(b"abc".to_vec()), vec![0, 0], "01 10 00 00 00 03 00 02 61 62 63 00 00"),
        (Message::Fin { final_offset: 3 }, vec![], "01 11 00 00 00 08 00 00 00 00 00 00 00 00 00 03"),
        (Message::Padding, vec![0xff], "01 12 00 00 00 00 00 01 ff"),
        (Message::SwitchReq { switch_id: 1, c2s_boundary: 256 }, vec![], "01 20 00 00 00 0c 00 00 00 00 00 01 00 00 00 00 00 00 01 00"),
        (Message::SwitchAck(boundaries()), vec![], "01 21 00 00 00 14 00 00 00 00 00 01 00 00 00 00 00 00 01 00 00 00 00 00 00 00 02 00"),
        (Message::Commit(boundaries()), vec![], "01 22 00 00 00 14 00 00 00 00 00 01 00 00 00 00 00 00 01 00 00 00 00 00 00 00 02 00"),
        (Message::CommitAck(boundaries()), vec![], "01 23 00 00 00 14 00 00 00 00 00 01 00 00 00 00 00 00 01 00 00 00 00 00 00 00 02 00"),
        (Message::SwitchReject { boundaries: boundaries(), reason: 2 }, vec![], "01 24 00 00 00 15 00 00 00 00 00 01 00 00 00 00 00 00 01 00 00 00 00 00 00 00 02 00 02"),
    ]
}

#[test]
fn approved_golden_vectors_and_every_prefix() {
    for (message, padding, vector) in golden() {
        let expected = Envelope::new(message, padding).expect("valid fixture");
        let wire = hex(vector);
        assert_eq!(expected.encode().expect("encode"), wire);
        assert_eq!(Envelope::decode(&wire).expect("decode"), expected);
        for end in 0..wire.len() {
            assert!(Envelope::decode(&wire[..end]).is_err(), "prefix {end}");
        }
        let mut concatenated = wire.clone();
        concatenated.extend_from_slice(&wire);
        assert!(Envelope::decode(&concatenated).is_err());
        let mut trailing = wire;
        trailing.push(0);
        assert!(Envelope::decode(&trailing).is_err());
    }
}

#[test]
fn exact_total_limits_and_removing_only_declared_padding() {
    let data = vec![0x17; MAX_DATA_LEN];
    let env = Envelope::new(Message::Data(data.clone()), vec![]).expect("maximum DATA");
    assert_eq!(env.encode().expect("encode").len(), MAX_ENVELOPE_LEN);
    assert_eq!(
        Envelope::decode(&env.encode().expect("encode"))
            .expect("decode")
            .message,
        Message::Data(data)
    );
    assert!(Envelope::new(Message::Data(vec![]), vec![]).is_err());
    assert!(Envelope::new(Message::Data(vec![0; MAX_DATA_LEN + 1]), vec![]).is_err());
    assert!(Envelope::new(Message::Data(vec![0; MAX_DATA_LEN]), vec![0]).is_err());
    assert!(Envelope::new(Message::Padding, vec![0; MAX_DATA_LEN]).is_ok());
    assert!(Envelope::new(Message::Padding, vec![0; MAX_DATA_LEN + 1]).is_err());
    assert!(Envelope::decode(&vec![0; MAX_ENVELOPE_LEN + 1]).is_err());
    let env = Envelope::new(Message::Data(vec![0, 0, 0, 0]), vec![0, 0]).expect("zero body");
    assert_eq!(
        Envelope::decode(&env.encode().expect("encode"))
            .expect("decode")
            .message,
        Message::Data(vec![0; 4])
    );
}

#[test]
fn reserved_fields_kinds_versions_and_control_padding_are_rejected() {
    for (message, padding, vector) in golden() {
        let mut wire = hex(vector);
        wire[0] = 2;
        assert_eq!(Envelope::decode(&wire), Err(VisionError::Version));
        wire[0] = 1;
        wire[1] = 0xff;
        assert_eq!(Envelope::decode(&wire), Err(VisionError::Kind));
        wire[1] = message.kind();
        wire[3] = 1;
        assert_eq!(Envelope::decode(&wire), Err(VisionError::Field));
        wire[3] = 0;
        wire[4] = 0xff;
        assert_eq!(Envelope::decode(&wire), Err(VisionError::Length));
        if matches!(message, Message::Data(_) | Message::Padding) {
            assert!(Envelope::new(message, padding).is_ok());
        } else {
            assert_eq!(Envelope::new(message, vec![0]), Err(VisionError::Padding));
        }
    }
    assert_eq!(
        Envelope::new(Message::Padding, vec![]),
        Err(VisionError::Padding)
    );
    for kind in [1, 2, 0x11, 0x12, 0x20, 0x21, 0x22, 0x23, 0x24] {
        let mut bad = vec![1, kind, 0, 0, 0, 1, 0, 0];
        bad.push(0);
        assert!(Envelope::decode(&bad).is_err());
    }
}

#[test]
fn invalid_capabilities_and_switch_fields_never_encode() {
    let messages = [
        Message::Hello {
            min_raw_ver: 0,
            max_raw_ver: 1,
            features: 1,
        },
        Message::Hello {
            min_raw_ver: 2,
            max_raw_ver: 1,
            features: 1,
        },
        Message::Hello {
            min_raw_ver: 1,
            max_raw_ver: 1,
            features: 2,
        },
        Message::HelloAck {
            selected_raw_ver: 1,
            target_result: 2,
            features: 1,
        },
        Message::HelloAck {
            selected_raw_ver: 0,
            target_result: 0,
            features: 1,
        },
        Message::HelloAck {
            selected_raw_ver: 1,
            target_result: 0,
            features: 0,
        },
        Message::HelloAck {
            selected_raw_ver: 2,
            target_result: 0,
            features: 1,
        },
        Message::SwitchReq {
            switch_id: 0,
            c2s_boundary: 0,
        },
        Message::SwitchAck(Boundaries {
            switch_id: 2,
            ..boundaries()
        }),
        Message::Commit(Boundaries {
            switch_id: 2,
            ..boundaries()
        }),
        Message::CommitAck(Boundaries {
            switch_id: 2,
            ..boundaries()
        }),
        Message::SwitchReject {
            boundaries: boundaries(),
            reason: 0,
        },
        Message::SwitchReject {
            boundaries: boundaries(),
            reason: 3,
        },
        Message::SwitchReject {
            boundaries: Boundaries {
                switch_id: 0,
                ..boundaries()
            },
            reason: 1,
        },
    ];
    for message in messages {
        assert_eq!(
            Envelope::new(message.clone(), vec![]),
            Err(VisionError::Field)
        );
        assert_eq!(
            Envelope {
                message,
                padding: vec![]
            }
            .encode(),
            Err(VisionError::Field)
        );
    }
    for (message, padding, vector) in golden() {
        if matches!(
            message,
            Message::SwitchReq { .. }
                | Message::SwitchAck(_)
                | Message::Commit(_)
                | Message::CommitAck(_)
                | Message::SwitchReject { .. }
        ) {
            let mut wire = hex(vector);
            wire[11] = 2;
            assert_eq!(Envelope::decode(&wire), Err(VisionError::Field));
        }
        assert!(Envelope::new(message, padding).is_ok());
    }
}

#[test]
fn diagnostic_output_contains_no_target_payload() {
    let env = Envelope::new(
        Message::Data(b"sensitive target bytes".to_vec()),
        b"secret padding".to_vec(),
    )
    .expect("fixture");
    let debug = format!("{env:?}");
    assert!(!debug.contains("sensitive"));
    assert!(!debug.contains("secret"));
}

proptest! {
    #[test]
    fn data_and_padding_roundtrip(data in prop::collection::vec(any::<u8>(), 1..2048), pad in prop::collection::vec(any::<u8>(), 0..1401)) {
        let env = Envelope::new(Message::Data(data), pad).expect("bounded");
        prop_assert_eq!(Envelope::decode(&env.encode().expect("encode")).expect("decode"), env);
    }

    #[test]
    fn boundary_offsets_roundtrip(c in any::<u64>(), s in any::<u64>()) {
        let b = Boundaries { switch_id: 1, c2s_boundary: c, s2c_boundary: s };
        for message in [Message::SwitchAck(b), Message::Commit(b), Message::CommitAck(b), Message::SwitchReject { boundaries: b, reason: 1 }] {
            let env = Envelope::new(message, vec![]).expect("valid");
            prop_assert_eq!(Envelope::decode(&env.encode().expect("encode")).expect("decode"), env);
        }
    }

    #[test]
    fn arbitrary_input_is_bounded_and_canonical(bytes in prop::collection::vec(any::<u8>(), 0..17_000)) {
        if let Ok(env) = Envelope::decode(&bytes) {
            prop_assert_eq!(env.encode().expect("validated"), bytes);
        }
    }
}
