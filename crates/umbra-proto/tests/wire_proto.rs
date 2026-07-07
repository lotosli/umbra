//! Integration tests for Umbra wire protocol types.

use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use umbra_proto::{
    addr::TargetAddr,
    frame::{MuxCommand, MuxFrame, MAX_FRAME_PAYLOAD_LEN},
    udp::UdpEnvelope,
    ProtocolError,
};

#[test]
fn scenario_domain_address_round_trip() {
    let addr = TargetAddr::domain("example.com", 443).expect("domain should be valid");
    let encoded = addr.encode().expect("address should encode");
    let decoded = TargetAddr::decode(&encoded).expect("address should decode");

    assert_eq!(decoded, addr);
    assert_eq!(decoded.port(), 443);
}

#[test]
fn scenario_ip_addresses_round_trip() {
    let ipv4 = TargetAddr::Ipv4(Ipv4Addr::new(192, 0, 2, 10), 8443);
    let ipv6 = TargetAddr::Ipv6(Ipv6Addr::LOCALHOST, 443);

    assert_eq!(
        TargetAddr::decode(&ipv4.encode().expect("ipv4 should encode")).expect("ipv4 decodes"),
        ipv4
    );
    assert_eq!(
        TargetAddr::decode(&ipv6.encode().expect("ipv6 should encode")).expect("ipv6 decodes"),
        ipv6
    );
}

#[test]
fn scenario_invalid_address_is_rejected() {
    assert_eq!(
        TargetAddr::decode(&[0xff, 0, 0]),
        Err(ProtocolError::InvalidAddress)
    );
    assert_eq!(
        TargetAddr::decode(&[0x01, 127, 0, 0, 1, 0]),
        Err(ProtocolError::TruncatedInput)
    );
    assert_eq!(
        TargetAddr::decode(&[0x03, 0, 0, 80]),
        Err(ProtocolError::InvalidAddress)
    );
}

#[test]
fn scenario_address_trailing_bytes_are_rejected() {
    let mut encoded = TargetAddr::domain("example.com", 443)
        .expect("domain should be valid")
        .encode()
        .expect("address should encode");
    encoded.push(0xaa);

    assert_eq!(
        TargetAddr::decode(&encoded),
        Err(ProtocolError::TrailingBytes)
    );
}

#[test]
fn scenario_data_frame_round_trip() {
    let frame = MuxFrame::new(MuxCommand::Data, 0x0102_0304, b"payload".to_vec())
        .expect("frame should be valid");
    let encoded = frame.encode().expect("frame should encode");
    let decoded = MuxFrame::decode(&encoded, MAX_FRAME_PAYLOAD_LEN).expect("frame should decode");

    assert_eq!(decoded, frame);
}

#[test]
fn scenario_oversized_frame_is_rejected() {
    let mut encoded = vec![0x01, 0x03, 0, 0, 0, 1, 0, 4, 1, 2];
    assert_eq!(
        MuxFrame::decode(&encoded, MAX_FRAME_PAYLOAD_LEN),
        Err(ProtocolError::TruncatedInput)
    );

    encoded = vec![0x01, 0x03, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4];
    assert_eq!(
        MuxFrame::decode(&encoded, 3),
        Err(ProtocolError::LengthViolation)
    );

    let oversized = vec![0_u8; MAX_FRAME_PAYLOAD_LEN + 1];
    assert_eq!(
        MuxFrame::new(MuxCommand::Data, 1, oversized),
        Err(ProtocolError::LengthViolation)
    );
}

#[test]
fn scenario_malformed_input_maps_to_stable_error() {
    assert_eq!(
        MuxFrame::decode(&[0x02, 0x03, 0, 0, 0, 1, 0, 0], MAX_FRAME_PAYLOAD_LEN),
        Err(ProtocolError::UnsupportedVersion(0x02))
    );
    assert_eq!(
        MuxFrame::decode(&[0x01, 0xff, 0, 0, 0, 1, 0, 0], MAX_FRAME_PAYLOAD_LEN),
        Err(ProtocolError::UnsupportedCommand(0xff))
    );
    assert_eq!(
        MuxFrame::decode(&[0x01, 0x03, 0, 0, 0, 1, 0, 0, 0xaa], MAX_FRAME_PAYLOAD_LEN),
        Err(ProtocolError::TrailingBytes)
    );
}

#[test]
fn scenario_udp_envelope_round_trip() {
    let target = TargetAddr::Ipv6(Ipv6Addr::LOCALHOST, 5353);
    let envelope = UdpEnvelope::new(target.clone(), b"dns-payload".to_vec())
        .expect("UDP envelope should be valid");
    let encoded = envelope.encode().expect("UDP envelope encodes");
    let decoded = UdpEnvelope::decode(&encoded).expect("UDP envelope decodes");

    assert_eq!(decoded.target, target);
    assert_eq!(decoded.payload, b"dns-payload");
}

#[test]
fn scenario_oversized_udp_envelope_is_rejected() {
    let target = TargetAddr::domain("example.com", 53).expect("target");
    let payload = vec![0_u8; MAX_FRAME_PAYLOAD_LEN];

    assert_eq!(
        UdpEnvelope::new(target, payload),
        Err(ProtocolError::LengthViolation)
    );
}

proptest! {
    #[test]
    fn prop_domain_address_round_trip(label in "[a-z0-9][a-z0-9-]{0,20}", port in any::<u16>()) {
        let domain = format!("{label}.example");
        let addr = TargetAddr::domain(domain, port)?;
        let encoded = addr.encode()?;
        let decoded = TargetAddr::decode(&encoded)?;

        prop_assert_eq!(decoded, addr);
    }

    #[test]
    fn prop_frame_round_trip(command in 1_u8..=9, stream_id in any::<u32>(), payload in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let command = MuxCommand::try_from(command)?;
        let frame = MuxFrame::new(command, stream_id, payload)?;
        let encoded = frame.encode()?;
        let decoded = MuxFrame::decode(&encoded, MAX_FRAME_PAYLOAD_LEN)?;

        prop_assert_eq!(decoded, frame);
    }

    #[test]
    fn prop_udp_envelope_round_trip(
        label in "[a-z0-9][a-z0-9-]{0,20}",
        port in any::<u16>(),
        payload in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let target = TargetAddr::domain(format!("{label}.example"), port)?;
        let envelope = UdpEnvelope::new(target, payload)?;
        let encoded = envelope.encode()?;
        let decoded = UdpEnvelope::decode(&encoded)?;

        prop_assert_eq!(decoded, envelope);
    }
}
