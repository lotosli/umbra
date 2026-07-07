//! UDP datagram envelope carried by authenticated Umbra transports.

use crate::{addr::TargetAddr, ProtocolError};

/// Maximum encoded UDP envelope length supported by current carriers.
pub const MAX_UDP_ENVELOPE_LEN: usize = u16::MAX as usize;

/// One proxied UDP datagram after SOCKS header processing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UdpEnvelope {
    /// Target address for client-to-server datagrams or reply source address for server-to-client.
    pub target: TargetAddr,
    /// UDP payload bytes.
    pub payload: Vec<u8>,
}

impl UdpEnvelope {
    /// Create a UDP envelope after validating carrier length.
    pub fn new(target: TargetAddr, payload: Vec<u8>) -> Result<Self, ProtocolError> {
        let envelope = Self { target, payload };
        envelope.validate_len()?;
        Ok(envelope)
    }

    /// Encode the target address followed by payload bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate_len()?;
        let mut out = self.target.encode()?;
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Decode a UDP envelope from one complete carrier payload.
    pub fn decode(input: &[u8]) -> Result<Self, ProtocolError> {
        let (target, consumed) = TargetAddr::decode_from(input)?;
        let payload = input
            .get(consumed..)
            .ok_or(ProtocolError::TruncatedInput)?
            .to_vec();
        Self::new(target, payload)
    }

    fn validate_len(&self) -> Result<(), ProtocolError> {
        let target_len = self.target.encode()?.len();
        target_len
            .checked_add(self.payload.len())
            .filter(|len| *len <= MAX_UDP_ENVELOPE_LEN)
            .map(|_| ())
            .ok_or(ProtocolError::LengthViolation)
    }
}
