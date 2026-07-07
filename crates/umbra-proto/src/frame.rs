//! Mux frame wire format.

use crate::{consts::MUX_VERSION, ProtocolError};

/// Maximum payload length representable by a mux frame.
pub const MAX_FRAME_PAYLOAD_LEN: usize = u16::MAX as usize;

/// Mux command values defined by `docs/protocol-design.md`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum MuxCommand {
    /// Open a logical stream. Payload is a target address.
    Syn = 0x01,
    /// Acknowledge stream creation.
    SynAck = 0x02,
    /// Carry stream data.
    Data = 0x03,
    /// Increase stream flow-control window. Payload is a big-endian `u32`.
    WindowUpdate = 0x04,
    /// Gracefully close a stream direction.
    Fin = 0x05,
    /// Reset a stream.
    Rst = 0x06,
    /// Random padding. Payload is discarded.
    Padding = 0x07,
    /// Keepalive or RTT probe.
    Ping = 0x08,
    /// Carry one UDP datagram envelope. Uses reserved stream id zero.
    UdpDatagram = 0x09,
}

impl TryFrom<u8> for MuxCommand {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Syn),
            0x02 => Ok(Self::SynAck),
            0x03 => Ok(Self::Data),
            0x04 => Ok(Self::WindowUpdate),
            0x05 => Ok(Self::Fin),
            0x06 => Ok(Self::Rst),
            0x07 => Ok(Self::Padding),
            0x08 => Ok(Self::Ping),
            0x09 => Ok(Self::UdpDatagram),
            other => Err(ProtocolError::UnsupportedCommand(other)),
        }
    }
}

impl From<MuxCommand> for u8 {
    fn from(value: MuxCommand) -> Self {
        value as u8
    }
}

/// A decoded mux frame.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MuxFrame {
    /// Frame command.
    pub command: MuxCommand,
    /// Logical stream identifier.
    pub stream_id: u32,
    /// Frame payload bytes.
    pub payload: Vec<u8>,
}

impl MuxFrame {
    /// Create a new mux frame after validating payload length.
    pub fn new(
        command: MuxCommand,
        stream_id: u32,
        payload: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_FRAME_PAYLOAD_LEN {
            return Err(ProtocolError::LengthViolation);
        }
        Ok(Self {
            command,
            stream_id,
            payload,
        })
    }

    /// Encode a frame to bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.payload.len() > MAX_FRAME_PAYLOAD_LEN {
            return Err(ProtocolError::LengthViolation);
        }
        let mut out = Vec::with_capacity(8 + self.payload.len());
        out.push(MUX_VERSION);
        out.push(self.command.into());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        let len = u16::try_from(self.payload.len()).map_err(|_| ProtocolError::LengthViolation)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Decode a frame and require the full input to be consumed.
    pub fn decode(input: &[u8], max_payload_len: usize) -> Result<Self, ProtocolError> {
        let (frame, consumed) = Self::decode_from(input, max_payload_len)?;
        if consumed == input.len() {
            Ok(frame)
        } else {
            Err(ProtocolError::TrailingBytes)
        }
    }

    /// Decode a frame and return the number of bytes consumed.
    pub fn decode_from(
        input: &[u8],
        max_payload_len: usize,
    ) -> Result<(Self, usize), ProtocolError> {
        if input.len() < 8 {
            return Err(ProtocolError::TruncatedInput);
        }
        if input[0] != MUX_VERSION {
            return Err(ProtocolError::UnsupportedVersion(input[0]));
        }
        let command = MuxCommand::try_from(input[1])?;
        let stream_id = u32::from_be_bytes([input[2], input[3], input[4], input[5]]);
        let len = usize::from(u16::from_be_bytes([input[6], input[7]]));
        if len > max_payload_len {
            return Err(ProtocolError::LengthViolation);
        }
        let total = 8_usize
            .checked_add(len)
            .ok_or(ProtocolError::LengthViolation)?;
        if input.len() < total {
            return Err(ProtocolError::TruncatedInput);
        }
        let payload = input[8..total].to_vec();
        Ok((
            Self {
                command,
                stream_id,
                payload,
            },
            total,
        ))
    }
}
