//! Authenticated solo v2 envelopes, as specified in `vision-runtime-wire-v2.md`.
//!
//! Decode exactly one complete outer TLS application plaintext at a time. This
//! codec validates wire fields, not endpoint roles or transaction state.

use thiserror::Error;

/// The fixed envelope header length.
pub const HEADER_LEN: usize = 8;
/// Maximum complete outer application plaintext.
pub const MAX_ENVELOPE_LEN: usize = 16_384;
/// Maximum unpadded DATA body.
pub const MAX_DATA_LEN: usize = MAX_ENVELOPE_LEN - HEADER_LEN;
/// Largest DATA body during the initial padding phase.
pub const MAX_PADDED_DATA_LEN: usize = 14_976;
/// Number of initially padded DATA envelopes in each direction.
pub const PADDED_DATA_COUNT: usize = 16;
/// TLS 1.3 raw profile v1 feature bit.
pub const RAW_TLS13_FEATURE: u16 = 1;

/// Invalid authenticated Vision envelope.
#[derive(Debug, Clone, Copy, Error, Eq, PartialEq)]
pub enum VisionError {
    /// A complete envelope must fit one record with exact lengths.
    #[error("invalid Vision envelope length")]
    Length,
    /// Only the approved envelope version is understood.
    #[error("unsupported Vision envelope version")]
    Version,
    /// The command is not defined by envelope v1.
    #[error("unknown Vision envelope kind")]
    Kind,
    /// Reserved bits, selections, or control values are invalid.
    #[error("invalid Vision envelope field")]
    Field,
    /// Padding is not permitted for this message.
    #[error("invalid Vision envelope padding")]
    Padding,
}

/// Exact DATA offsets agreed by the one permitted switch transaction.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Boundaries {
    /// The only currently valid transaction identifier is one.
    pub switch_id: u32,
    /// Client-to-server target bytes before raw handoff.
    pub c2s_boundary: u64,
    /// Server-to-client target bytes before raw handoff (or rejection).
    pub s2c_boundary: u64,
}

/// Typed contents of one Vision application record.
#[derive(Clone, Eq, PartialEq)]
pub enum Message {
    /// Initial client capability offer.
    Hello {
        /// Lowest supported raw version, at least one.
        min_raw_ver: u8,
        /// Highest supported raw version.
        max_raw_ver: u8,
        /// Requested feature bits.
        features: u16,
    },
    /// Server capability selection and target connection result.
    HelloAck {
        /// Zero for wrapped-only, or one for raw profile v1.
        selected_raw_ver: u8,
        /// Zero on target success, one on target failure.
        target_result: u8,
        /// Negotiated feature bits.
        features: u16,
    },
    /// Unmodified target bytes; never empty.
    Data(Vec<u8>),
    /// Target half-close after the exact preceding DATA offset.
    Fin {
        /// Count of preceding target bytes in this direction.
        final_offset: u64,
    },
    /// Cover-only record, with a nonempty padding field.
    Padding,
    /// Client requests its exact outgoing boundary.
    SwitchReq {
        /// The only currently valid transaction identifier is one.
        switch_id: u32,
        /// Client-to-server target bytes before the switch.
        c2s_boundary: u64,
    },
    /// Server has frozen its own boundary.
    SwitchAck(Boundaries),
    /// Final client outer TLS application record.
    Commit(Boundaries),
    /// Final server outer TLS application record.
    CommitAck(Boundaries),
    /// Server declines before acknowledging a switch.
    SwitchReject {
        /// Exact DATA counts; the reverse offset need not be a TLS boundary.
        boundaries: Boundaries,
        /// One for unavailable eligibility, two for an already queued/sent FIN.
        reason: u8,
    },
}

impl core::fmt::Debug for Message {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VisionMessage")
            .field("kind", &self.kind())
            .field("body_len", &self.body_len())
            .finish()
    }
}

impl Message {
    /// Stable command byte from the approved wire table.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Hello { .. } => 0x01,
            Self::HelloAck { .. } => 0x02,
            Self::Data(_) => 0x10,
            Self::Fin { .. } => 0x11,
            Self::Padding => 0x12,
            Self::SwitchReq { .. } => 0x20,
            Self::SwitchAck(_) => 0x21,
            Self::Commit(_) => 0x22,
            Self::CommitAck(_) => 0x23,
            Self::SwitchReject { .. } => 0x24,
        }
    }

    fn body_len(&self) -> usize {
        match self {
            Self::Hello { .. } | Self::HelloAck { .. } => 4,
            Self::Data(data) => data.len(),
            Self::Fin { .. } => 8,
            Self::Padding => 0,
            Self::SwitchReq { .. } => 12,
            Self::SwitchAck(_) | Self::Commit(_) | Self::CommitAck(_) => 20,
            Self::SwitchReject { .. } => 21,
        }
    }

    fn validate(&self) -> Result<(), VisionError> {
        let valid = match self {
            Self::Hello {
                min_raw_ver,
                max_raw_ver,
                features,
            } => {
                *min_raw_ver > 0 && min_raw_ver <= max_raw_ver && features & !RAW_TLS13_FEATURE == 0
            }
            Self::HelloAck {
                selected_raw_ver,
                target_result,
                features,
            } => *target_result <= 1 && matches!((*selected_raw_ver, *features), (0, 0) | (1, 1)),
            Self::Data(data) => !data.is_empty() && data.len() <= MAX_DATA_LEN,
            Self::Fin { .. } | Self::Padding => true,
            Self::SwitchReq { switch_id, .. } => *switch_id == 1,
            Self::SwitchAck(b) | Self::Commit(b) | Self::CommitAck(b) => b.switch_id == 1,
            Self::SwitchReject { boundaries, reason } => {
                boundaries.switch_id == 1 && matches!(reason, 1 | 2)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(VisionError::Field)
        }
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        match self {
            Self::Hello {
                min_raw_ver,
                max_raw_ver,
                features,
            } => {
                out.extend_from_slice(&[*min_raw_ver, *max_raw_ver]);
                out.extend_from_slice(&features.to_be_bytes());
            }
            Self::HelloAck {
                selected_raw_ver,
                target_result,
                features,
            } => {
                out.extend_from_slice(&[*selected_raw_ver, *target_result]);
                out.extend_from_slice(&features.to_be_bytes());
            }
            Self::Data(data) => out.extend_from_slice(data),
            Self::Fin { final_offset } => out.extend_from_slice(&final_offset.to_be_bytes()),
            Self::Padding => {}
            Self::SwitchReq {
                switch_id,
                c2s_boundary,
            } => {
                out.extend_from_slice(&switch_id.to_be_bytes());
                out.extend_from_slice(&c2s_boundary.to_be_bytes());
            }
            Self::SwitchAck(b) | Self::Commit(b) | Self::CommitAck(b) => write_boundaries(*b, out),
            Self::SwitchReject { boundaries, reason } => {
                write_boundaries(*boundaries, out);
                out.push(*reason);
            }
        }
    }
}

/// One complete authenticated application plaintext with removable padding.
#[derive(Clone, Eq, PartialEq)]
pub struct Envelope {
    /// Typed target data or control message.
    pub message: Message,
    /// Only these bytes are discarded by the receiver.
    pub padding: Vec<u8>,
}

impl core::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VisionEnvelope")
            .field("message", &self.message)
            .field("padding_len", &self.padding.len())
            .finish()
    }
}

impl Envelope {
    /// Create a wire-valid envelope; endpoint state validation remains separate.
    pub fn new(message: Message, padding: Vec<u8>) -> Result<Self, VisionError> {
        let envelope = Self { message, padding };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Serialize one complete outer TLS application plaintext.
    pub fn encode(&self) -> Result<Vec<u8>, VisionError> {
        let total = self.validate()?;
        let body_len = u16::try_from(self.message.body_len()).map_err(|_| VisionError::Length)?;
        let padding_len = u16::try_from(self.padding.len()).map_err(|_| VisionError::Length)?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&[1, self.message.kind(), 0, 0]);
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(&padding_len.to_be_bytes());
        self.message.write_body(&mut out);
        out.extend_from_slice(&self.padding);
        Ok(out)
    }

    /// Decode exactly one complete record, rejecting truncation and concatenation.
    pub fn decode(input: &[u8]) -> Result<Self, VisionError> {
        let (body_len, _) = envelope_lengths(input)?;
        let body = &input[HEADER_LEN..HEADER_LEN + body_len];
        let message = decode_message(input[1], body)?;
        let padding = input[HEADER_LEN + body_len..].to_vec();
        Self::new(message, padding)
    }

    /// Construct only the DATA prefix so callers can encode borrowed payload
    /// and padding directly into the final authenticated record buffer.
    pub fn data_header(
        body_len: usize,
        padding_len: usize,
    ) -> Result<[u8; HEADER_LEN], VisionError> {
        if !(1..=MAX_DATA_LEN).contains(&body_len) {
            return Err(VisionError::Field);
        }
        HEADER_LEN
            .checked_add(body_len)
            .and_then(|n| n.checked_add(padding_len))
            .filter(|n| *n <= MAX_ENVELOPE_LEN)
            .ok_or(VisionError::Length)?;
        let body = u16::try_from(body_len)
            .map_err(|_| VisionError::Length)?
            .to_be_bytes();
        let padding = u16::try_from(padding_len)
            .map_err(|_| VisionError::Length)?
            .to_be_bytes();
        Ok([1, 0x10, 0, 0, body[0], body[1], padding[0], padding[1]])
    }

    /// Validate one owned envelope and transfer DATA's allocation to its message.
    /// Control messages leave the cleared allocation available for reuse. Only
    /// declared padding is discarded; errors leave the original buffer intact.
    pub fn take_message(input: &mut Vec<u8>) -> Result<Message, VisionError> {
        let (body_len, padding_len) = envelope_lengths(input)?;
        if input[1] == 0x10 {
            if body_len == 0 {
                return Err(VisionError::Field);
            }
            input.truncate(HEADER_LEN + body_len);
            input.copy_within(HEADER_LEN.., 0);
            input.truncate(body_len);
            return Ok(Message::Data(core::mem::take(input)));
        }
        let message = decode_message(input[1], &input[HEADER_LEN..HEADER_LEN + body_len])?;
        validate_padding(&message, padding_len)?;
        input.clear();
        Ok(message)
    }

    fn validate(&self) -> Result<usize, VisionError> {
        validate_padding(&self.message, self.padding.len())?;
        HEADER_LEN
            .checked_add(self.message.body_len())
            .and_then(|n| n.checked_add(self.padding.len()))
            .filter(|n| *n <= MAX_ENVELOPE_LEN)
            .ok_or(VisionError::Length)
    }
}

fn envelope_lengths(input: &[u8]) -> Result<(usize, usize), VisionError> {
    if !(HEADER_LEN..=MAX_ENVELOPE_LEN).contains(&input.len()) {
        return Err(VisionError::Length);
    }
    if input[0] != 1 {
        return Err(VisionError::Version);
    }
    if input[2..4] != [0, 0] {
        return Err(VisionError::Field);
    }
    let body_len = usize::from(u16::from_be_bytes([input[4], input[5]]));
    let padding_len = usize::from(u16::from_be_bytes([input[6], input[7]]));
    if HEADER_LEN + body_len + padding_len != input.len() {
        return Err(VisionError::Length);
    }
    Ok((body_len, padding_len))
}

fn validate_padding(message: &Message, padding_len: usize) -> Result<(), VisionError> {
    message.validate()?;
    match message {
        Message::Data(_) => Ok(()),
        Message::Padding if padding_len != 0 => Ok(()),
        Message::Padding => Err(VisionError::Padding),
        _ if padding_len != 0 => Err(VisionError::Padding),
        _ => Ok(()),
    }
}

fn write_boundaries(b: Boundaries, out: &mut Vec<u8>) {
    out.extend_from_slice(&b.switch_id.to_be_bytes());
    out.extend_from_slice(&b.c2s_boundary.to_be_bytes());
    out.extend_from_slice(&b.s2c_boundary.to_be_bytes());
}

fn exact<const N: usize>(input: &[u8]) -> Result<[u8; N], VisionError> {
    input.try_into().map_err(|_| VisionError::Length)
}

fn read_boundaries(input: &[u8]) -> Result<Boundaries, VisionError> {
    let bytes = exact::<20>(input)?;
    Ok(Boundaries {
        switch_id: u32::from_be_bytes(exact(&bytes[..4])?),
        c2s_boundary: u64::from_be_bytes(exact(&bytes[4..12])?),
        s2c_boundary: u64::from_be_bytes(exact(&bytes[12..])?),
    })
}

fn decode_message(kind: u8, body: &[u8]) -> Result<Message, VisionError> {
    Ok(match kind {
        0x01 => {
            let b = exact::<4>(body)?;
            Message::Hello {
                min_raw_ver: b[0],
                max_raw_ver: b[1],
                features: u16::from_be_bytes([b[2], b[3]]),
            }
        }
        0x02 => {
            let b = exact::<4>(body)?;
            Message::HelloAck {
                selected_raw_ver: b[0],
                target_result: b[1],
                features: u16::from_be_bytes([b[2], b[3]]),
            }
        }
        0x10 => Message::Data(body.to_vec()),
        0x11 => Message::Fin {
            final_offset: u64::from_be_bytes(exact(body)?),
        },
        0x12 => {
            let _ = exact::<0>(body)?;
            Message::Padding
        }
        0x20 => {
            let b = exact::<12>(body)?;
            Message::SwitchReq {
                switch_id: u32::from_be_bytes(exact(&b[..4])?),
                c2s_boundary: u64::from_be_bytes(exact(&b[4..])?),
            }
        }
        0x21 => Message::SwitchAck(read_boundaries(body)?),
        0x22 => Message::Commit(read_boundaries(body)?),
        0x23 => Message::CommitAck(read_boundaries(body)?),
        0x24 => {
            let b = exact::<21>(body)?;
            Message::SwitchReject {
                boundaries: read_boundaries(&b[..20])?,
                reason: b[20],
            }
        }
        _ => return Err(VisionError::Kind),
    })
}
