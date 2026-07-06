//! Adaptive padding scheme parsing and PADDING frame scheduling.

use rand::{rngs::OsRng, RngCore};
use umbra_proto::frame::{MuxCommand, MuxFrame, MAX_FRAME_PAYLOAD_LEN};

use crate::InnerError;

const DEFAULT_EARLY_RECORDS: usize = 16;
const DEFAULT_MIN_PADDING: usize = 100;
const DEFAULT_MAX_PADDING: usize = 1400;
const DEFAULT_LATER_EVERY: usize = 32;

/// Parsed adaptive padding policy.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PadScheme {
    /// Number of early business writes that receive front-loaded padding.
    pub early_records: usize,
    /// Minimum generated PADDING payload length.
    pub min_len: usize,
    /// Maximum generated PADDING payload length.
    pub max_len: usize,
    /// After the early window, emit one PADDING frame every N business writes.
    pub later_every: usize,
}

impl PadScheme {
    /// Return a disabled padding scheme.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            early_records: 0,
            min_len: 0,
            max_len: 0,
            later_every: 0,
        }
    }

    fn validate(&self) -> Result<(), InnerError> {
        if self.min_len > self.max_len {
            return Err(InnerError::InvalidPaddingScheme("min exceeds max"));
        }
        if self.max_len > MAX_FRAME_PAYLOAD_LEN {
            return Err(InnerError::InvalidPaddingScheme(
                "padding length exceeds frame capacity",
            ));
        }
        if self.early_records > 0 && self.max_len == 0 {
            return Err(InnerError::InvalidPaddingScheme(
                "early padding requires nonzero max",
            ));
        }
        Ok(())
    }
}

impl Default for PadScheme {
    fn default() -> Self {
        Self {
            early_records: DEFAULT_EARLY_RECORDS,
            min_len: DEFAULT_MIN_PADDING,
            max_len: DEFAULT_MAX_PADDING,
            later_every: DEFAULT_LATER_EVERY,
        }
    }
}

/// Parse a named or explicit padding scheme.
///
/// Supported strings are `default`, `none`, and
/// `early=<n>,min=<n>,max=<n>,later=<n>`.
pub fn parse_pad_scheme(input: &str) -> Result<PadScheme, InnerError> {
    let trimmed = input.trim();
    match trimmed {
        "default" => Ok(PadScheme::default()),
        "none" => Ok(PadScheme::none()),
        "" => Err(InnerError::InvalidPaddingScheme("scheme is empty")),
        _ => parse_explicit(trimmed),
    }
}

/// Stateful padding scheduler for one send direction.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PaddingPlanner {
    scheme: PadScheme,
    business_writes: usize,
}

impl PaddingPlanner {
    /// Construct a planner from a parsed scheme.
    pub fn new(scheme: PadScheme) -> Result<Self, InnerError> {
        scheme.validate()?;
        Ok(Self {
            scheme,
            business_writes: 0,
        })
    }

    /// Return the number of business writes already scheduled.
    #[must_use]
    pub const fn business_writes(&self) -> usize {
        self.business_writes
    }

    /// Schedule one business frame with OS-random padding payloads.
    pub fn schedule(&mut self, frame: MuxFrame) -> Result<Vec<MuxFrame>, InnerError> {
        let mut rng = OsRng;
        self.schedule_with_rng(frame, &mut rng)
    }

    /// Schedule one business frame with an injected RNG.
    pub fn schedule_with_rng<R: RngCore>(
        &mut self,
        frame: MuxFrame,
        rng: &mut R,
    ) -> Result<Vec<MuxFrame>, InnerError> {
        if frame.command == MuxCommand::Padding || self.scheme.max_len == 0 {
            return Ok(vec![frame]);
        }

        self.business_writes = self
            .business_writes
            .checked_add(1)
            .ok_or(InnerError::WindowOverflow)?;
        let mut out = Vec::new();
        if self.business_writes <= self.scheme.early_records {
            out.push(random_padding_frame(rng, &self.scheme)?);
            out.push(frame);
            out.push(random_padding_frame(rng, &self.scheme)?);
        } else if self.scheme.later_every != 0
            && self.business_writes.is_multiple_of(self.scheme.later_every)
        {
            out.push(random_padding_frame(rng, &self.scheme)?);
            out.push(frame);
        } else {
            out.push(frame);
        }
        Ok(out)
    }
}

/// Return true when a frame is PADDING and should be discarded.
#[must_use]
pub const fn is_padding(frame: &MuxFrame) -> bool {
    matches!(frame.command, MuxCommand::Padding)
}

fn parse_explicit(input: &str) -> Result<PadScheme, InnerError> {
    let mut scheme = PadScheme::none();
    let mut saw_field = false;
    for part in input.split(',') {
        let (key, value) = part
            .split_once('=')
            .ok_or(InnerError::InvalidPaddingScheme("missing key/value"))?;
        let parsed = value
            .parse::<usize>()
            .map_err(|_| InnerError::InvalidPaddingScheme("numeric value is invalid"))?;
        match key.trim() {
            "early" => scheme.early_records = parsed,
            "min" => scheme.min_len = parsed,
            "max" => scheme.max_len = parsed,
            "later" => scheme.later_every = parsed,
            _ => return Err(InnerError::InvalidPaddingScheme("unknown field")),
        }
        saw_field = true;
    }
    if !saw_field {
        return Err(InnerError::InvalidPaddingScheme("scheme is empty"));
    }
    scheme.validate()?;
    Ok(scheme)
}

fn random_padding_frame<R: RngCore>(
    rng: &mut R,
    scheme: &PadScheme,
) -> Result<MuxFrame, InnerError> {
    let len = random_len(rng, scheme)?;
    let mut payload = vec![0_u8; len];
    rng.fill_bytes(&mut payload);
    MuxFrame::new(MuxCommand::Padding, 0, payload).map_err(InnerError::from)
}

fn random_len<R: RngCore>(rng: &mut R, scheme: &PadScheme) -> Result<usize, InnerError> {
    if scheme.min_len == scheme.max_len {
        return Ok(scheme.min_len);
    }
    let span = scheme
        .max_len
        .checked_sub(scheme.min_len)
        .and_then(|value| value.checked_add(1))
        .ok_or(InnerError::InvalidPaddingScheme("invalid length range"))?;
    let span_u64 = u64::try_from(span)
        .map_err(|_| InnerError::InvalidPaddingScheme("length range is too large"))?;
    let offset_u64 = rng.next_u64() % span_u64;
    let offset = usize::try_from(offset_u64)
        .map_err(|_| InnerError::InvalidPaddingScheme("length offset is too large"))?;
    scheme
        .min_len
        .checked_add(offset)
        .ok_or(InnerError::InvalidPaddingScheme("padding length overflow"))
}
