//! TCP evasion policy parsing, conservative segmentation, and fallback plans.

use crate::TransportError;

/// Conservative segment threshold for ClientHello writes.
pub const DEFAULT_SEGMENT_THRESHOLD: usize = 64;
/// Conservative first segment length.
pub const DEFAULT_FIRST_SEGMENT_LEN: usize = 32;

/// TCP evasion policy.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TcpEvasionPolicy {
    /// Ordinary ordered TCP write.
    Off,
    /// Conservative ordered segmentation.
    Segment {
        /// Segment threshold.
        threshold: usize,
        /// Length of the first segment.
        first_segment_len: usize,
    },
    /// Parsed Geneva-style strategy string retained for privileged senders.
    Geneva(String),
}

impl TcpEvasionPolicy {
    /// Return true when ordinary TCP sending should be used.
    #[must_use]
    pub const fn is_off(&self) -> bool {
        matches!(self, Self::Off)
    }
}

/// Outcome from an evasion planner.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EvasionPlan {
    /// Use ordered chunks produced by the evasion path.
    Evasion(Vec<Vec<u8>>),
    /// Fall back to one ordinary ordered write.
    Ordinary(Vec<u8>),
}

/// Recoverable planning failure that occurs before bytes are sent.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RecoverableBeforeSend;

/// Parse `off`, `segment`, or a Geneva-style strategy string.
pub fn parse_tcp_evasion(input: &str) -> Result<TcpEvasionPolicy, TransportError> {
    let trimmed = input.trim();
    if trimmed == "off" {
        Ok(TcpEvasionPolicy::Off)
    } else if trimmed == "segment" {
        Ok(TcpEvasionPolicy::Segment {
            threshold: DEFAULT_SEGMENT_THRESHOLD,
            first_segment_len: DEFAULT_FIRST_SEGMENT_LEN,
        })
    } else if let Some(strategy) = trimmed.strip_prefix("geneva:") {
        if strategy.is_empty() {
            Err(TransportError::InvalidEvasionStrategy(
                "Geneva strategy is empty",
            ))
        } else {
            Ok(TcpEvasionPolicy::Geneva(strategy.to_owned()))
        }
    } else if let Some(rest) = trimmed.strip_prefix("segment:") {
        parse_explicit_segment(rest)
    } else {
        Err(TransportError::InvalidEvasionStrategy(
            "unsupported strategy",
        ))
    }
}

/// Plan ordered writes for a ClientHello under a policy.
pub fn plan_client_hello_writes(
    client_hello: &[u8],
    policy: &TcpEvasionPolicy,
) -> Result<Vec<Vec<u8>>, TransportError> {
    match policy {
        TcpEvasionPolicy::Off | TcpEvasionPolicy::Geneva(_) => Ok(vec![client_hello.to_vec()]),
        TcpEvasionPolicy::Segment {
            threshold,
            first_segment_len,
        } => conservative_segments(client_hello, *threshold, *first_segment_len),
    }
}

/// Fall back to an ordinary write if evasion failed before bytes were sent.
pub fn fallback_plan_on_recoverable_error(
    client_hello: &[u8],
    evasion_result: Result<Vec<Vec<u8>>, RecoverableBeforeSend>,
) -> EvasionPlan {
    match evasion_result {
        Ok(chunks) => EvasionPlan::Evasion(chunks),
        Err(RecoverableBeforeSend) => EvasionPlan::Ordinary(client_hello.to_vec()),
    }
}

fn conservative_segments(
    client_hello: &[u8],
    threshold: usize,
    first_segment_len: usize,
) -> Result<Vec<Vec<u8>>, TransportError> {
    if threshold == 0 || first_segment_len == 0 {
        return Err(TransportError::InvalidEvasionStrategy(
            "segment lengths must be positive",
        ));
    }
    if client_hello.len() <= threshold {
        return Ok(vec![client_hello.to_vec()]);
    }
    let split = first_segment_len.min(client_hello.len() - 1);
    Ok(vec![
        client_hello[..split].to_vec(),
        client_hello[split..].to_vec(),
    ])
}

fn parse_explicit_segment(rest: &str) -> Result<TcpEvasionPolicy, TransportError> {
    let mut threshold = None;
    let mut first = None;
    for field in rest.split(',') {
        let (key, value) = field
            .split_once('=')
            .ok_or(TransportError::InvalidEvasionStrategy("missing key/value"))?;
        let parsed = value
            .parse::<usize>()
            .map_err(|_| TransportError::InvalidEvasionStrategy("segment value must be numeric"))?;
        match key {
            "threshold" => threshold = Some(parsed),
            "first" => first = Some(parsed),
            _ => return Err(TransportError::InvalidEvasionStrategy("unknown field")),
        }
    }
    Ok(TcpEvasionPolicy::Segment {
        threshold: threshold.ok_or(TransportError::InvalidEvasionStrategy("threshold missing"))?,
        first_segment_len: first.ok_or(TransportError::InvalidEvasionStrategy("first missing"))?,
    })
}
