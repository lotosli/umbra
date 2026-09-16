//! Bounded control payloads for negotiated adaptive mux flow control.

use crate::ProtocolError;

/// Largest supported adaptive receive window (64 MiB).
pub const MAX_WINDOW: u32 = 64 * 1024 * 1024;

/// Direction-specific receive settings advertised by an adaptive mux peer.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FlowSettings {
    /// Initial per-stream receive window.
    pub stream: u32,
    /// Initial aggregate connection receive window.
    pub connection: u32,
    /// Largest per-stream receive window.
    pub max_stream: u32,
    /// Largest aggregate connection receive window.
    pub max_connection: u32,
}

impl Default for FlowSettings {
    fn default() -> Self {
        Self {
            stream: 256 * 1024,
            connection: 1024 * 1024,
            max_stream: 32 * 1024 * 1024,
            max_connection: MAX_WINDOW,
        }
    }
}

impl FlowSettings {
    /// Validate nonzero, ordered and bounded receive limits.
    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.stream == 0
            || self.connection == 0
            || self.stream > self.max_stream
            || self.connection > self.max_connection
            || self.max_stream > self.max_connection
            || self.max_connection > MAX_WINDOW
            || self.stream > self.connection
        {
            return Err(ProtocolError::LengthViolation);
        }
        Ok(())
    }

    /// Encode the UAF1 settings payload.
    pub fn encode(self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(20);
        out.extend_from_slice(b"UAF1");
        for value in [
            self.stream,
            self.connection,
            self.max_stream,
            self.max_connection,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        Ok(out)
    }

    /// Decode one exact settings payload without allocating peer-sized storage.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != 20 || &bytes[..4] != b"UAF1" {
            return Err(ProtocolError::LengthViolation);
        }
        let read = |offset| -> Result<u32, ProtocolError> {
            Ok(u32::from_be_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .map_err(|_| ProtocolError::LengthViolation)?,
            ))
        };
        let out = Self {
            stream: read(4)?,
            connection: read(8)?,
            max_stream: read(12)?,
            max_connection: read(16)?,
        };
        out.validate()?;
        Ok(out)
    }
}

/// Cumulative credit and consumed-byte acknowledgement; stream zero is aggregate.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CreditUpdate {
    /// Largest exclusive byte position the peer is allowed to send.
    pub limit: u64,
    /// Cumulative byte position consumed by the receiving application.
    pub consumed: u64,
}

impl CreditUpdate {
    /// Encode one bounded cumulative credit payload.
    pub fn encode(self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&self.limit.to_be_bytes());
        out.extend_from_slice(&self.consumed.to_be_bytes());
        Ok(out)
    }

    /// Parse an exact credit payload, rejecting inverted or excessive grants.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != 16 {
            return Err(ProtocolError::LengthViolation);
        }
        let out = Self {
            limit: u64::from_be_bytes(
                bytes[..8]
                    .try_into()
                    .map_err(|_| ProtocolError::LengthViolation)?,
            ),
            consumed: u64::from_be_bytes(
                bytes[8..]
                    .try_into()
                    .map_err(|_| ProtocolError::LengthViolation)?,
            ),
        };
        out.validate()?;
        Ok(out)
    }

    fn validate(self) -> Result<(), ProtocolError> {
        if self.limit < self.consumed || self.limit - self.consumed > u64::from(MAX_WINDOW) {
            return Err(ProtocolError::LengthViolation);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn exact_payloads_round_trip_and_reject_bad_limits() {
        let settings = FlowSettings::default();
        assert_eq!(
            FlowSettings::decode(&settings.encode().unwrap()).unwrap(),
            settings
        );
        assert!(FlowSettings {
            stream: 0,
            ..settings
        }
        .validate()
        .is_err());
        assert!(FlowSettings {
            max_connection: MAX_WINDOW + 1,
            ..settings
        }
        .validate()
        .is_err());
        assert!(FlowSettings {
            connection: 1,
            ..settings
        }
        .validate()
        .is_err());
        let credit = CreditUpdate {
            limit: 4096,
            consumed: 1024,
        };
        assert_eq!(
            CreditUpdate::decode(&credit.encode().unwrap()).unwrap(),
            credit
        );
        assert!(CreditUpdate {
            limit: 1,
            consumed: 2
        }
        .encode()
        .is_err());
        assert!(CreditUpdate {
            limit: u64::MAX,
            consumed: 0
        }
        .encode()
        .is_err());
    }

    proptest! {
        #[test]
        fn arbitrary_controls_never_panic_and_valid_controls_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..96)) {
            if let Ok(settings) = FlowSettings::decode(&bytes) {
                prop_assert_eq!(settings.encode().unwrap(), bytes.clone());
            }
            if let Ok(credit) = CreditUpdate::decode(&bytes) {
                prop_assert_eq!(credit.encode().unwrap(), bytes);
            }
        }
    }
}
