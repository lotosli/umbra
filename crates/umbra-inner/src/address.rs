//! Target address helpers for mux SYN payloads and Vision solo prefaces.

pub use umbra_proto::addr::TargetAddr;

use crate::InnerError;

/// Encode a target address.
pub fn encode_target_addr(addr: &TargetAddr) -> Result<Vec<u8>, InnerError> {
    addr.encode().map_err(InnerError::from)
}

/// Decode one target address and require full input consumption.
pub fn decode_target_addr(input: &[u8]) -> Result<TargetAddr, InnerError> {
    TargetAddr::decode(input).map_err(InnerError::from)
}

/// Decode one target address and return the number of consumed bytes.
pub fn decode_target_addr_from(input: &[u8]) -> Result<(TargetAddr, usize), InnerError> {
    TargetAddr::decode_from(input).map_err(InnerError::from)
}
