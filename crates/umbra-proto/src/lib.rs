//! Shared wire-format types, constants, and errors for Umbra.
//!
//! The crate contains pure parsers and serializers for protocol bytes used by
//! higher layers. Parsers return structured errors and never panic on malformed
//! network input.

pub mod addr;
pub mod consts;
pub mod error;
pub mod flow;
pub mod frame;
pub mod udp;
pub mod vision;

pub use error::ProtocolError;
