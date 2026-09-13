//! `umbra-inner` implements authenticated inner transports.
//!
//! `mux` provides `MuxFrame`-based logical streams with flow-control windows,
//! `padding` adds adaptive cover frames, `vision` handles solo-mode TLS
//! sniffing, shaping, and raw splice, and `address` wraps target address
//! encoding for SYN payloads and solo prefaces.
//!
//! The default path is mux plus padding. Solo/Vision is reserved for known TLS
//! inner streams or single-stream high-throughput flows.
//!
//! The normative design lives in the inner transport section of
//! `docs/protocol-design.md`; matching OpenSpec capabilities are `inner-mux`,
//! `inner-vision`, and `inner-padding`.

pub mod address;
pub mod error;
pub mod mux;
pub mod padding;
pub mod spider;
pub mod vision_observer;

pub use error::InnerError;
