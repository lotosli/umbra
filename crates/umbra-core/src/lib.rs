//! `umbra-core` orchestrates runnable client and server sessions.
//!
//! Planned modules are `config` for server/client TOML, `dispatch` for
//! ClientHello classification and authenticated-or-fallback routing, `socks`
//! for local SOCKS5 ingress, `relay` for bidirectional copy and half-close
//! handling, and `prefixed` for replaying already-read bytes.
//!
//! The normative design lives in the server dispatch, SOCKS5, and runtime
//! configuration sections of `docs/protocol-design.md`; matching OpenSpec
//! capabilities are `server-dispatch`, `socks-inbound`, `config`, and
//! `orchestration`.

pub mod config;
pub mod dispatch;
pub mod error;
pub(crate) mod mux_io;
pub mod prefixed;
pub mod probe;
pub(crate) mod quic_crypto;
pub mod relay;
pub mod runtime;
pub mod socks;
pub mod tls_io;

pub use error::CoreError;
