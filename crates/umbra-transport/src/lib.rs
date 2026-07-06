//! `umbra-transport` — 外层传输。
//!
//! 模块：`tcp`（TCP 外层）、`quic`（QUIC/HTTP-3，复用 `umbra-tls` 握手；REALITY-over-QUIC 认证载体）、
//! `geneva`（TCP 分段/TTL 诱饵/乱序，TCB 去同步抗 RST 注入）。
//!
//! 说明：QUIC 指纹与 REALITY-over-QUIC 载体须以真实 Chrome 抓包核对；Geneva 高级策略需 `CAP_NET_RAW`，
//! 默认仅启用低风险分段且失败回退普通发送。
//!
//! 规范来源：`docs/protocol-design.md` 的外层传输章节；OpenSpec 能力：`transport-tcp`、
//! `transport-quic`、`tcp-evasion`。

pub mod error;
pub mod evasion;
pub mod quic;
pub mod tcp;

pub use error::TransportError;
