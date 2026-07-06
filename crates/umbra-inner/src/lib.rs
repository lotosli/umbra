//! `umbra-inner` — 内层传输。
//!
//! 模块：`mux`（`MuxFrame` 多路复用会话，含流控窗口）、`padding`（自适应填充 scheme，抗 TLS-in-TLS）、
//! `vision`（Vision 真拼接：内层握手嗅探、整形、原始 splice，solo 模式）、`address`（目标地址编解码）。
//!
//! 选择逻辑：默认 mux+padding；被标记单流大吞吐/已知 TLS 内层者走 solo/Vision。
//!
//! 规范来源：`docs/protocol-design.md` 的内层传输章节；OpenSpec 能力：`inner-mux`、
//! `inner-vision`、`inner-padding`。

pub mod address;
pub mod error;
pub mod mux;
pub mod padding;
pub mod spider;
pub mod vision;

pub use error::InnerError;
