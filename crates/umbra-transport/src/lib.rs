//! `umbra-transport` — 外层传输（组件 G/H）。
//!
//! 计划模块：`tcp`（TCP 外层）、`quic`（QUIC/HTTP-3，复用 `umbra-tls` 握手；REALITY-over-QUIC 认证载体）、
//! `geneva`（TCP 分段/TTL 诱饵/乱序，TCB 去同步抗 RST 注入）。
//!
//! 说明：QUIC 指纹与 REALITY-over-QUIC 载体须以真实 Chrome 抓包核对；Geneva 高级策略需 `CAP_NET_RAW`，
//! 默认仅启用低风险分段且失败回退普通发送。
//!
//! 规范来源：`docs/protocol-design.md` §组件 G/H；OpenSpec 能力：`transport-tcp`、`transport-quic`、`tcp-evasion`。
//! 脚手架阶段：**无实现**。
