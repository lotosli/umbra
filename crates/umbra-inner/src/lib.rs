//! `umbra-inner` — 内层传输（组件 F）。
//!
//! 计划模块：`mux`（`MuxFrame` 多路复用会话，含流控窗口）、`padding`（自适应填充 scheme，抗 TLS-in-TLS）、
//! `vision`（Vision 真拼接：内层握手嗅探→整形→原始 splice，solo 模式）、`address`（目标地址编解码）、
//! `spider`（RealSite 判定后的浏览器式回落）。
//!
//! 选择逻辑：默认 mux+padding；被标记单流大吞吐/已知 TLS 内层者走 solo/Vision。
//! 测试要求：mux 帧往返/流控；开填充后前若干记录长度分布不确定；splice 后与直连 TLS 同形；≥90% 行覆盖率。
//!
//! 规范来源：`docs/protocol-design.md` §组件 F；OpenSpec 能力：`inner-mux`、`inner-vision`、`inner-padding`。
//! 脚手架阶段：**无实现**。
