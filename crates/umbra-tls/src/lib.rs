//! `umbra-tls` — 自研极简 TLS 1.3 栈（Rust 版 uTLS，组件 A）。
//!
//! 计划模块：`clienthello`（逐字节构造，注入指纹 + `legacy_session_id` + X25519 keyshare 私钥）、
//! `keyschedule`（HKDF-Expand-Label / Derive-Secret / 各流量密钥）、`records`（AEAD 记录层）、
//! `handshake`（客户端状态机）、`server`（服务端冒充栈）、`parse`（ClientHello 解析，服务端用）。
//!
//! 范围：**仅 TLS 1.3**（RFC 8446），仅实现 Chrome 使用的套件/扩展；不做 TLS 1.2。
//! 关键能力：保留 keyshare 私钥供 REALITY 认证复用（组件 B）；证书校验回调交给 `umbra-reality`。
//! 测试要求：RFC 8448 密钥调度向量；对真实 TLS 1.3 站点握手互通；≥90% 行覆盖率。
//!
//! 规范来源：`docs/protocol-design.md` §组件 A；OpenSpec 能力：`tls13-utls-stack`。
//! 脚手架阶段：**无实现**。
