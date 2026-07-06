//! `umbra-core` — 编排层：把各组件粘合为可运行的 client / server 会话。
//!
//! 计划模块：`config`（server/client TOML）、`dispatch`（服务端分派：读 ClientHello→认证→冒充/转发）、
//! `socks`（SOCKS5 入站）、`relay`（中继/半关闭）、`session`（client/server 每连接编排）、`prefixed`（回放流）。
//!
//! 规范来源：`docs/protocol-design.md` 的服务端分派、SOCKS5、运行参数章节；OpenSpec 能力：
//! `server-dispatch`、`socks-inbound`、`config`、`orchestration`。

pub mod config;
pub mod dispatch;
pub mod error;
pub mod prefixed;
pub mod probe;
pub mod relay;
pub mod runtime;
pub mod socks;
pub mod tls_io;

pub use error::CoreError;
