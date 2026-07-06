//! `umbra-testkit` — 测试工具与回环 harness（单元/组件/端到端测试共用）。
//!
//! 计划模块：`loopback`（进程内 client↔server 回环，免真实网络）、`fake_dest`（可控的真实 TLS “借用站点”桩）、
//! `vectors`（RFC 8448 TLS 1.3 密钥调度向量、FIPS 203/204 KAT）、`assert`（常量时间/长度分布断言助手）。
//!
//! 仅供测试使用（各 crate 以 `dev-dependencies` 引入）。脚手架阶段：**无实现**。
