//! `umbra-reality` — REALITY 认证与冒充证书（组件 B/D/E）。
//!
//! 计划模块：`auth`（`seal_session_id`/`open_session_id`：X25519 ECDH → AES-GCM 令牌，AAD=整条 ClientHello）、
//! `replay`（LRU + TTL 反重放）、`cert`（伪造叶子 + `cert_mac`(HMAC) + ML-DSA-65 私有扩展）、
//! `prebuild`（组件 D：探测 dest，采集 `DestProfile` 供镜像）。
//!
//! 安全要求：常量时间比较；时间窗 `max_time_diff`；`ReplayCache` 有界（防 DoS）；`S_priv` 永不出栈。
//! 测试要求：篡改/过期/重放/AAD 变动均须拒绝；MITM 无法伪造 `cert_mac`；≥90% 行覆盖率。
//!
//! 规范来源：`docs/protocol-design.md` §组件 B/D/E；OpenSpec 能力：`reality-auth`、`cert-forge`、`dest-prebuild`。
//! 脚手架阶段：**无实现**。
