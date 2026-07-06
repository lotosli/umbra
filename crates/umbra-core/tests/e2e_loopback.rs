//! 端到端测试骨架 —— 进程内 client↔server 回环（借助 `umbra-testkit`）。
//!
//! 前缀 `e2e_` 的用例在 CI 中默认仅以 `--run-ignored only` 运行（见 `.config/nextest.toml`）。
//! 当前 `#[ignore]`（尚无实现）。

/// Scenario: 认证成功 → 冒充握手 → SOCKS5 CONNECT 经隧道到达目标。
#[test]
#[ignore = "pending orchestration implementation"]
fn e2e_authenticated_tunnel_roundtrip() {
    todo!("回环拉起 server+client，经 SOCKS5 代理一次请求并校验往返");
}

/// Scenario: 认证失败 → 服务端转发 dest → 客户端进入爬虫模式。
#[test]
#[ignore = "pending orchestration implementation"]
fn e2e_unauthenticated_falls_back_to_dest() {
    todo!("错误口令连接应被转发到 fake_dest，并观测到真站响应");
}
