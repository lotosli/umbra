# Umbra（影）

[![CI](https://github.com/lotosli/umbra/actions/workflows/ci.yml/badge.svg)](https://github.com/lotosli/umbra/actions/workflows/ci.yml)
[![Dist](https://github.com/lotosli/umbra/actions/workflows/dist.yml/badge.svg)](https://github.com/lotosli/umbra/actions/workflows/dist.yml)
[![Release](https://img.shields.io/github/v/release/lotosli/umbra?include_prereleases&sort=semver)](https://github.com/lotosli/umbra/releases)

[English](README.md)

Umbra 是一个 Rust 实现的抗审查隐私传输。它的外层连接不是伪装成随机噪声，而是设计成一条真实的、通往真实目标站点的 TLS 1.3 或 QUIC 连接。

Umbra 把协议伪装、响应前认证、浏览器级指纹保真、抗量子感知密码学原语和严格工程闸门组织在一个 client/server 隐私传输 monorepo 中。

> 用途：隐私保护与访问开放互联网。请仅在所在司法辖区法律允许范围内使用，不得用于非法目的。

## 为什么是 Umbra

- 真实站点掩护模型：未认证或主动探测流量不会收到代理特征错误，而是转发到配置的真实 dest。
- Chrome 形态 TLS 表面：TLS 层掌控 ClientHello 构造、扩展顺序、GREASE、JA3/JA4 自检和密钥调度。
- REALITY 风格认证：认证令牌绑定整条 ClientHello，并隐藏在 `legacy_session_id` 中，服务端可在响应前完成判定。
- 现代密码学组合：X25519、HKDF、HMAC、AEAD、ML-KEM、ML-DSA、常量时间校验和 secret zeroize 统一封装在 `umbra-crypto`。
- 内层流量整形：mux、自适应填充、目标寻址和 Vision 真拼接路径是独立 crate 的一等能力。
- 多外层传输：TCP、QUIC 和低风险 TCP evasion 逻辑由 `umbra-transport` 分层承载。
- 工程质量硬闸门：OpenSpec 驱动开发，`cargo-nextest`、`cargo-llvm-cov`、cargo-deny、严格 lint，以及 90% 行覆盖率硬门槛。
- 可复现发布流程：推送 `v*` 版本 tag 自动触发多平台构建，并把二进制挂到 GitHub Releases。

## 当前状态

**0.0.8** 修复标准混合 TLS/QUIC 互通，并支持一个 SOCKS 客户端实例：TCP 走 TCP/Vision，UDP 走 QUIC。客户端与服务端需一起升级，不保留旧版错误混合格式的兼容分支。

在已有客户端配置中设置：

```toml
transport = "tcp"
udp_transport = "quic"
mux = false
socks_listen = "127.0.0.1:1080"
```

服务端一个实例即可同时配置 `listen` 与 `udp_listen`。Clash 只需一个 `127.0.0.1:1080` 的 SOCKS5 节点，并设置 `udp: true`；该选项表示允许 UDP，不会让 TCP 强制走 UDP。

使用步骤见[服务端配置](docs/usage.zh-CN.md#2-配置服务端)、[客户端配置](docs/usage.zh-CN.md#4-配置客户端)与[单实例分流说明](docs/usage.zh-CN.md#单实例-tcp-vision--quic-udp)。TLS 1.3 主握手与记录层由 Umbra 实现，QUIC 传输基于 Quinn。

已保存真实 [Chrome 153.0.8010.37 的 TCP/QUIC 采样证据](fingerprints/chrome-153-macos.capture.md)。默认 `chrome-latest` 仍跟随历史 Chrome 150 档案；本次采样不代表已实现完整 Chrome 153 指纹一致性。

最终协议形态见 [`docs/protocol-design.md`](docs/protocol-design.md)，crate 架构见 [`docs/architecture.md`](docs/architecture.md)。实现遵循 OpenSpec，规则见 [`AGENTS.md`](AGENTS.md)。

## 仓库结构

| 路径 | 职责 |
|---|---|
| `crates/umbra-proto` | 线格式、常量、地址和帧解析 |
| `crates/umbra-crypto` | X25519、ML-KEM、ML-DSA、HKDF、HMAC、AEAD、流密码、zeroize |
| `crates/umbra-tls` | TLS 1.3 ClientHello、解析器、密钥调度、记录层、客户端/服务端表面 |
| `crates/umbra-fingerprint` | Chrome 指纹档案、GREASE、JA3/JA4 辅助 |
| `crates/umbra-reality` | REALITY 认证、反重放、证书伪造、dest 预构建 |
| `crates/umbra-inner` | mux、自适应填充、Vision 拼接、目标寻址 |
| `crates/umbra-transport` | TCP、QUIC 和 TCP evasion 外层传输 |
| `crates/umbra-core` | 配置、分派、SOCKS5、中继、运行时编排 |
| `crates/umbra` | `umbra` CLI：`server`、`client`、`keygen` |
| `xtask` | 开发、CI、覆盖率、指纹检查和 dist 任务 |
| `openspec` | SDD 变更和已接受规范 |
| `.github/workflows` | CI 与 tag 触发的发布构建 |

## 快速开始

```bash
cargo build --workspace
cargo test --workspace
cargo nextest run --workspace
```

运行本地完整闸门：

```bash
cargo xtask ci
```

检查 90% 行覆盖率硬门槛：

```bash
cargo xtask coverage
```

本地构建 release artifacts：

```bash
cargo xtask dist
```

生成密钥材料：

```bash
cargo run --bin umbra -- keygen
```

## 发布

日常开发走分支。版本发布通过 tag 触发：

```bash
git tag -a v0.0.1 -m "Release v0.0.1"
git push origin v0.0.1
```

推送 `v*` tag 会触发 `Dist` workflow：构建 macOS、Linux、Windows 二进制，上传 workflow artifacts，并为该 tag 创建 GitHub Release。

普通分支 push 只触发 `CI`。这样每个分支都能被验证，同时不会为每个开发提交消耗完整 release 构建时间。

本次按明确要求手动发布 0.0.8：本地构建二进制，提交使用 `[skip ci]`，发布已有产物，不经过 Actions 构建。提供 macOS Apple Silicon/Intel 和 Linux x86_64/aarch64 四个程序及 SHA-256 校验文件。检查范围和最终部署情况见[验证记录](openspec/changes/archive/2026-09-14-fix-standard-quic-tls/verification.md)。

## 开发模型

Umbra 使用 Specification-Driven Development：

1. 在 `openspec/changes/` 提出或更新 OpenSpec 变更。
2. spec 评审批准后再实现。
3. 每个 spec scenario 对应测试。
4. 保持 CI 通过，行覆盖率不低于 90%。
5. 合并后把已接受变更归档进 `openspec/specs/`。

常用命令：

```bash
npx --yes @fission-ai/openspec@latest list
npx --yes @fission-ai/openspec@latest validate --all --strict
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
```

## 安全姿态

- secret 比较使用常量时间校验。
- secret 材料使用 zeroize 封装。
- 网络字节解析返回结构化错误，设计目标是畸形输入不 panic。
- 探测抵抗是协议要求：认证失败走真实 dest 转发，而不是返回代理特征响应。
- 指纹工作可测试、档案驱动，并把 Chrome 保真视为发布质量要求。

## 文档

- 使用手册：[`docs/usage.md`](docs/usage.md)（[中文](docs/usage.zh-CN.md)）
- 服务端：[配置步骤](docs/usage.zh-CN.md#2-配置服务端)与[字段参考](docs/usage.zh-CN.md#服务端配置)
- 客户端：[配置步骤](docs/usage.zh-CN.md#4-配置客户端)与[单实例 TCP/UDP 分流](docs/usage.zh-CN.md#单实例-tcp-vision--quic-udp)
- 协议设计：[`docs/protocol-design.md`](docs/protocol-design.md)
- 架构：[`docs/architecture.md`](docs/architecture.md)
- 贡献者与 AI 代理规则：[`AGENTS.md`](AGENTS.md)

## 许可证

MIT。见 [`LICENSE`](LICENSE)。
