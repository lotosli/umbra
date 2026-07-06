# Umbra（影）

一个以“**本身就是一条通往真实大站的真 TLS 1.3 / QUIC 连接**”来隐身的抗审查代理协议实现（Rust）。
面向稳定、尽可能不可检测地访问开放互联网。仅 client + server，不做机场/多用户面板。

> ⚠️ 用途：隐私保护与对抗网络审查，属正当的抗审查/隐私工程。请在所在司法辖区法律允许范围内使用。

## 现状
**脚手架阶段**：workspace / 工具链 / harness / SDD 引擎（OpenSpec）已就位，**尚无协议实现**。
开发遵循 **SDD**：任何实现前先在 `openspec/` 提出并批准变更。详见 [`AGENTS.md`](AGENTS.md)。

## 文档
- 协议规范（最终技术形态）：[`docs/protocol-design.md`](docs/protocol-design.md)
- monorepo 架构与能力清单：[`docs/architecture.md`](docs/architecture.md)
- 开发者与 AI 代理须知（含 SDD 工作流、Rust 规范、90% 覆盖率要求）：[`AGENTS.md`](AGENTS.md)

## 快速开始（开发）
```bash
# 构建 / 检查
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check

# 测试与覆盖率（需 cargo-nextest / cargo-llvm-cov）
cargo install cargo-nextest cargo-llvm-cov
cargo nextest run --workspace
cargo xtask coverage      # 强制行覆盖率 >= 90%

# SDD（OpenSpec，经 npx 运行，无需全局安装）
npx @fission-ai/openspec@latest list
#   或在支持的编辑器中使用斜杠命令：/opsx:propose "<capability>"
```

## 许可证
MIT（见 [`LICENSE`](LICENSE)）。
