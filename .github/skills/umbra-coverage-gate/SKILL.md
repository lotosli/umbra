---
name: umbra-coverage-gate
description: Measure and enforce Umbra's mandatory 90% line-coverage gate before pushing or opening a PR. Use when implementing or reviewing a capability, or when CI coverage fails.
license: MIT
metadata:
  author: umbra
  version: "1.0"
---

Umbra 的**硬性要求：行覆盖率 ≥ 90%**（CI 的 `coverage` job 与本地 `cargo xtask coverage` 强制）。

## 何时用
- 实现某能力后、推送/开 PR 前自检。
- CI `coverage` 失败需定位未覆盖代码时。

## 步骤
1. 安装工具（首次）：
   ```bash
   cargo install cargo-nextest cargo-llvm-cov
   ```
2. 跑覆盖率闸门（与 CI 同口径）：
   ```bash
   cargo xtask coverage
   # 等价：cargo llvm-cov nextest --workspace --all-features --fail-under-lines 90
   ```
3. 看逐文件缺口，定位未覆盖行：
   ```bash
   cargo llvm-cov nextest --workspace --summary-only
   cargo llvm-cov nextest --workspace --html && open target/llvm-cov/html/index.html
   ```
4. 补测直到达标。原则：
   - 每个 spec `#### Scenario` ≥ 1 个集成测试；错误/边界分支也要覆盖。
   - 解析器/编解码器补 **proptest** 性质测试与 **fuzz** 目标（见 `fuzz/`）。
   - 不通过降低阈值来“达标”；不为凑覆盖率写无断言的测试。

## 注意
- 脚手架/CLI/构建工具（`xtask`、`fuzz`、`crates/umbra/src/main.rs`）不计入库覆盖率（见 `ci.yml` 的 ignore 正则）。
- 覆盖率是**下限**而非目标；安全关键路径（认证、密钥、解析）应尽量 100% 并配 fuzz。
