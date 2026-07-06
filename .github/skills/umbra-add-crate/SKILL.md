---
name: umbra-add-crate
description: Add a new crate to the Umbra Cargo workspace consistently (manifest inheritance, workspace lints, dependency catalog, docs). Use when a capability needs a new crate.
license: MIT
metadata:
  author: umbra
  version: "1.0"
---

在 Umbra workspace 里新增 crate 的一致做法（保持 lint/依赖/文档规范）。

## 步骤
1. 目录：库放 `crates/<name>/`，二进制同理。建 `crates/<name>/src/lib.rs`。
2. `crates/<name>/Cargo.toml` 用 workspace 继承：
   ```toml
   [package]
   name = "umbra-<name>"
   description = "<一句话职责>"
   version.workspace = true
   edition.workspace = true
   rust-version.workspace = true
   license.workspace = true
   repository.workspace = true
   authors.workspace = true
   publish = false

   [lints]
   workspace = true

   [dependencies]
   # 仅从根 [workspace.dependencies] catalog 引入：dep.workspace = true
   ```
3. 注册成员：编辑根 `Cargo.toml` 的 `[workspace] members`。内部依赖用 `umbra-xxx.workspace = true`（catalog 已声明 path）。
4. `lib.rs` 顶部写 `//!` crate 文档：职责、计划模块、对应设计组件与 OpenSpec 能力。
5. 新增外部依赖时：先加到根 `[workspace.dependencies]` catalog（带版本），再在 crate 里 `dep.workspace = true`；
   如引入新许可证/来源，更新 `deny.toml`。
6. 校验：`cargo build --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`。

## 规则
- **不**在 crate 内直接写死依赖版本（一律走 catalog，避免版本漂移）。
- 公共项必须有文档（`missing_docs = warn`）。库代码不得 `unwrap/expect/panic`（用 `Result` + `thiserror`）。
- 新 crate 的能力同样要有 OpenSpec 变更与 ≥90% 覆盖率。
