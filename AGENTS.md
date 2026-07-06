# AGENTS.md — Umbra 开发者与 AI 代理操作手册

本文件是本仓库对**人类开发者与 AI 编码代理**的权威约束。开工前必读。协议规范见
[`docs/protocol-design.md`](docs/protocol-design.md)，架构见 [`docs/architecture.md`](docs/architecture.md)。

> 用途声明：Umbra 用于隐私保护与对抗网络审查（访问开放互联网），属正当的抗审查/隐私工程。
> 仅在法律允许范围内使用；不得用于任何非法目的。

---

## 0. 三条黄金法则（不可协商）
1. **SDD 优先：没有已批准的 OpenSpec 变更，就不写实现代码。** 先 spec，后码。见 §2。
2. **行覆盖率 ≥ 90%（硬性闸门）。** CI 与 `cargo xtask coverage` 强制；安全关键路径尽量 100%。见 §7。
3. **指纹与密码学保真。** ClientHello 逐字节匹配目标 Chrome；密码学对照标准向量；比较常量时间。见 §6。

---

## 1. 仓库地图
```
Cargo.toml            workspace（成员/依赖 catalog/全局 lint/profile）
rust-toolchain.toml   固定 1.96.1 + rustfmt/clippy/llvm-tools
rustfmt.toml clippy.toml deny.toml .editorconfig
.cargo/config.toml    `cargo xtask` 别名
.config/nextest.toml  测试运行器
.github/workflows/ci.yml   CI 闸门
.github/prompts/opsx-*.prompt.md   OpenSpec 斜杠命令（Copilot）
.github/skills/       OpenSpec 工作流 skill + 本项目 skill（见 §10）
openspec/             SDD 引擎：config.yaml（项目上下文）+ changes/ + specs/
docs/                 protocol-design.md（规范）· architecture.md（架构）
crates/               各库 crate + `umbra` CLI（见 §5）
xtask/                开发/CI 任务运行器
fuzz/                 cargo-fuzz（独立 workspace，需 nightly）
```

---

## 2. SDD 工作流（OpenSpec 为引擎）
本仓库用 **OpenSpec**（`@fission-ai/openspec`）驱动规格化开发。项目上下文写在
`openspec/config.yaml` 的 `context:`，会注入到每次 artifact 生成。

**每个能力（capability）的生命周期：**
1. `explore`（可选）：`/opsx:explore` 或 `openspec` 讨论方案。
2. `propose`：`/opsx:propose "<capability>"` → 在 `openspec/changes/<name>/` 生成
   `proposal.md`（why/what）→ `design.md`（how）→ `specs/<cap>/spec.md`（需求+场景）→ `tasks.md`（清单）。
3. **人评审并批准 spec**（对齐“要做什么”）。
4. `apply`：`/opsx:apply` 按 `tasks.md` 实现（此时才写代码），保持 CI 绿 + 覆盖率 ≥90%。
5. `archive`：`/opsx:archive` 归档变更并把需求并入 `openspec/specs/`（当前事实）。

**CLI（无需全局安装，经 npx）：**
```bash
npx @fission-ai/openspec@latest list                 # 列出变更/规范
npx @fission-ai/openspec@latest status --change <n>  # 某变更进度
npx @fission-ai/openspec@latest validate --all --strict   # CI 同款校验
```
**spec 格式硬规则**（见各 `openspec instructions`）：需求用 `### Requirement:`（措辞用 SHALL/MUST），
场景用 **恰好 4 个 `#` 的 `#### Scenario:`** + `- **WHEN**` / `- **THEN**`；每个需求至少一个场景。
**每个 `#### Scenario` 至少对应一个测试**（§7）。

能力清单与建议顺序见 [`docs/architecture.md`](docs/architecture.md#能力清单openspec与建议实现顺序)。
已有种子变更：`openspec/changes/crypto-primitives/`（可作范例）。

---

## 3. 构建 / 开发 / CI 命令
```bash
cargo build --workspace
cargo fmt --all                 # 格式化（--check 用于校验）
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace   # 测试（需 cargo-nextest）
cargo xtask coverage            # 行覆盖率 >=90% 闸门（需 cargo-llvm-cov）
cargo xtask ci                  # 本地复现 CI：fmt+clippy+deny+coverage
cargo deny check                # 许可证/公告/来源（需 cargo-deny）
cargo +nightly fuzz run <target>  # 模糊测试（见 fuzz/）
```
首次装工具：`cargo install cargo-nextest cargo-llvm-cov cargo-deny`；fuzz 需 `cargo install cargo-fuzz` + nightly。

CI（`.github/workflows/ci.yml`）闸门：**fmt · clippy(-D warnings) · nextest · 覆盖率≥90% · cargo-deny · openspec validate**。全绿方可合并。

---

## 4. Rust 最佳实践（编码规范）
- **版本/工具链**：edition 2021，工具链固定于 `rust-toolchain.toml`（1.96.1），MSRV=1.96.1（`rust-version`）。
- **Lint**：各 crate `[lints] workspace = true` 继承根 `[workspace.lints]`（clippy `all`+`pedantic`）。CI 视警告为错误。
  开发工具 `xtask` 除外。**不要**为过关而 `#[allow(...)]`，除非有充分理由并写明原因。
- **错误处理**：库 crate 用 `thiserror` 定义具体错误枚举并返回 `Result`；**禁止** `unwrap()/expect()/panic!()/todo!()/unimplemented!()`
  出现在库的非测试代码路径（二进制入口/`xtask` 可用少量 `expect` 于启动期）。二进制可用 `anyhow`。
- **unsafe**：默认 `unsafe_code = "warn"`。仅在必要处（如 `umbra-transport::geneva` 原始套接字）局部
  `#[allow(unsafe_code)]`，且必须有安全性注释（`// SAFETY: ...`）与针对性测试。
- **模块与可见性**：小模块、单一职责；`unreachable_pub = warn`，非必要不 `pub`。公共项必须有文档（`missing_docs = warn`）。
- **依赖**：一律走根 `[workspace.dependencies]` catalog（`dep.workspace = true`），不在 crate 内写死版本；
  新增依赖需评估体量/许可证并更新 `deny.toml`。优先成熟、审计过的 crate（尤其密码学：RustCrypto/dalek 系）。
- **异步**：统一 `tokio`；注意取消安全（cancellation-safety）与 `select!` 分支；不要在 async 中做阻塞调用。
- **性能**：热路径避免多余分配；优先 `&[u8]`/切片；但**正确性/常量时间 > 微优化**。
- **API 文档**：每个 crate `//!` 概述 + 每个公共项 `///`；示例代码用 `no_run`/`ignore` 避免网络依赖。

---

## 5. monorepo 架构（摘要）
详见 [`docs/architecture.md`](docs/architecture.md)。crate 与设计组件映射：

| crate | 职责 | 组件 |
|---|---|---|
| `umbra-proto` | 线格式类型/常量/错误 | 基础 |
| `umbra-crypto` | ECDH/KEM/签名/KDF/MAC/AEAD/常量时间 | I |
| `umbra-tls` | 自研极简 TLS 1.3（Rust 版 uTLS） | A |
| `umbra-fingerprint` | Chrome 指纹档案 + JA3/JA4 | J |
| `umbra-reality` | REALITY 认证 + 证书伪造 + 预构建 | B/D/E |
| `umbra-inner` | mux + 填充 + Vision 拼接 + 寻址 | F |
| `umbra-transport` | TCP/QUIC/Geneva 分段 | G/H |
| `umbra-core` | 分派/SOCKS5/中继/编排/探测抵抗 | C/K |
| `umbra` | CLI（server/client/keygen） | — |
| `umbra-testkit` | 回环 harness/向量（dev） | — |

依赖单向：`proto ← crypto/fingerprint ← tls ← {reality,inner,transport} ← core ← umbra`。**不得引入环。**

---

## 6. 安全要求（抗审查/密码学特有）
- **常量时间**：所有 MAC/标签/证书绑定/口令比较用 `subtle::ConstantTimeEq` 或 `hmac::verify_slice`；禁用 `==` 比较秘密。
- **密钥零化**：私钥/共享秘密/会话密钥类型实现 `Zeroize` 并在 `Drop` 清零；不 `Clone` 秘密除非必要。
- **不泄露**：日志**默认不记录**用户目标地址、流量内容、口令、密钥、`session_id` 明文；`tracing` 级别谨慎。
- **边界校验**：所有来自网络的字节（ClientHello、帧、session_id、证书）在解析处严格校验；解析器必须**永不 panic**（配 fuzz）。
- **反重放**：`ReplayCache` 必须**有界**（容量+TTL），防内存耗尽 DoS。
- **标准对照**：密码学与 TLS 对照 RFC 8446/8448/8439/5869、FIPS 203/204 向量；不自造密码学，只按规范组合原语。
- **指纹保真**：ClientHello/QUIC 指纹须以**真实 Chrome 抓包**核对（skill `umbra-fingerprint-check`）；档案随 Chrome 更新。
- **探测抵抗**：认证失败一律转发真 dest；**不得**早断/限速/回代理特征应答（组件 K）；认证路径与转发路径时序对齐。
- **秘密不入库**：`private_key`/`mldsa_seed`/口令等严禁提交（`.gitignore` 已挡常见后缀）；示例配置用占位值。
- 供应链：锁定 `Cargo.lock`（本仓库交付二进制，需提交）；定期 `cargo audit` / `cargo deny check`。

---

## 7. 测试与覆盖率（**90% 硬性**）
- **闸门**：**行覆盖率 ≥ 90%**，由 CI `coverage` job 与 `cargo xtask coverage`（`cargo llvm-cov ... --fail-under-lines 90`）强制。
  覆盖率是**下限**：认证/密钥/解析等安全关键路径应尽量 100% 并配 fuzz。**严禁**为达标而降低阈值或写无断言测试。
- **运行器**：`cargo-nextest`（配置见 `.config/nextest.toml`）。
- **测试层次**：
  - **单元**：模块内 `#[cfg(test)]`，覆盖分支/边界/错误路径。
  - **集成**：`crates/<crate>/tests/`，**每个 spec `#### Scenario` ≥ 1 用例**（骨架见 `crates/umbra-crypto/tests/`）。
  - **性质**：`proptest` 覆盖解析/编解码往返、不变量。
  - **模糊**：`fuzz/`（cargo-fuzz），覆盖所有字节解析器（ClientHello / session_id / mux 帧）。
  - **端到端**：`umbra-testkit` 进程内回环（`e2e_*` 前缀；CI 中以 `--run-ignored only` 跑）；需真实境外网络的用例标 `#[ignore]`，仅手动/专门环境运行。
  - **向量**：RFC 8448（TLS1.3 密钥调度）、8439（ChaCha20）、5869（HKDF）、FIPS 203/204（ML-KEM/ML-DSA）。
- **规则**：改动某能力必须同 PR 补齐/更新其测试；新公共 API 必有测试与文档。

---

## 8. 提交 / 分支 / PR 规范
- **提交**：Conventional Commits，单行主题：`type(scope): subject`（如 `feat(reality): seal/open session_id`）。
  AI 生成的代码在 PR 说明中注明所用代理与模型。
- **分支**：`feat/<capability>`、`fix/<...>`、`spec/<capability>`。
- **PR 必须**：① 关联一个 OpenSpec 变更（改动实现前该变更的 spec 已批准）；② CI 全绿（含覆盖率≥90%）；
  ③ 无秘密泄露；④ 公共 API 有文档与测试。评审对照 `specs/` 场景。
- **合并后**：`/opsx:archive` 归档变更、更新 `openspec/specs/`。

---

## 9. Do / Don't
**Do**
- 先 `propose` spec、评审、再实现；每个 scenario 配测试；保持覆盖率 ≥90%。
- 依赖走 catalog；秘密用占位；解析器防 panic；密码学对照向量。
- 指纹改动附“Chrome 抓包 + 比对”证据。

**Don't**
- ❌ 无 OpenSpec 变更就写实现。
- ❌ 降低/绕过 90% 覆盖率闸门；写无断言测试凑数。
- ❌ 库代码 `unwrap/expect/panic/todo/unimplemented`（测试与二进制启动期除外）。
- ❌ 用 `==` 比较秘密；把密钥/目标地址写进日志；提交任何密钥/口令。
- ❌ 在 crate 内写死依赖版本；引入环形依赖；开启 nightly-only rustfmt 选项。
- ❌ 让服务端对未认证/垃圾流量早断或限速（破坏探测抵抗）。

---

## 10. Skills 索引（`.github/skills/`）
- OpenSpec 工作流（自带）：`openspec-explore` · `openspec-propose` · `openspec-apply-change` · `openspec-archive-change` · `openspec-sync-specs`。
- 本项目：
  - `umbra-coverage-gate` — 本地测量并强制 90% 覆盖率。
  - `umbra-fingerprint-check` — 校验 ClientHello/QUIC 指纹与目标 Chrome 一致（组件 A/J）。
  - `umbra-add-crate` — 一致地新增 workspace crate。
