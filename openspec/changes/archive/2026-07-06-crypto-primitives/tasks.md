## 1. Crate 骨架

- [x] 1.1 在 `umbra-crypto` 引入 catalog 依赖（x25519-dalek / hkdf / sha2 / hmac / aes-gcm / chacha20poly1305 / chacha20 / subtle / zeroize / rand）
- [x] 1.2 定义 `CryptoError`（thiserror）与模块骨架：`x25519` `kdf` `mac` `aead` `stream` `secret`

## 2. 原语实现

- [x] 2.1 `x25519`：keypair 生成 + ECDH agree（RFC 7748）
- [x] 2.2 `kdf`：HKDF-SHA256 extract / expand
- [x] 2.3 `mac`：HMAC-SHA256 + 常量时间 `verify`
- [x] 2.4 `aead`：AES-128/256-GCM 与 ChaCha20-Poly1305 的 seal / open（含 AAD）
- [x] 2.5 `stream`：ChaCha20 keystream
- [x] 2.6 `secret`：`Zeroize`/`ZeroizeOnDrop` newtype，无 `Debug`/`Display`，常量时间相等

## 3. 测试与覆盖率（>= 90%）

- [x] 3.1 标准向量：RFC 7748 / 5869 / 8439 / AES-GCM
- [x] 3.2 错误与常量时间路径：篡改标签、错误 AAD、错误长度
- [x] 3.3 proptest：AEAD/HKDF 往返与不变量
- [x] 3.4 fuzz：为 `aead::open` 接入 `fuzz/` 目标
- [x] 3.5 `cargo xtask coverage` 通过（行覆盖率 >= 90%）

## 4. 文档与归档

- [x] 4.1 每个公共项 `///` 文档 + crate `//!` 概述
- [x] 4.2 `/opsx:archive` 归档变更并更新 `openspec/specs/`
