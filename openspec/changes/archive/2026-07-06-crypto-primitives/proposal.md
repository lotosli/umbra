## Why

Umbra 的认证、密钥派生、记录加密、证书绑定与抗量子能力，全部建立在一组**正确、常量时间、可对照标准向量**
的密码学原语之上。它是最底层依赖，必须最先稳定，否则上层（`umbra-tls` / `umbra-reality`）无从落地。

## What Changes

- 新增 `umbra-crypto` 的经典密码学原语薄封装：X25519 ECDH、HKDF-SHA256、HMAC-SHA256（常量时间校验）、
  AES-128/256-GCM 与 ChaCha20-Poly1305 AEAD、ChaCha20 流密码。
- 提供 `zeroize` 包裹的密钥/秘密类型（Drop 清零，不实现 Debug/Display）。
- 统一 `CryptoError`（`thiserror`）。
- 抗量子原语（ML-KEM-768 / ML-DSA-65）**不在**本变更范围（见能力 `pq-primitives`）。

## Capabilities

### New Capabilities
- `crypto-primitives`: 经典密码学原语（ECDH / KDF / MAC / AEAD / 流密码）与秘密零化封装，含标准向量测试。

### Modified Capabilities
- （无）

## Impact

- crate：`umbra-crypto`（依赖 `umbra-proto` 的错误类型）。
- 依赖（catalog 已声明）：x25519-dalek、hkdf、sha2、hmac、aes-gcm、chacha20poly1305、chacha20、subtle、zeroize、rand。
- 下游：`umbra-tls`（密钥调度/记录）、`umbra-reality`（认证令牌/证书绑定）将依赖本能力。
