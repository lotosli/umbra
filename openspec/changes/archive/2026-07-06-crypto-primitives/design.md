## Context

`umbra-crypto` 是最底层 crate。定位是**薄封装**：不自造密码学，只以类型安全、常量时间、零化的方式组合
成熟原语（RustCrypto / dalek），并统一错误类型。协议对这些原语的具体用法（密钥调度、`session_id` 认证令牌、
`cert_mac` 证书绑定）分别属于 `umbra-tls` / `umbra-reality`，见 `docs/protocol-design.md` §5/§组件 B/E。

## Goals / Non-Goals

**Goals:**
- 正确性：对照 RFC 5869(HKDF) / 8439(ChaCha20) / 标准 AES-GCM / RFC 7748(X25519) 向量。
- 常量时间比较（`subtle`）；秘密零化（`zeroize`）。
- 稳定、最小、文档完备的 API 供上层复用；行覆盖率 ≥ 90%。

**Non-Goals:**
- 抗量子（ML-KEM/ML-DSA）→ 能力 `pq-primitives`。
- TLS 记录组帧与密钥调度 → `umbra-tls`。
- 协议语义（`session_id`/`cert_mac` 字节布局）→ `umbra-reality`。

## Decisions

- **选型**：X25519=`x25519-dalek`；HKDF=`hkdf`+`sha2`；HMAC=`hmac`；AEAD=`aes-gcm`+`chacha20poly1305`；
  流=`chacha20`；常量时间=`subtle`；零化=`zeroize`。
  理由：纯 Rust、社区审计、API 细粒度。备选 `ring`（C 依赖、粒度不足）被否。
- **秘密类型**：`Secret<[u8; N]>` newtype，`#[derive(Zeroize, ZeroizeOnDrop)]`，不实现 `Debug`/`Display`（防泄露），
  取值仅经受控方法；相等性用常量时间。
- **AEAD 语义**：显式传入 `nonce`/`aad`，**不**隐式管理 nonce（由上层保证 per-key 唯一），并在文档中强调。
- **错误**：`CryptoError` 覆盖 AEAD 校验失败/长度错误等，且**不泄露**导致失败的细节。

## Risks / Trade-offs

- [AEAD nonce 误用致灾] → 本层显式暴露 nonce 参数并文档化“per-key 唯一”约束；由上层与代码审查保证。
- [向量覆盖不全导致隐性错误] → 强制 RFC/FIPS 向量测试 + proptest 往返 + 对 `open()` 接入 fuzz。
- [依赖版本漂移] → 统一走 catalog，`cargo deny check` 把关许可证/来源/重复版本。
