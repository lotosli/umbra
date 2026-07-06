---
name: umbra-fingerprint-check
description: Verify that Umbra's self-built TLS 1.3 ClientHello (and QUIC) byte-for-byte matches the target Chrome fingerprint (JA3/JA4). Use when implementing or updating umbra-tls / umbra-fingerprint (component A/J), or when circumvention becomes unstable.
license: MIT
metadata:
  author: umbra
  version: "1.0"
---

Umbra 的隐蔽性依赖 ClientHello 与目标 Chrome **逐字节一致**（组件 A/J）。指纹漂移会直接暴露。

## 何时用
- 实现/修改 `umbra-tls`（ClientHello 构造）或 `umbra-fingerprint`（档案）。
- 翻墙变得不稳定，怀疑指纹被识别。
- 目标 Chrome 版本升级，需要更新档案。

## 步骤
1. **取参照**：从真实目标 Chrome 抓一份 ClientHello（Wireshark），或访问指纹服务：
   - `https://tls.peet.ws/api/all`（JA3/JA4/扩展顺序/ALPS 等）
   - 记录：套件表、扩展集合与**顺序**、GREASE 位点、supported_groups、sig_algs、ALPN、key_share 组合。
2. **取我方**：让 `umbra-tls` 产出 ClientHello 字节，计算 JA3/JA4（`umbra-fingerprint::ja3/ja4`）。
3. **逐项比对**（必须一致）：JA3、JA4、扩展顺序、GREASE 位置、key_share（含 X25519MLKEM768 与经典 X25519）、
   ALPN(`h2,http/1.1`)、`legacy_session_id` 长度=32B。
4. **QUIC**：另比对 transport parameters 顺序/值、ALPN=`h3`、GREASE transport parameter。
5. 不一致 → 更新 `fingerprints/chrome-latest.toml` 档案或修正构造逻辑；把差异写进对应 OpenSpec 变更。

## 注意
- 档案与代码解耦（数据文件在 `fingerprints/`），随 Chrome 版本更新，勿硬编码。
- `legacy_session_id` 承载 REALITY 认证令牌但**不进 JA3/JA4**；确认其为 32B 且外观随机。
- 把一次“参照抓包 + 比对结果”作为证据附到该能力的 PR / OpenSpec 变更里。
