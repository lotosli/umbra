## Why

`docs/protocol-design.md` defines Umbra's final protocol surface across TLS 1.3 fingerprinting, REALITY authentication, probe-resistant dispatch, inner transport, TCP/QUIC outer transports, post-quantum checks, configuration and CLI. The current workspace is scaffolding plus a seed `crypto-primitives` change, so the remaining protocol contract must be captured before implementation can proceed under SDD.

## What Changes

- Implement the full non-overlapping protocol capabilities described by `docs/protocol-design.md`, using the existing `crypto-primitives` change as the prerequisite for classic primitives.
- Add wire types, fingerprint profiles, self-built TLS 1.3 ClientHello/record/handshake support, REALITY `session_id` authentication, forged certificate binding, dest prebuild profiling, server dispatch and probe fallback, inner mux/padding/Vision transport, TCP/QUIC transport surfaces, SOCKS/config/orchestration, probe-resistance hardening and CLI.
- Expose every configuration file option from §16 as a CLI parameter override for `umbra server`, `umbra client` and `umbra keygen`.
- Add tests mapping each OpenSpec scenario to coverage, including unit, integration, property/fuzz hooks and coverage gate execution.
- **BREAKING**: Replace all scaffold placeholder crate APIs and the placeholder CLI output with real protocol APIs and executable behavior.

## Capabilities

### New Capabilities
- `wire-proto`: Address, frame, constants and protocol error types used by inner transport and dispatch.
- `pq-primitives`: ML-KEM-768 and ML-DSA-65 wrappers used by hybrid key exchange and certificate signatures.
- `fingerprint-profiles`: Data-driven Chrome TLS/QUIC fingerprint profiles plus JA3/JA4 self-checks.
- `tls13-utls-stack`: Self-built TLS 1.3 ClientHello, key schedule, record protection and minimal client/server state machines.
- `reality-auth`: REALITY authentication token seal/open, `HELLO0` binding and bounded replay cache.
- `cert-forge`: Forged leaf certificate generation, `cert_mac` private extension and ML-DSA extension verification.
- `dest-prebuild`: Startup/periodic destination probing and `DestProfile` mirroring inputs.
- `server-dispatch`: Read ClientHello before response, authenticate or forward to dest, and support prefixed streams.
- `inner-mux`: Multiplexed logical streams and target address negotiation.
- `inner-padding`: Configurable adaptive padding scheme and padding frame emission.
- `inner-vision`: Solo-mode TLS sniffing, handshake shaping and splice relay.
- `transport-tcp`: TCP outer transport and ordinary ClientHello sending.
- `tcp-evasion`: Conservative Geneva-style TCP segmentation strategy with fallback.
- `transport-quic`: QUIC/HTTP-3 outer transport surface, QUIC fingerprint parameters and REALITY-over-QUIC carrier.
- `socks-inbound`: SOCKS5 listener and target request translation.
- `config`: Server/client config parsing, validation and CLI override merging.
- `orchestration`: `run_server`, `run_client`, relay lifecycle and shutdown handling.
- `probe-resistance`: Timing alignment, useless-record limits, RealSite spider behavior and fallback invariants.
- `cli`: `umbra server|client|keygen` commands with all optional config fields available as flags.

### Modified Capabilities
- （无；`crypto-primitives` remains a separate active prerequisite change.）

## Impact

- Crates: `umbra-proto`, `umbra-crypto`, `umbra-fingerprint`, `umbra-tls`, `umbra-reality`, `umbra-inner`, `umbra-transport`, `umbra-core`, `umbra-testkit`, `umbra`.
- Workspace dependencies: uses the existing catalog entries for tokio, crypto, TLS parsing/cert generation, transport, CLI/config/logging, property tests and coverage tooling.
- Runtime/API: introduces real config files, CLI flags, network listeners, key generation output, TLS/QUIC fingerprint data files and protocol state machines.
- CI: must keep fmt, clippy, nextest, coverage >= 90%, cargo-deny and OpenSpec validation passing.
