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

## Review Remediation — Approved For Implementation

The user approved this revision for implementation on 2026-09-12. The sections above describe the original implementation proposal, and their checked tasks remain historical records rather than evidence of completed remediation. The exact Vision wire amendment retains the separate design and approval prerequisite in task 13.3; approval of this revision does not authorize guessing that format.

### Confirmed Scope

- Repair mux cancellation safety, event loss during credit/open waits, directional closure, bounded receive credit, and production multi-stream connection reuse.
- Separate TLS application/exporter and resumption transcript boundaries; canonicalize TCP HELLO0 independently of record framing; retain replay entries for the entire token acceptance window.
- Require UmbraTrusted before QUIC proxy readiness, independently validate ordinary certificates before RealSite classification, redact configuration diagnostics, and zeroize remaining owned secrets.
- Preserve TCP fallback prefixes on classification limits, deadlines, and EOF; give QUIC flows independent lifetimes with one physical UDP receive owner and resumable UDP-envelope parsing.
- Correct certificate-compression encoding and decoding, validate negotiated TLS parameters, support streamed server flights and advertised TLS 1.3 signatures, implement independently verified standard JA4, and require production-byte fingerprint evidence.
- Complete production TCP Vision behavior through bounded parsing, removable padding, and an authenticated, versioned switch protocol; keep ordinary traffic inside outer TLS when splice eligibility or capability negotiation is absent.
- Define effective prebuild behavior, nonblocking bounded probing, comparable first-response timing, supported spider application protocols, and explicit rejection of unsupported sending or early-close policies.

### Compatibility And Deliberate Limits

- **BREAKING**: corrected TLS traffic-secret derivation and TCP HELLO0 are not compatible with peers relying on the old derivation/AAD bugs. Upgrade both endpoints together; do not add fallback to insecure or nonstandard authentication behavior.
- **BREAKING**: Vision framing and capability/switch negotiation require an explicit protocol amendment before implementation. A plain relay inside outer TLS does not satisfy the raw-splice requirement.
- **BEHAVIOR CHANGE**: `prebuild = false` still performs the mandatory validated startup probe but disables periodic refresh. Zero-probe startup is not included.
- **BEHAVIOR CHANGE**: configured Geneva strategies with no sender fail before startup instead of silently sending as `off`. This follow-up does not implement privileged raw-packet strategies; `segment` promises ordered writes, not packet boundaries or measured interference resistance.
- **BEHAVIOR CHANGE**: RealSite is never proxy authorization. QUIC RealSite fails locally with no automatic TCP downgrade; HTTP/3 spider behavior is not claimed.
- TCP mux UDP associations remain separate while their wire format has no association identifier. No business-payload replay, connection migration, or broad transport redesign is included.
- Missing capture evidence remains explicitly unverified. A TLS capture, matching JA3, or custom JA4-style digest is not proof of complete TLS/QUIC fingerprint parity.

### Acceptance

Every new or changed scenario requires an assertion-bearing regression test. Use loopback peers, controlled clocks/I/O, independent TLS/reference cryptography, and reviewed non-secret fixtures; do not test against third-party infrastructure. Keep strict linting, all workspace tests including ignored loopback tests, line coverage >= 90%, cargo-deny, fingerprint checks, and strict OpenSpec validation. Update protocol and review documents to match actual supported behavior, and leave unverifiable claims or unimplemented tasks visibly incomplete.


## Runtime Reliability Follow-up — User Requested (2026-09-13)

The user requested fixing the runtime `mux target setup` failure and delivering a usable client/server, rather than stopping at analysis or merely disabling multiplexing. The follow-up stays within orchestration/inner-mux/TCP reliability and revises the earlier single-TCP-outer design to a bounded, capacity-aware pool. It adds bounded multi-address target connection attempts and explicit failure stages. There is no new authentication fallback, wire-format change, dependency, or application-payload replay.

Impact: `umbra-core` mux/runtime/TCP target connection and SOCKS failure paths; `umbra-inner` effective-capacity reporting; regression tests and operational documentation. No raw Vision/Geneva redesign or fingerprint claim is included.
