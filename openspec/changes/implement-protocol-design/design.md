## Context

The repository is a Rust workspace whose crates already match the protocol component split in `docs/architecture.md`, but most crates are scaffolding. `docs/protocol-design.md` is the implementation baseline: no feature in this change is allowed to intentionally diverge from that document unless the protocol document is amended first.

This change is an umbrella implementation change for the full protocol except the active prerequisite `crypto-primitives` change. Work must preserve the one-way crate dependency graph:

`proto <- crypto/fingerprint <- tls <- {reality,inner,transport} <- core <- umbra`

## Goals / Non-Goals

**Goals:**
- Implement all remaining protocol components A-K plus configuration and CLI from `docs/protocol-design.md`.
- Keep public APIs small, documented, lint-clean, and testable by scenario.
- Preserve byte-level protocol layouts: REALITY `session_id`, certificate extensions, mux frames, target addresses, TLS ClientHello and QUIC carrier rules.
- Expose every optional `server.toml` and `client.toml` field as a CLI flag override.
- Run fmt, clippy, nextest, coverage >= 90%, cargo-deny, OpenSpec validation, and a document-to-code review before considering the change complete.

**Non-Goals:**
- Changing the protocol semantics in `docs/protocol-design.md`.
- Replacing the self-built TLS 1.3 stack with rustls/BoringSSL as the primary handshake implementation.
- Adding a multi-user panel, airport-style account system, or any destination controlled by untrusted client input.
- Lowering coverage, weakening constant-time checks, logging secrets, or committing real keys.

## Decisions

- **Keep the current crate split.** Each capability maps to the crate already listed in `docs/architecture.md`. Alternative: collapse into the single crate layout shown in protocol section 17. Rejected because the repository is already a workspace and AGENTS defines the workspace mapping as authoritative.
- **Treat `crypto-primitives` as a prerequisite.** This change does not redefine its classic X25519/HKDF/HMAC/AEAD/ChaCha20 requirements. The implementation sequence must apply or otherwise satisfy that active change before dependent TLS and REALITY code.
- **Use data-driven fingerprints.** `umbra-fingerprint` owns Chrome profile data and JA3/JA4 calculation. `umbra-tls` consumes profiles but does not hard-code Chrome tables. Alternative: compile constants directly into the TLS builder. Rejected because Chrome drift must be handled by profile updates.
- **Separate parsers from network orchestration.** Byte parsers for ClientHello, mux frames, target addresses and config validation are pure functions with property/fuzz coverage. Async network code composes those types and remains thin.
- **Fail fast at trust boundaries.** Invalid CLI flags, config values, key material, protocol lengths and parser state MUST return typed errors before runtime startup or before a protocol state transition. The protocol-required unauthenticated/probe path remains an explicit dispatch branch to `dest`, not a silent internal failure.
- **Make fallback behavior explicit and testable.** `server-dispatch` returns authenticated traffic to the local Umbra TLS server path and sends every failure case to the configured dest without early response. Tests use `umbra-testkit` loopback destinations.
- **Use conservative transport defaults.** TCP is the default outer transport with basic segmentation for `tcp_evasion = "segment"`. Advanced raw-socket Geneva strategies are parsed and represented, but unsafe/raw packet sending must remain isolated behind a documented implementation boundary.
- **Expose CLI overrides through config merge.** The CLI parses optional flags into partial config structs and merges them over file-loaded TOML before validation. This prevents separate runtime semantics between files and flags.

## Risks / Trade-offs

- [Full TLS 1.3 and QUIC are large security-critical surfaces] -> Implement in dependency order, keep pure cryptographic and parser pieces independently tested, and require RFC/vector/fingerprint tests before network e2e claims.
- [Chrome fingerprint drift can make a correct implementation detectable] -> Store versioned profiles, add JA3/JA4 self-checks, and require capture evidence for profile updates.
- [Probe fallback can accidentally become distinguishable] -> Test failure cases with invalid SNI, bad token, replay and random bytes against a real loopback dest, and assert no Umbra response is emitted before fallback.
- [Coverage pressure can encourage weak tests] -> Tie every OpenSpec scenario to an assertion-bearing test and keep coverage threshold unchanged at 90%.
- [QUIC implementation may depend on provider limitations] -> Keep the public transport surface protocol-correct, isolate the provider adapter, and require captured QUIC fingerprint evidence before enabling production defaults.
- [Raw-socket evasion may need platform privileges] -> Default to safe segmentation; gate privileged strategies behind explicit config, safety comments and fallback to ordinary TCP sending.

## Migration Plan

1. Apply the prerequisite `crypto-primitives` change or keep it green in parallel.
2. Implement crate capabilities from leaf to root: proto, PQ, fingerprint, TLS, REALITY, inner, transport, core, CLI.
3. Add testkit loopback fixtures before server/client orchestration tests.
4. Replace scaffold CLI output with real subcommands only after config and keygen are implemented.
5. Run local CI commands, then do a line-by-line review against `docs/protocol-design.md` and record any implementation gaps as OpenSpec task failures.

## Open Questions

- Which exact Chrome version should seed `chrome-latest` before the first fingerprint evidence capture?
- Should QUIC use `quinn` first with a constrained adapter or wait for a provider that permits closer Chrome parity?
- Which ML-DSA crate version and encoding are accepted for the first stable implementation if upstream APIs shift?
