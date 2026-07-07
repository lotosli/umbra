# Umbra

[![CI](https://github.com/lotosli/umbra/actions/workflows/ci.yml/badge.svg)](https://github.com/lotosli/umbra/actions/workflows/ci.yml)
[![Dist](https://github.com/lotosli/umbra/actions/workflows/dist.yml/badge.svg)](https://github.com/lotosli/umbra/actions/workflows/dist.yml)
[![Release](https://img.shields.io/github/v/release/lotosli/umbra?include_prereleases&sort=semver)](https://github.com/lotosli/umbra/releases)

[简体中文](README.zh-CN.md)

Umbra is a Rust implementation of a censorship-resistant privacy transport whose outer connection is designed to look like, and behave like, a real TLS 1.3 or QUIC connection to a real destination site.

The project combines protocol camouflage, pre-response authentication, browser-grade fingerprint discipline, post-quantum-aware primitives, and strict engineering gates. The result is not a generic proxy scaffold; it is an opinionated monorepo for building a high-assurance client/server transport with a measurable security and release process.

> Umbra is intended for privacy protection and access to the open internet where lawful. Do not use it for illegal activity.

## Why Umbra

- Real-site cover model: unauthenticated or probing traffic is forwarded to the configured destination instead of receiving a proxy-shaped failure.
- Chrome-shaped TLS surface: the TLS layer owns ClientHello construction, profile-driven extension ordering, GREASE handling, JA3/JA4 checks, and key schedule primitives.
- REALITY-style authentication: the authentication token is bound to the ClientHello and hidden in `legacy_session_id`, allowing the server to decide before responding.
- Modern cryptography: X25519, HKDF, HMAC, AEAD, ML-KEM, ML-DSA, constant-time verification, and zeroized secret wrappers are centralized in `umbra-crypto`.
- Inner traffic shaping: mux, adaptive padding, target addressing, and Vision-style splice paths are modeled as first-class crates instead of incidental tunnel code.
- Multi-transport design: TCP, QUIC, and low-risk TCP evasion hooks are separated behind `umbra-transport`.
- Engineering discipline: OpenSpec-driven changes, `cargo-nextest`, `cargo-llvm-cov`, cargo-deny, strict linting, and a hard 90% line-coverage gate.
- Reproducible release flow: version tags trigger multi-platform GitHub Actions builds and attach binaries to GitHub Releases.

## Status

Umbra is under active implementation. The repository now contains the real crate structure, CLI entry point, protocol modules, test harness, CI gates, and tag-based release automation. It is no longer just a workspace scaffold.

The protocol target is documented in [`docs/protocol-design.md`](docs/protocol-design.md), and the crate architecture is mapped in [`docs/architecture.md`](docs/architecture.md). Implementation work follows OpenSpec; see [`AGENTS.md`](AGENTS.md).

## Repository Layout

| Path | Purpose |
|---|---|
| `crates/umbra-proto` | Wire formats, constants, address and frame parsing |
| `crates/umbra-crypto` | X25519, ML-KEM, ML-DSA, HKDF, HMAC, AEAD, stream crypto, zeroization |
| `crates/umbra-tls` | TLS 1.3 ClientHello, parser, key schedule, records, client/server surfaces |
| `crates/umbra-fingerprint` | Chrome fingerprint profiles, GREASE, JA3/JA4 helpers |
| `crates/umbra-reality` | REALITY authentication, replay cache, certificate forging, destination prebuild |
| `crates/umbra-inner` | Mux, adaptive padding, Vision splice, target addressing |
| `crates/umbra-transport` | TCP, QUIC, and TCP evasion transport layer |
| `crates/umbra-core` | Config, dispatch, SOCKS5, relay, runtime orchestration |
| `crates/umbra` | `umbra` CLI: `server`, `client`, `keygen` |
| `xtask` | Development, CI, coverage, fingerprint, and dist tasks |
| `openspec` | Specification-driven development changes and accepted specs |
| `.github/workflows` | CI and tag-based release builds |

## Quick Start

```bash
cargo build --workspace
cargo test --workspace
cargo nextest run --workspace
```

Run the full local gate:

```bash
cargo xtask ci
```

Measure the hard coverage gate:

```bash
cargo xtask coverage
```

Build release artifacts locally:

```bash
cargo xtask dist
```

Generate key material:

```bash
cargo run --bin umbra -- keygen
```

## Releases

Development happens on branches. Releases are cut from version tags:

```bash
git tag -a v0.0.1 -m "Release v0.0.1"
git push origin v0.0.1
```

Pushing a `v*` tag triggers the `Dist` workflow. It builds macOS, Linux, and Windows binaries, uploads workflow artifacts, and publishes a GitHub Release for the tag.

Regular branch pushes run `CI` only. This keeps every branch validated without spending release-build minutes on every development commit.

## Development Model

Umbra uses Specification-Driven Development:

1. Propose or update an OpenSpec change under `openspec/changes/`.
2. Review and approve the spec before implementation.
3. Implement with tests mapped to spec scenarios.
4. Keep CI green and line coverage at or above 90%.
5. Archive accepted changes into `openspec/specs/`.

Useful commands:

```bash
npx --yes @fission-ai/openspec@latest list
npx --yes @fission-ai/openspec@latest validate --all --strict
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
```

## Security Posture

- Secret comparisons use constant-time verification.
- Secret material is wrapped for zeroization.
- Network parsers return structured errors and are designed not to panic on malformed input.
- Probe resistance is a protocol requirement, not an afterthought: authentication failure routes to the real destination.
- Fingerprint work is testable and profile-driven, with Chrome conformance treated as a release-quality concern.

## Documentation

- Protocol design: [`docs/protocol-design.md`](docs/protocol-design.md)
- Architecture: [`docs/architecture.md`](docs/architecture.md)
- Contributor and agent rules: [`AGENTS.md`](AGENTS.md)

## License

MIT. See [`LICENSE`](LICENSE).
