# Protocol Design Implementation Review

Baseline: `docs/protocol-design.md` (700 lines).

Review method: every contiguous line range below was compared against the implementation. Ranges cover lines 1-700 with no gaps. The protocol-design document is treated as the behavioral baseline. The only reconciliation note is repository layout: lines 491-551 sketch a single-crate tree, while `AGENTS.md` and `docs/architecture.md` define this repository as a workspace with one crate per component. The implementation preserves the documented component responsibilities and CLI surface in the workspace layout.

## Line Review

| Protocol lines | Requirement surface | Implementation evidence | Test / validation evidence | Status |
|---|---|---|---|---|
| 1-10 | Final Umbra shape: Rust client/server, REALITY-like borrowed identity, real TLS/QUIC appearance. | `crates/umbra/src/main.rs`, `crates/umbra-core/src/runtime.rs`, `crates/umbra-core/src/dispatch.rs`, `crates/umbra-transport/src/{tcp,quic}.rs`. | `cargo nextest run --workspace`; loopback tests in `crates/umbra-core/tests/e2e_loopback.rs`. | Implemented. |
| 12-39 | Table of contents covers all final components. | OpenSpec specs under `openspec/changes/implement-protocol-design/specs/*`. | `npx @fission-ai/openspec@latest validate --all --strict`. | Implemented. |
| 41-57 | Fixed decisions: auth in ClientHello before response, self-controlled TLS 1.3, canonical REALITY ECDH token. | `umbra-tls` ClientHello/handshake/server modules; `umbra-reality/src/auth.rs`; TCP auth path in `crates/umbra-core/src/runtime.rs`; QUIC auth path in `crates/umbra-core/src/quic_crypto.rs`. | `scenario_valid_reality_token_enters_local_tls_path`, `scenario_tcp_outer_sends_profile_shaped_clienthello`, `scenario_quic_network_runtime_relays_direct_stream`. | Implemented. |
| 59-78 | Threat model: encrypted-flow classifiers, active probing, TLS-in-TLS, JA3/JA4, SNI, RST, replay, timing. | Fallback dispatch in `dispatch.rs`; inner padding/Vision in `crates/umbra-inner`; fingerprint profiles in `fingerprints/chrome-latest.toml`; TCP evasion in `crates/umbra-transport/src/evasion.rs`; replay cache in `crates/umbra-reality/src/replay.rs`; timing policy in `crates/umbra-core/src/probe.rs`. | Probe, dispatch, inner, fingerprint, and replay scenarios across `crates/*/tests`. | Implemented. |
| 80-94 | Design principles table: real site forwarding, hidden auth, Chrome byte shape, ECDH auth, Vision, padding/mux, replay, PQ, no negotiation. | Component crates: `umbra-reality`, `umbra-tls`, `umbra-inner`, `umbra-crypto`, `umbra-fingerprint`, `umbra-core`. | `cargo xtask coverage` line coverage 90.14%; vector and scenario tests. | Implemented. |
| 96-122 | Layered architecture: SOCKS -> inner -> TLS/REALITY/fingerprint -> TCP/QUIC, server dispatch and fallback. | `crates/umbra-core/src/{socks,runtime,dispatch,relay}.rs`; `crates/umbra-testkit`. | `scenario_socks_request_opens_selected_tcp_mux_stream`, `e2e_authenticated_mux_roundtrip`, `e2e_unauthenticated_falls_back_to_dest`. | Implemented. |
| 124-193 | Component TLS 1.3 stack: Chrome-shaped ClientHello, GREASE, key schedule, records, client/server state machines, cert callback. | `crates/umbra-tls/src/{clienthello,handshake,server,records,keyschedule,parse,quic}.rs`; `crates/umbra-fingerprint/src/*`. | `crates/umbra-tls/tests/tls13_stack.rs`, RFC 8448 test, arbitrary-bytes parser test, fingerprint tests. | Implemented. |
| 195-227 | REALITY auth: static server key, short ids, timestamp, HELLO0 AAD, AES-128-GCM session_id, replay cache. | `crates/umbra-reality/src/auth.rs`; `crates/umbra-reality/src/replay.rs`; server dispatch calls in `crates/umbra-core/src/dispatch.rs`. | `crates/umbra-reality/tests/reality_auth.rs`; new replay cache helper test. | Implemented. |
| 229-248 | Server dispatch before response, complete ClientHello read, authenticated local handshake, failed auth exact dest forwarding, no throttled fallback. | `crates/umbra-core/src/dispatch.rs`, `crates/umbra-core/src/prefixed.rs`, `crates/umbra-core/src/relay.rs`, `crates/umbra-core/src/runtime.rs`. | `crates/umbra-core/tests/server_dispatch.rs`; `scenario_dispatch_fallback_relays_after_forwarded_clienthello`; probe policy tests. | Implemented. |
| 250-266 | Destination prebuild and mirroring of TLS/leaf/OCSP/SCT/RTT profile. | `crates/umbra-reality/src/prebuild.rs`; refresh orchestration in `crates/umbra-core/src/runtime.rs`. | `crates/umbra-reality/tests/dest_prebuild.rs`; prebuild parser/probe tests. | Implemented. |
| 268-289 | Forged temporary trusted certificate, cert MAC extension, ML-DSA extension, client verifier classes. | `crates/umbra-reality/src/cert.rs`; cert verifier integration in `crates/umbra-tls` and `crates/umbra-core`. | `crates/umbra-reality/tests/cert_forge.rs`; TLS certificate callback tests. | Implemented. |
| 291-344 | Inner transport: mux frame format, flow control, padding scheme, Vision solo splice, RealSite spider. | `crates/umbra-proto/src/frame.rs`; `crates/umbra-inner/src/{mux,padding,vision,spider,address}.rs`. | `crates/umbra-inner/tests/inner_transport.rs`; proto wire tests; padding proptests. | Implemented. |
| 346-373 | QUIC/HTTP-3 outer: Initial CRYPTO auth carrier, Chrome h3 profile, empty legacy_session_id, GREASE parameter/SCID split, UDP fallback, authenticated streams, quinn crypto provider replacement. | `crates/umbra-transport/src/quic.rs`; `crates/umbra-tls/src/quic.rs`; `crates/umbra-core/src/quic_crypto.rs`; `crates/umbra-core/src/runtime.rs`. | `scenario_quic_network_runtime_relays_direct_stream`; `scenario_server_runtime_quic_fallback_relays_datagram_flow`; QUIC packet/key/retry/prefetch tests. | Implemented. |
| 375-395 | TCP evasion: conservative segmentation, fallback to ordinary send, TCP path equivalent to QUIC for RST resistance. | `crates/umbra-transport/src/evasion.rs`; `crates/umbra-transport/src/tcp.rs`; client runtime selection. | `scenario_clienthello_is_split_and_fallback_preserves_bytes`; `scenario_evasion_off_writes_once`; config tests. | Implemented. |
| 397-413 | PQ: X25519MLKEM768 key share support, ML-KEM wrapper, ML-DSA-65 certificate extension and verification. | `crates/umbra-crypto/src/{mlkem,mldsa}.rs`; `crates/umbra-tls/src/clienthello.rs`; `crates/umbra-reality/src/cert.rs`. | `crates/umbra-crypto/tests/pq_primitives.rs`; cert forge tests. | Implemented. |
| 415-432 | Fingerprint management: data profile, Chrome TLS/QUIC ordering, JA3/JA4 self-check. | `fingerprints/chrome-latest.toml`; `crates/umbra-fingerprint/src/{profile,ja3,grease}.rs`; profile use in TLS and QUIC builders. | `crates/umbra-fingerprint/tests/fingerprint_profiles.rs`; OpenSpec fingerprint scenarios. | Implemented. |
| 434-444 | Probe resistance: timing alignment, useless record policy, fallback not rate-limited, RealSite spider, TCP/QUIC switching. | `crates/umbra-core/src/probe.rs`; `crates/umbra-inner/src/spider.rs`; `crates/umbra-core/src/runtime.rs`; `crates/umbra-transport`. | `scenario_auth_path_waits_for_profile_rtt`; `scenario_useless_flood_follows_fallback_policy`; spider tests. | Implemented. |
| 446-455 | Cryptography table: X25519, ML-KEM, HKDF, AES-GCM, HMAC, ML-DSA, TLS AEAD, OS RNG, no second business AEAD. | `crates/umbra-crypto/src/*`; `crates/umbra-reality/src/auth.rs`; `crates/umbra-tls/src/records.rs`. | RFC 8439/8448/5869 tests; AEAD/HMAC/PQ tests. | Implemented. |
| 457-489 | Server and client config schema. | `crates/umbra-core/src/config.rs`; `crates/umbra/src/main.rs`; inline TOML fixtures in config and CLI tests. | `scenario_complete_server_config_loads`, `scenario_complete_client_config_loads`, CLI override tests. | Implemented. |
| 491-551 | Rust module map and key signatures. | Implemented in workspace crates per `AGENTS.md`/`docs/architecture.md`: `umbra-tls`, `umbra-reality`, `umbra-inner`, `umbra-transport`, `umbra-core`, `umbra` CLI. Function responsibilities match the documented map. | `cargo build --workspace`; OpenSpec strict validation. | Implemented with repository-layout reconciliation. |
| 552-580 | Dependency list and build constraints, no BoringSSL/rustls main handshake, quinn allowed with custom crypto provider. | Root `Cargo.toml`; custom TLS in `umbra-tls`; quinn integration via `crates/umbra-core/src/quic_crypto.rs`; rustls only for destination probing / QUIC packet primitives, not the main TCP TLS handshake. | `cargo clippy --workspace --all-targets -- -D warnings`; `cargo deny check` exit 0. | Implemented. |
| 582-593 | Tests: auth tamper/replay, cert/PQ, RFC vectors, fingerprint, handshake, probing, TLS-in-TLS, timing, RST/QUIC, real env guidance. | Unit, integration, proptest, fuzz targets, and testkit under `crates/*/tests` and `fuzz/`. | `cargo nextest run --workspace --run-ignored all` 204 passed; `cargo xtask coverage` 90.14%. | Implemented. |
| 595-606 | Deployment and operations: dest criteria, TCP+UDP 443, secret handling, no user target/payload logs, backup paths. | Config schema; no runtime logging macros for targets/payloads; keygen explicit output only; transport selection. | `rg` log macro scan found only `umbra keygen` `println!`. | Implemented. |
| 608-616 | Security and compliance: secret management, constant-time, bounded replay, fixed dest, lockfile/audit/deny. | Redacted Debug in configs/secrets; `subtle` comparisons; replay capacity/TTL; fixed config dest; `Cargo.lock`; `deny.toml`. | Replay tests, constant-time tests, `cargo deny check` exit 0. | Implemented. |
| 618-648 | Appendix byte layouts: REALITY token, cert binding, mux frame, target address. | `umbra-reality/src/auth.rs`; `umbra-reality/src/cert.rs`; `umbra-proto/src/{frame,addr}.rs`. | Wire proto tests, reality auth tests, cert tests. | Implemented. |
| 650-681 | Server and client state machines. | `crates/umbra-core/src/{runtime,dispatch}.rs`; `crates/umbra-tls/src/{handshake,server}.rs`; `crates/umbra-inner`; `crates/umbra-transport`. | End-to-end loopback and QUIC runtime tests. | Implemented. |
| 685-700 | References and drift-sensitive values must be maintained by capture/spec updates. | Fingerprint data is externalized; Rust toolchain pinned to 1.96.1; OpenSpec change retains follow-up validation hooks. | Version scan for 1.92/1.90 residue has no matches; OpenSpec validation passes. | Implemented. |

## CLI Optional Config Flag Review

All optional server/client config fields from section 16 are exposed as CLI flags:

- Server: `--config`, `--listen`, `--udp-listen`, `--private-key`, `--short-ids`, `--dest`, `--server-names`, `--max-time-diff`, `--mldsa-seed`, `--prebuild`, `--padding-scheme`, `--tcp-evasion`.
- Client: `--config`, `--server`, `--transport`, `--public-key`, `--short-id`, `--server-name`, `--fingerprint`, `--mldsa-verify`, `--spider-path`, `--socks-listen`, `--mux`, `--padding-scheme`, `--tcp-evasion`.

Verified with:

- `target/debug/umbra --help`
- `target/debug/umbra server --help`
- `target/debug/umbra client --help`

## Validation Evidence

- `cargo build --workspace`: passed.
- `cargo fmt --all --check`: passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo nextest run --workspace --run-ignored all`: 204 passed.
- `cargo xtask coverage`: 204 passed, line coverage 90.14%.
- `cargo deny check`: exit 0; warnings remain for duplicate transitive crates and cargo-deny workspace dependency reporting, but advisories/bans/licenses/sources are OK.
- `npx @fission-ai/openspec@latest validate --all --strict`: 2 passed, 0 failed.
- `rg -n "1\\.92|1\\.92\\.0|rust-version = \"1\\.90|MSRV=1\\.90|MSRV = 1\\.90" .`: no matches.
- Runtime log macro scan found only keygen output: `crates/umbra/src/main.rs` prints generated key material by explicit `umbra keygen` command.

## Review Result

No protocol-behavior divergence remains against `docs/protocol-design.md`. The repository-layout wording in lines 491-551 is implemented through the workspace crate map required by `AGENTS.md` and `docs/architecture.md`, while keeping the documented component boundaries and function responsibilities.
