## 1. Prerequisites

- [x] 1.1 Apply or otherwise complete the active `crypto-primitives` change and keep its tests green.
- [x] 1.2 Confirm workspace dependencies are declared only through root `[workspace.dependencies]`.
- [x] 1.3 Replace scaffold comments only in crates touched by an approved task.

## 2. Wire Protocol And PQ

- [x] 2.1 Implement target address encoding/decoding and protocol errors in `umbra-proto`.
- [x] 2.2 Implement mux frame encode/decode constants and validation in `umbra-proto`.
- [x] 2.3 Implement ML-KEM-768 wrapper APIs in `umbra-crypto`.
- [x] 2.4 Implement ML-DSA-65 wrapper APIs in `umbra-crypto`.
- [x] 2.5 Add zeroizing wrappers and redacted debug output for PQ secrets.

## 3. Fingerprint Profiles

- [x] 3.1 Add fingerprint data files for `chrome-latest` TLS and QUIC profiles.
- [x] 3.2 Implement profile loading, validation, and error handling in `umbra-fingerprint`.
- [x] 3.3 Implement JA3/JA4 calculation over generated ClientHello bytes.
- [x] 3.4 Add QUIC transport parameter ordering and GREASE profile support.

## 4. TLS 1.3 Stack

- [x] 4.1 Implement ClientHello builder driven by `FingerprintProfile`.
- [x] 4.2 Implement safe ClientHello parsing for SNI, session id, classic X25519 key_share, and QUIC carrier data.
- [x] 4.3 Implement RFC 8446 key schedule helpers and RFC 8448 vector tests.
- [x] 4.4 Implement TLS 1.3 record seal/open for AES-GCM and ChaCha20-Poly1305.
- [x] 4.5 Implement minimal client handshake state machine with certificate verification callback.
- [x] 4.6 Implement minimal server handshake state machine that accepts prefetched ClientHello bytes and echoes session id.

## 5. REALITY Authentication And Certificates

- [x] 5.1 Implement `HELLO0` construction and REALITY session id seal/open.
- [x] 5.2 Implement version, timestamp, short id, SNI policy, and bounded replay validation.
- [x] 5.3 Implement replay cache capacity, TTL cleanup, and constant-time comparisons where secrets are involved.
- [x] 5.4 Implement forged certificate generation from `DestProfile`.
- [x] 5.5 Implement cert MAC private extension and verifier classification.
- [x] 5.6 Implement ML-DSA certificate extension signing and verification.

## 6. Destination Prebuild And Dispatch

- [x] 6.1 Implement `DestProfile` model and destination probe collection.
- [x] 6.2 Implement startup and periodic profile refresh with last-known-good retention.
- [x] 6.3 Implement complete ClientHello read-before-response behavior.
- [x] 6.4 Implement authenticated dispatch into forged TLS handshake.
- [x] 6.5 Implement fallback forwarding to dest for all unauthenticated and malformed cases.
- [x] 6.6 Implement `PrefixedStream` and bidirectional relay helpers.

## 7. Inner Transport

- [x] 7.1 Implement client and server mux sessions with SYN, SYN_ACK, DATA, WINDOW_UPDATE, FIN, RST, PADDING, and PING.
- [x] 7.2 Implement per-stream flow control and stream close semantics.
- [x] 7.3 Implement padding scheme parser and default adaptive padding policy.
- [x] 7.4 Integrate padding frame emission and discard behavior.
- [x] 7.5 Implement Vision solo target preface, TLS sniffing, handshake shaping, splice switching, and non-TLS relay.
- [x] 7.6 Implement RealSite spider helper for configured paths.

## 8. Transport Layer

- [x] 8.1 Implement TCP outer connect, listener, and ordinary ClientHello send path.
- [x] 8.2 Implement TCP evasion strategy parser and conservative segmentation writer.
- [x] 8.3 Implement evasion fallback to ordinary TCP sending.
- [x] 8.4 Implement QUIC fingerprint model and REALITY-over-QUIC auth carrier parsing.
- [x] 8.5 Implement QUIC dispatch fallback and authenticated stream carrying surface. (Initial parse/decrypt/auth, client first flight, bad-auth UDP fallback relay, QUIC packet/header protection, target stream prefix helpers, multi-datagram ClientHello prefetch, authenticated quinn stream relay complete)

## 9. Core Runtime

- [x] 9.1 Implement server and client config structs, TOML parsing, validation, and redacted debug output.
- [x] 9.2 Implement CLI override merge for server and client configs.
- [x] 9.3 Implement SOCKS5 no-auth handshake and CONNECT parsing.
- [x] 9.4 Implement server orchestration for TCP, UDP, dest profile, replay cache, dispatch, and shutdown. (TCP, UDP/QUIC fallback, and authenticated QUIC server stream path complete)
- [x] 9.5 Implement client orchestration for SOCKS, TCP/QUIC selection, mux/Vision selection, and relay lifecycle. (TCP mux/Vision relay and QUIC authenticated stream relay complete)
- [x] 9.6 Implement probe-resistance timing alignment, useless-record policy, and no-throttled fallback invariants.

## 10. CLI

- [x] 10.1 Replace placeholder binary with `clap` subcommands `server`, `client`, and `keygen`.
- [x] 10.2 Add `server` flags for every documented server config option.
- [x] 10.3 Add `client` flags for every documented client config option.
- [x] 10.4 Implement key generation output for X25519 and ML-DSA material using base64.
- [x] 10.5 Add CLI error handling that exits non-zero before runtime startup on validation failure.

## 11. Tests And Coverage >= 90%

- [x] 11.1 Add unit and integration tests for every `#### Scenario` in this change.
- [x] 11.2 Add proptest coverage for address parsing, mux frames, ClientHello parsing, config validation, and padding strategy parsing.
- [x] 11.3 Add fuzz targets for network byte parsers: ClientHello, mux frame, target address, and QUIC auth carrier.
- [x] 11.4 Add RFC/FIPS/vector tests for TLS key schedule, record protection, PQ wrappers, and certificate binding.
- [x] 11.5 Add loopback testkit tests for dispatch fallback, authenticated path, SOCKS-to-inner relay, and CLI config overrides.
- [x] 11.6 Run `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo nextest run --workspace`.
- [x] 11.7 Run `cargo xtask coverage` and keep line coverage >= 90% without lowering the threshold.
- [x] 11.8 Run `cargo deny check` and OpenSpec strict validation.

## 12. Protocol Document Review

- [x] 12.1 Perform a line-by-line implementation review against `docs/protocol-design.md`.
- [x] 12.2 Record every protocol-design requirement as implemented, intentionally pending, or requiring a protocol/OpenSpec amendment.
- [x] 12.3 Fix any code behavior that diverges from `docs/protocol-design.md` before marking implementation complete.
- [x] 12.4 Confirm all optional config fields from section 16 are exposed as CLI flags.
- [x] 12.5 Confirm no customer/user-visible logs reveal private keys, short ids, session ids, targets, or payload bytes.

## 13. Review Remediation Approval And Protocol Baseline

Sections 1–12 are historical implementation records. Their checked state does not certify the revised requirements below. The user approved implementation of this revision on 2026-09-12. The exact Vision wire amendment retains the separate approval prerequisite in 13.3; specification preparation is not a completed fix.

- [x] 13.1 Obtain human approval of the revised proposal, design, and scenarios, including paired-endpoint upgrades, prebuild semantics, unsupported Geneva rejection, and the Vision protocol change.
- [x] 13.2 Amend `docs/protocol-design.md` to match approved HELLO0, TLS secret boundaries, replay retention, RealSite authorization, probing/timing, fallback, and implemented sending-policy semantics before changing the corresponding code.
- [ ] 13.3 Define and approve the exact Vision capability, envelope, directional switch/ack wire layouts, limits, state transitions, simultaneous-switch handling, and test vectors before implementing Vision framing or splice.
- [x] 13.4 Map the verified findings and every revised scenario to a regression test; retain withdrawn review claims as exclusions rather than inventing fixes for them.

## 14. Authentication, TLS Secrets, And Secret Handling

- [x] 14.1 Gate QUIC application readiness and key release on UmbraTrusted; test valid RealSite and Invalid peers with no target, UDP, SOCKS success, or business bytes emitted.
- [x] 14.2 Replace unconditional ordinary-certificate validity with chain, hostname, time, and proof-of-possession verification on TCP and QUIC, preserving private Umbra bindings for forged certificates.
- [x] 14.3 Separate server-Finished application/exporter derivation from client-Finished resumption derivation in shared TLS, TCP client/server, and QUIC paths; add published or independently sourced vector expectations.
- [x] 14.4 Canonicalize TCP HELLO0 over the complete bare handshake and add record-reframing, mutation, and paired-endpoint authentication tests; preserve QUIC carrier canonicalization.
- [x] 14.5 Retain replay entries through token timestamp plus accepted skew, reject new authentication when valid entries fill capacity, and test inclusive boundaries, future timestamps, cleanup, and concurrent duplicate admission.
- [x] 14.6 Sanitize TOML syntax/type diagnostics and their nested Display/Debug sources; test fake private keys, seeds, short ids, and arrays through library errors and CLI stderr.
- [x] 14.7 Move owned certificate signing keys, record traffic keys, binding secrets, sensitive KDF temporaries, and probe key-log material to zeroizing storage with redacted formatting; avoid unnecessary secret copies and unsafe post-free tests.

## 15. TLS Interoperability And Fingerprint Evidence

- [x] 15.1 Correct RFC 8879 certificate-compression extension encoding and add bounded Brotli certificate decoding with correct transcript hashing and malformed/oversized input tests.
- [x] 15.2 Validate ServerHello version, compression, selected cipher/group, echoed session id, unique extensions, and explicit unsupported HelloRetryRequest behavior.
- [x] 15.3 Replace fixed-record-count handshake reads with bounded cross-record reassembly and permitted CCS handling; verify all advertised TLS-1.3-usable signatures using maintained libraries.
- [x] 15.4 Exchange bidirectional application data with an independent loopback standard TLS peer, including ordinary certificate validation, fragmented server flights, and supported alternate signature algorithms.
- [x] 15.5 Implement structured nonempty ECH GREASE and randomized profile fields using injectable fresh randomness; follow captured padding placement rather than forcing one historical ClientHello length.
- [x] 15.6 Compare production ClientHello bytes against reviewed versioned Chrome evidence with explicit normalization masks and provenance; label unavailable full-extension or QUIC evidence unverified, without weakening existing checks.
- [x] 15.7 Replace the custom JA4-style result with standards-conformant JA4 using a pinned authoritative definition and independent fixtures; cover transport context, GREASE, normalization, sorting, formatting, and stored profile expectations.

## 16. Mux Driver And Shared Connection Runtime

- [x] 16.1 Replace operation-local frame reads with a persistent session reader and serialized writer; test cancellation at every header/payload offset and during partial writes.
- [x] 16.2 Dispatch all stream and UDP events to their owners during opens and credit waits; test DATA before WINDOW_UPDATE, concurrent SYN_ACK, RST during blocked writes, and exact-once ordering.
- [x] 16.3 Enforce consumption-based receive credit, reserved bounded buffering, checked window arithmetic, stream limits, and fair progress for unrelated streams and control traffic.
- [x] 16.4 Implement directional FIN, terminal RST, unknown-stream control rejection, and stream reclamation; test delayed responses after request half-close.
- [x] 16.5 Reuse one healthy outer per compatible client configuration with coordinated concurrent establishment for TCP mux and QUIC; keep TCP solo and stream-zero UDP associations isolated.
- [x] 16.6 Serve multiple target streams concurrently; acknowledge TCP mux opens only after target connection success and isolate target failures.
- [ ] 16.7 Test idle cleanup, outer failure, future replacement connections, no automatic payload replay, and shutdown of all pending opens and owned tasks.

## 17. Dispatch, QUIC Ownership, And Framed UDP

- [x] 17.1 Retain every consumed ClientHello prefix across bounded reads, deadline expiry, oversized declarations, and EOF; transfer ownership to transparent fallback without a local pre-authentication reply.
- [x] 17.2 Supervise the UDP listener independently of TCP accept/join selection; give the physical socket one receiver and route peer/CID datagrams to owned QUIC or fallback flows.
- [x] 17.3 Preserve Initial fragment/retransmission checks and original fallback datagram boundaries; test interleaved clients, duplicate Initials, TCP activity, finite queue budgets, and graceful flow cleanup.
- [x] 17.4 Make QUIC UDP-envelope decoding resumable across competing target replies and validate size bounds with fragmentation and cancellation tests.
- [x] 17.5 Preserve TCP request half-close and reverse responses on ordinary and fallback relays; distinguish unavoidable transport failure from an Umbra-specific early close.

## 18. Effective Configuration And Production Vision

- [x] 18.1 Implement mandatory validated startup probing and prebuild-controlled periodic refresh, including explicit initial failure and last-known-good retention.
- [x] 18.2 Remove blocking probe I/O from async executor threads, enforce an overall deadline and bounded concurrency, and test slow DNS/TLS/HTTP plus timeout cleanup without external networking.
- [x] 18.3 Measure destination connection-to-first-TLS-response separately from HTTP latency, subtract comparable local preparation, and test nonnegative best-effort delay.
- [x] 18.4 Reject programmatically configured unauthenticated early-close actions and reject unimplemented Geneva policies from file/CLI before startup; test byte-preserving segmentation and no resend after partial writes without adding new configuration fields.
- [x] 18.5 Keep TCP RealSite requests compatible with negotiated HTTP protocols and prohibit proxy bytes; fail QUIC RealSite locally without downgrade or a fabricated HTTP/3 spider.
- [ ] 18.6 After 13.3 approval, implement bounded bidirectional inner TLS reassembly and authenticated Vision envelopes with removable padding and controlled outer TLS record boundaries.
- [ ] 18.7 Implement negotiated directional switch barriers, drain outer TLS output, transfer read-ahead bytes, and connect the real solo runtime to raw TCP handoff; do not treat `0x17` as verified Finished.
- [ ] 18.8 Test actual on-wire raw handoff, simultaneous/failed negotiation, coalesced switch boundaries, non-TLS and ineligible TLS fallback, half-close, cancellation, and secret cleanup.

## 19. Verification And Completion Evidence

- [ ] 19.1 Add property/fuzz regressions for changed network parsers and state transitions, including mux, fragmented ClientHello, compressed certificates, Vision envelopes, and QUIC UDP framing.
- [x] 19.2 Run `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings`.
- [x] 19.3 Run `cargo nextest run --workspace --run-ignored all` and investigate any failure or leaky-test report without suppressing it.
- [x] 19.4 Run `cargo xtask coverage`; keep measured line coverage >= 90% without lowering thresholds or excluding changed paths.
- [x] 19.5 Replace the pre-existing archived `crypto-primitives` Purpose placeholder with an accurate capability description, then run `cargo deny check`, `cargo xtask fingerprint-check`, and OpenSpec `validate --all --strict`; distinguish passing available checks from missing capture evidence.
- [ ] 19.6 Update the existing protocol review and user-facing configuration/support descriptions with actual verified behavior, paired-endpoint migration, and remaining evidence gaps; do not mark unsupported raw Geneva or unmeasured fingerprint parity complete.
- [x] 19.7 Review diffs for secrets, unintended configuration/CI changes, and dependency graph violations; report fixes, exact verification commands/results, and any uncompleted tasks without committing or publishing unless requested.
