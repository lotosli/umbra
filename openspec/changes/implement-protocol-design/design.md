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

## Review Remediation Design — Approved For Implementation

The user approved this follow-up for implementation on 2026-09-12; it supersedes conflicting original assumptions in the preceding historical design context. Previously checked tasks do not establish completion of this revision. The exact Vision wire amendment still requires the separate design and approval step in task 13.3, and permission or CI-gate changes are not authorized.

### Scope And Evidence

Repair confirmed correctness and security defects and make the reviewed functional gaps explicit. Dynamic reproductions exist for cancelled partial mux reads, DATA lost during a send-credit wait, malformed certificate-compression bytes, empty ECH payload, a replay accepted after premature eviction, TOML diagnostic disclosure, and record-header-dependent HELLO0. The remaining findings are supported by code-path analysis; their regression tests must establish observable behavior before claiming a runtime fix.

Do not revive withdrawn claims about identical GREASE extensions, sequence-number wraparound, absent QUIC Initial reassembly, fixed production ServerProfile values, an eight-byte IPv4 target preface, plaintext HTTP user agents, or a universal ClientHello length. An unverified low-order X25519 hypothesis is not silently added to this approved-scope candidate.

### Authentication And Cryptographic Boundaries

- In `umbra-core/src/quic_crypto.rs`, consume the verified peer classification before publishing application keys, readiness, or Connected state. UmbraTrusted is the sole proxy authorization. RealSite and Invalid terminate proxy establishment; no target prefix, UDP envelope, SOCKS success, business data, or automatic TCP downgrade is permitted.
- Ordinary certificates use maintained chain/name/time verification plus the negotiated TLS CertificateVerify check. A privately bound Umbra certificate still requires both MAC and ML-DSA bindings and proof of possession, not a public CA signature. Keep trust classification separate from TLS parsing and from proxy authorization. Use injected test roots only in local tests.
- In shared TLS key-schedule APIs, name and carry the server-Finished and client-Finished transcript hashes separately. Derive application traffic/exporter secrets at the former and resumption secrets at the latter in both TCP roles and QUIC. Expectations come from published vectors or an independent implementation, not a second invocation of the function under test.
- TCP HELLO0 is reconstructed from the complete bare handshake, with the session id zeroed. TLS record headers never enter this AAD. QUIC retains its existing carrier-specific canonicalization. Both endpoints change together; never retry an old nonstandard derivation after authentication failure.
- Replay entries carry their inclusive token-validity deadline, computed with checked arithmetic from timestamp plus skew. Cleanup removes only expired entries. Capacity exhaustion does not evict a still-valid entry: new local authentication fails into ordinary destination forwarding. Timestamp validation remains mandatory even after cache cleanup; check-and-insert is atomic across concurrent authentication.
- Configuration parse errors retain only safe categories, line/column, and allowlisted field names. Do not retain TOML source snippets or the unsanitized parser error in a nested source chain. Signing DER, record keys, binding secrets, sensitive KDF output, and memory key logs use zeroizing ownership and redacted Debug. Test explicit zeroization and formatting, never read freed memory.

### Persistent Mux Driver And Connection Reuse

- In `umbra-inner/src/mux.rs`, a session-owned reader retains incremental frame state; a serialized writer owns a frame once transmission begins. Stream handles submit commands and receive their own events rather than recursively reading the transport while opening or waiting for credit. Cancelling a caller does not cancel a partially emitted frame.
- Reserve receive capacity before advertising credit. Queueing decoded DATA is not consumption; replenish credit only after the application consumes it. Bound per-stream queues, total reserved bytes, pending opens, and active streams. Preserve control progress and fair DATA scheduling; never hold a shared I/O lock while waiting for stream credit.
- FIN follows preceding DATA and closes one direction only. RST terminates that stream's waiters. Reclaim state after both directions close or reset; zero/overflowing window updates and unknown-stream control frames do not allocate new stream state.
- In `umbra-core/src/runtime.rs`, coordinate one reusable healthy TCP mux or QUIC connection per validated client runtime/configuration. Concurrent first requests share establishment. The server dispatches each target stream independently; TCP mux SYN_ACK follows successful target connection. A stalled target must not block another stream's open.
- TCP solo connections remain exclusive. Stream-zero UDP associations remain on dedicated outers until a separately specified association-id format exists. Broken outers fail their existing streams without replaying payload; only later requests establish replacements. Runtime shutdown joins owned driver, relay, and timer tasks.

### Dispatch And QUIC Ownership

- Replace classification-local read buffers in `umbra-reality/src/dispatch.rs` with an owned prefix and explicit authenticated/forward outcomes. Enforce one finite classification deadline and bounded byte/record budgets. Preserve even a partially read header; limits, EOF, or incomplete classification hand that prefix and stream to transparent fallback. Do not allocate a declared oversized body before selecting fallback.
- Request EOF forwards a half-close while preserving the reverse response path. Reset sockets or an unavailable destination can terminate transport; do not describe these failures as successful forwarding or fabricate a protocol reply.
- Supervise UDP independently from the main TCP accept/join select. Exactly one task reads the physical UDP socket and routes each peer/CID to an owned classification, authenticated, or fallback flow. Quinn adapters receive virtual per-flow datagram I/O; they do not compete on cloned physical socket receivers. Keep CID ownership tied to the original peer; migration and NAT rebinding are out of scope.
- Retain existing Initial reassembly, overlap/retransmission checks, and original fallback datagram boundaries. A classification deadline or byte budget moves the existing flow to fallback, not to a second owner. Queues and classification storage are finite; no per-flow filtering loop may consume another client's datagram. Ordinary UDP/socket loss is not a delivery guarantee, and this change does not authorize new Umbra-specific fallback rate limits or early-close policy.
- QUIC UDP stream envelopes retain parser progress across competing target replies. Preserve exact-once target delivery and bounded length checks through cancellation and EOF.

### TLS Interoperability And Fingerprint Fidelity

- Correct RFC 8879 uint8 algorithm-list length and support advertised Brotli certificate decoding with compressed/output limits. Hash CompressedCertificate exactly as required by the handshake transcript, not a fabricated decompressed replacement message.
- Replace fixed two-record server-flight reads with bounded handshake reassembly. Validate ServerHello legacy fields, offered selections, echo, and unique extensions. Explicitly reject unsupported HelloRetryRequest. Verify advertised TLS-1.3-usable signatures through maintained library algorithms; TLS-1.2-only advertisements do not become valid TLS 1.3 CertificateVerify choices.
- Keep the custom TLS architecture. Add independent standard-peer loopback application-data tests to expose symmetric client/server mistakes. Any added dependency uses the root workspace catalog and receives license/size review; do not silently replace the primary handshake engine.
- ECH GREASE uses a valid nonempty structure and profile-supported randomized fields, with injectable randomness for tests. This is not implementation of encrypted SNI. Padding follows actual captured extension placement, not a forced historical byte count.
- Compare actual production builder output to reviewed Chrome fixtures with explicit masks for random/caller-controlled fields. Preserve capture version and provenance, and reject a malformed extension even when its JA3 is unchanged. If available evidence lacks full extension bytes or QUIC capture, report that gap; neither synthesized evidence nor weakened checks may satisfy it.
- Replace the existing custom JA4-style output with standard JA4 according to a pinned authoritative definition, with independent fixtures for transport context, GREASE exclusion, normalization, sorting, and hash formatting. Update profile expectations from that reference, not from self-comparison. A conformant identifier still does not replace full extension-payload evidence.

### Effective Runtime Configuration

- A validated startup DestProfile is a prerequisite for serving traffic in both prebuild modes. `prebuild = true` schedules periodic replacement; `false` disables that refresh, not the startup probe. First probe failure fails startup; refresh failure retains the previous valid profile. This meaning must replace the ambiguous protocol/configuration description before implementation.
- Isolate synchronous probe work from async executor threads or use async transport. Bound concurrent probes with ownership that persists until underlying work actually finishes, including a blocking operation that outlives a caller timeout. Apply a single overall deadline across DNS, connect, TLS, and metadata processing; a cancelled wrapper alone does not cancel a blocking task.
- Measure destination latency from starting the fallback-equivalent connection attempt through receiving its first TLS response. Measure local preparation from the corresponding post-classification decision. Delay by the nonnegative remaining interval; HTTP response latency is separate. No fixed indistinguishability claim follows from this best-effort delay.
- Reject unsupported Geneva policies during configuration validation; retain only working `off` and ordered-write `segment` behavior. Ordinary-send fallback is legal only before any bytes were emitted. Do not add privileged packet manipulation in this revision.
- Reject a configured unauthenticated early-close action rather than silently ignoring it. Preserve byte/record limits as transitions to destination forwarding. TCP RealSite spider sends only a supported negotiated HTTP protocol after full ordinary-certificate verification; QUIC RealSite fails locally with no HTTP/3 claim.

### Vision Protocol Amendment And Production Integration

Merely connecting the current helper is insufficient: it does not establish record boundaries or transfer ownership out of outer TLS. The revised goal is real solo-mode handoff, not renaming ordinary TLS relay to splice.

- Before Vision implementation, amend and review the exact capability negotiation, versioned payload/padding envelope, directional switch/ack messages, byte-count semantics, hard size limits, and state-transition table in `docs/protocol-design.md`. Include simultaneous switch, acknowledgement loss, EOF, and cancellation cases with golden wire vectors. This wire-format approval is a separate prerequisite, not delegated to coding-time guesses.
- Keep the target preface first. Capability negotiation must be unambiguous inside authenticated outer TLS and must not consume target application bytes as control messages. Unsupported capabilities keep payload inside outer TLS; there is no implicit raw-mode fallback.
- Reassemble inner TLS records and handshake messages incrementally with bounded storage. A valid inner TLS 1.3 negotiation followed by bidirectional protected records is an observable eligibility condition, not verification of the encrypted Finished. A lone `0x17`, malformed header, TLS 1.2 stream, or stalled prefix never authorizes raw mode.
- Shaping uses length-delimited payload and removable padding in deliberately sized outer TLS records. It does not rely on TCP packet boundaries or splitting a write call. The receiving side strips padding exactly once without changing target bytes.
- A controllable TLS I/O owner drains pending ciphertext and exchanges authenticated switch boundaries before transferring the raw TCP halves and all read-ahead bytes. Each direction tracks its boundary independently; the state machine must avoid simultaneous-switch deadlock. If safe agreement is absent, remain inside outer TLS. After raw handoff, failure closes rather than guessing how to restore outer TLS framing.
- Exercise the actual client/server solo runtime with a local inner TLS peer. Assert exact target bytes, preserved half-close, and raw post-boundary wire bytes without outer encryption. Keep mux and QUIC out of this raw TCP handoff path.

### Implementation Order And Completion Gates

Approve the revised scope first, then amend contradictory protocol text before each affected implementation. Deliver authentication/secret fixes and TLS correctness before shared runtime ownership; build the mux driver before pooling, and UDP demultiplexing before multi-client QUIC tests. Vision implementation additionally waits for the exact wire amendment approval. These dependencies do not require postponing independently approved safety fixes until all functional work is finished.

Every revised scenario must have an assertion-bearing regression test. Use controlled clocks, fragmented/cancelled local I/O, concurrent loopback clients, independent TLS peers, and non-secret fixtures. Run strict fmt/clippy, nextest including ignored loopback tests, line coverage >= 90%, cargo-deny, the existing fingerprint check, and strict OpenSpec validation. Update the existing protocol review to distinguish implementation evidence from missing capture or interoperability evidence. No CI weakening, secrets, publishing, commits, or live infrastructure testing is part of this change.
