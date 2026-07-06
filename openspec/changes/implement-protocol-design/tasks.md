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
