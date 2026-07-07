## 1. Protocol and Parser Foundations

- [x] 1.1 Add Umbra UDP envelope encode/decode types in `umbra-proto` with target address parsing, payload length limits, and unit tests.
- [x] 1.2 Add SOCKS UDP request/reply encode/decode helpers in `umbra-core::socks` for IPv4, domain, and IPv6 targets.
- [x] 1.3 Implement RFC 1928 SOCKS UDP fragmentation parsing, reassembly queues, reset rules, response fragmentation, and bounded state limits.
- [x] 1.4 Add proptest coverage for UDP envelope and SOCKS UDP parser round trips, malformed inputs, and fragmentation ordering.
- [x] 1.5 Add or update fuzz targets for SOCKS UDP datagram and Umbra UDP envelope parsers.

## 2. TCP Outer UDP Carrier

- [x] 2.1 Extend mux commands/events with a reserved UDP datagram frame that uses `stream_id = 0` and preserves existing TCP stream behavior.
- [x] 2.2 Implement client-side TCP outer UDP association relay from the bound SOCKS UDP socket to mux UDP datagram frames.
- [x] 2.3 Implement server-side TCP outer UDP target socket relay with bounded per-association target maps and reply routing.
- [x] 2.4 Update TCP CONNECT/mux/Vision tests to prove existing TCP stream behavior remains compatible.

## 3. QUIC Outer UDP Carrier

- [x] 3.1 Add QUIC UDP association stream framing that preserves the selected Chrome QUIC fingerprint.
- [x] 3.2 Explicitly disable QUIC DATAGRAM buffers for UDP proxy sessions so no DATAGRAM transport parameter is added.
- [x] 3.3 Implement client-side QUIC outer UDP association relay from the SOCKS UDP socket to the selected QUIC carrier.
- [x] 3.4 Implement server-side QUIC outer UDP target socket relay with bounded target maps and reply routing.

## 4. SOCKS Runtime and CLI Behavior

- [x] 4.1 Change SOCKS request handling so UDP ASSOCIATE succeeds and unsupported commands such as BIND still return unsupported-command replies.
- [x] 4.2 Keep each SOCKS UDP TCP control connection alive for association lifetime and shut down UDP/outer state when the control connection closes or idles.
- [x] 4.3 Return a usable UDP bound address for loopback and wildcard `socks_listen` configurations.
- [x] 4.4 Ensure logs and errors do not expose UDP target addresses, payloads, keys, session ids, or authentication tokens.

## 5. Tests and Coverage >= 90%

- [x] 5.1 Add scenario tests for SOCKS UDP associate success, control close cleanup, malformed UDP request rejection, and unsupported BIND rejection.
- [x] 5.2 Add scenario tests for SOCKS UDP fragmentation reassembly, timer reset, lower-fragment reset, state limits, and large reply fragmentation.
- [x] 5.3 Add loopback tests proving UDP request/reply relay over TCP outer transport.
- [x] 5.4 Add loopback tests proving UDP request/reply relay over QUIC outer transport and QUIC fingerprint-preserving carrier selection.
- [x] 5.5 Run `rustup run 1.96.1 cargo fmt --all`, `rustup run 1.96.1 cargo clippy --workspace --all-targets -- -D warnings`, `rustup run 1.96.1 cargo nextest run --workspace`, `rustup run 1.96.1 cargo xtask coverage`, and `npx @fission-ai/openspec@latest validate --all --strict`; fix all failures.
