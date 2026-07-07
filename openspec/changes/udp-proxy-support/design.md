## Context

Umbra currently supports TCP-like client traffic over authenticated TCP/TLS mux or QUIC streams. The QUIC listener uses UDP on the outer network and unauthenticated QUIC Initial datagrams are forwarded to the configured real destination for probe resistance, but the local SOCKS client rejects UDP ASSOCIATE and the authenticated inner protocol has no datagram envelope. Supporting UDP proxying therefore crosses SOCKS parsing, protocol framing, client runtime, server runtime, and both outer transports.

The implementation must preserve existing TCP stream behavior, REALITY authentication, QUIC bad-auth fallback, fingerprint constraints, and the 90% coverage gate. No new mandatory configuration or new external dependency is required.

## Goals / Non-Goals

**Goals:**
- Accept SOCKS5 UDP ASSOCIATE after no-auth negotiation and return a bound local UDP relay address.
- Parse and emit RFC 1928 UDP request headers for IPv4, domain, and IPv6 targets with strict length validation and complete SOCKS UDP fragmentation/reassembly support.
- Add an authenticated UDP datagram envelope that carries `TargetAddr` plus payload bytes with bounded length checks.
- Carry proxied UDP datagrams over TCP outer transport by extending the existing mux frame layer with a UDP datagram event.
- Carry proxied UDP datagrams over QUIC outer transport using an authenticated QUIC bidirectional association stream with length-delimited UDP datagram envelopes while explicitly avoiding extra QUIC DATAGRAM transport parameters.
- Relay target UDP replies back to the original SOCKS UDP peer while bounding target socket/session state and idle lifetime.

**Non-Goals:**
- Raw IP, ICMP, transparent TUN/TAP, and multicast forwarding are out of scope.
- Unauthenticated outer traffic behavior is unchanged: failed TCP authentication is forwarded as TCP and failed QUIC authentication is forwarded as UDP to the configured real destination.
- Adding QUIC DATAGRAM transport parameters for proxy UDP is out of scope; fingerprint fidelity and complete UDP payload sizing take priority over datagram micro-optimization.

## Decisions

1. **Add a protocol-level UDP datagram envelope instead of overloading TCP target streams.**
   - The envelope is `TargetAddr` encoding followed by UDP payload bytes inside an already length-delimited carrier: a mux frame payload for TCP outer, or a `u16` length-prefixed record on a QUIC association stream.
   - Rationale: `TargetAddr::decode_from` already gives the address boundary, and the carrier supplies total length, so the format stays compact and parser-safe.
   - Alternative considered: add protocol markers to `TargetAddr`; rejected because it would make every existing TCP target parse protocol-aware.

2. **Implement SOCKS UDP fragmentation at the SOCKS boundary.**
   - `FRAG = 0` is a standalone datagram. `FRAG & 0x7f` is the fragment position for `1..127`, and `FRAG & 0x80 != 0` marks the end of the sequence.
   - The client maintains bounded reassembly queues keyed by local UDP peer and target address, with a timer no shorter than 5 seconds. A timer expiry or a fragment whose position is lower than the highest processed position resets that queue.
   - Reassembled payloads are forwarded as one authenticated Umbra UDP envelope. Replies from targets can be emitted as standalone SOCKS UDP datagrams when they fit the local UDP send limit or fragmented with the same RFC 1928 FRAG semantics when configured limits require fragmentation.
   - Rationale: fragmentation is a SOCKS wire concern, not an Umbra inner transport concern. Keeping it at the boundary prevents partial fragments from crossing the authenticated relay and limits attacker-controlled state to the local association.
   - Alternative considered: forwarding each SOCKS fragment through Umbra independently; rejected because the server target would see invalid partial application datagrams.

3. **Use one new mux command for TCP outer UDP datagrams.**
   - Add `MuxCommand::UdpDatagram` with reserved `stream_id = 0`.
   - The client sends UDP datagrams from the local UDP relay as independent mux events; the server returns replies as the same event type.
   - Rationale: this preserves existing mux stream IDs and flow-control behavior for TCP streams while allowing unordered datagram-like payloads.
   - Alternative considered: open one mux stream per UDP target; rejected because stream EOF semantics and flow control do not match recurring datagrams.

4. **Use a fingerprint-safe QUIC carrier for proxied UDP.**
   - The client opens a bidirectional QUIC stream whose first byte is a dedicated UDP association marker, then exchanges length-delimited UDP envelopes.
   - Quinn DATAGRAM send/receive buffers are explicitly disabled so the runtime does not advertise `max_datagram_frame_size` for this capability.
   - Rationale: this preserves the project rule that QUIC fingerprint fidelity outranks performance tuning while still providing correct full-size UDP proxy behavior.
   - Alternative considered: using QUIC DATAGRAM; rejected because adding `max_datagram_frame_size` when Chrome would not advertise it breaks the fingerprint contract, and QUIC DATAGRAM payload size is path-MTU limited rather than full SOCKS UDP sized.

5. **Keep the SOCKS TCP control connection alive for the UDP association lifetime.**
   - The client binds a local UDP socket, returns its address in the SOCKS reply, and relays datagrams until the TCP control connection closes or the association idles out.
   - Rationale: this matches SOCKS5 association lifetime semantics and gives a clear shutdown signal without adding config.

6. **Bound UDP runtime state.**
   - Each association tracks a limited number of target UDP sockets, ignores datagrams from unexpected local SOCKS UDP peers after the first packet, and expires on existing session idle timeouts.
   - Rationale: UDP is easy to abuse for memory and socket exhaustion; limits must be enforced at the relay boundary.

## Risks / Trade-offs

- [QUIC stream-framed UDP has head-of-line blocking within the association stream] -> Accept the trade-off because correctness, full SOCKS UDP payload support, and fingerprint fidelity are higher priority.
- [UDP target maps can grow under malicious local clients] -> Enforce maximum targets per association, maximum datagram size, and idle shutdown.
- [SOCKS UDP fragmentation state can be abused] -> Bound the number of reassembly queues and fragments, reset queues exactly as RFC 1928 requires, and expire incomplete queues after the reassembly timer.
- [Binding the reply address on wildcard SOCKS listeners can be ambiguous] -> Prefer the configured SOCKS listener IP when concrete, otherwise use loopback for local clients and document the behavior in tests.
- [Changing UDP ASSOCIATE from rejected to supported invalidates existing tests] -> Update the OpenSpec scenario and tests so unsupported-command coverage remains for truly unsupported commands such as BIND.

## Migration Plan

1. Add and validate protocol parsers/encoders for SOCKS UDP and Umbra UDP envelopes.
2. Extend mux and QUIC authenticated carriers without changing existing TCP stream wire behavior.
3. Update client/server runtimes to route UDP associations and target sockets.
4. Replace the old UDP ASSOCIATE rejection test with UDP association success and malformed datagram tests; keep unsupported-command tests for SOCKS BIND.
5. Run OpenSpec validation, Rust 1.96.1 fmt/clippy/tests, coverage, and local CI before pushing the branch for remote testing.
