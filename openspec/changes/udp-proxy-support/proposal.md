## Why

Umbra already supports QUIC as an outer transport, but client applications still cannot proxy UDP traffic because SOCKS5 UDP ASSOCIATE is rejected and the authenticated inner protocol only models TCP-like byte streams. Full UDP proxy support is needed so DNS, QUIC-based applications, games, and other datagram workloads can use Umbra without falling back to a separate proxy.

## What Changes

- Add SOCKS5 UDP ASSOCIATE support on the client listener, including a bound local UDP relay address, RFC 1928 UDP request parsing, and full SOCKS UDP fragmentation/reassembly.
- Add an authenticated inner UDP datagram envelope that carries target address, payload bytes, and bounded session state without changing existing TCP stream semantics.
- Relay UDP datagrams through both TCP and QUIC outer transports while preserving existing REALITY authentication, QUIC fallback, and probe-resistance behavior.
- Add server-side UDP target sockets with bounded idle lifetime and reply routing back to the originating SOCKS UDP client.
- Update tests and docs so UDP proxy behavior is covered by OpenSpec scenarios, including malformed UDP requests, SOCKS fragmentation, IPv4/domain/IPv6 targets, and both outer transports.

## Capabilities

### New Capabilities
- `udp-proxy`: SOCKS5 UDP ASSOCIATE, authenticated inner UDP datagram framing, client/server UDP relay runtime, and TCP/QUIC outer transport support for proxied UDP traffic.

### Modified Capabilities
- None in archived specs. This change supersedes the unarchived `socks-inbound` seed behavior that rejected SOCKS5 UDP ASSOCIATE.

## Impact

- Crates: `umbra-proto`, `umbra-inner`, `umbra-core`, `umbra-transport`, `umbra`, and targeted tests in `crates/*/tests`.
- Wire/API: adds UDP datagram envelope types and runtime paths; existing TCP target address encoding and TCP stream behavior remain compatible.
- Config/CLI: no new mandatory configuration; UDP proxy uses the existing client SOCKS listener and selected outer transport.
- Security/runtime: requires strict datagram length checks, bounded UDP association/session maps, idle cleanup, no logging of target addresses or payloads, and no early responses on unauthenticated outer traffic.
