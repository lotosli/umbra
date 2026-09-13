## Why

Umbra 0.0.7's X25519MLKEM768 shares and hybrid secret use the opposite byte order to RFC 10024, and its QUIC ClientHello inherits a TLS 1.2 supported-version entry prohibited by RFC 9001. Umbra-to-Umbra tests hid these interoperability errors; an independent QUIC matcher rejects the handshake.

## What Changes

- **BREAKING**: encode, parse, and combine X25519MLKEM768 material in standard ML-KEM-first order on both TCP and QUIC; validate exact wire lengths.
- Offer only QUIC-permitted TLS versions while retaining appropriate GREASE and keeping TCP version advertisement separate.
- Add independent standard-peer interoperability, negative-boundary and regression coverage; maintain the existing authentication and encrypted/raw forwarding boundaries.
- Publish 0.0.8 and update both client and server together. Do not implement legacy wrong-order negotiation or automatic downgrade.
- Retest Caddy's QUIC routing using the corrected deployment, and migrate the existing web/transport endpoints only if the required behavior works.
- Provide one SOCKS client instance with optional `udp_transport`; TCP CONNECT keeps the main transport while UDP ASSOCIATE can use QUIC. Omission inherits the main transport.

## Capabilities

### New Capabilities
- `tls-standard-interop`: standard hybrid wire layout, transport-specific TLS versions and independent TLS/QUIC interoperability.
- `per-network-client-transport`: select UDP's outer transport separately on the existing single SOCKS listener.

### Modified Capabilities
None. Existing cryptographic primitive algorithms remain unchanged.

## Impact

Affected: `umbra-tls`, TCP/QUIC construction in `umbra-core`, related fixtures and tests, protocol/user documentation, package versions, release artifacts and deployment configuration. Authentication credentials can be reused; hybrid connections require coordinated endpoint upgrades. External interoperability checks must not substitute for authentication or lower security checks.

## Authorization

The user explicitly authorized correcting these two identified standards deviations, releasing/deploying 0.0.8, and retesting Caddy. They explicitly waived old-version compatibility and authorized direct online deployment/testing and downtime. The scope above records that approved behavior before implementation; no additional approval round is required for this scope.

The user subsequently explicitly selected a true single client instance on SOCKS port 1080, with TCP over TCP/Vision and UDP over QUIC, and accepted the small implementation change required. This extends the approved 0.0.8 scope before publishing the release.
