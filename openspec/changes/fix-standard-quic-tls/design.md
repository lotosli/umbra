## Context

See proposal.md for the observed independent QUIC-matcher failure. TCP and QUIC share the TLS handshake implementation but construct ClientHello material through separate runtime paths. REALITY authentication binds the serialized ClientHello, so transport normalization must occur before token generation.

## Goals / Non-Goals

Goals: standard X25519MLKEM768 wire format and key derivation; transport-correct supported versions; independent full-handshake proof; coordinated 0.0.8 release and live validation.

Non-goals: compatibility with the old wrong-order format, automatic downgrade, changing proxy authentication or cipher algorithms, replacing the custom TLS implementation, claiming unmeasured performance or complete Chrome fingerprint equivalence.

## Decisions

1. Use ML-KEM-first client share (1184+32), server share (1088+32), and combined secret (32+32), with exact length checks before slicing. Preserve the classic X25519 authentication share and its consistency check.
2. Normalize both QUIC profile derivation paths before HELLO0/AAD/authentication is calculated. Retain TLS 1.3 and legal GREASE entries; leave the TCP profile intact. The QUIC TLS API validates inputs rather than silently rewriting an authenticated ClientHello.
3. Update all production and fixture constructors together. Negative tests cover truncated/oversized shares, mismatched classic/hybrid shares, and invalid QUIC version offers; independent standard peers force the hybrid group so successful classic X25519 negotiation cannot hide regressions.
4. Keep secret zeroization, constant-time authentication checks, credential storage and unauthenticated fallback behavior. No insecure certificate-validation or cipher downgrade is part of this fix.
5. Retest the existing Caddy QUIC matcher against the corrected real client, then execute the authorized direct server migration if it works. Caddy deployment configuration and real infrastructure material stay outside the public source tree.
6. Add optional `udp_transport` and the corresponding CLI override. Resolve it as `udp_transport.unwrap_or(transport)` after CLI merging. Only UDP ASSOCIATE dispatch and its reported transport use this effective value; TCP CONNECT and Vision selection continue using `transport`. SOCKS retains one fixed TCP control listener and its existing negotiated per-association UDP relay addresses; no fixed shared UDP socket is introduced.

## Risks / Trade-offs

- Breaking wire correction → upgrade both endpoints together; user explicitly waived compatibility.
- Self-consistent tests can hide errors → independently force hybrid TLS/QUIC handshakes and exchange application data.
- QUIC fingerprint fields change → record the transport-specific difference and retain accurate capture-evidence status.
- Shared runtime regression → run TCP Vision, mux, QUIC and fallback checks plus the existing mandatory coverage gate.
- Caddy may have remaining matcher limitations → test the corrected live path; if required behavior fails, restore the existing web/proxy configuration and remove Caddy.

## Migration Plan

Build and checksum 0.0.8 artifacts after checks. Back up installed configuration and binaries, deploy the server and Mac client pair, restart both modes, and verify authenticated requests. Caddy, if accepted, takes public 80/TCP443/UDP443 while web covers and proxy backends remain private; migrate Certbot hooks and systemd dependencies together. Rollback restores the prior binaries and endpoint configuration as a pair.

## Approved Scope

The user's explicit request and follow-up authorize direct implementation and online deployment, waive old-version compatibility, and allow stopping the currently unused server for testing. This design specifies that authorized repair; it does not require a second confirmation.

The later explicit selection of a true single-instance 1080 client authorizes the optional per-network transport setting. Both remote transports use the same configured server endpoint; deployments requiring different remote endpoints remain outside this change.
