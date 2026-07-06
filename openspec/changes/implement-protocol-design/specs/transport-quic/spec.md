## ADDED Requirements

### Requirement: QUIC fingerprint profile
The system SHALL build QUIC Initial and transport parameter surfaces from the selected Chrome QUIC fingerprint profile.

#### Scenario: QUIC ALPN is h3
- **WHEN** a QUIC connection is built from the default QUIC profile
- **THEN** the advertised ALPN is `h3`

### Requirement: REALITY over QUIC carrier
The system SHALL carry the 32-byte REALITY token in a Chrome-style GREASE QUIC transport parameter or the documented split carrier when a single parameter cannot hold it.

#### Scenario: Token carrier is recoverable
- **WHEN** the client builds a QUIC ClientHello with an auth token
- **THEN** server-side parsing recovers the exact token before authentication

### Requirement: QUIC dispatch fallback
The server SHALL forward unauthenticated QUIC Initial packets and subsequent datagrams to the configured destination QUIC service.

#### Scenario: Bad QUIC auth is forwarded
- **WHEN** a QUIC Initial contains an invalid auth token
- **THEN** the datagram is forwarded to dest rather than answered as Umbra

### Requirement: QUIC streams carry inner traffic
Authenticated QUIC connections SHALL use QUIC streams for target traffic and SHALL not require the TCP mux frame layer for ordinary multiplexing.

#### Scenario: Authenticated QUIC opens target stream
- **WHEN** a client opens a target over an authenticated QUIC connection
- **THEN** a QUIC stream carries the encoded target address and target bytes
