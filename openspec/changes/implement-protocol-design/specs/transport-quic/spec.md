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

### Requirement: QUIC proxy use requires UmbraTrusted
The QUIC adapter SHALL require UmbraTrusted before reporting an application-ready proxy connection or releasing application keys to the proxy runtime. RealSite and Invalid SHALL NOT authorize target addresses, SOCKS success replies, UDP envelopes, or business payloads. RealSite SHALL fail locally without initiating a TCP downgrade or pretending that raw QUIC streams implement an HTTP/3 spider.

#### Scenario: Valid TLS peer lacks Umbra bindings
- **WHEN** a QUIC server completes TLS proof of possession but its certificate is classified RealSite
- **THEN** the client rejects proxy establishment and sends no target or business bytes

#### Scenario: Invalid certificate is rejected
- **WHEN** the certificate is Invalid or required private bindings are tampered with
- **THEN** no application-ready proxy session is exposed

### Requirement: Independent QUIC connection ownership
The server SHALL centrally receive and demultiplex UDP datagrams to independently owned classification, authenticated, or fallback flows. Other clients' datagrams SHALL NOT be consumed and discarded by a per-flow reader. Existing Initial reassembly and exact fallback datagrams SHALL be preserved.

#### Scenario: TCP activity does not cancel QUIC
- **WHEN** a QUIC session is active while TCP connections are accepted or completed
- **THEN** its handshake and relay continue until that QUIC session ends or shutdown cancels it

#### Scenario: Concurrent QUIC and fallback clients
- **WHEN** two clients send interleaved Initial fragments and subsequent traffic, with one requiring fallback
- **THEN** each flow receives only its own datagrams and both make progress without losing the other flow's packets

#### Scenario: Duplicate Initial retains its owner
- **WHEN** a client retransmits an Initial for an existing flow
- **THEN** the datagram reaches that flow rather than starting a second authentication or fallback owner

### Requirement: Cancellation-safe QUIC UDP framing
Length-prefixed UDP envelopes carried on QUIC streams SHALL retain read progress across competing events, with bounded envelope sizes.

#### Scenario: UDP reply interrupts an envelope read
- **WHEN** a target reply becomes ready after only part of an incoming envelope has been read
- **THEN** the reply can be sent and the incoming envelope subsequently decodes exactly once without byte loss
