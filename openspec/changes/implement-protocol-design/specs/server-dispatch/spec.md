## ADDED Requirements

### Requirement: Read complete ClientHello before response
The server SHALL read the full initial ClientHello bytes before sending any response bytes on the connection.

#### Scenario: No response before classification
- **WHEN** a connection sends only a partial ClientHello
- **THEN** the server does not emit TLS response bytes

### Requirement: Authenticated dispatch
The server SHALL parse SNI, classic X25519 key_share, and authentication carrier, validate REALITY auth, and route successful connections into the local TLS server path.

#### Scenario: Valid authenticated ClientHello enters Umbra path
- **WHEN** the ClientHello has allowed SNI, valid token, fresh timestamp, allowed short id, and no replay
- **THEN** dispatch invokes the forged-handshake path with the derived shared secret

### Requirement: Probe fallback forwarding
The server SHALL forward unauthenticated, malformed, disallowed-SNI, failed-GCM, expired, and replayed connections to the configured dest without an Umbra-specific early response.

#### Scenario: Invalid token is forwarded
- **WHEN** a ClientHello has a bad authentication tag
- **THEN** the original ClientHello bytes are written to the dest connection and bidirectional copy starts

### Requirement: Prefixed stream
The system SHALL provide a stream wrapper that replays prefetched bytes before reading from the underlying stream.

#### Scenario: Prefix is read before inner stream
- **WHEN** a prefixed stream is read by downstream code
- **THEN** it yields the ClientHello prefix before subsequent network bytes
