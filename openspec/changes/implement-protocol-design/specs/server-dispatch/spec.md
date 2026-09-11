## ADDED Requirements

### Requirement: Read complete ClientHello before response
The server SHALL read the full initial ClientHello bytes before emitting a local TLS response. If classification cannot complete within bounded buffering or its deadline, the server SHALL transfer ownership to transparent dest forwarding without emitting an Umbra-specific response.

#### Scenario: No response before classification
- **WHEN** a connection sends only a partial ClientHello while classification remains within its limits
- **THEN** the server does not emit a local TLS response

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

### Requirement: Bounded classification preserves fallback bytes
Initial classification SHALL have a finite total deadline and bounded storage. Every consumed byte, including a partial TLS record header or body, SHALL remain owned until classification succeeds or transfers it to dest. Exceeding classification limits SHALL select transparent forwarding rather than an Umbra-specific close.

#### Scenario: Oversized ClientHello falls back
- **WHEN** a record or handshake length exceeds the classification byte or record budget
- **THEN** the server forwards the exact consumed prefix followed by remaining bytes without allocating the declared oversized body

#### Scenario: Partial ClientHello deadline
- **WHEN** a peer pauses inside a record header or payload until the classification deadline expires
- **THEN** the server transfers its retained prefix to dest and relays subsequent bytes without losing partially read data

#### Scenario: EOF during classification
- **WHEN** the client half-closes after a partial ClientHello
- **THEN** available prefix bytes and EOF are forwarded to dest and any destination response remains relayable

#### Scenario: Transport cannot continue
- **WHEN** the client connection is already reset or dest cannot be reached
- **THEN** dispatch releases local resources without manufacturing an Umbra protocol response or claiming successful forwarding
