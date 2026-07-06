## ADDED Requirements

### Requirement: Chrome-shaped ClientHello
The system SHALL build TLS 1.3 ClientHello records whose visible fields, extension order, GREASE placements, key shares, ALPN, session id length, and padding are driven by the selected fingerprint profile.

#### Scenario: Session id and key share are caller controlled
- **WHEN** ClientHello parameters provide a 32-byte session id and X25519 keypair
- **THEN** the serialized ClientHello contains those exact values in `legacy_session_id` and the classic X25519 key_share

#### Scenario: Extension order follows profile
- **WHEN** a profile lists a Chrome extension order
- **THEN** the serialized ClientHello extensions appear in that order

### Requirement: TLS 1.3 key schedule
The system SHALL implement RFC 8446 HKDF-Expand-Label, Derive-Secret, handshake traffic secrets, application traffic secrets, exporter secret, and resumption secret.

#### Scenario: RFC 8448 key schedule vector
- **WHEN** the key schedule is run with RFC 8448 test inputs
- **THEN** the derived secrets match the published vector

### Requirement: TLS record protection
The system SHALL seal and open TLS 1.3 records with AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 using per-direction sequence-number nonces.

#### Scenario: Record round trip
- **WHEN** an application record is sealed and then opened with the same key, IV, sequence number, and content type
- **THEN** the plaintext and content type are recovered

#### Scenario: Tampered record is rejected
- **WHEN** ciphertext, tag, or associated data is modified
- **THEN** record opening fails without returning plaintext

### Requirement: Minimal TLS client state machine
The system SHALL drive a TLS 1.3 client handshake through ClientHello, dummy ChangeCipherSpec, ServerHello, encrypted handshake messages, certificate verification callback, Finished, and application data readiness.

#### Scenario: Client handshake completes against test server
- **WHEN** the test TLS server sends valid handshake messages and a certificate classified as UmbraTrusted
- **THEN** the client reaches application data state and emits Client Finished

### Requirement: Minimal TLS server state machine
The system SHALL accept a prefetched ClientHello, echo `legacy_session_id`, choose profile-compatible parameters, send forged certificate data, complete Finished, and expose application data I/O.

#### Scenario: Server echoes compatibility session id
- **WHEN** the server accepts a ClientHello with a 32-byte session id
- **THEN** its ServerHello echoes the same session id

### Requirement: ClientHello parser safety
The system SHALL parse SNI, classic X25519 key_share, session id, and QUIC carrier inputs without panicking on arbitrary bytes.

#### Scenario: Arbitrary bytes do not panic
- **WHEN** malformed ClientHello bytes are passed to the parser
- **THEN** the parser returns an error or incomplete status without panicking
