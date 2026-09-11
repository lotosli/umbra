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

### Requirement: Distinct TLS secret transcript boundaries
TCP and QUIC SHALL derive application traffic and exporter secrets from the transcript through server Finished, and resumption secrets from the transcript through client Finished. The APIs SHALL represent these boundaries separately.

#### Scenario: Standard application and resumption vectors
- **WHEN** RFC 8448 handshake inputs are processed by the production derivation path
- **THEN** derived secrets match published values where available and an independent RFC 8446 reference implementation otherwise, with the provenance of every expected value recorded

#### Scenario: Standard peer application data interoperates
- **WHEN** the custom client completes a local handshake with an independent standard TLS server using supported parameters
- **THEN** both peers decrypt application data in both directions rather than relying only on Umbra-to-Umbra round trips

### Requirement: Certificate compression matches advertised support
The ClientHello certificate-compression extension SHALL use the RFC 8879 uint8 algorithm-vector length. The client SHALL decode advertised certificate-compression algorithms with explicit compressed and decompressed size bounds and the RFC-defined transcript representation.

#### Scenario: Brotli extension encoding
- **WHEN** the client advertises Brotli algorithm 2
- **THEN** extension 27 contains exactly the algorithm-list payload `02 00 02`

#### Scenario: Valid compressed certificate
- **WHEN** a peer sends a valid Brotli CompressedCertificate within the configured bounds
- **THEN** certificate and Finished verification succeed using the protocol-correct transcript

#### Scenario: Invalid or oversized compressed certificate
- **WHEN** compressed certificate data is malformed or its advertised or actual output exceeds the bound
- **THEN** the handshake fails without unbounded allocation or returning application-ready state

### Requirement: Validate negotiated TLS parameters
The client SHALL validate ServerHello legacy version, null compression, TLS 1.3 supported_versions, session-id echo, extension uniqueness, and selection from the offered cipher suites and key-share groups. Unsupported HelloRetryRequest SHALL fail explicitly rather than be treated as an ordinary ServerHello.

#### Scenario: Invalid ServerHello selection
- **WHEN** a peer omits TLS 1.3 selection, changes the session-id echo, duplicates a prohibited extension, or chooses an unoffered parameter
- **THEN** the client rejects the handshake before application readiness

### Requirement: Streamed handshake and signature verification
TCP handshake parsing SHALL reassemble messages across TLS records, tolerate valid compatibility CCS, and verify every advertised TLS-1.3-usable CertificateVerify algorithm using maintained cryptographic libraries. TLS-1.2-only advertised algorithms SHALL NOT become acceptable TLS 1.3 signatures.

#### Scenario: Fragmented standard server flight
- **WHEN** a valid server flight is split across several records with a permitted compatibility CCS
- **THEN** the client completes the handshake without assuming exactly two server records

#### Scenario: Advertised signature algorithm
- **WHEN** a supported peer uses any advertised TLS-1.3-usable signature algorithm with a matching certificate key
- **THEN** its valid signature verifies and a tampered signature is rejected
