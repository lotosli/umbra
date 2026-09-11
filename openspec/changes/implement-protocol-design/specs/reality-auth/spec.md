## ADDED Requirements

### Requirement: Session id seal
The system SHALL seal a 16-byte REALITY plaintext `ver || flags || timestamp || short_id || reserved`, where `reserved` is two zero bytes, into a 32-byte `legacy_session_id` using AES-128-GCM, an HKDF-SHA256 key and nonce derived from X25519 shared secret, and `HELLO0` as AAD.

#### Scenario: Sealed token opens with same hello
- **WHEN** a client seals a token with a shared secret, short id, timestamp, and `HELLO0`
- **THEN** the server opens it with the same shared secret and `HELLO0`

#### Scenario: AAD change is rejected
- **WHEN** a sealed token is opened with any modified `HELLO0`
- **THEN** authentication fails

### Requirement: Session id open validation
The system SHALL validate version, reserved zero bytes, timestamp window, allowed short id, and replay cache before accepting an opened token.

#### Scenario: Expired token is rejected
- **WHEN** a token timestamp differs from server time by more than `max_time_diff`
- **THEN** opening returns a failure

#### Scenario: Replayed key share is rejected
- **WHEN** the same replay key is observed a second time within the cache TTL
- **THEN** the second open returns a replay failure

#### Scenario: Reserved token bytes are rejected
- **WHEN** an opened token plaintext has nonzero reserved bytes
- **THEN** opening returns an authentication failure

### Requirement: Bounded replay cache
The system SHALL bound replay cache memory by capacity and expiry. Cache expiry SHALL NOT grant authentication independently of token timestamp validation.

#### Scenario: Expired cache entry releases capacity
- **WHEN** a replay entry passes its authentication-validity deadline and cleanup runs
- **THEN** its capacity is reclaimed, while presenting the expired token still fails timestamp validation

### Requirement: Replay retention covers token validity
The authentication runtime SHALL retain accepted tokens through the inclusive end of their timestamp acceptance window, including tokens first accepted with future timestamps. Capacity exhaustion SHALL reject new local authentication rather than evict still-valid replay entries; dispatch SHALL use its ordinary fallback path.

#### Scenario: Future token remains replay-protected
- **WHEN** a token with timestamp 220 and maximum skew 120 is first accepted at time 100 and replayed at time 221 or 340
- **THEN** authentication rejects the replay even though more than 120 seconds have passed since first acceptance

#### Scenario: Expired token cannot regain authentication
- **WHEN** the same token is presented at time 341 after cache cleanup
- **THEN** timestamp validation rejects it regardless of cache membership

#### Scenario: Replay cache reaches capacity
- **WHEN** all replay entries remain valid and a new authenticated token would exceed capacity
- **THEN** local authentication is rejected without removing an existing valid entry or exceeding the memory bound

### Requirement: Canonical ClientHello associated data
TCP HELLO0 SHALL be the complete ClientHello handshake message with its 32-byte session id zeroed, excluding TLS record headers. Refragmenting unchanged handshake bytes SHALL NOT change authentication. QUIC SHALL retain its separate transport-parameter carrier canonicalization.

#### Scenario: TLS record reframing preserves authentication
- **WHEN** an authenticated TCP ClientHello is split across different TLS record boundaries without modifying handshake bytes
- **THEN** the server reconstructs the same HELLO0 and validates the token
