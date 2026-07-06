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
The system SHALL bound replay cache memory by capacity and TTL.

#### Scenario: Expired entry can be accepted again
- **WHEN** a replay entry expires beyond TTL and cleanup runs
- **THEN** a later insert for the same key is not rejected as an active replay
