# tls-standard-interop Specification

## Purpose
Ensure Umbra's TLS and QUIC handshake encoding interoperates with independent implementations of the standards while preserving authenticated proxy behavior.

## Requirements

### Requirement: Standard X25519MLKEM768 exchange
The system SHALL encode and consume group 0x11EC as RFC 10024 specifies: client ML-KEM public key followed by X25519 public key, server ML-KEM ciphertext followed by X25519 public key, and ML-KEM shared secret followed by X25519 shared secret. It SHALL enforce exact encoded lengths and SHALL NOT negotiate the legacy reversed format.

#### Scenario: Standard hybrid field layout
- **WHEN** client and server hybrid shares and the combined secret are produced
- **THEN** their field order and lengths are respectively 1184+32, 1088+32 and 32+32 bytes with ML-KEM first

#### Scenario: Invalid hybrid share boundary
- **WHEN** a peer supplies a truncated or oversized hybrid share, or a hybrid X25519 part inconsistent with its classic authentication share
- **THEN** the handshake fails without panic or application readiness

#### Scenario: Independent hybrid peer
- **WHEN** an independent standard TLS peer and an Umbra endpoint negotiate X25519MLKEM768
- **THEN** Finished verification completes and application data is decrypted in both directions

### Requirement: QUIC-specific TLS version advertisement
The system SHALL offer TLS 1.3 and valid GREASE values on its QUIC path without offering older TLS versions. It SHALL apply this normalization before binding proxy authentication to ClientHello. TCP version advertisement SHALL continue to follow the TCP profile.

#### Scenario: QUIC profile derived from TCP profile
- **WHEN** a profile containing TLS 1.2, TLS 1.3 and GREASE is used for QUIC
- **THEN** the emitted QUIC ClientHello omits TLS 1.2, retains TLS 1.3 and GREASE, and its authentication verifies

#### Scenario: Direct QUIC API rejects old TLS versions
- **WHEN** a direct QUIC TLS caller supplies a ClientHello configuration offering an old TLS version
- **THEN** the API rejects it rather than silently modifying authentication-bound bytes

#### Scenario: TCP advertisement preserved
- **WHEN** the same source profile is used for TCP
- **THEN** TCP supported-version advertisement and the classic X25519 path remain valid

### Requirement: Proxy handshake and forwarding integrity
The corrected TLS/QUIC paths SHALL preserve proxy authentication, unauthenticated real-site fallback and bidirectional data integrity. A QUIC-aware transparent intermediary SHALL be able to recognize the corrected standard ClientHello without terminating the authenticated connection.

#### Scenario: Corrected proxy round trip
- **WHEN** upgraded endpoints establish TCP Vision, TCP mux or QUIC proxy sessions
- **THEN** authenticated bidirectional traffic succeeds and invalid authentication follows the existing real-site fallback path

#### Scenario: Independent QUIC recognition
- **WHEN** the real corrected QUIC client connects through an independent standard QUIC SNI matcher
- **THEN** the intended backend is selected and an authenticated request succeeds end to end
