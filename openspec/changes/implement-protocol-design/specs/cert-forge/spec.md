## ADDED Requirements

### Requirement: Forged leaf mirrors dest template
The system SHALL generate an ephemeral leaf certificate whose visible subject, SAN, validity, issuer-style fields, and signature scheme are derived from the destination profile template where supported.

#### Scenario: SAN mirrors server name
- **WHEN** a forged certificate is generated for an authenticated SNI
- **THEN** the leaf certificate contains that server name in its SAN set

### Requirement: Certificate MAC extension
The system SHALL add private extension OID `1.3.6.1.4.1.62397.1` containing `HMAC-SHA256(cert_key, leaf_SPKI_DER)` where `cert_key` is derived from the shared secret and session id.

#### Scenario: Valid cert MAC verifies
- **WHEN** a client verifies a forged leaf using the same shared secret and session id
- **THEN** certificate classification returns UmbraTrusted if all other required checks pass

#### Scenario: Wrong shared secret does not verify
- **WHEN** a forged leaf is verified with a different shared secret
- **THEN** certificate classification is not UmbraTrusted

### Requirement: ML-DSA certificate extension
The system SHALL add private extension OID `1.3.6.1.4.1.62397.2` containing an ML-DSA-65 signature over `leaf_SPKI_DER` and require successful verification for UmbraTrusted.

#### Scenario: Tampered PQ signature is rejected
- **WHEN** the ML-DSA extension signature is modified
- **THEN** certificate classification is not UmbraTrusted

### Requirement: RealSite classification
The system SHALL classify certificates without valid Umbra private extensions as RealSite when the underlying TLS certificate is otherwise valid for the borrowed site.

#### Scenario: Real certificate is not UmbraTrusted
- **WHEN** a valid destination certificate lacks Umbra extensions
- **THEN** the verifier returns RealSite
