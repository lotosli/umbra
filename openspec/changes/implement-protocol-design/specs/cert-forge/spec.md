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

### Requirement: RealSite requires independent certificate validation
RealSite classification SHALL require a valid certificate chain under configured trust roots, the expected server name, certificate validity dates, and handshake signature verification. UmbraTrusted SHALL require both private bindings and handshake proof of possession; it SHALL NOT require a public CA signature on the forged certificate.

#### Scenario: Untrusted ordinary certificate
- **WHEN** a certificate lacks valid Umbra bindings and its chain is untrusted under configured roots, expired, or issued for another name
- **THEN** classification returns Invalid rather than RealSite

#### Scenario: Trusted borrowed-site certificate
- **WHEN** an ordinary certificate chain verifies for the expected name and current time and its handshake signature is valid
- **THEN** classification returns RealSite without authorizing proxy traffic

### Requirement: Certificate signing material is zeroized
Ephemeral private DER, certificate binding keys, retained traffic keys, and probe key-log secrets SHALL use zeroizing storage and redacted diagnostic formatting. Implementations SHALL avoid unnecessary secret copies and explicitly protect required copies.

#### Scenario: Secret holders are formatted or released
- **WHEN** a secret-bearing certificate or TLS state holder is formatted or its zeroization path runs
- **THEN** formatting excludes secret bytes and owned secret storage is cleared before release
