## ADDED Requirements

### Requirement: Chrome profile loading
The system SHALL load named TLS and QUIC fingerprint profiles from data files instead of hard-coded protocol tables.

#### Scenario: Known profile loads
- **WHEN** `chrome-latest` is requested
- **THEN** the returned profile contains cipher suites, extension order, GREASE slots, groups, signature algorithms, ALPN, and padding policy

#### Scenario: Unknown profile is rejected
- **WHEN** a profile name is not present in the fingerprint data directory
- **THEN** loading returns an explicit error

### Requirement: JA3 and JA4 self-check
The system SHALL compute JA3 and JA4 identifiers from generated ClientHello bytes for comparison with the target profile.

#### Scenario: Generated hello matches profile identifiers
- **WHEN** a ClientHello is built from a profile fixture
- **THEN** the computed JA3 and JA4 equal the expected identifiers stored with the profile

### Requirement: QUIC fingerprint data
The system SHALL represent QUIC version, transport parameter order, GREASE transport parameter policy, ALPN, SCID length, and HTTP/3 settings in the profile.

#### Scenario: QUIC profile preserves parameter order
- **WHEN** a QUIC profile is loaded and serialized for a test handshake
- **THEN** transport parameters appear in the configured order
