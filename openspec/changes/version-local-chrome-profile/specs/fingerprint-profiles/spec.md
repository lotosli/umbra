## MODIFIED Requirements

### Requirement: Chrome profile loading
The system SHALL load named TLS and QUIC fingerprint profiles from versioned data files, SHALL provide `chrome-latest` as the default profile alias, and SHALL embed built-in default profiles into compiled release binaries.

#### Scenario: Versioned local Chrome profile loads
- **WHEN** `chrome-150-macos` is requested
- **THEN** the returned profile contains the captured Chrome version label, cipher suites, extension order, GREASE slots, supported_versions, supported groups, signature algorithms, ALPN, and padding policy

#### Scenario: Latest profile tracks captured version
- **WHEN** `chrome-latest` is requested
- **THEN** its fingerprint fields match the versioned Chrome profile selected as the current default

### Requirement: JA3 and JA4 self-check
The system SHALL compute JA3 and JA4 identifiers from generated ClientHello bytes for comparison with the target profile.

#### Scenario: Generated hello matches captured Chrome identifiers
- **WHEN** a ClientHello is built from the versioned Chrome profile fixture
- **THEN** the computed JA3 and JA4 equal the captured identifiers stored with the profile

### Requirement: TLS supported versions profile
The system SHALL serialize the ClientHello `supported_versions` extension from explicit profile data instead of deriving its GREASE value from supported_groups.

#### Scenario: Supported versions follow profile
- **WHEN** a ClientHello is built from a profile whose supported_versions GREASE differs from supported_groups GREASE
- **THEN** the supported_versions extension uses the profile's supported_versions values in wire order
