## ADDED Requirements

### Requirement: Strategy parsing
The system SHALL parse `off`, `segment`, and explicit Geneva-style strategy strings into a TCP evasion policy.

#### Scenario: Segment strategy parses
- **WHEN** `segment` is parsed
- **THEN** the result enables conservative ClientHello segmentation

#### Scenario: Unknown strategy is rejected
- **WHEN** an unsupported strategy string is parsed
- **THEN** parsing returns a configuration error

### Requirement: Conservative segmentation
The system SHALL split ClientHello bytes into multiple ordered writes for the conservative segment strategy.

#### Scenario: ClientHello is split
- **WHEN** a ClientHello larger than the configured segment threshold is sent with segment strategy
- **THEN** multiple ordered writes are issued and their concatenation equals the original ClientHello

### Requirement: Evasion fallback
The system SHALL fall back to ordinary sending when a non-critical evasion operation fails.

#### Scenario: Segmentation failure falls back
- **WHEN** the evasion writer reports a recoverable segmentation error before bytes are sent
- **THEN** the ordinary TCP write path is attempted
