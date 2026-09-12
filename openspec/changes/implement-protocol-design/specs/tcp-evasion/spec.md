## ADDED Requirements

### Requirement: Strategy parsing
The system SHALL accept `off` and `segment` as implemented TCP sending policies. Geneva-style strategies without an implemented sender SHALL fail configuration validation before listeners or connections start, rather than silently behaving as `off`.

#### Scenario: Segment strategy parses
- **WHEN** `segment` is parsed
- **THEN** the result enables conservative ClientHello write segmentation

#### Scenario: Unknown strategy is rejected
- **WHEN** an unsupported strategy string is parsed
- **THEN** parsing returns a configuration error

#### Scenario: Geneva sender is unavailable
- **WHEN** file configuration or a CLI override selects a Geneva-style strategy with no implemented sender
- **THEN** startup returns a redacted unsupported-strategy error before network activity

### Requirement: Conservative segmentation
The system SHALL split ClientHello bytes into multiple ordered writes for the conservative segment strategy. Its documented guarantee SHALL cover byte preservation and write order, not a one-to-one mapping to TCP packets or proven resistance to network interference.

#### Scenario: ClientHello is split
- **WHEN** a ClientHello larger than the configured segment threshold is sent with segment strategy
- **THEN** multiple ordered writes are issued and their concatenation equals the original ClientHello

### Requirement: Evasion fallback
The system SHALL fall back to ordinary sending for a recoverable segmentation setup failure only when no ClientHello bytes have been sent. A partial-write failure SHALL NOT restart transmission from the beginning on the same connection.

#### Scenario: Segmentation failure falls back
- **WHEN** the evasion writer reports a recoverable segmentation error before bytes are sent
- **THEN** the ordinary TCP write path is attempted

#### Scenario: Partial write is not replayed
- **WHEN** the writer fails after transmitting part of the ClientHello
- **THEN** the connection returns a transport error without duplicating the transmitted prefix
