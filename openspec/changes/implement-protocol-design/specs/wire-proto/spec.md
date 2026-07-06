## ADDED Requirements

### Requirement: Target address encoding
The system SHALL encode target addresses as `atyp || addr || port` with IPv4, domain, and IPv6 variants exactly as defined in `docs/protocol-design.md`.

#### Scenario: Domain address round trip
- **WHEN** a domain target address is encoded and then decoded
- **THEN** the decoded host and port match the original values and no trailing bytes are accepted

#### Scenario: Invalid address is rejected
- **WHEN** an address buffer has an unknown `atyp` or an incomplete port
- **THEN** decoding returns a protocol error without panicking

### Requirement: Mux frame wire format
The system SHALL encode mux frames as `ver || cmd || stream_id || len || payload` with big-endian numeric fields and documented command values.

#### Scenario: Data frame round trip
- **WHEN** a DATA frame is encoded and then decoded
- **THEN** version, command, stream id, length, and payload are preserved

#### Scenario: Oversized frame is rejected
- **WHEN** a frame declares a payload length that exceeds available bytes or the configured maximum
- **THEN** decoding returns an error without reading beyond the input

### Requirement: Protocol error taxonomy
The system SHALL expose protocol errors that distinguish malformed input, unsupported versions, unsupported commands, invalid addresses, and length violations.

#### Scenario: Malformed input maps to stable error
- **WHEN** malformed bytes are parsed by address or frame decoders
- **THEN** the returned error variant is stable and does not leak secret material
