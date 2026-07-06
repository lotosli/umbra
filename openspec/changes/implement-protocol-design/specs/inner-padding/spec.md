## ADDED Requirements

### Requirement: Padding scheme parsing
The system SHALL parse named and explicit padding schemes into deterministic policy objects.

#### Scenario: Default scheme parses
- **WHEN** `default` is parsed
- **THEN** the result contains front-loaded padding for early records and low-rate later padding

#### Scenario: Invalid scheme is rejected
- **WHEN** a malformed padding scheme string is parsed
- **THEN** parsing returns a configuration error

### Requirement: Early adaptive padding
The system SHALL inject random PADDING frames around early write events according to the selected scheme.

#### Scenario: Early business frame is padded
- **WHEN** the first business frame is scheduled with the default scheme
- **THEN** at least one PADDING frame is emitted before or after it within configured bounds

### Requirement: Padding frames are discarded
The system SHALL discard received PADDING frames without exposing their payload to logical streams.

#### Scenario: Padding payload is not delivered
- **WHEN** a PADDING frame is received by the mux session
- **THEN** no application stream receives the padding bytes
