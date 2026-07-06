## ADDED Requirements

### Requirement: Mux session roles
The system SHALL provide client and server mux session roles over an authenticated TLS I/O object.

#### Scenario: Client opens stream
- **WHEN** the client opens a target address
- **THEN** a SYN frame with the encoded target address is sent and a stream handle is returned after SYN_ACK

### Requirement: Independent stream flow control
The system SHALL maintain per-stream windows and process WINDOW_UPDATE frames as big-endian u32 increments.

#### Scenario: Data waits for window
- **WHEN** a stream window is exhausted
- **THEN** further DATA frames for that stream are withheld until WINDOW_UPDATE increases the window

### Requirement: Stream close semantics
The system SHALL support FIN and RST commands per logical stream without closing unrelated streams.

#### Scenario: One stream reset leaves others open
- **WHEN** one logical stream receives RST
- **THEN** other active streams on the same mux session remain usable
