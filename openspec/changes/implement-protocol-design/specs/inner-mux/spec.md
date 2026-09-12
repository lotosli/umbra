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

### Requirement: Cancellation-safe frame processing
The mux session SHALL retain partially consumed frame headers and payloads across cancelled receive operations and SHALL serialize writes without interleaving frame bytes.

#### Scenario: Receive cancelled inside a frame
- **WHEN** receiving a frame is cancelled after any partial header or payload and subsequently resumed
- **THEN** the complete original event is delivered exactly once without losing bytes or corrupting the next frame

### Requirement: Lossless event dispatch under backpressure
Opening streams and waiting for send credit SHALL NOT discard unrelated events. The session SHALL deliver DATA, FIN, RST, and UDP events to their owners while servicing control frames, with bounded queues and per-stream receive windows.

#### Scenario: Data arrives while waiting for credit
- **WHEN** a sender with an exhausted window receives DATA before WINDOW_UPDATE
- **THEN** the DATA is delivered exactly once and sending resumes only after credit is available

#### Scenario: Reset interrupts a credit wait
- **WHEN** RST arrives while a stream waits for send credit
- **THEN** the pending send terminates with a reset error without waiting for another WINDOW_UPDATE

#### Scenario: Concurrent open preserves established traffic
- **WHEN** DATA for an established stream arrives while another stream awaits SYN_ACK
- **THEN** the established stream receives its data and the new stream completes independently

#### Scenario: A slow reader cannot grow memory without bound
- **WHEN** one logical stream stops consuming data while another remains active
- **THEN** the slow stream is constrained by its receive window and bounded buffering while the other stream continues within its own credit

### Requirement: Directional shutdown and stream reclamation
FIN SHALL close only its corresponding data direction. Fully closed or reset streams SHALL release their state, and control frames for unknown streams SHALL NOT create unbounded stream entries.

#### Scenario: Response after request half-close
- **WHEN** a client sends FIN after its request while the target has response data pending
- **THEN** the response remains deliverable before both directions are reclaimed

#### Scenario: Unknown stream window update
- **WHEN** WINDOW_UPDATE names a stream that was never opened or has been reclaimed
- **THEN** the session applies a defined protocol rejection without allocating stream state

### Requirement: Receive credit follows consumption
The session SHALL grant receive credit only for capacity reserved within its bounded storage and SHALL replenish credit only as the application consumes data. Window increments SHALL use checked arithmetic, and invalid zero or overflowing increments SHALL be rejected. Control processing SHALL remain available while an individual stream is blocked.

#### Scenario: Queued data does not replenish credit
- **WHEN** DATA has been decoded into a stream queue but has not been consumed by the application
- **THEN** the receive window remains debited, and only actual application consumption makes that credit available again

#### Scenario: Invalid window increment
- **WHEN** a WINDOW_UPDATE contains zero or would overflow a stream window
- **THEN** the update is rejected without wrapping credit or authorizing excess DATA

#### Scenario: Cancelled sender cannot leave a partial frame
- **WHEN** a send request is cancelled after the serialized writer has transmitted a frame prefix
- **THEN** the session finishes that owned frame before another frame or closes the outer transport on a terminal write error
