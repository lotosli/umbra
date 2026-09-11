## ADDED Requirements

### Requirement: Solo target preface
The system SHALL send the encoded target address as the first solo-mode payload before relaying target bytes.

#### Scenario: Server receives target address first
- **WHEN** a solo connection starts
- **THEN** the server decodes the target address before connecting to the target

### Requirement: TLS sniffing and shaping
The production solo relay SHALL track each direction using bounded TLS record and handshake reassembly independent of read boundaries. Shaping SHALL use explicitly length-delimited payload and removable padding inside authenticated outer TLS records. Multiple socket writes alone SHALL NOT count as TLS record shaping.

#### Scenario: TLS handshake enters shaping phase
- **WHEN** a valid inner ClientHello is received across arbitrary read and record boundaries
- **THEN** Vision enters shaping without losing or duplicating target bytes, and the peer strips only declared envelope padding

#### Scenario: Coalesced and oversized records
- **WHEN** input contains multiple complete records and a partial next record, or declares an unsupported record length
- **THEN** parsing preserves boundaries within fixed storage limits and does not enable splice on invalid input

### Requirement: Authenticated directional splice
Solo peers SHALL negotiate a versioned Vision capability over authenticated outer TLS before enabling shaping or raw splice. After observing a valid inner TLS 1.3 negotiation and protected records in both directions, each direction SHALL switch only at an explicitly agreed byte boundary, with pending outer TLS writes drained and read-ahead bytes preserved. Observing content type `0x17` SHALL NOT be treated as verification of the inner Finished message. QUIC and mux connections SHALL NOT use raw TCP splice.

#### Scenario: Splice after acknowledged boundaries
- **WHEN** both capable peers observe the required inner TLS 1.3 protected-record phase and acknowledge the directional switch boundaries
- **THEN** subsequent inner TLS bytes traverse the raw outer TCP connection without outer TLS encryption, mux framing, or padding, and arrive exactly once in order

#### Scenario: Application content type is insufficient
- **WHEN** a stream contains `0x17` records without an observed valid inner TLS 1.3 negotiation
- **THEN** the relay remains inside outer TLS and does not claim that the inner handshake is verified

#### Scenario: Pending output and read-ahead survive switching
- **WHEN** a switch boundary coincides with buffered outer TLS output or coalesced post-boundary input
- **THEN** the relay drains pre-boundary output, transfers post-boundary input to the raw reader, and never interprets outer TLS ciphertext as inner data

#### Scenario: Capability or boundary agreement fails
- **WHEN** peers do not agree on the Vision version or cannot establish a safe switch boundary
- **THEN** the session remains in authenticated outer TLS without speculative raw writes; a terminal failure after switching closes the session rather than attempting to reframe raw bytes

### Requirement: Non-TLS relay
The system SHALL relay non-TLS and noneligible TLS solo streams inside outer TLS without false handshake state or indefinite sniffing. Withholding a complete sniffing prefix SHALL NOT withhold already available payload indefinitely.

#### Scenario: Non-TLS stream bypasses TLS shaping
- **WHEN** the inner first bytes do not form an eligible TLS stream
- **THEN** relay proceeds inside outer TLS without waiting for protected-record markers or negotiating a raw switch
