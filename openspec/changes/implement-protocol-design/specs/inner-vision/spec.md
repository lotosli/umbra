## ADDED Requirements

### Requirement: Solo target preface
The system SHALL send the encoded target address as the first solo-mode payload before relaying target bytes.

#### Scenario: Server receives target address first
- **WHEN** a solo connection starts
- **THEN** the server decodes the target address before connecting to the target

### Requirement: TLS sniffing and shaping
The system SHALL detect inner TLS records beginning with `0x16 0x03` and shape handshake records before splice mode.

#### Scenario: TLS handshake enters shaping phase
- **WHEN** the inner stream begins with TLS handshake record bytes
- **THEN** Vision relay enters handshake shaping before raw splice

### Requirement: Application data splice
The system SHALL switch to raw bidirectional copy after both directions have reached TLS application data.

#### Scenario: Splice after bidirectional application data
- **WHEN** both directions have observed TLS application_data records after handshake
- **THEN** subsequent bytes are copied without mux framing or padding

### Requirement: Non-TLS relay
The system SHALL relay non-TLS solo streams without false TLS handshake state.

#### Scenario: Non-TLS stream bypasses TLS shaping
- **WHEN** the inner first bytes do not look like a TLS record
- **THEN** relay proceeds without waiting for TLS application_data markers
