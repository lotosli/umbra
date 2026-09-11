## ADDED Requirements

### Requirement: TCP outer connect
The system SHALL establish TCP outer connections to the configured server address and use the configured SNI inside the TLS ClientHello.

#### Scenario: TCP connect sends ClientHello
- **WHEN** the client starts a TCP outer connection
- **THEN** it sends a profile-shaped ClientHello containing the configured SNI

### Requirement: Plain TCP fallback sending
The system SHALL support ordinary ordered writes of ClientHello bytes when `tcp_evasion = "off"` or a recoverable segmentation setup failure occurs before any bytes are emitted. Configuring an unavailable Geneva sender SHALL fail validation rather than select ordinary sending.

#### Scenario: Evasion off writes once
- **WHEN** `tcp_evasion = "off"`
- **THEN** the ClientHello is written through the ordinary TCP path

#### Scenario: Unsupported sender is not a fallback mode
- **WHEN** configuration selects a Geneva strategy without an implemented sender
- **THEN** the client fails before opening a TCP connection instead of silently writing the ClientHello normally

### Requirement: TCP listener
The system SHALL bind the configured server TCP listener address and pass accepted streams to server dispatch.

#### Scenario: Accepted TCP stream is dispatched
- **WHEN** a connection is accepted on the listen socket
- **THEN** dispatch is invoked with the stream and active server profile
