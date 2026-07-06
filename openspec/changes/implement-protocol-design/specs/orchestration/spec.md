## ADDED Requirements

### Requirement: Server orchestration
The system SHALL run configured TCP and optional UDP listeners, maintain destination profiles and replay caches, and dispatch accepted traffic.

#### Scenario: Server starts configured listeners
- **WHEN** server orchestration starts with TCP and UDP listen addresses
- **THEN** both listener tasks are created or an explicit startup error is returned

### Requirement: Client orchestration
The system SHALL run the SOCKS listener, establish TCP or QUIC outer connections, choose mux or Vision mode, and relay target traffic.

#### Scenario: SOCKS request opens selected transport
- **WHEN** a SOCKS CONNECT request is accepted with `transport = "tcp"` and `mux = true`
- **THEN** client orchestration opens a TCP authenticated connection and a mux stream for the target

### Requirement: Relay lifecycle
The system SHALL propagate half-close, EOF, and cancellation between local and remote sides without leaking tasks.

#### Scenario: EOF closes peer direction
- **WHEN** one side of a relay reaches EOF
- **THEN** the opposite write side is shut down and the relay task completes

### Requirement: Graceful shutdown
The system SHALL support cancellation or signal-triggered shutdown for listeners and active sessions.

#### Scenario: Shutdown stops accepting
- **WHEN** shutdown is requested
- **THEN** listeners stop accepting new connections and active sessions are allowed to finish or are cancelled by policy
