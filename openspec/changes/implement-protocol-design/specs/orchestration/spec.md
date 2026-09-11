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
- **THEN** only the opposite write side is shut down, and reverse traffic remains deliverable until reverse EOF or a terminal error

### Requirement: Graceful shutdown
The system SHALL support cancellation or signal-triggered shutdown for listeners and active sessions.

#### Scenario: Shutdown stops accepting
- **WHEN** shutdown is requested
- **THEN** listeners stop accepting new connections and active sessions are allowed to finish or are cancelled by policy

### Requirement: Shared authenticated outer connections
A client runtime SHALL reuse a healthy authenticated TCP mux session or QUIC connection for compatible concurrent SOCKS CONNECT requests under the same validated configuration. Connection establishment SHALL be coordinated so concurrent requests do not independently create identical outer sessions. TCP solo streams SHALL retain exclusive outer connections.

#### Scenario: Concurrent SOCKS requests share one mux session
- **WHEN** two SOCKS CONNECT requests arrive concurrently with TCP mux enabled
- **THEN** one authenticated outer handshake serves two distinct logical streams, each with independent target traffic and closure

#### Scenario: QUIC requests share one connection
- **WHEN** concurrent SOCKS CONNECT requests use the same QUIC client configuration
- **THEN** they open distinct bidirectional streams on one authenticated QUIC connection

### Requirement: Concurrent server target streams
The server SHALL continue accepting logical streams while earlier streams are connecting or relaying, and one target failure SHALL NOT close unrelated streams. For TCP mux, target connection success SHALL precede SYN_ACK and the corresponding SOCKS success response. QUIC stream establishment alone SHALL NOT be described as confirmation of a successful target connection.

#### Scenario: Slow target does not block another stream
- **WHEN** one TCP mux target connection is delayed or fails and another logical stream opens a reachable target
- **THEN** the reachable target proceeds independently and only the failed stream receives a failure

### Requirement: Bounded shared-session lifecycle
Session count, stream count, queued opens, and buffered payloads SHALL have explicit limits. Idle sessions SHALL be reclaimed; failure of an outer connection SHALL fail its existing streams without replaying requests or payloads. A later new request MAY establish a replacement connection.

#### Scenario: Outer connection fails
- **WHEN** a shared outer connection fails after target bytes were sent
- **THEN** pending operations receive terminal errors, no business bytes are replayed, and a new unrelated request can establish a replacement

#### Scenario: Runtime shutdown reclaims shared sessions
- **WHEN** shutdown occurs with pending opens and active streams
- **THEN** all waiters resolve and owned drivers, timers, and relay tasks terminate without leaving background work detached

### Requirement: UDP association isolation
TCP mux UDP associations SHALL retain dedicated outer sessions while the wire protocol uses stream zero without an association identifier. Reuse of CONNECT sessions SHALL NOT merge independent UDP association ownership.

#### Scenario: Concurrent UDP associations remain separate
- **WHEN** two SOCKS UDP associations coexist with pooled CONNECT streams
- **THEN** each association receives only its own replies, and closing one association does not close the other association or the CONNECT session
