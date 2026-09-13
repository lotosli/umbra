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
A client runtime SHALL reuse capacity-eligible healthy authenticated TCP mux sessions from a bounded pool, or a QUIC connection, for compatible concurrent SOCKS CONNECT requests under the same validated configuration. Connection establishment SHALL be coordinated so concurrent requests do not independently create identical outer sessions. TCP solo streams SHALL retain exclusive outer connections.

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


### Requirement: Capacity-aware mux admission
A TCP client SHALL reserve actual session capacity before submitting a logical open. When one session has no capacity and the bounded outer-session budget permits another session, the client SHALL coordinate a new outer rather than wait only on the full session. Session, reserved-stream, and waiting-open counts SHALL remain bounded.

#### Scenario: More than one outer of held streams
- **WHEN** forty successful CONNECT streams remain open under default receive-credit settings
- **THEN** they share two authenticated outer sessions and all complete setup without waiting for an unrelated stream to close

#### Scenario: Capacity reclaimed after close
- **WHEN** a closed or reset stream releases its inner receive reservation
- **THEN** a waiting compatible open can reserve that capacity without exceeding the configured bounds

#### Scenario: Bounded admission and shutdown
- **WHEN** all outer capacities and the bounded admission queue are occupied, or runtime shutdown begins
- **THEN** excess requests fail explicitly and shutdown wakes every queued waiter and cancels pending establishment

### Requirement: Recoverable mux opening progress
The client SHALL distinguish admission, SYN transmission, and target acknowledgement failure. An outer that stops making opening progress SHALL stop accepting new streams so later requests can use a replacement, while a single target rejection SHALL NOT terminate unrelated healthy streams. No business payload SHALL be replayed.

#### Scenario: Silent outer after a successful stream
- **WHEN** an established outer stops returning opening acknowledgements without EOF or RST
- **THEN** an opening deadline makes that outer ineligible for new streams and a later request can establish a replacement without replaying prior business data

#### Scenario: A slow target and a healthy sibling
- **WHEN** one target rejects or delays setup while another stream continues normally
- **THEN** the healthy sibling survives and ordinary target rejection does not invalidate its entire outer

### Requirement: Bounded multi-address target connection
Production TCP target connection SHALL resolve and attempt candidate addresses within a total setup budget. A black-holed first candidate SHALL NOT prevent trying a reachable later candidate. DNS and TCP errors SHALL identify their stage without revealing target or credential values.

#### Scenario: First candidate is unreachable
- **WHEN** the first address stays pending and a later resolved address is reachable
- **THEN** a staggered bounded attempt connects to the reachable address without waiting for the first address's full operating-system timeout

#### Scenario: All attempts or DNS fail
- **WHEN** DNS fails, the candidate set is empty, or all bounded TCP attempts fail or time out
- **THEN** the operation returns a stage-specific error and its owned attempts are cancelled and reaped

#### Scenario: A single slow address remains viable
- **WHEN** no untried candidate needs a connection slot
- **THEN** the remaining attempt retains the overall setup budget instead of being prematurely removed by a slot-recycling deadline


### Requirement: Bounded retirement does not starve fresh connections
Retiring outers SHALL have a separate bounded allowance from accepting outers. A small number of old streams SHALL NOT occupy every accepting slot indefinitely. If the total outer bound is exhausted and a replacement is needed, the runtime MAY terminate the oldest retiring outer, reporting terminal stream errors without replay; it SHALL NOT evict a healthy accepting outer under this rule.

#### Scenario: Four retiring outers still have old streams
- **WHEN** four non-accepting outers each retain one old stream and a new CONNECT arrives
- **THEN** the client establishes an accepting replacement while preserving the old streams within the separate retirement budget

#### Scenario: Total retirement budget is exhausted
- **WHEN** a new accepting outer is needed at the total bounded outer count and at least one outer is retiring
- **THEN** the oldest retiring outer is terminated and replaced, unrelated accepting outers survive, and no business data is replayed
