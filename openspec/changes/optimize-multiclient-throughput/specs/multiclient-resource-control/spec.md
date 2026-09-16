## Purpose

Coordinate authenticated connection resources across multiple clients and transports without changing untrusted fallback semantics.

## ADDED Requirements

### Requirement: Credential group budgets
The service SHALL group authenticated connections by canonical accepted credential and enforce process and group resource ceilings across transports; shared credentials SHALL share the same group.

#### Scenario: Multiple outers one credential
- **WHEN** one credential opens several outer connections
- **THEN** all those connections consume the same bounded group budget

#### Scenario: Multiple active credentials
- **WHEN** clients with distinct credentials compete for resources
- **THEN** bounded admission preserves progress for eligible groups without treating connection count as identity

### Requirement: Committed capacity ownership
Memory accounting MUST include receive commitments and separate transport storage; permits SHALL follow resource lifetime and MUST NOT be released while usable credit or child tasks remain.

#### Scenario: Cancellation releases owners
- **WHEN** an outer is cancelled with workers and pending buffers
- **THEN** workers stop and associated owned permits are released

#### Scenario: No credit oversubscription
- **WHEN** several clients try to grow outstanding receive grants
- **THEN** combined commitments never exceed their shared budget

### Requirement: Slow client isolation
A blocked client SHALL NOT suspend unrelated clients or the opposite relay direction. Authentication failures SHALL preserve true-destination fallback behavior.

#### Scenario: Slow reader beside fast client
- **WHEN** one client stops reading while another transfers
- **THEN** the fast client progresses and slow-client storage stays bounded

#### Scenario: Unauthenticated fallback
- **WHEN** a request fails authentication while authenticated budgets are in use
- **THEN** it follows the existing transparent fallback contract

### Requirement: Funded native QUIC receive growth
The server MUST admit a native QUIC connection within the supported minimum memory budget when sufficient initial capacity is free. Its receive commitment SHALL grow only after demonstrated consumption and successful group/process funding; existing grants MUST remain owned until all transport and retained receive owners are gone. Native application stream storage SHALL be charged separately.

#### Scenario: Low-memory native connection
- **WHEN** an authenticated QUIC client connects to a server with the valid 16MiB group/process budget
- **THEN** the connection can transfer an exact payload within that budget and release all commitments after shutdown

#### Scenario: Native growth and retained owners
- **WHEN** a native receiver consumes rapidly, exhausts its growth budget, and later drops its connection before a retained reader
- **THEN** only funded growth is granted, no live commitment shrinks, and the final reader releases its owned commitment

### Requirement: Work-conserving credential-group readiness
Authenticated task processing SHALL rotate ready credential groups before their individual ready tasks. Waiting I/O SHALL NOT occupy a processing permit, cancellation MUST return permits and remove queued work, and a sole ready group SHALL be able to use all process permits. Unauthenticated classification and fallback MUST retain their existing scheduling semantics.

#### Scenario: Unequal ready task counts
- **WHEN** one credential has eight continuously ready tasks and another has one equivalent task competing for one processing permit
- **THEN** both groups receive balanced poll opportunities rather than shares proportional to task count

#### Scenario: Blocked or cancelled work
- **WHEN** a task waits for input or is cancelled while queued or permitted
- **THEN** other ready groups progress and the scheduler retains no leaked processing permit or cancelled queue entry

#### Scenario: One group borrows idle processing capacity
- **WHEN** only one credential group has ready work and multiple process permits are free
- **THEN** it may use all permits concurrently without an artificial one-worker ceiling
