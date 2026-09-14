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
