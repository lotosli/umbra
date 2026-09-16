## Purpose

Adaptive credit for authenticated multiplexed streams with heterogeneous latency, independent directions and bounded receiver memory.

## ADDED Requirements

### Requirement: Negotiated independent receive limits
Adaptive peers SHALL advertise independent initial and maximum stream and connection receive limits before exchanging adaptive DATA; legacy sessions SHALL keep their existing behavior.

#### Scenario: Different receiver limits
- **WHEN** two adaptive peers advertise different valid limits
- **THEN** each sender obeys the other receiver and transfers data in both directions

#### Scenario: Legacy connection
- **WHEN** a legacy peer opens a stream without adaptive settings
- **THEN** the server retains the legacy flow-control contract

### Requirement: Cumulative dual credit
Every adaptive DATA byte MUST fit both stream and connection cumulative limits. Consumption and newly granted capacity SHALL be accounted independently without wraparound.

#### Scenario: Credit exhaustion and refresh
- **WHEN** a stream or connection exhausts its credit
- **THEN** DATA waits while control messages and other eligible streams continue

#### Scenario: Invalid credit
- **WHEN** a peer sends malformed, decreasing, overflowing or impossible credit
- **THEN** the connection fails without adding stream state or replaying bytes

### Requirement: Bounded automatic growth
Receive windows SHALL grow with demonstrated consumption and RTT demand only when funded by available budget, and MUST NOT revoke outstanding grants.

#### Scenario: High bandwidth delay demand
- **WHEN** a continuously consumed stream repeatedly uses its window quickly
- **THEN** its receive window grows beyond its starting value within the configured bounds

#### Scenario: Slow consumer or exhausted budget
- **WHEN** the receiver does not consume data or lacks growth budget
- **THEN** window growth stops and committed memory remains bounded

### Requirement: Cancellation and close settlement
Partial framing, consumption, FIN and RST SHALL remain cancellation safe and SHALL reclaim credit and memory exactly once.

#### Scenario: Reset with in flight data
- **WHEN** a reset crosses already committed DATA and credit updates
- **THEN** all outstanding positions settle without leaking connection credit or delivering reset data

#### Scenario: Concurrent directions and close
- **WHEN** one peer finishes its sending direction while a response remains
- **THEN** the reverse direction completes and all state is reclaimed
