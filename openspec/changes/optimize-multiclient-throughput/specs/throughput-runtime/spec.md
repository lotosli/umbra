## Purpose

Preserve exact authenticated byte transport while reducing data-path work and publishing independently verified 0.0.9 artifacts.

## ADDED Requirements

### Requirement: Exact efficient transport
TCP mux, wrapped Vision, raw Vision and native QUIC SHALL retain byte equality, half-close and authenticated readiness while reducing redundant buffer work.

#### Scenario: Bidirectional payload integrity
- **WHEN** large payloads transfer concurrently through each supported mode
- **THEN** both directions match their input and complete half-close

#### Scenario: Truncated record
- **WHEN** a raw Vision input ends inside a protected record
- **THEN** no partial invalid record is forwarded

### Requirement: Reproducible throughput evidence
The change SHALL provide reproducible same-environment throughput evidence, distinguishing application goodput, constraints and unmeasured claims.

#### Scenario: Mixed client measurement
- **WHEN** clients with different delays, consumption rates and stream counts transfer simultaneously
- **THEN** results include per-client progress and aggregate goodput with test conditions

### Requirement: Verified release and deployment
Version 0.0.9 SHALL pass required formatting, lint, dependency, fingerprint, specification, property/fuzz and at-least-90-percent line-coverage gates before deployment; installed hashes SHALL match release artifacts.

#### Scenario: Paired release
- **WHEN** the authorized server and Mac client are upgraded to 0.0.9
- **THEN** installed versions and hashes match and actual authenticated routing succeeds

### Requirement: Selectable QUIC congestion policy
The client and server SHALL apply the configured QUIC congestion algorithm independently, supporting BBR, Cubic and NewReno. Version 0.0.9 SHALL default to the explicitly requested BBR trial, retain a Cubic option and reject unknown policy names without exposing configuration secrets. TCP congestion settings SHALL remain independent.

#### Scenario: Configured QUIC algorithm
- **WHEN** a client or server selects a supported congestion policy
- **THEN** its outgoing QUIC uses that factory and authenticated bidirectional transfer remains functional

#### Scenario: Unknown congestion algorithm
- **WHEN** an unknown QUIC congestion policy is configured
- **THEN** configuration fails with a sanitized error

### Requirement: Bounded anonymous bottleneck observations
Opt-in runtime diagnostics SHALL distinguish outer transport and target read/write progress, pending I/O, DATA credit/buffering and shared budget refusals by opaque group and mode. Observations MUST omit addresses, SNI, credentials and session identifiers, retain at most 128 closed flows, and label unavailable metrics honestly. Disabled diagnostics MUST NOT alter flow control or scheduling.

#### Scenario: Pending I/O and retained observation
- **WHEN** a synthetic transport has partial reads/writes and backpressure before its last observer closes
- **THEN** counters reflect actual progress and pending waits, and its final snapshot is retained within the bounded history

#### Scenario: Real grouped runtime observation
- **WHEN** multiple authenticated clients transfer with diagnostics enabled
- **THEN** observations identify their opaque groups/modes, report target and transport progress separately, and show no active observation after all owners stop
