## Purpose

Provide predictable high-throughput authenticated forwarding through TCP mux, Vision and native QUIC while preserving bounded ownership, independent progress and verifiable alpha releases.

## ADDED Requirements

### Requirement: Independent reusable application records
Established TLS application directions SHALL own independent key/sequence state, support reusable caller buffers, validate a record header before accepting its body length, and retain partial I/O across cancellation. A failed or truncated record MUST NOT expose unauthenticated plaintext or be forwarded as valid raw traffic.

#### Scenario: Concurrent records and cancellation
- **WHEN** both directions transfer multiple records with partial writes and cancelled reads
- **THEN** every payload is delivered once, sequence/nonce progression remains correct and reusable buffer capacity remains available after completion

#### Scenario: Oversized header and truncated EOF
- **WHEN** a peer sends an oversized application-record header or closes inside a header/body
- **THEN** the record is rejected without waiting for an oversized body or confusing truncation with clean EOF

### Requirement: Funded native QUIC windows
Both native endpoints SHALL apply explicit bounded stream, aggregate receive and send-storage policies. Aggregate growth SHALL reflect actual consumption rate and RTT independently of the controller polling interval, SHALL require available budget, and MUST NOT revoke or double-lend grants. Public parameter evidence SHALL identify exact matching fields and unverified fingerprint scope.

#### Scenario: High-BDP native policy and bounds
- **WHEN** default or explicit stream/send window settings are loaded on both endpoints
- **THEN** actual transport parameters use the selected valid limits, invalid values fail safely and retained buffers remain within the owning budget

#### Scenario: Low RTT with delayed growth sampling
- **WHEN** a fast consumer is sampled every 50ms on a 10ms-RTT connection
- **THEN** sustained demand can grow funded aggregate credit, while idle/slow consumption and exhausted budgets cannot grow it

### Requirement: Bounded batch-preserving QUIC ingress
QUIC ingress SHALL preserve complete datagram batches, per-datagram metadata, ordering and peer/CID isolation within explicit byte/batch ceilings. A legal ready burst exceeding sixteen ordinary datagrams SHALL fit an otherwise empty default flow queue. Saturation SHALL be counted anonymously without blocking unrelated flows.

#### Scenario: GRO burst exceeds previous packet capacity
- **WHEN** a ready batch contains more than sixteen valid datagrams for one flow
- **THEN** every datagram fits the default empty queue and is delivered once with its original boundary and metadata

#### Scenario: Saturated ingress remains isolated and observable
- **WHEN** one flow exhausts its retained-byte budget while another has available capacity
- **THEN** the healthy flow progresses, refusal counters reflect rejected datagrams/bytes and all retained commitments are released on shutdown

### Requirement: Independent UDP association progress
UDP associations over TCP and QUIC SHALL continue opposite-direction progress, control closure and idle expiry while one carrier write or new-target setup is pending. Partial envelope writes MUST retain offsets without replay. Shared endpoint shutdown MUST NOT be owned by an individual association.

#### Scenario: Blocked writer and slow target setup
- **WHEN** carrier output is blocked or one new target setup is delayed while established reverse traffic arrives
- **THEN** established reverse traffic progresses, control closure cancels owned work and resuming output emits each accepted envelope exactly once

#### Scenario: Shared endpoint survives sibling closure
- **WHEN** two UDP associations share the client endpoint and one control stream closes
- **THEN** only that association closes, its sibling continues bidirectional transfer and runtime shutdown reclaims the shared endpoint

### Requirement: Work-proportional fair mux dispatch
Mux scheduling SHALL service changed or ready streams without repeatedly polling every idle retained stream. Output completion SHALL apply only to the participating batch, and coalesced consumption updates MUST preserve monotone credit, zero-window recovery, round-robin progress and exact FIN/RST settlement.

#### Scenario: Busy stream beside idle and blocked siblings
- **WHEN** one stream transfers while many retained streams are idle and another lacks credit
- **THEN** scheduling work follows ready streams, the blocked stream resumes when granted credit and unrelated streams retain ordering and half-close semantics

### Requirement: Throughput-oriented mux startup
Adaptive mux SHALL use funded throughput-oriented initial stream/connection windows within configured maxima and retain bounded fairness across credential groups.

#### Scenario: Startup and warmed mixed transfers
- **WHEN** startup-inclusive and warmed transfers run across different RTTs and a paused receiver
- **THEN** byte integrity, commitment limits and independent progress hold and measurements distinguish startup from sustained goodput

### Requirement: Efficient Vision record forwarding
Wrapped Vision SHALL avoid redundant payload ownership copies and raw Vision SHALL preserve complete-record validation with bounded read-ahead and activity-based idle expiry. Neither optimization SHALL change padding distributions or raw handoff boundaries.

#### Scenario: Wrapped bytes and raw partial activity
- **WHEN** wrapped DATA uses reusable encoding and raw records arrive across partial reads/writes with continuing activity
- **THEN** delivered bytes match exactly, partial activity prevents false idle expiry and malformed/truncated records are not forwarded

### Requirement: Verified alpha delivery
The `1.0.0-alpha` release SHALL pass required local gates including at least ninety percent line coverage, publish reproducible optimization evidence and retain recoverable endpoint backups. Installed binaries SHALL match generated version and digests; public releases SHALL be marked prerelease, and unavailable remote checks MUST NOT be reported as passed.

#### Scenario: Alpha artifacts and paired deployment
- **WHEN** the authorized alpha build is installed on the existing server and Mac client
- **THEN** version/digests match the tested source, authenticated Vision/mux/QUIC/UDP smoke checks pass and privately retained backups permit restoration
