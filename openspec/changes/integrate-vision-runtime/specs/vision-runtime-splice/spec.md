## Purpose

Provide an explicitly enabled, authenticated TCP solo transition that forwards existing inner TLS 1.3 records without duplicate outer TLS encryption, with bounded state, safe compatibility, and observable runtime evidence.

## ADDED Requirements

### Requirement: Authenticated mode and legacy isolation
The system SHALL implement the exact approved contract in `docs/vision-runtime-wire-v2.md`. For TCP, the existing `mux=false` setting SHALL select authenticated v2 Vision solo, while `mux=true` retains v1 multiplexing. No separate Vision flag or legacy solo implementation SHALL remain. Existing v1 mux, UDP associations, and QUIC SHALL remain supported. RealSite or Invalid peers SHALL never receive target, Vision, or business bytes, and the client SHALL NOT automatically downgrade or replay.

#### Scenario: Old server receives new solo client
- **WHEN** a new solo client reaches a server that only authenticates v1
- **THEN** no target, control, or business data is sent to the real-site fallback, and no automatic v1 retry occurs

#### Scenario: Legacy mux client reaches new server
- **WHEN** an existing v1 client opens mux against an upgraded server
- **THEN** it receives no v2 control bytes and existing multiplexed target behavior is preserved

#### Scenario: Legacy solo is removed
- **WHEN** a v1 client sends a legacy solo target preface
- **THEN** the new server rejects it without connecting the target or retaining an alternate solo relay

### Requirement: Target-first bounded capability negotiation
The v2 client SHALL send exactly one target address in its first authenticated application record, then HELLO. The server SHALL validate both before opening the target and SHALL report its bounded connection result in HELLO_ACK. SOCKS success and DATA SHALL wait for target success. Unsupported raw capability on an authenticated v2 session SHALL retain encrypted envelopes without an implicit raw fallback.

#### Scenario: Target receives only its application bytes
- **WHEN** capable v2 endpoints negotiate and connect a target successfully
- **THEN** the target sees no target preface, capability messages, envelope headers, or padding, and the client receives SOCKS success only after target connection

#### Scenario: Raw capability is unavailable
- **WHEN** a v2 server returns selected raw version zero with target success
- **THEN** the session forwards through encrypted envelopes and never attempts a raw switch

#### Scenario: Target connection fails
- **WHEN** the target connection fails or exhausts its bounded deadline
- **THEN** the client receives SOCKS failure, no business payload is replayed, and the session is closed

### Requirement: Authenticated record-aligned envelopes
Each post-preface outer TLS application record SHALL contain exactly one complete bounded Vision envelope. Lengths, roles, versions, flags, and control payload sizes SHALL be validated before use. Declared padding SHALL be removed exactly once. DATA and FIN offsets SHALL count target bytes independently in both directions using checked arithmetic.

#### Scenario: Golden framing and adversarial fragmentation
- **WHEN** valid or malformed golden vectors are delivered with arbitrary TCP fragmentation and coalescing
- **THEN** valid target bytes are delivered exactly once in order, and malformed or cross-record envelopes close without authorizing raw mode

#### Scenario: Partial write is cancelled during scheduling
- **WHEN** an outer ciphertext write makes partial progress and its polling future is cancelled
- **THEN** continuation writes the remaining bytes of the same sealed record without resealing, duplicate bytes, or sequence reuse

### Requirement: Conservative and bounded TLS eligibility
The system SHALL observe inner TLS from stream offset zero using bounded bidirectional record and handshake reassembly. It SHALL require a valid offered/selected TLS 1.3 negotiation and complete protected records in both directions before requesting raw mode. It SHALL NOT equate visible application_data records with verified Finished or inner authentication. Non-TLS, TLS 1.2, unsupported negotiation, malformed input, and observation limits SHALL retain encrypted relay without altering already accepted bytes.

#### Scenario: Fragmented real TLS 1.3 becomes eligible
- **WHEN** a real TLS 1.3 ClientHello and matching ServerHello are fragmented across records and DATA boundaries, followed by complete protected records in both directions
- **THEN** eligibility is reached only at complete protected-record boundaries and all target bytes remain unchanged

#### Scenario: False markers and unsupported TLS remain wrapped
- **WHEN** bytes contain standalone protected-record headers, embedded marker bytes, TLS 1.2, HelloRetryRequest, or early-data negotiation
- **THEN** the session remains wrapped and no claim of verified inner Finished is made

#### Scenario: Slow or oversized sniffing remains bounded
- **WHEN** a prefix exceeds the fixed byte, record, handshake, or time budgets
- **THEN** raw eligibility is permanently disabled while available target bytes continue through bounded encrypted relay

### Requirement: Committed directional boundary handoff
The client SHALL be the sole switch coordinator. Endpoints SHALL use the specified SWITCH_REQ, SWITCH_ACK, COMMIT, and COMMIT_ACK transaction with exact independent C/S offsets and complete-record boundaries. The client SHALL write no outer records after COMMIT; the server SHALL write no outer records after COMMIT_ACK. Raw writes SHALL begin only after the required final control has been authenticated or completely flushed. A valid pre-ACK SWITCH_REJECT SHALL retain wrapped relay; other failed agreement SHALL close rather than resume or replay uncertain framing.

#### Scenario: Both endpoints become eligible together
- **WHEN** both endpoints reach eligibility concurrently
- **THEN** only the client initiates and the four-message transaction completes without losing the control channel or creating simultaneous-switch deadlock

#### Scenario: Final acknowledgement and raw bytes arrive together
- **WHEN** the final outer control record and subsequent raw records are coalesced in one socket read
- **THEN** the receiver stops outer interpretation at the exact authenticated record end and delivers every raw suffix byte once in order

#### Scenario: Agreement fails after request
- **WHEN** offsets disagree, a wrong-role or duplicate control arrives, the deadline expires, or a partial control write fails after SWITCH_REQ
- **THEN** the connection closes without speculative raw data, wrapped-mode rollback, or automatic business replay

#### Scenario: Target FIN crosses a switch request
- **WHEN** the server has already queued or sent FIN while a client SWITCH_REQ is in transit
- **THEN** the server rejects the request before ACK with matching byte offsets, both endpoints remain wrapped, and the crossed FIN and reverse data retain normal half-close semantics

### Requirement: Raw forwarding preserves end-to-end records and lifecycle
After committed handoff, the runtime SHALL forward eligible protected inner TLS record bytes without outer encryption, envelope framing, or padding. It SHALL validate protected-record structure before forwarding an offending record, retain all pending ordered data, and preserve directional half-close. Session cancellation and terminal errors SHALL clean up owned transport work and obsolete outer keys.

#### Scenario: Raw suffix is the original inner ciphertext
- **WHEN** the actual client and server runtime carry a successful independent inner TLS session across commit
- **THEN** captured post-boundary proxy TCP bytes equal the original inner protected records and the outer seal/open counters stop increasing after final controls

#### Scenario: Half-close retains the reverse response
- **WHEN** one side reaches EOF on a complete protected-record boundary
- **THEN** that direction drains and half-closes while the reverse response continues until its own completion

#### Scenario: Plaintext or malformed records follow handoff
- **WHEN** post-handoff input contains an invalid header, unprotected record type, trailing non-TLS bytes, or a truncated record
- **THEN** the offending record is not forwarded as normal raw application data and the connection terminates without returning to outer TLS

#### Scenario: Cancellation retains no detached transport work
- **WHEN** a session is cancelled during negotiation, partial I/O, or raw forwarding
- **THEN** all owned tasks and buffers are cleaned up, no abandoned TLS task accesses the raw socket, and payload is not replayed

### Requirement: Verification separates correctness from performance
The change SHALL include real paired-runtime wire evidence, negative compatibility tests, property/fuzz coverage for new parsers, and the existing full validation gates with line coverage at least 90%. The release SHALL report byte/counter proof without performance comparisons, as requested by the user, and SHALL distinguish user-space raw forwarding from kernel zero-copy.

#### Scenario: A helper-only splice result is insufficient
- **WHEN** a helper reports a Splice state but outer wire equality or stopped encryption counters are absent
- **THEN** production raw handoff is not marked verified or complete

#### Scenario: Optimization is proved without speed comparisons
- **WHEN** the optimization is reported complete
- **THEN** actual runtime raw-byte equality and stopped encryption counters are provided, without an unmeasured speedup percentage or performance benchmark requirement
