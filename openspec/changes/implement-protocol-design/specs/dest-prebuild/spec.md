## ADDED Requirements

### Requirement: Destination profile probing
The system SHALL probe the configured destination and collect TLS version, cipher suite, key share group, ALPN, encrypted extension identifiers, leaf certificate template, OCSP staple presence, and first-byte RTT.

#### Scenario: Probe captures successful profile
- **WHEN** a test destination completes a TLS 1.3 handshake
- **THEN** `probe_dest` returns a DestProfile containing the negotiated parameters and measured RTT

### Requirement: Profile refresh
The system SHALL obtain one validated destination profile before serving traffic. `prebuild = true` SHALL enable periodic refresh; `prebuild = false` SHALL retain the startup profile without periodic refresh. Disabling refresh SHALL NOT substitute a fabricated profile or bypass certificate validation.

#### Scenario: Refresh replaces stale profile
- **WHEN** a scheduled refresh observes changed destination parameters
- **THEN** the active profile is updated atomically for subsequent handshakes

#### Scenario: Prebuild disabled keeps startup profile
- **WHEN** the server starts with `prebuild = false`
- **THEN** it performs one startup probe, serves with that profile, and schedules no periodic probe

### Requirement: Probe failure fallback
The system SHALL fail startup if no validated profile can be obtained and SHALL retain the last known good profile when a later refresh fails.

#### Scenario: Failed refresh keeps prior profile
- **WHEN** a refresh attempt fails after a valid profile is already active
- **THEN** existing authenticated handshakes continue using the prior profile

#### Scenario: Initial probe fails
- **WHEN** the first probe fails and no valid profile exists
- **THEN** startup returns a redacted error without accepting authenticated sessions using placeholder parameters

### Requirement: Bounded nonblocking probing
Destination DNS resolution, connection establishment, TLS negotiation, and optional HTTP metadata collection SHALL run without blocking async executor threads and SHALL share one finite overall deadline. Probe concurrency SHALL remain bounded even if an underlying blocking operation outlives its caller's deadline.

#### Scenario: Slow probe does not stall the runtime
- **WHEN** a controlled test resolver or destination stalls while unrelated async work is ready
- **THEN** unrelated work progresses, the probe caller finishes within its overall deadline, and timed-out work does not cause unbounded replacement tasks

### Requirement: Comparable first-response measurement
The profile SHALL record the destination connection-to-first-TLS-response interval separately from subsequent TLS and HTTP processing. Authenticated dispatch SHALL measure local preparation from the corresponding classification decision point and delay only the remaining interval.

#### Scenario: Slow HTTP response is not TLS latency
- **WHEN** a destination sends its first TLS response promptly but delays its HTTP response
- **THEN** the HTTP delay does not increase the first-TLS-response timing target
