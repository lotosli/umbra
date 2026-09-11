## ADDED Requirements

### Requirement: Timing alignment
The server SHALL delay the authenticated local handshake path before first ServerHello using a destination first-response measurement with matching start and end points. If local preparation already exceeds that target, no additional delay SHALL be introduced and no bounded indistinguishability claim SHALL be made.

#### Scenario: Auth path waits for profile RTT
- **WHEN** destination profile RTT is greater than local handshake preparation time
- **THEN** dispatch waits before emitting the first authenticated response byte

### Requirement: Useless record limit
The server SHALL apply `maxUselessRecords` policy to useless TLS records such as ChangeCipherSpec flooding without exposing an Umbra-specific response.

#### Scenario: Useless flood follows fallback policy
- **WHEN** a connection exceeds the configured useless record limit before authentication
- **THEN** the connection is forwarded to dest without an Umbra-specific early close

### Requirement: No throttled fallback
Fallback forwarding SHALL NOT apply Umbra-specific rate limiting or early-close behavior to unauthenticated traffic.

#### Scenario: Forwarded bytes are copied bidirectionally
- **WHEN** a fallback connection is established to dest
- **THEN** bytes are copied in both directions using the ordinary relay path

### Requirement: RealSite spider mode
The TCP client SHALL request `spider_path` only after independent chain, hostname, time, and TLS proof-of-possession validation classifies the peer as RealSite, using a supported negotiated HTTP application protocol. RealSite SHALL NOT authorize proxy traffic. The QUIC client SHALL fail proxy establishment for RealSite without claiming HTTP/3 spider support or silently downgrading to TCP.

#### Scenario: RealSite triggers spider path
- **WHEN** TCP certificate verification returns RealSite and the selected HTTP application protocol is supported by the spider
- **THEN** the client requests the configured path, sends no target address or business payload, and closes normally

#### Scenario: Spider cannot speak negotiated protocol
- **WHEN** a RealSite peer selects an application protocol that the spider cannot encode
- **THEN** the client closes without writing a mismatched HTTP request or proxy payload

### Requirement: Safe probe policy configuration
The server SHALL reject a configurable unauthenticated early-close policy before startup. Classification byte, record, and time limits SHALL select transparent destination forwarding rather than a local rejection response.

#### Scenario: Early-close policy is rejected
- **WHEN** a server configuration selects early closure for unauthenticated useless-record traffic
- **THEN** validation fails before startup rather than silently ignoring that policy or violating transparent fallback

### Requirement: Timing alignment is best effort
The first-response delay SHALL be the nonnegative difference between the comparable destination measurement and elapsed local preparation. The implementation SHALL NOT promise a measured indistinguishability bound without corresponding evidence.

#### Scenario: Preparation exceeds destination target
- **WHEN** local preparation takes longer than the recorded destination first-response interval
- **THEN** the server adds no delay and does not report that the first-byte timings matched within a fixed tolerance
