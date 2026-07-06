## ADDED Requirements

### Requirement: Timing alignment
The server SHALL delay the authenticated local handshake path before first ServerHello so its first-byte timing matches the destination RTT profile within configured tolerance.

#### Scenario: Auth path waits for profile RTT
- **WHEN** destination profile RTT is greater than local handshake preparation time
- **THEN** dispatch waits before emitting the first authenticated response byte

### Requirement: Useless record limit
The server SHALL apply `maxUselessRecords` policy to useless TLS records such as ChangeCipherSpec flooding without exposing an Umbra-specific response.

#### Scenario: Useless flood follows fallback policy
- **WHEN** a connection exceeds the configured useless record limit before authentication
- **THEN** the connection is forwarded to dest or closed according to documented fallback policy

### Requirement: No throttled fallback
Fallback forwarding SHALL NOT apply Umbra-specific rate limiting or early-close behavior to unauthenticated traffic.

#### Scenario: Forwarded bytes are copied bidirectionally
- **WHEN** a fallback connection is established to dest
- **THEN** bytes are copied in both directions using the ordinary relay path

### Requirement: RealSite spider mode
The client SHALL run browser-like spider behavior against `spider_path` when certificate verification classifies the peer as RealSite.

#### Scenario: RealSite triggers spider path
- **WHEN** certificate verification returns RealSite
- **THEN** the client sends a normal-looking request for the configured spider path and closes normally
