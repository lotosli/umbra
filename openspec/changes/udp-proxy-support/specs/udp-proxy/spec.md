## ADDED Requirements

### Requirement: SOCKS5 UDP associate
The client SHALL accept SOCKS5 UDP ASSOCIATE after no-auth negotiation, bind a local UDP relay socket, return that bound address in the SOCKS reply, and keep the TCP control connection alive for the UDP association lifetime.

#### Scenario: UDP associate returns relay endpoint
- **WHEN** a SOCKS5 client sends a UDP ASSOCIATE request
- **THEN** the client replies with success and a UDP endpoint that accepts SOCKS UDP request datagrams

#### Scenario: Control close ends association
- **WHEN** the SOCKS5 TCP control connection for a UDP association closes
- **THEN** the client stops accepting UDP datagrams for that association and closes the authenticated outer relay

### Requirement: SOCKS UDP datagram parsing
The client SHALL parse RFC 1928 UDP request headers with IPv4, domain, and IPv6 target addresses, require `RSV == 0`, and reject malformed UDP requests without forwarding payload bytes.

#### Scenario: Domain UDP request is forwarded
- **WHEN** a SOCKS UDP datagram contains `RSV == 0`, `FRAG == 0`, a domain target, and payload bytes
- **THEN** the same target and payload are carried in the authenticated Umbra UDP envelope

#### Scenario: Malformed UDP request is rejected
- **WHEN** a SOCKS UDP datagram has a nonzero reserved field or truncated target address
- **THEN** the client does not forward the datagram to the Umbra server

### Requirement: SOCKS UDP fragmentation
The client SHALL implement SOCKS UDP fragmentation and reassembly for nonzero `FRAG` values, using the low seven bits as the fragment position, the high bit as end-of-sequence, and a bounded reassembly queue with a timer no shorter than five seconds.

#### Scenario: Fragmented UDP request is reassembled
- **WHEN** a SOCKS UDP payload arrives as fragments `1`, `2`, and `0x83` for the same UDP peer and target
- **THEN** the client forwards one Umbra UDP envelope containing the concatenated payload bytes in fragment order

#### Scenario: Fragment timer resets queue
- **WHEN** an incomplete SOCKS UDP fragment sequence exceeds the reassembly timer
- **THEN** the queued fragments are abandoned and no partial payload is forwarded

#### Scenario: Lower fragment resets queue
- **WHEN** a SOCKS UDP fragment arrives with a position lower than the highest position already processed for that sequence
- **THEN** the existing reassembly queue is reset before the new fragment is processed

#### Scenario: Fragment state is bounded
- **WHEN** one UDP association exceeds the configured maximum number of fragment queues or queued fragment bytes
- **THEN** additional fragments are dropped without allocating unbounded state

#### Scenario: Large UDP reply is fragmented for SOCKS client
- **WHEN** a target UDP reply exceeds the configured SOCKS UDP response fragment payload size
- **THEN** the client emits an ordered SOCKS UDP fragment sequence whose final fragment has the high-order `FRAG` bit set

### Requirement: Authenticated UDP envelope
The system SHALL encode each proxied UDP datagram as a bounded authenticated envelope containing the target address and payload bytes, and all decoders MUST reject truncated, trailing-invalid, or oversized datagrams without panicking.

#### Scenario: UDP envelope round trip
- **WHEN** a UDP envelope is encoded with an IPv6 target and payload bytes
- **THEN** decoding recovers the exact target and payload

#### Scenario: Oversized UDP envelope is rejected
- **WHEN** a UDP payload cannot fit in the configured carrier frame
- **THEN** encoding fails before any network write is attempted

### Requirement: TCP outer UDP relay
The system SHALL carry proxied UDP datagrams over authenticated TCP outer transport using mux UDP datagram frames without changing existing mux stream behavior for TCP CONNECT traffic.

#### Scenario: TCP outer relays UDP request and reply
- **WHEN** the client is configured with `transport = "tcp"` and a local application sends a SOCKS UDP datagram
- **THEN** the server sends the payload to the requested UDP target and relays the target reply back as a SOCKS UDP response

#### Scenario: TCP CONNECT remains compatible
- **WHEN** the client uses SOCKS CONNECT over TCP outer transport after UDP support is enabled
- **THEN** the existing mux or Vision stream relay behavior remains unchanged

### Requirement: QUIC outer UDP relay
The system SHALL carry proxied UDP datagrams over authenticated QUIC outer transport using an authenticated length-delimited QUIC association stream without changing the visible Chrome QUIC profile or adding QUIC DATAGRAM transport parameters.

#### Scenario: QUIC outer relays UDP request and reply
- **WHEN** the client is configured with `transport = "quic"` and a local application sends a SOCKS UDP datagram
- **THEN** the server sends the payload to the requested UDP target and relays the target reply back as a SOCKS UDP response

#### Scenario: QUIC carrier preserves fingerprint
- **WHEN** the client establishes a QUIC UDP association
- **THEN** UDP proxy traffic uses the authenticated stream carrier and does not add QUIC DATAGRAM transport parameters

### Requirement: Server UDP target sessions
The server SHALL maintain bounded UDP target sessions per authenticated association, route replies to the originating client association, and expire idle UDP state without logging target addresses or payload bytes.

#### Scenario: Multiple UDP targets are isolated
- **WHEN** one UDP association sends datagrams to two different target addresses
- **THEN** replies from each target are returned with the matching SOCKS UDP source address

#### Scenario: UDP target limit is enforced
- **WHEN** one UDP association exceeds the configured maximum number of target UDP sockets
- **THEN** additional target datagrams are dropped without allocating unbounded state
