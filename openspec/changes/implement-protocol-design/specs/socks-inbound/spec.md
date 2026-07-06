## ADDED Requirements

### Requirement: SOCKS5 no-auth handshake
The client SHALL accept SOCKS5 no-auth negotiation on the configured listen address.

#### Scenario: No-auth method selected
- **WHEN** a client offers the no-auth SOCKS5 method
- **THEN** the listener selects no-auth and proceeds to request parsing

### Requirement: SOCKS5 connect requests
The client SHALL parse CONNECT requests for IPv4, domain, and IPv6 targets and convert them to Umbra target addresses.

#### Scenario: Domain connect creates target address
- **WHEN** a SOCKS5 CONNECT request contains a domain and port
- **THEN** the same domain and port are passed to the inner transport

### Requirement: Unsupported SOCKS commands
The client SHALL reject unsupported SOCKS commands without opening an Umbra stream.

#### Scenario: UDP associate is rejected
- **WHEN** a SOCKS5 UDP ASSOCIATE request is received
- **THEN** the listener returns an unsupported-command reply
