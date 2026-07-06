## ADDED Requirements

### Requirement: Destination profile probing
The system SHALL probe the configured destination and collect TLS version, cipher suite, key share group, ALPN, encrypted extension identifiers, leaf certificate template, OCSP staple presence, and first-byte RTT.

#### Scenario: Probe captures successful profile
- **WHEN** a test destination completes a TLS 1.3 handshake
- **THEN** `probe_dest` returns a DestProfile containing the negotiated parameters and measured RTT

### Requirement: Profile refresh
The system SHALL support startup probing and periodic refresh when `prebuild = true`.

#### Scenario: Refresh replaces stale profile
- **WHEN** a scheduled refresh observes changed destination parameters
- **THEN** the active profile is updated atomically for subsequent handshakes

### Requirement: Probe failure fallback
The system SHALL return an explicit error or retain the last known good profile when destination probing fails.

#### Scenario: Failed refresh keeps prior profile
- **WHEN** a refresh attempt fails after a valid profile is already active
- **THEN** existing authenticated handshakes continue using the prior profile
