# per-network-client-transport Specification

## Purpose
Allow one Umbra SOCKS client instance to choose a separate outer transport for UDP associations while preserving the selected TCP transport and ordinary SOCKS negotiation.

## Requirements

### Requirement: Optional UDP transport selection
Client configuration SHALL accept optional `udp_transport` with values `tcp` or `quic`, and the CLI SHALL expose a matching override. When omitted, UDP SHALL inherit the final main transport after configuration and CLI merging. Invalid values SHALL be rejected without exposing credentials.

#### Scenario: Omitted UDP override
- **WHEN** no UDP transport is configured and the CLI overrides the main transport
- **THEN** UDP uses the final overridden main transport

#### Scenario: Explicit UDP override and invalid values
- **WHEN** a file or CLI explicitly selects UDP transport
- **THEN** the CLI UDP value takes precedence over the file UDP value, valid values are honored and invalid values produce a safe configuration error

### Requirement: Single SOCKS listener with per-network routing
One client instance SHALL accept TCP CONNECT and UDP ASSOCIATE on the same configured SOCKS control listener. TCP SHALL use the main transport and its configured Vision/mux mode; UDP SHALL use the effective UDP transport and report it accurately. UDP relay addresses SHALL continue to be returned through standard SOCKS negotiation.

#### Scenario: TCP Vision and QUIC UDP together
- **WHEN** a client runs with main TCP, mux disabled and UDP QUIC, and TCP and UDP requests use the same SOCKS listener
- **THEN** TCP uses Vision, UDP uses QUIC, bidirectional data succeeds and UDP control-connection closure releases its association

#### Scenario: Injected TCP-only outer rejects QUIC UDP
- **WHEN** a TCP-only injected transport interface receives a request whose effective UDP transport is QUIC
- **THEN** it rejects the unsupported operation rather than silently sending UDP through the main TCP transport
