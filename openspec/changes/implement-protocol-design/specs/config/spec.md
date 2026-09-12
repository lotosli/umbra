## ADDED Requirements

### Requirement: Server config parsing
The system SHALL parse server TOML fields from `docs/protocol-design.md` section 16, including listen, udp_listen, private_key, short_ids, dest, server_names, max_time_diff, mldsa_seed, prebuild, padding_scheme, and tcp_evasion.

#### Scenario: Complete server config loads
- **WHEN** a server TOML file contains all documented fields
- **THEN** parsing and validation produce a ServerCfg with matching values

### Requirement: Client config parsing
The system SHALL parse client TOML fields from section 16, including server, transport, public_key, short_id, server_name, fingerprint, mldsa_verify, spider_path, socks_listen, mux, padding_scheme, and tcp_evasion.

#### Scenario: Complete client config loads
- **WHEN** a client TOML file contains all documented fields
- **THEN** parsing and validation produce a ClientCfg with matching values

### Requirement: Config validation
The system SHALL reject invalid base64 keys, invalid durations, empty required addresses, unsupported transports, and server names outside configured policy.

#### Scenario: Invalid key is rejected
- **WHEN** a config contains a non-base64 or wrong-length key
- **THEN** validation returns a configuration error before network startup

### Requirement: CLI override merge
The system SHALL merge CLI flag overrides over file-loaded configuration before validation.

#### Scenario: CLI listen overrides file
- **WHEN** a server config file specifies one listen address and the CLI specifies another
- **THEN** the effective ServerCfg uses the CLI listen address

### Requirement: Secret-safe configuration diagnostics
Configuration parse and validation errors SHALL omit source excerpts and user-provided values from Display, Debug, nested error causes, and CLI stderr. Diagnostics MAY retain line and column numbers and allowlisted field names.

#### Scenario: Syntax error on a secret-bearing line
- **WHEN** invalid TOML syntax occurs on a line containing a synthetic private key, seed, or short id
- **THEN** the returned error and CLI stderr contain none of those values while identifying the parse location

#### Scenario: Type error contains a secret value
- **WHEN** valid TOML provides a secret-bearing value with the wrong type, including inside an array
- **THEN** the diagnostic omits that value and any source excerpt
