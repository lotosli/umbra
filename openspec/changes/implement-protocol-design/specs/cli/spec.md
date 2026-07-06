## ADDED Requirements

### Requirement: CLI subcommands
The binary SHALL provide `server`, `client`, and `keygen` subcommands.

#### Scenario: Help lists subcommands
- **WHEN** `umbra --help` is executed
- **THEN** help output lists `server`, `client`, and `keygen`

### Requirement: Server flags for all options
The `server` subcommand SHALL expose flags for every documented server config option: listen, udp_listen, private_key, short_ids, dest, server_names, max_time_diff, mldsa_seed, prebuild, padding_scheme, and tcp_evasion.

#### Scenario: Server flags override config
- **WHEN** `umbra server` is run with a config path and optional flags
- **THEN** every supplied flag overrides the corresponding file value

### Requirement: Client flags for all options
The `client` subcommand SHALL expose flags for every documented client config option: server, transport, public_key, short_id, server_name, fingerprint, mldsa_verify, spider_path, socks_listen, mux, padding_scheme, and tcp_evasion.

#### Scenario: Client flags override config
- **WHEN** `umbra client` is run with a config path and optional flags
- **THEN** every supplied flag overrides the corresponding file value

### Requirement: Key generation output
The `keygen` subcommand SHALL generate and print base64 X25519 private/public keys and ML-DSA seed/public verification material without logging secrets elsewhere.

#### Scenario: Keygen prints parseable keys
- **WHEN** `umbra keygen` is executed
- **THEN** the printed base64 values decode to the documented lengths

### Requirement: CLI validation failures
The CLI SHALL report invalid config or flag combinations with non-zero exit status and without starting network listeners.

#### Scenario: Invalid transport exits
- **WHEN** `umbra client --transport invalid` is executed
- **THEN** the command exits with an error before runtime startup
