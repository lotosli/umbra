## Why

The default `chrome-latest` fingerprint profile is still labeled as a seed profile, so it does not identify the Chrome version it represents or preserve local capture evidence. That weakens fingerprint review and makes it unclear whether a release binary actually carries the updated profile data.

## What Changes

- Add a versioned profile captured from the local Google Chrome 150.0.7871.47 browser on macOS.
- Keep `chrome-latest` aligned with that captured profile while preserving a versioned profile name for audits and rollback.
- Embed the default profile catalog into the compiled binary, while keeping repository TOML profile files as the data source.
- Add an explicit `supported_versions` profile field so Chrome's supported_versions GREASE value does not have to be inferred from supported_groups.
- Record capture evidence and current limitations, including that QUIC transport parameters are still inherited from the previous seed data until a QUIC capture is supplied.

## Capabilities

### Modified Capabilities
- `fingerprint-profiles`: Versioned, evidence-backed Chrome profile data and binary-embedded default profile loading.

## Impact

- Crates: `umbra-fingerprint`, `umbra-tls`, and profile-focused tests.
- Data: adds `fingerprints/chrome-150-macos.toml` and updates `fingerprints/chrome-latest.toml`.
- Release behavior: default profiles are embedded in the binary at compile time; changing built-in profile data requires rebuilding release artifacts.
- Security/runtime: TLS ClientHello profile fields are based on a local Chrome capture; QUIC fields remain marked as seed data until separate QUIC evidence is captured.
