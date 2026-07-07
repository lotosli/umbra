## 1. Profile Data

- [x] 1.1 Add `fingerprints/chrome-150-macos.toml` from the local Google Chrome 150.0.7871.47 TLS ClientHello capture.
- [x] 1.2 Update `fingerprints/chrome-latest.toml` to track the Chrome 150 profile fields.
- [x] 1.3 Add capture evidence documenting source, date, parsed fields, JA3/JA4, and QUIC limitations.

## 2. Loader and Builder

- [x] 2.1 Embed built-in profiles in `umbra-fingerprint` while retaining filesystem fallback for non-built-in profiles.
- [x] 2.2 Add explicit `supported_versions` profile data and serialize it from `umbra-tls`.
- [x] 2.3 Preserve ALPS/application-settings serialization for the Chrome 150 extension identifier.

## 3. Tests and Validation

- [x] 3.1 Add tests that load the versioned Chrome 150 profile and prove `chrome-latest` tracks it.
- [x] 3.2 Update fingerprint self-check expectations for the captured Chrome 150 profile.
- [x] 3.3 Run `cargo fmt --all`, targeted fingerprint/TLS tests, and `npx @fission-ai/openspec@latest validate --all --strict`.
