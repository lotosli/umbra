## Context

The current fingerprint schema can express cipher order, extension order, supported groups, signature algorithms, ALPN, ALPS, padding target, JA3/JA4 identifiers, and QUIC transport parameter order. A local Chrome 150 capture showed that supported_versions now uses a different GREASE value from supported_groups, so deriving supported_versions from supported_groups is no longer faithful.

## Decisions

- **Use versioned profile files.** Store the captured profile as `chrome-150-macos` and keep `chrome-latest` as the default alias with the same profile fields. This keeps existing configs working while giving audits a stable versioned target.
- **Embed the built-in catalog.** Use `include_str!` against the TOML files for built-in profiles so release binaries contain the profile data they were tested with. Retain filesystem fallback for non-built-in local profiles.
- **Model supported_versions explicitly.** Add `supported_versions` to `FingerprintProfile` and have the TLS ClientHello builder serialize that list directly.
- **Do not claim QUIC capture parity yet.** The local capture covers TCP/TLS ClientHello. QUIC profile fields stay inherited from the seed profile and are documented as pending tcpdump/qlog validation.

## Risks / Trade-offs

- [Chrome ECH/application-settings extension contents may drift] -> The profile captures extension identifiers and supported data in the current schema, but the TLS builder still needs a future profile schema for full ECH GREASE payload parity.
- [Embedding profiles reduces live patchability] -> External filesystem fallback remains available for non-built-in profiles, while built-in defaults become reproducible release inputs.
- [QUIC profile is not newly verified] -> Keep the inherited QUIC fields explicit in capture evidence and avoid marking QUIC fingerprint work complete from this change.
