## 1. Standard handshake repair

- [x] 1.1 Correct all hybrid share and secret encoding/parsing paths; verify exact RFC field-layout and invalid-length tests.
- [x] 1.2 Normalize both QUIC profile paths before authentication and reject invalid direct QUIC API inputs; verify serialized versions, authentication and unchanged TCP advertisement.
- [x] 1.3 Update affected fixtures and add independent forced-hybrid standard-peer application-data tests; verify both endpoint roles where supported.
- [x] 1.4 Add optional UDP transport configuration/CLI override and single-listener dispatch; verify merge precedence, invalid values, real mixed TCP/UDP behavior and association cleanup.

## 2. Tests and coverage >= 90%

- [x] 2.1 Run formatting, strict clippy, workspace nextest and cargo-deny; resolve regressions without weakening checks.
- [x] 2.2 Run property tests, targeted parser/auth-carrier fuzz smoke tests and fingerprint checks; record the exact scope and capture evidence.
- [x] 2.3 Run the standards-repair coverage gate and verify at least 90%; record its revision scope and the user's later instruction not to rerun after the single-instance addition.

## 3. Release and deployment

- [x] 3.1 Document standard layout and coordinated upgrade, bump workspace to 0.0.8 and build/checksum release artifacts; verify binary versions.
- [ ] 3.2 Commit and publish the authorized release with validation evidence; verify remote release assets and report any external CI limitation accurately.
- [x] 3.3 Deploy 0.0.8 to both endpoints with retained rollback files; verify TCP Vision, mux/QUIC and authenticated HTTPS behavior.
- [x] 3.4 Rebuild and test Caddy with the corrected client on the server; if compatible, migrate web/QUIC/TCP endpoints, certificate renewal and service dependencies to public 80/443, then verify the live Clash path.
- [ ] 3.5 Verify final service state, remove failed temporary deployment components if necessary, and deliver usage/recovery notes and test evidence.
- [x] 3.6 Rebuild/redeploy the single-instance client change, consolidate configuration on SOCKS1080 and verify process/listener startup; omit further functional tests per the user's explicit instruction.
