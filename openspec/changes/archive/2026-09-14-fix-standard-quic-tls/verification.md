# 0.0.8 verification

Verified on 2026-09-14. The authorized change corrects the standard hybrid TLS layout and QUIC version offers; legacy wrong-order compatibility is intentionally omitted.

## Standards-repair checks before the single-instance addition

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| Workspace nextest through coverage, including ignored tests | 489 passed, 0 skipped |
| `cargo xtask coverage` | 94.83% line coverage, unchanged 90% threshold |
| `cargo deny check` | Advisories, bans, licenses and sources passed |
| OpenSpec strict validation | 6 passed, 0 failed; pre-existing unrelated archive informational note remains |
| `clienthello_parse` ASAN fuzz | 10,000 runs completed |
| `quic_auth_carrier` ASAN fuzz | 10,000 runs completed after fixing its empty-input harness slice |
| Fingerprint checks | Existing field/builder checks passed; no claim of complete Chrome parity |

The empty-input panic was in the fuzz harness's construction of its SCID test input, before calling the parser. Its offset is now bounded so empty input reaches the production code; the default empty seed and subsequent fuzz run complete. This harness-only correction does not change the release executable.

`crates/umbra-tls/tests/hybrid_interop.rs` uses independent rustls/AWS-LC peers forced to X25519MLKEM768. Both TCP and QUIC endpoint roles complete Finished verification and exchange protected application data in both directions, using the full default ClientHello profile including ECH GREASE. A classic X25519 negotiation cannot satisfy these tests. AWS-LC is enabled only as a test dependency; the production dependency tree does not include it.

## Real browser reference

The running GUI browser was confirmed as Chrome 153.0.8010.37 after the user restarted it. TCP was captured from that browser; QUIC was captured from a fresh headless process of the same installed version forced to a synthetic loopback origin. Raw samples, hashes, decoded fields and limitations are in `fingerprints/chrome-153-macos.capture.md` and its linked capture directory. No Chrome 152 sample or complete production Chrome 153 profile is claimed. Existing Chrome 150 defaults are not silently relabeled.

## Release and live checks

Four release binaries were built for Apple Silicon, Intel macOS, Linux x86_64 and Linux aarch64. The deployed Apple Silicon and Linux x86_64 binaries identify as 0.0.8 and match local artifact SHA-256 hashes. Both Mac clients and both server modes were upgraded together with private rollback backups. Identity keys and credentials were retained.

Caddy 2.11.4 with caddy-l4 0.1.2 now recognizes the corrected real QUIC ClientHello. The authorized migration preserved web covers, HTTP/2 and HTTP/3 fallback, ACME webroot, renewal hooks, and service dependencies. TCP and UDP share public port 443 by SNI; backend listeners remain private. Real authenticated TCP Vision, TCP mux, QUIC and Hysteria2 clients each passed 512 KiB download, 512 KiB upload/echo integrity and external HTTPS checks. Independent Mihomo processes on the Mac verified the Umbra QUIC, Xray and Hysteria2 routes with the expected exit. The normal Clash selection was not replaced by the test processes.

Full configuration, private deployment backups and live diagnostic records remain outside the source repository. These checks establish interoperability and the tested live paths, not a throughput comparison, exhaustive network-fault tolerance, or complete Chrome fingerprint equivalence.

## Final single-instance addition and deployment

The user subsequently selected a true single SOCKS client with `transport="tcp"`, `udp_transport="quic"`, `mux=false`, and port 1080. The file and CLI override precedence, safe invalid-value handling, both effective-transport branches and reported outcomes have regression coverage. A real same-listener integration test runs TCP Vision and QUIC UDP concurrently, verifies bidirectional data, the raw TLS handoff, negotiated UDP relay address and release after control-channel closure while TCP continues transferring.

Before the user's instruction to stop further testing, targeted core/CLI nextest passed 226 tests, the two ignored core end-to-end tests passed, and strict core/CLI clippy and formatting passed. The full workspace coverage figure above was measured before this final addition; it was not rerun and must not be presented as a final-revision measurement.

The final four binaries were rebuilt. The Mac now runs only `com.umbra.client` with one config and SOCKS1080. The server now runs only the main Umbra service with both TCP and QUIC listeners, behind Caddy. The temporary dedicated QUIC service/config and Mac agent/config were removed after backup. Final deployment checked executable versions/hashes and service/listener startup only; no additional functional or performance retest was run, as explicitly requested by the user.

## Publication

Published v0.0.8 manually from local artifacts and merged the implementation into main as `ddcb302`. All four executable assets and SHA256SUMS match the uploaded GitHub SHA-256 digests. Commits contain `[skip ci]` as explicitly requested; no Actions run was created for the implementation commit. README and both language editions of the client/server guide were updated.
