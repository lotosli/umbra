# 0.0.7 verification

Verified on 2026-09-13. The user authorized implementation, deletion of the old solo implementation, release 0.0.7, remote push, and direct online deployment/testing. Performance comparisons were explicitly omitted.

## Optimization proof

`crates/umbra-core/tests/vision_runtime.rs` runs the actual Umbra client/server with independent rustls endpoints. The TLS1.3 scenario exchanges 256 KiB in each direction and checks business integrity, protected-record suffix equality between inner TLS and outer TCP taps, and unchanged outer seal/open counters after handoff. TLS1.2 and non-TLS remain wrapped, and an unreachable target returns SOCKS failure before success.

`crates/umbra-core/src/vision_io_tests.rs` additionally covers roles, offsets, duplicate requests, FIN/REQ rejection, limits, partial cancellation, truncation, raw half-close and idle progress. The owned-record layer has independent tests for partial headers/writes, read-ahead, exact cipher accounting, poisoning, and key-owner destruction.

## Executed checks

| Check | Result |
| --- | --- |
| cargo fmt --all --check | Passed |
| cargo clippy --workspace --all-targets -- -D warnings | Passed |
| cargo nextest run --workspace --run-ignored all | 475 passed, 0 skipped |
| cargo xtask coverage | 94.77% line coverage; threshold unchanged at 90% |
| cargo deny check | Advisories, bans, licenses and sources passed |
| cargo xtask fingerprint-check | Available field/builder checks passed; does not claim full raw Chrome capture parity |
| OpenSpec validate --all --strict | 5 passed, 0 failed; existing unrelated archive-target informational note remains |
| vision_envelope ASAN fuzz | 10,000 runs, exit 0, no crash artifacts |
| vision_observer ASAN fuzz | 10,000 runs, exit 0, no crash artifacts |

Fuzz used cargo-fuzz 0.13.2, rustc 1.100.0-nightly (2026-09-12), explicit address sanitizer and instrumented standard library. Compile flags and linked ASAN symbols were checked. Raw local logs remain in ignored build output; they are not publication artifacts.

## Online verification

Native Apple Silicon and Linux x86_64 release binaries identify as 0.0.7. Both endpoints were deployed, and the Mac’s existing SOCKS entry now uses TCP solo (`mux=false`). Three serial HTTPS requests and six concurrent HTTPS requests succeeded; the expected server exit was verified. Both endpoints logged actual splice completion with `outer_records_unchanged=true`; the Mac had no new error lines during these requests. Restricted deployment backups and detailed live evidence are retained outside the source repository.

This demonstrates removal of the outer cryptographic layer after committed handoff. It does not measure a throughput/CPU speedup, prove inner ciphertext for malicious simulated TLS applications, or claim kernel zero-copy.

## Published release and remote CI limitation

[v0.0.7](https://github.com/lotosli/umbra/releases/tag/v0.0.7) is tagged at implementation commit `ab92cc6`. The two published platform binaries and SHA256SUMS match the deployed Mac/server artifacts. A final SOCKS request passed after deploying the exact committed-source builds; the server configuration hash stayed unchanged. Existing Xray and Hysteria 2 each independently passed HTTPS and expected-exit regression.

[PR #6](https://github.com/lotosli/umbra/pull/6) is intentionally unmerged. GitHub-hosted checks did not start because of the account billing/spending-limit condition, as recorded in [the failed run](https://github.com/lotosli/umbra/actions/runs/34760692973). This is an infrastructure limitation, not a remotely executed test result. Local checks above are the executed validation evidence.
