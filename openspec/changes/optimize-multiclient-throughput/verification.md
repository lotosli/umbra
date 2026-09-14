# 0.0.9 verification

Current implementation: `201bca93746c850274115636eaf1f30955025e4e`. The final binaries are built, deployed and checked against their uploaded SHA-256 digests. Their identity and final online checks are recorded in the last section. Earlier release sections retain the initial cut's historical evidence and hashes, which the final bundle supersedes.

Final public delivery is verified: [v0.0.9](https://github.com/lotosli/umbra/releases/tag/v0.0.9) is non-draft/non-prerelease, published at 2026-09-14 22:17:06 UTC, with tag target `a9ce1c56dfe66a827d7b869ad122a20bc5f87147`. Its production source tree is identical to implementation commit `201bca9`. Both native deployed-platform binaries and SHA256SUMS were downloaded again from the public release and their hashes matched. Subsequent evidence/task-checklist commits change documentation only.

## Scope and authorization

The user authorized the discussed throughput/resource optimization, direct deployment and testing on the unused product, and the BBR trial with quinn 0.11.12 / quinn-proto 0.11.18. Each implementation point has a preceding code review and evidence in prechange-review.md. A single strong evidence point was used rather than an exhaustive performance matrix.

## Local gates

- cargo xtask ci passed: formatting, clippy with warnings denied, dependency advisories/licenses/sources, fingerprint field/production-builder self-checks and instrumented tests.
- 513 tests passed, including ignored e2e/diagnostic cases; line coverage 94.94% (22,472 lines, 1,136 uncovered). The coverage floor remains 90%.
- Strict OpenSpec validation passed all eight items; the pre-existing archive-info warning on another change is unrelated.
- mux_frame AddressSanitizer fuzzing completed 10,000 runs, including adaptive SETTINGS/CREDIT seeds, without a crash.
- Quinn is locked to 0.11.12 / proto 0.11.18. rustls was upgraded to 0.23.45 to resolve RUSTSEC-2026-0285; yanked transitive chacha20/der patches were updated. No advisory was ignored.

The fingerprint command is a field/builder regression check; it does not prove complete Chrome packet/traffic equivalence. ClientHello construction and client QUIC transport-parameter settings were not modified by the application congestion selector.

## Focused evidence

The reverse-backpressure regression failed before the relay change (a five-byte reply was blocked by an unread forward destination), and passes afterward. The existing injected-outer half-close test caught an eager-flush regression during development; the final independent relay preserves the prior read/write/shutdown contract.

Three real client runtimes, including two sharing one credential and one with a different credential, completed concurrent SOCKS transfers and returned all server commitments to zero after shutdown. Asymmetric adaptive receivers transferred 64KiB one way and 512KiB back with exact payload checks. Batch receive filled three QUIC slots in one call without changing datagram boundaries. Actual connected QUIC controller objects matched each selected BBR/Cubic/NewReno policy.

## Synthetic throughput

Release-mode tests ran serially (`--test-threads=1`) with an 8MiB payload, no padding, pipelined propagation delay and a 1Gbps serialization model. Transfer time includes window growth. These are emulator observations, not NIC/WAN speeds or guaranteed speedup percentages.

| Added RTT | Fixed mux median | Adaptive mux median |
|---|---:|---:|
| 0 ms | 635.163 Mbps | 958.594 Mbps |
| 50 ms | 38.173 Mbps | 218.412 Mbps |
| 100 ms | 20.101 Mbps | 116.592 Mbps |

Exact samples are in final-mux.txt. The initial fixed-window samples are in baseline-mux.txt. The zero-added-delay case still includes software/timer overhead.

Raw forwarding processed 134,397,952 synthetic bytes in roughly 9–11ms in the final samples. The buffer change eliminates per-record scratch allocation; this does not establish a significant separate WAN speedup. Samples are retained in baseline-raw.txt and final-raw.txt.

## Online baseline

Before deployment, the installed 0.0.8 pair completed authenticated requests to a temporary loopback TLS1.3 target on the server. The main Vision path varied from about 8.9 to 25.5Mbps across three 64MiB downloads; a separate TCP mux sample was about 10Mbps and QUIC about 25.8Mbps. This variation prevents attributing a small later difference solely to this release. Linux TCP BBR/fq and the public TCP listener's BBR were already active before the change.

## Release and deployment

Implementation commit: `e9c4f6d`. Four release binaries were built for Apple Silicon, Intel macOS, Linux x86_64 and Linux aarch64. Apple Silicon and Linux x86_64 were executed on the actual endpoints; the other architectures were build/link verified.

Both the existing Linux service and Mac LaunchAgent now run 0.0.9. Running executable paths/versions and SHA-256 hashes match the built artifacts. Original configurations, service definitions and versioned executables were retained privately for recovery. The single SOCKS1080 setup keeps TCP Vision plus QUIC UDP, with QUIC BBR explicitly selected on both endpoints; Linux TCP BBR/fq was already enabled and was not changed.

Online checks after deployment:

- An actual HTTPS request through SOCKS1080 returned HTTP 200 with normal certificate verification.
- A 320-byte UDP payload traversed the main SOCKS association over QUIC and matched its echo exactly.
- Each mode completed a 64MiB download from the same temporary loopback TLS1.3 target on the server.

| Mode | Observed 0.0.9 goodput |
|---|---:|
| Main TCP Vision | 25.395 Mbps |
| Adaptive TCP mux | 26.462 Mbps |
| QUIC BBR | 21.607 Mbps |

The earlier TCP mux sample was about 10Mbps, but the WAN varied during collection, so the online values are observations rather than controlled speedup claims. In particular, the QUIC result was below the earlier Cubic sample: this does not establish a BBR benefit. The explicit BBR trial remains selected with Cubic available as a configuration alternative. Vision logs confirm raw-splice completion with stopped outer-record counters. Temporary benchmark targets and temporary client processes were removed.

Deployed artifact hashes:

```text
c5d3dfa07db57cbdf83d3b3b6e123ebab00f182669223f3006cc18aabe2d7fe5  umbra-aarch64-apple-darwin
3852acec03d1d325dc0a05a6609e0604ed3b95173b55f0cdf5313c9628b8586f  umbra-aarch64-unknown-linux-gnu
967f003dfc7b0b038273bbe4bb485547620212aa97f25254b36d93ffa21ba8b8  umbra-x86_64-apple-darwin
eb48c7e7f1d948936ba878cf7090e65c5371ac1421fffddb56083e89a53343f2  umbra-x86_64-unknown-linux-gnu
```

## Remote CI and integration

PR #7 contains the implementation and evidence. Its GitHub Actions jobs were not started because of account billing/spending restrictions; the check annotations explicitly report failed payments or a spending limit. These are not remotely executed test failures, and no remote CI pass is claimed. Full local gates passed as recorded above. Main-branch integration and OpenSpec archive remain pending the remote-CI/human integration step; no protected gate is bypassed.

Private endpoints, credentials, detailed logs and recovery files remain outside the repository.

## Published artifacts

The initial v0.0.9 cut used source commit `07a97db` (implementation tree `e9c4f6d`; the intervening commit changed documentation only). Its five uploaded digests matched that initial bundle. The final bundle below supersedes those artifacts; original binaries, metadata and tag reference were retained privately for recovery.

## Completion-audit measurements

The later audit adds evidence without changing production code or replacing the deployed binaries. See completion-audit.md for requirements still open; publication/deployment is not treated as completion of those requirements.

`cargo test --release -p umbra-inner --test mixed_throughput -- --ignored --nocapture` exercises four outers in three groups. Two outers share one credential group and use four/one streams. All upload through a common 500Mbps serializer; path RTT/rate pairs are 20ms/100Mbps, 20ms/100Mbps, 100ms/1000Mbps and 200ms/10Mbps. Each outer sends 4MiB. The last receiver retains actual payload chunks without returning credit until the 100ms client's complete payload has arrived. The server commitment pool is 64MiB with 32MiB group caps, and the adaptive aggregate maximum is 8MiB. Reverse control traffic has independent serialization.

| Client | Fixed mux Mbps | Adaptive mux Mbps | Credit-wait time fixed / adaptive |
|---|---:|---:|---:|
| 0: 20ms, 100Mbps, four streams | 95.563 | 96.118 | 272 / 104 ms |
| 1: same group, 20ms, 100Mbps, one stream | 78.413 | 94.391 | 408 / 114 ms |
| 2: 100ms, 1000Mbps, one stream | 20.528 | 68.914 | 1573 / 334 ms |
| 3: initially paused, 200ms, 10Mbps | 6.328 | 8.685 | 5164 / 1470 ms |

All bytes matched; the paused receiver held at most its initial 256KiB stream credit, other groups completed, and all commitments returned to zero. Aggregate goodput over the full makespan was 25.313 / 34.740Mbps; this includes the deliberate pause and long slow-client tail and is not a link-utilization measurement. Full per-client/group output, output-flush wait and receive windows are in final-mixed.txt. Credit wait counts are repeated waits for incoming control when all unfinished streams lack credit, not distinct stalls or network packet counts. These results show progress and isolation, not equal group scheduling shares.

Full `cargo xtask ci` passed again: 514 tests including the new diagnostic, 94.94% line coverage; fmt, clippy, dependency and fingerprint checks passed. The additional test changes no production executable source.

### Current TCP Vision bottleneck observation

A further 64MiB synthetic TLS1.3 download through the installed TCP Vision client yielded 26.464Mbps. Over approximately 20.3 seconds the Mac client used 0.32 CPU seconds (1.58% of one core); server Umbra used 0.08 CPU seconds over the approximately 20.75-second sampling period (0.39% of one core). Peak sampled server Umbra RSS was about 11.9MiB. Caddy and the temporary target each used about 0.05 CPU seconds. These are one-transfer process observations, not CPU cost predictions under full server saturation.

Public TCP samples showed BBR, roughly 171ms RTT, a peer receive window reaching 4,194,240 bytes, and delivery-rate samples near 28Mbps. A late established-state sample reported 57,958,008 transmitted bytes, 42,132,340 acknowledged bytes and 14,465,428 retransmitted bytes. These counters are not a packet-loss percentage; sampling stops covering a socket when it leaves ESTABLISHED, and no full-transfer retransmission ratio is asserted. The evidence points toward network congestion/loss in this observation, not a saturated Umbra CPU or the old mux window (Vision does not use it).

An adjacent direct SSH TCP transfer from the same server, with compression disabled and every one of the 64MiB zero bytes verified, yielded 25.729Mbps including SSH setup. It uses a different port and encryption stack, so it is only a same-endpoint reference, not a controlled port-identical baseline or proof of the host's maximum bandwidth. Together these observations do not justify a TLS bridge rewrite to improve the currently observed Vision download.

The temporary TLS target, keys, certificate and sampler marker were removed. The service remains active with the same verified 0.0.9 Linux executable hash; no application or host network configuration changed. Private addresses, credentials and detailed per-sample operational data remain outside the repository.

## Native QUIC admission correction (included in the final bundle)

The `native_quic_admits_and_transfers_with_minimum_memory` regression first failed on the released implementation: a valid 16MiB configuration produced `authenticated resource budget exhausted` and could not finish the QUIC handshake within five seconds. After the reviewed correction, the same real authenticated connection completes a byte-exact 512KiB upload and echo, keeps commitments within 16MiB, and releases all owners after shutdown (about 0.21 seconds in the focused local run).

The initial native connection now reserves 3MiB transport staging + 10,000,000 bytes send storage + up to 2,500,000 bytes aggregate receive credit, totaling 15,645,728 bytes at normal settings. The old 64MiB precommit admitted only four idle connections per default 256MiB group; the new initial terms can fund seventeen before additional application-stream/UDP storage. This is a capacity calculation, not a seventeen-client performance claim. Each accepted stream is charged separately before starting its application handler.

The receive controller counts actual native stream reads, observes consumption and RTT every 50ms, and funds an increase before calling Quinn's cumulative aggregate receive setter. Focused tests verify growth from 2,500,000 to 5,000,000 and 10,000,000 bytes, rejection of an unfunded increase, no idle/slow-consumer growth, configured maxima and retention of the entire grant until the last reader drops. Client QUIC transport parameters are unchanged. The default native per-stream limit remains 1,250,000 bytes; this correction does not claim to remove the separate single-stream high-BDP ceiling.

This correction is included in the final rebuilt/deployed bundle below. The earlier hashes remain historical evidence of the initial implementation.

For the corrected source, `cargo xtask ci` completed successfully: 517 tests passed and line coverage was 94.97% (22,678 lines, 1,141 uncovered). The new quic_resources module reached 100% line coverage. Strict OpenSpec validation passed all eight items. Two pre-existing configuration tests received nextest `LEAK` labels in the full instrumented run (a process-output pipe observation, not a heap-leak diagnosis); their assertions passed. Their code only parses configuration, and targeted sequential reruns both with and without LLVM instrumentation passed without the label. No test or gate configuration was relaxed.

## Credential-group ready-work scheduling (included in the final bundle)

The preceding R14 review identified that independent Tokio tasks have no credential identity. A deterministic single-worker fixture with 90,000 equivalent continuously ready polls measured 80,000 for the group with eight tasks and 10,000 for the group with one task. With the shared ready-work gate, the same fixture measured 45,001 / 44,999. Tests also verify that blocked work relinquishes permits, dropping queued/granted work removes it, concurrent duplicate wakes do not lose permits, and one ready group can obtain all four permits in a four-permit fixture.

The gate is connected to authenticated Vision relay, TCP mux outer/driver/target/TLS record tasks, native QUIC runtime-spawned drivers/streams and UDP target readers. Futures stay in their original Tokio tasks, preserving cancellation ownership. The actual three-client TCP test observes two scheduler identities for credentials [1,1,2], nonzero processing in each, and zero live/queued/active gates after shutdown. The actual low-memory native QUIC test also observes driver processing through the public snapshot and complete task cleanup. Unauthenticated classification/fallback are not gated.

Run the readiness checks with `cargo test -p umbra-core work::tests -- --nocapture`. Run the explicit record-cost diagnostic with `cargo test --release -p umbra-core --lib work::tests::measure_record_work_with_and_without_group_gate -- --ignored --nocapture`. The latter seals 4,096 AES-128-GCM records of 16KiB each, yielding between records. One final-source sample was 0.409635 seconds without the gate and 0.379497 seconds with it (about 1,311 / 1,415Mbps of payload processing). Fixed order, warmup and measurement variation prevent attributing the difference to a speedup; this sample does not establish WAN throughput or a precise scheduling overhead percentage. It shows no large added cost in that particular record-processing workload. Raw output is in group-work.txt.

Full `cargo xtask ci` on the final scheduler source passed all 523 tests; line coverage was 95.01% (23,245 lines, 1,160 uncovered). A config-only test, `scenario_invalid_transport_exits_before_runtime_startup`, received a non-failing nextest pipe-leak label in the full instrumented run; its targeted instrumented rerun passed without that label. No thresholds, exclusions or test assertions were relaxed. Production artifacts still need to be rebuilt and deployed after all remaining observation work.

## Pipeline diagnostics and final implementation gates

R15 precedes the optional diagnostic implementation. The registry contains only typed modes, opaque group/observation numbers and numerical counters. It retains active observations and at most 128 closed entries, distinguishes target from outer I/O, records pending polls and owned-await durations, tracks target setup including cancellation, samples mux/native credit and exposes group budget admission/growth refusals. Unsupported measurements are None. Collection/reporting defaults off; enabled server reports use async stderr at the configured interval (1–3600 seconds).

Focused evidence includes a duplex I/O test with a cancelled pending read, exact two-byte read, partial four-byte write, blocked follow-up write and eventual five-byte output; separate target counters remain 3/4 bytes. Last-observer drop closes the record, and 200 completed observations retain only the newest 128. The real three-client TCP test verifies two credential groups, separate transport/target counters, exactly 48 bytes in each target direction and closed records after shutdown. The real low-memory QUIC test verifies exactly 512KiB in both target directions, nonzero outer bytes and native credit samples; callback wait duration remains explicitly unavailable. Budget tests verify refusal causes and zero final commitments.

The full run found a pre-existing injected-outer test race: its fake server dropped the outer immediately after one logical stream FIN. It now retains that outer until client completion, preserving all byte, target, half-close and success assertions; production errors are not suppressed. The final `cargo xtask ci` run passed all 525 tests with no failed/leaky tests and 95.02% line coverage (23,772 lines, 1,183 uncovered). The diagnostics module reached 99.32% line coverage. No test/gate thresholds were changed. Release artifacts and paired deployment still require reconciliation with this final implementation.

## Final bundle and online verification

`cargo xtask dist` built all four Mac/Linux targets from clean implementation commit `201bca9`. The final documentation changes do not modify that production source tree. Both deployed executables identify as 0.0.9. The Linux running executable was hashed through `/proc/<pid>/exe`; the Mac running text inode matches the installed file. Both match the new bundle, and the upload API reports matching digests for all four binaries and SHA256SUMS.

```text
2949caef2a4321f60ad340f6b457e2a874ba79ebf0fc68e208e96d67bd2f62b1  umbra-aarch64-apple-darwin
6a516003fb3b27b3faf7bcef97f3e910d08bc4d26ea1b37cf678007e410c8a64  umbra-aarch64-unknown-linux-gnu
6e5c3d923d03af3bb7f48c9558f66d94234fdd7506d2fc50082bccd6b41a07aa  umbra-x86_64-apple-darwin
22dee3681f6ffec0bd3cdca25563ce60e863eb8fc92dcef950f1fed547c24dfd  umbra-x86_64-unknown-linux-gnu
```

Online acceptance on the final implementation:

- Normal certificate-verified HTTPS through the main SOCKS listener returned 200.
- Each transport completed a 64MiB TLS1.3 download from the temporary server-loopback target. The main Vision download also checked every payload byte.
- Main-listener QUIC UDP echoed both a 320-byte payload and an empty payload exactly.
- 135 diagnostic reports were observed, including TcpVision, TcpMux and Quic, positive target-byte counters and native credit samples. Reports were checked against private configuration values and contained no addresses/credential/session fields.
- Diagnostic collection was then disabled by restoring the original configuration. A restoration-script permission mistake temporarily prevented the unprivileged service from reading it; original permissions were restored from backup, startup failure state cleared, and readiness and the running binary hash rechecked. With diagnostics disabled, Vision, TCP mux and native QUIC each passed a new certificate-verified HTTPS 200 check.
- Server and Mac services are active, existing TCP Vision plus QUIC UDP routing is retained, both Quinn endpoints select BBR, and existing Linux TCP BBR remains unchanged. Temporary targets, keys/certificates, client processes and credential-bearing test configurations were removed. Private backups retain original executable/configuration state for recovery.

| Final online mode | Observed goodput |
|---|---:|
| TCP Vision | 25.921 Mbps |
| Adaptive TCP mux | 26.850 Mbps |
| QUIC BBR | 22.625 Mbps |

These are one-path observations, not controlled speedup claims; in particular, BBR has not demonstrated an advantage over the earlier Cubic sample. The current Vision result remains close to the adjacent same-endpoint direct SSH reference (25.729Mbps). No claim is made that a code change can exceed the measured path capacity.

The final-source release-mode mux diagnostic was rerun serially with the same 8MiB/1Gbps model. Medians over three samples were fixed/adaptive: 593.676/960.007Mbps at zero added RTT, 38.132/218.652Mbps at 50ms, and 20.058/116.010Mbps at 100ms. Exact samples are in final-mux-after-audit.txt. These demonstrate the window mechanism on the emulator, not physical WAN bandwidth.

Public release visibility and final tag identity were verified as the delivery step. GitHub Actions annotations still state that jobs were not started because account payments/spending limits block execution; the PR remains unmerged. All required local gates passed, and no remote CI success or protected-gate bypass is claimed. Archive follows any later source integration.

Private recovery instructions and receipts identify the original executable/configuration backups on both endpoints. Recovery preserves configuration ownership and permissions, atomically replaces the executable, restarts the existing Umbra service/LaunchAgent and checks the running executable plus actual SOCKS routing. The original tag object remains retained locally, and the initial release binaries/metadata are kept privately. No credential-bearing test configurations or temporary benchmark targets remain.
