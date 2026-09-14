# 0.0.9 verification

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

[v0.0.9](https://github.com/lotosli/umbra/releases/tag/v0.0.9) is published at source commit `07a97db` (implementation tree `e9c4f6d`; the intervening commit changes documentation only). GitHub-reported SHA-256 digests for all four binaries and SHA256SUMS match the local release artifacts. Both deployed binaries match those same artifacts.

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
