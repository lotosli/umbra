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

Pending final artifact publication and paired deployment verification. Private endpoints, credentials, logs and recovery files stay outside the repository. The previous GitHub Actions jobs did not start because of account billing/spending restrictions; no remote CI pass is claimed.
