## 1. Authorized specification and baseline

- [x] 1.1 Record the approved review scope, map all scenarios to checks, and pass strict OpenSpec validation before implementation.
- [x] 1.2 Preserve source/build identity and baseline measurements; locate private endpoint backups and verify installed state without exposing credentials.

## 2. Accelerated reusable cryptography

- [x] 2.1 Enable portable runtime-detected ARM64 AES/PMULL builds and zeroizing dependency features; verify accelerated and forced-software standard vectors.
- [x] 2.2 Add reusable AEAD contexts and caller-buffer operations; test multi-nonce/all-suite agreement, cleared-context rejection, authentication-failure clearing and measure cached versus stateless work.

## 3. Native QUIC throughput

- [x] 3.1 Apply explicit stream/send/aggregate policies to both endpoints with budget ownership; test config bounds, serialized parameters and real transfer; compare changed fields to raw Chrome capture evidence.
- [x] 3.2 Correct consumption-rate growth under delayed sampling; test low RTT at 50ms ticks, idle/slow consumption, budget refusal and last-owner release.
- [x] 3.3 Implement bounded shared receive batches, byte ceilings, physical batching and anonymous saturation counters; test >16-datagram bursts, metadata/order, saturation isolation and release; measure ingress overhead.

## 4. Independent UDP and connection ownership

- [x] 4.1 Separate pending output/target setup from UDP association receive/control/idle progress over TCP and QUIC; test reverse progress under blocked writes, slow setup, cancellation and exact partial envelope resumption.
- [x] 4.2 Share client QUIC endpoints across associations while preserving connection ownership; test sibling closure, reuse, failed establishment and complete runtime shutdown.

## 5. Mux scheduling and startup

- [x] 5.1 Introduce deduplicated dirty/blocked/participant scheduling and coalesced credit; test idle-stream scaling, round-robin progress, zero-credit wakeup, cancellation and FIN/RST/flush settlement.
- [x] 5.2 Tune funded mux startup within configured maxima; compare startup/warmed transfers and mixed-client fairness with exact bytes and retained commitments.
- [x] 5.3 Reduce connection-pool establishment lock scope with explicit pending reservations; verify concurrent deduplication, capacity including pending opens, failure/cancellation and shutdown.

## 6. TLS and Vision data path

- [x] 6.1 Transfer independent application traffic-key owners and reuse record buffers; test concurrent directions, vectors, oversized headers, clean/truncated EOF and cancellation without resealing.
- [x] 6.2 Encode/decode wrapped Vision with borrowed or transferred payload ownership and reusable outputs; verify byte-for-byte envelopes, padding and handoff/half-close tests.
- [x] 6.3 Batch validated raw records with retained partial suffixes and an activity clock; test malformed/truncated input, continuing partial activity, write-zero and reverse half-close; measure raw forwarding.

## 7. 测试与覆盖率 >= 90%

- [x] 7.1 Add/update scenario tests, parser properties and fuzz targets as needed; run bounded targeted fuzzing and record exact commands/results.
- [x] 7.2 Pass cargo xtask ci, workspace nextest, strict OpenSpec validation and fingerprint checks with >=90% line coverage; do not relax thresholds or assertions.
- [x] 7.3 Run serial release-mode before/after diagnostics for cipher, native queues/windows, mux startup/steady/mixed streams and raw/wrapped record work; record conditions and limitations.

## 8. Alpha release and deployment

- [x] 8.1 Set workspace/internal dependencies and lockfiles to 1.0.0-alpha, update docs/release notes and verify CLI version/config compatibility.
- [ ] 8.2 Build supported macOS/Linux distribution artifacts from reviewed source, verify version/digests, retain exact source identity and mark the release prerelease; inspect remote checks without bypassing protected gates.
- [x] 8.3 Back up and deploy the server and Mac client atomically; verify installed hashes, normal HTTPS via Vision/mux/QUIC, UDP, shutdown and rollback readiness, then record sanitized final evidence.
