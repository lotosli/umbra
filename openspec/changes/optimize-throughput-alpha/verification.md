# Alpha throughput verification

## Baseline before implementation

Source: bc967e6, implementation 201bca9, version 0.0.9. The original two uncommitted documentation edits describe the user-approved >=1GiB server-memory assumption and remain preserved. Baseline release binaries and private deployment receipts are retained outside git.

On the local ARM64 Mac, the existing release-mode `work::tests::measure_record_work_with_and_without_group_gate` seals 4,096 16KiB AES-128-GCM payloads (64MiB), including allocation and yield overhead. Three ungated baseline samples were 1205.377, 1259.555, 1253.680Mbps (median 1253.680). In an isolated build with `--cfg aes_armv8 --cfg polyval_armv8`, samples were 5555.901, 6156.176, 6169.928Mbps (median 6156.176). Ratio 4.910; no WAN improvement is inferred. Existing release artifact fingerprints had empty rustflags. All 16 crypto primitive/vector/property tests and the in-place all-suite comparison passed under the accelerated build.

The existing release-mode mux diagnostic models a 1Gbps pipelined link and transfers 8MiB including startup/finish. Medians over three samples (fixed/adaptive Mbps): RTT0 693.104/964.709; RTT50ms 38.884/224.233; RTT100ms 20.354/117.002. These are emulator results, not physical network measurements.

## Scenario verification map

- Reusable/cleared/accelerated contexts: crypto vector/property/context tests and forced-software runs.
- Record ownership/cancellation/header/EOF: TLS record, owned_tls, tls_io and Vision tests.
- Native policy/sample cadence: resources/config/transport-parameter and quic_resources tests plus authenticated native runtime transfers.
- Batch burst/saturation: QUIC queue/adapter/routing tests and ingress diagnostic.
- UDP blocked writer/setup/endpoint sibling: UDP association state and actual TCP/QUIC runtime tests.
- Ready mux/credit/startup: mux driver/session tests and startup/warmed/mixed-stream diagnostics.
- Vision borrowed encoding/raw activity: proto envelope properties, owned record and raw relay tests.
- Alpha identity/deployment: CLI version tests, distribution checksums and private paired-deployment receipts.

Final outcomes are appended only after execution; task checkboxes are not substitutes for test evidence.

## Completed crypto implementation

Dependency inspection found incomplete ARM PMULL/autodetect zeroization in the old POLYVAL generation. The implementation therefore uses stable aes-gcm 0.11.1, aes 0.9.3, ghash 0.6.0 and polyval 0.7.3 with propagated zeroize features and default runtime hardware detection. Compile-time ZeroizeOnDrop bounds cover every retained cipher. No custom unsafe cryptographic code was added. MIT/Apache licenses remain compatible; the expected dual API generations retained for ChaCha are documented in deny.toml.

Commands passed: `cargo test -p umbra-crypto --test crypto_primitives` (16), `cargo test -p umbra-crypto --lib in_place_tests` (1), `cargo test -p umbra-crypto --test reusable_aead` (2 plus one explicitly ignored diagnostic), and crypto all-target clippy with warnings denied. A separate build with `RUSTFLAGS='--cfg aes_backend="soft" --cfg polyval_backend="soft"'` passed all 18 integration tests. Reused-context output was compared with ring for all three algorithms, seven message lengths and distinct nonces; wrong AAD/tags, invalid lengths and explicitly destroyed contexts were checked.

Three serial warmed release samples of `measure_reusable_context_and_buffers` (64MiB, AES-128-GCM) had median stateless/cached+buffer-reuse rates: 1KiB messages 13,839.614/36,031.000Mbps; 16KiB messages 38,761.726/43,256.214Mbps. These subsecond CPU/memory diagnostics compare API work in the new dependency family, not full TLS records, wire throughput or the old scheduler diagnostic's absolute speed.

The existing Mac service and server service were read-only checked: both run 0.0.9 and their executable digests match the retained final 0.0.9 artifacts. Private access context and previous receipts were located; no deployment has happened yet.

## Native QUIC and UDP implementation

Both endpoints now select explicit stream/send/aggregate windows. Public default receive fields are 6MiB/15MiB, with bounded configuration overrides; send storage defaults to at most 32MiB. Group ceilings clip initial send/receive commitments (one quarter/eighth respectively). Actual client Initial packets were captured on loopback, decrypted/reassembled and their four flow-control parameter encodings compared against the checked-in real Chrome 153 ClientHello. Defaults match those exact fields; a 32MiB override is also present on wire. This is not a claim of full Chrome parity: the pre-existing full-TLS/QUIC evidence limitations remain.

Both client and server count native reads and own funded window controllers. A delayed sample compares consumption rate against RTT instead of rejecting all 50ms samples on short-RTT paths. Handshake time is excluded from the first consumption epoch. Tests cover 10ms RTT with 50ms sampling, 15→30→60→64MiB funded growth, slow/idle refusal and last-reader ownership.

Ingress now retains one shared allocation per same-flow batch, preserves per-packet ECN/destination metadata, uses four physical receive slots and bounds retained payload allocation to 1MiB plus 64 batch descriptors per flow. Last packet ownership retains the authenticated lease. Anonymous sampled counters expose retained/peak bytes and dropped datagrams/bytes. Tests cover a 48-packet GRO burst sharing one allocation, byte/batch saturation, healthy sibling progress, empty datagrams, metadata bounds, and routing/prefetch/fallback regressions.

TCP and QUIC UDP associations retain partial carrier writes in their select loops rather than awaiting them inside an input branch. The reusable QUIC envelope writer coalesces length/address/payload in one final buffer and preserves its offset across cancellation. New-target setup and pending sends are bounded and independently polled; target readers share the activity clock and are joined on normal shutdown. Client connections share family-specific endpoints while each association owns only its connection; receive controllers and read owners keep the shared budget alive.

Focused checks passed: the original 17 QUIC routing/resource tests; a subsequent 17-case selection covering real TCP/QUIC UDP runtime, actual Initial parameters, low-RTT growth, shared endpoint sibling transfer, byte-exact partial envelope resumption, slow/failed setup and physical receive metadata. Two new deterministic regressions deliberately fill a 64-byte carrier buffer: another UDP request still reaches its target while the reply writer is blocked, and control EOF cancels the client's blocked write. Abandoning the intentionally unread partial reply correctly reports BrokenPipe; that error is asserted, not suppressed. Core/inner/transport all-target clippy passes with warnings denied.

The explicit release `quic_ingress::tests::measure_shared_batch_ingress` compares per-packet and shared-batch admission in the new bounded queue. One serial sample transferred/asserted 157,286,400 bytes in 0.091842s / 0.051380s, with zero remaining ownership or refused datagrams. It measures allocation/queue/byte-check work in memory, not kernel or WAN throughput, and is not a direct old-binary comparison. Final diagnostics are repeated after remaining data-path work.

## Mux dispatch and establishment

The driver now dequeues weak references to changed streams, deduplicates wakes, retains a blocked-credit set and records finite output-batch participants. Retiring streams remove queued references under the queue lock; queue locks are released before stream-state locks. A test with 128 retained streams and 32 duplicate wakes performs one stream visit and no subsequent idle visits. Existing round-robin/progress, cancellation, stream reclamation and backpressure tests pass.

Adaptive driver consumption coalesces updates at one eighth of the receive window, with immediate low-credit, growth and FIN/RST settlement. Explicit application `queue_window_update` remains immediate. A final cumulative credit that reclaims a stream now notifies the driver even when its prior available credit was nonzero. A regression deliberately retains a closed application handle, sends the last acknowledgement after the driver becomes idle and verifies that admission capacity returns without another application wake.

The pool uses one explicit in-flight setup permit while releasing its mutex for handshakes and driver shutdown. Tests verify that a slot freed in a healthy existing outer can be reserved while another handshake is pending, cancellation releases setup capacity, forty concurrent legacy requests still create only two outers, and shutdown wakes setup/capacity waiters. Native QUIC setup also listens for runtime shutdown rather than waiting for its full handshake timeout.

The combined inner/core selection passed 99 cases after scheduling/credit changes. Ten focused admission/final-credit tests also passed. Production mux startup now selects 1MiB stream / 4MiB connection windows, clipped to configured maxima; standalone FlowSettings defaults remain available for explicit library callers and baseline diagnostics. Startup and continuously warmed production-driver diagnostics are measured separately below.

`mux_io::bench::measure_driver_startup_and_idle_stream_scaling` runs the actual driver over a synthetic link (no TLS). A serial sample with 100ms RTT and a 1Gbps serializer gave 114.779Mbps for an 8MiB transfer with small initial windows and 175.875Mbps with production initial windows; setup handshakes are excluded but window growth is included. With 32MiB continuous warmup followed immediately by 16MiB measured at the receiver, the result was approximately 1Gbps (1005.663Mbps; short-window timing and already-buffered boundary bytes can slightly exceed the nominal serializer rate). On an unthrottled in-memory link, 1/32/128 retained streams with one active stream measured 5667.569/5574.935/6177.131Mbps; fixed ordering and noise do not establish a speedup from adding idle streams. The assertions verify all payload bytes, EOF and owned-task cleanup. Mixed/paused-stream correctness remains covered by the inner/core suite; final mixed diagnostics are repeated in the final verification phase.
