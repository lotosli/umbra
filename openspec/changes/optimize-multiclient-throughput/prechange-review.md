# Review before each implementation change

The user requires a code review before every change, with a credible benefit rather than speculative optimization. This ledger is written before product-code edits. Each subsequent change must add its evidence, decision and validation; absence of measured speedup is not presented as a speedup.

## R0 — Reproducible throughput diagnostic (before adding test code)

Current tests assert bytes and correctness but do not measure sustained transfer, CPU costs or the fixed-window ceiling. A diagnostic is necessary to make later optimization decisions reviewable. Add explicitly ignored release-mode measurements using bounded synthetic inputs and exact byte assertions, with warmup/repetition and printed conditions. For mux, emulate a pipeline delay, not a sleep per application packet: separate bounded forwarding tasks allow many records in flight. Measure fixed-window large transfers at controlled RTT, then retain that case for comparison with adaptive mode. No production endpoint or credential belongs in the test. This is measurement infrastructure, not a throughput improvement claim.

## Candidate review queue (not implementation approval by itself)

- R1: fixed 256KiB mux credit mathematically limits bytes in flight; measure delayed-link stalls before adaptive changes.
- R2: raw Vision allocates a whole record per iteration at vision_io.rs:758; compare the same raw record stream after scratch reuse, preserving whole-record rejection.
- R3: mux FrameReader discards capacity every frame at mux.rs:921; TLS bridge separately allocates/pastes record payloads. Measure record/frame throughput before a narrow reuse change.
- R4: relay select branches await writes at runtime.rs:2579/2589; demonstrate reverse-direction starvation under sustained backpressure before restructuring.
- R5: DATA is copied in mux_io.rs:677, mux.rs:419 and frame.rs:96; inspect ownership/cancellation and measure reduction before selecting an API change.
- R6: per-DATA all-stream scan at mux_io.rs:924 and temporary scheduler ids at 849; test multi-stream CPU scaling before wider scheduling changes.
- R7: process-wide budget and credential identity are prerequisites for safely increasing per-connection commitments; validate arithmetic/ownership and multi-client pressure, rather than claim they directly accelerate a single stream.
- R8: QUIC currently returns one datagram from a batch-capable API; measure receive work and verify metadata/ordering before enabling batching.
- Cipher-object reuse and whole TLS bridge replacement remain candidates until profiling identifies material cost and lifetime/zeroization review passes.

## R4a — Backpressure regression before relay changes

Reviewed runtime.rs:2552–2594: after selecting a left read, awaiting right.write_all prevents polling the reverse read. The normal TCP mux client and server both use this function. A bounded duplex with an unread destination deterministically exercises that condition; a reverse reply must still reach the other peer. Add the regression first, record its expected baseline failure, and only then replace the relay with independently polled directions and a shared progress clock. The new implementation must continue half-closes rather than cancel the reverse future after the first EOF.

## R2a — Raw record diagnostic before reuse changes

The deployed TCP path can switch to Vision raw. forward_records reads and verifies a complete record before forwarding; it drops the record Vec at each iteration even though the next record is processed only after the preceding write completes. This is a safe lifetime for exclusive scratch reuse. First measure the existing function on a fixed bounded protected-record stream; compare after the narrow change with identical byte counts. Do not change parsing or forwarding boundaries.

## R1 decision — fixed-window limitation reproduced

Before implementation, the release-mode diagnostic measured median legacy mux goodput of 39.091Mbps at simulated 50ms RTT and 20.371Mbps at 100ms RTT, with a 1Gbps serialization model and 8MiB payload. This closely matches the 256KiB/window round-trip ceiling. Zero-added-delay results are about 600Mbps because the emulator/runtime has its own overhead; the model does not establish a physical 1Gbps baseline. Proceed with adaptive credit subject to global commitments and dual-limit validation. Exact samples are in baseline-mux.txt.

## R4 decision — independent reverse progress failure reproduced

The new regression failed on the unchanged implementation: a 128-byte forward transfer fills a 64-byte unread destination buffer, and a five-byte reverse reply cannot arrive within 250ms. Replace only the shared relay helper with Tokio's independently driven bidirectional copying and an owner-local atomic progress clock. Keep 16KiB per-direction buffers, half-close behavior and terminal cancellation. Timer monitoring must regard actual positive read/write progress in either direction as activity.

## R2 decision — narrow scratch reuse trial

Before change, raw-record processing of 134,397,952 synthetic bytes (8,192 full TLS-sized records) took 10.0–16.6ms across five release samples. This is far faster than the WAN and does not establish a real network bottleneck. Trial only moving the existing scratch Vec outside the loop; retain it only if the same diagnostic does not regress and allocation lifetime is demonstrably simpler. Do not expand this into global pooling or a bridge rewrite on this evidence.

## R7 decision — resource commitments are required for measured window growth

The 100ms measurement establishes a benefit for growing credit, but multiplying a 64MiB ceiling by independent client outers would remove the current memory bound. ServerRuntime owns no shared budget, and validated credential identity is dropped by dispatch. Implement a shared byte-commitment pool with group ceilings and connection-owned leases before enabling growth. Proof obligation: each successful reservation increases group/process totals once; growth fails without mutation when either cap is exceeded; only lease drop returns commitment. Growth leaves a small process reserve for new admissions. This is a prerequisite for safe multi-client throughput, not a claimed standalone speedup.

## R1a — Adaptive control wire review before parser changes

The fixed-window benchmark justifies larger in-flight credit. Existing WINDOW_UPDATE is consumption-only and cannot safely encode expanded grants. Add distinct settings/cumulative-credit/probe commands so legacy semantics stay intact. Use fixed-width bounded payloads, separate consumed and granted totals, and cap advertised window differences. The parser can reject wrong lengths/magic/order before allocation. A connection-level limit is essential: without one, 128 independently large stream windows would overcommit memory. Do not alter ClientHello, REALITY authentication or default padding to implement this inner-protocol change.

## R1 integration decision — adaptive counterpart improves the same workload

On the same release-mode 8MiB pipelined-link diagnostic, adaptive mux medians are 222.418Mbps at 50ms RTT and 117.023Mbps at 100ms, versus 39.091/20.371Mbps before. These include startup/window growth and are not WAN results. Integrate it behind explicit settings detection, preserve the legacy path, and bind receive leases to the same server/client resource manager. The event driver must wake when either credit limit unblocks; cumulative updates must not be swallowed while senders wait.

## R7a — Config/identity integration review

Current authentication already validates canonical padded short ids, so propagate a non-secret configuration-group index without changing authentication bytes. ServerRuntime currently shares dispatch/replay state but no budgets; create one resource owner at bind and pass it through authenticated handlers. Configuration supplies memory ceilings and adaptive limits rather than guessed bandwidth. Missing performance configuration retains bounded defaults. Every authenticated transport reserves its separate staging allowance; mux growth draws from the same pool. This prevents the demonstrated growth from multiplying unboundedly across clients.

## R7b — TLS worker ownership before connection accounting

spawn_tls_app_io currently discards two JoinHandles, so session cancellation does not directly stop those workers. Return an I/O owner that aborts its workers on Drop, and keep the fixed storage lease inside the raw I/O held by those workers. This ties permit release to actual worker resource destruction. Preserve the existing duplex API behavior; replacing the entire bridge is not justified by this ownership evidence. The record-read worker can retain its one record Vec, avoiding its observed header/payload/paste allocation chain without changing record boundaries.

## R7c — QUIC server accounting review

Quinn owns its receive/send buffers outside the mux. A server admission lease alone is meaningless unless those buffers have matching bounds. Bound authenticated server receive credit to 32MiB and send buffering to 8MiB, retain per-flow datagram and stream-count limits, and reserve 64MiB per admitted flow for transport plus application staging. The fixed lease is held by the socket wrapper until Quinn releases it. ClientHello construction is unchanged: these are server transport limits. Operators can configure the aggregate memory ceiling; no assertion is made that a 64-flow listener can fund all its maximum-sized flows under a smaller process budget. Fallback flows keep their existing path.

## R7d — Retained receive data ownership review

MuxIo can retain buffered bytes after an outer EOF, so releasing a receive commitment merely when MuxSession drops would be too early. Share each reservation through reference-counted leases (one accounting entry, many owners), and retain those leases in stream state until its queued data is destroyed. A lease clone must not charge twice or release early; verify last-owner release. This closes a concrete accounting hole before production integration.

## R5/R6 decision — preserve received payload ownership

The default driver copies every decoded Vec into a VecDeque<u8>, then copies it out; each DATA also locks every stream to sum byte counts. Store complete owned chunks plus an offset and one outer-local atomic total. Only the serialized driver adds bytes; consumers/drop subtract them, so admission can check the aggregate without locking unrelated streams. The existing exact-byte, slow-reader and half-close tests are the sufficient correctness evidence for this narrow ownership change. Keep one bounded scheduled batch and round-robin order; do not introduce an unmeasured global byte scheduler.

## R5a — Direct borrowed DATA encoding

MuxIo must own a caller's accepted bytes across asynchronous writes, but try_send_data immediately copies those already-owned bytes into a temporary MuxFrame Vec only for encode() to copy them again. Encode the borrowed slice directly into the final owned wire frame. Padding scheduling still uses a DATA marker and commits its counter only after queue admission; no borrowed data survives the synchronous call. This removes one payload-sized allocation/copy per DATA admission while preserving the existing ownership boundary.

## R8 decision — use the existing QUIC receive batch contract

PrefetchedUdpSocket::poll_recv receives arrays of buffers/metadata yet always fills the first slot and returns one. Queue draining under one short lock can fill multiple already-ready slots, reducing callback/lock overhead by construction. Do not wait for a full batch or reorder datagrams. If a later slot is unavailable or invalid, return the completed prefix and retain unconsumed input. Verify a multi-datagram call rather than build a separate large performance matrix.

## R3a — TLS in-place record protection review

seal_record currently allocates inner plaintext, allocates ciphertext through Aead::encrypt, then copies ciphertext into a growing header Vec. open_record allocates decrypted bytes and copies them again into OpenRecord. All three suites already expose standard detached/in-place AEAD operations. Build one final-sized protected record, encrypt its payload in place, append the tag, and decrypt one owned buffer then transfer it after truncating the content type/padding. This removes payload-sized intermediates by construction without caching cryptographic state or changing nonce/sequence/key derivation. Zeroize temporary buffers on failure and preserve RFC/vector tests. Cipher context caching remains deferred because its independent CPU benefit is unmeasured.

## R4 follow-up — preserve the existing write/flush contract

The first workspace run exposed an EOF regression in the injected-outer test. Tokio copy_bidirectional adds flush barriers that the former relay did not request, and a mux peer can finish/drop while the reverse payload remains readable. Keep independently polled directions but use the existing read/write-all/shutdown contract, with the same shared progress clock; do not add eager flushes. Re-run the precise failing half-close case and reverse-backpressure regression before broader verification.

## R1b — Startup settings and RTT bootstrap review

New settings would otherwise be an isolated fixed-size first application write. Preserve a variable early shape by putting SETTINGS first in one owned write batch followed by configured cover frames, using a cloned planner so the existing business-write schedule is unchanged. Account for all wire frames in that batch. With padding disabled, diagnostic behavior remains unchanged. Replace the bootstrap RTT estimate with the first actual matching sample, then smooth subsequent samples; retaining a made-up 100ms weight on a short path would encourage unnecessary window growth.

## R7e — Production multi-client verification point

Pool arithmetic alone cannot prove that authenticated runtime identity and leases are connected correctly. Expose an anonymous committed-byte snapshot and exercise three independent client runtimes (two sharing one credential, one using another), then stop all owners and require commitment to return to zero. This one end-to-end check covers actual multi-client routing and lifetime accounting without building a large scenario matrix.

## R7f — UDP per-target and queued-payload accounting

Review found a concrete missing term: each UDP association can own 256 target readers, each with a 65,535-byte buffer, plus a channel of reply payloads. These cannot be covered by a TCP-sized stream staging estimate. Carry the authenticated group into UDP associations, reserve each target reader's storage before spawning it, and attach a lease to each queued reply. Release follows task/message destruction. Budget exhaustion drops an unadmitted UDP datagram or target instead of blocking unrelated clients; existing targets and unauthenticated fallback are unaffected.

## R9 — BBR requested trial review

The user explicitly requests BBR. Reviewed locked quinn-proto 0.11.16: it already supplies BbrConfig, CubicConfig and NewRenoConfig, and congestion_controller_factory is local policy rather than a serialized transport parameter. The BBR implementation is experimental, based on Google's earlier QUIC bbr_sender, not claimed as BBRv3. The deployed Linux host already reports tcp_congestion_control=bbr and default_qdisc=fq, so there is no reason to alter kernel configuration. Add a small validated selector at both Quinn config construction sites and compare actual transfers; do not introduce a new congestion implementation or promise a percentage gain.

## R10 — User-selected Quinn patch release review

Verified crates.io and the official signed release tag: quinn 0.11.12 depends on quinn-proto 0.11.18, both MIT OR Apache-2.0, MSRV 1.85 (below this workspace's 1.96.1). The release fixes receive/send storage and flow-control edge cases as well as published security issues, directly relevant to a bounded high-throughput runtime. The downloaded 0.11.18 BBR main source still has the experimental/source comments and is byte-identical to the 0.11.16 BBR main source; do not describe the upgrade as a BBRv3 migration. Update only the requested Quinn pair and required lockfile resolution, then rerun actual-controller and interoperability checks.

Source: https://github.com/quinn-rs/quinn/releases/tag/quinn-proto-0.11.18

## R11 — Required dependency safety remediation

cargo-deny rejected rustls 0.23.41 under RUSTSEC-2026-0285 (handshake encryption-level boundaries); the advisory requires >=0.23.45. Reviewed rustls 0.23.45 metadata: same compatible license family and MSRV 1.71. Upgrade to that fixed patch. Resolve the two reported yanked transitive patches (chacha20 0.10.1 and der 0.8.0) within their existing compatible lines, retaining exact duplicate-version policy rather than adding advisory exceptions. These are release-gate fixes, not throughput claims.

## R1c / R7c follow-up — final protocol review

Require the peer's SETTINGS before any adaptive stream/credit readiness; an authenticated peer must not produce SOCKS success through a premature SYN_ACK. Also retain Quinn's existing 10,000,000-byte default send window: the initially proposed 8MiB bound was smaller without evidence of benefit. The 64MiB conservative flow reservation still covers the 32MiB receiver bound, default sender storage and separate bounded staging. UDP-specific storage remains separately charged.

## R12 — Completion audit: heterogeneous-client evidence

The current throughput diagnostic constructs an independent pool and link for each single-stream measurement; the runtime's three-client test only transfers short ping/pong payloads. Neither proves the approved mixed-delay/rate/stream-count scenario. Before adding any scheduler or changing receive policy, add one bounded diagnostic with four simultaneous outers in three credential groups, a common serialization budget, distinct path rates/RTTs, different stream counts, and a receiver withholding consumption until another group completes. Use the real MuxSession protocol, exact payload assertions, bounded commitments and last-owner reclamation. Report client/group and aggregate goodput, observed credit-wait episodes, receive windows and emulator conditions. Repeat the same scenario with fixed and adaptive mux; do not interpret the emulator's FIFO bottleneck as proof of real-network fairness or CPU scheduling. This adds evidence only, not a production data-path change.

## R13 — Native QUIC admission and growth review

`PerformanceCfg::validate` accepts a 16MiB process/group, but the authenticated QUIC branch unconditionally reserves 64MiB before creating Quinn. Therefore a valid low-memory server cannot complete a QUIC handshake; a default 256MiB group admits only four idle connections. This is a concrete availability/aggregate-throughput regression, not an assumed allocator bottleneck.

Reviewed quinn-proto 0.11.18 transport defaults and `StreamsState::set_receive_window`: the default per-stream receive limit is 1,250,000 bytes and send storage limit 10,000,000 bytes; the dynamic aggregate receive setter adds the increase to cumulative MAX_DATA without revoking old credit. Retain the default stream and send limits for normal settings. Start aggregate receive credit at twice the stream limit (2,500,000 bytes), capped by the configured maximum; this leaves capacity beside one stalled stream. Separately reserve 3MiB transport staging (two bounded 16-datagram prefetch/inbox sets, crypto and connection state), the default send limit, and aggregate receive credit. Charge 64KiB per accepted application stream for its two 16KiB copy buffers plus framing/task allowance; UDP association/readers/messages retain their additional existing charges. Default initial connection commitment becomes 15,645,728 bytes, fitting 16MiB with room for active stream storage. This is a logical commitment policy, not an exact RSS guarantee.

Count bytes read from native receive streams and grow aggregate credit geometrically only with consumption/RTT evidence and a successful additional budget reservation. Never shrink or release a live receive grant. Keep the whole connection reservation alive through both the Quinn socket and retained receive wrappers. A connection-local 50ms controller checks aggregate consumption without a global lock per DATA. Per-stream limits stay at Quinn's existing value because this version exposes no runtime per-stream receive-window setter; this fix does not claim to remove that separate high-BDP single-stream limit. The client transport-parameter fingerprint is unchanged. Verify one real authenticated low-memory QUIC connection and byte-exact transfer, plus growth/budget/last-owner invariants; do not reduce configured memory support by rejecting previously valid values.
