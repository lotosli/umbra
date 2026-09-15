## Context

See proposal.md for the authorized scope. Baseline source is bc967e6 (implementation 201bca9). The reviewed ARM64 AES-128-GCM diagnostic processed 64MiB at median 1.254Gbps with default build flags and 6.156Gbps with ARM AES/PMULL enabled; this is a primitive benchmark, not WAN goodput. The current TLS bridge has independent worker tasks but shares the complete TLS endpoint under one mutex. Native QUIC uses 1,250,000-byte stream credit, a 50ms aggregate controller and 16 packet mailboxes. UDP association branch bodies await writes/setup before returning to select. Mux scans all retained streams on each output cycle.

## Goals / Non-Goals

Goals: complete each reviewed optimization area with meaningful regression evidence; prioritize throughput on hosts with at least 1GiB RAM; keep shared commitments, secret destruction, validated record boundaries, no replay and independent half-close. Preserve compatibility with existing config files. The release is SemVer `1.0.0-alpha`, not stable 1.0.0.

Non-goals: new cryptography, unauthenticated throttling, speculative 0-RTT, kernel zero-copy, changing padding distributions, replacing Quinn, or guaranteed WAN speedups. Existing unverified full Chrome parity remains explicitly unverified; a field-level match must not be advertised as complete parity.

## Decisions

### 1. Acceleration and application record ownership

Use the stable RustCrypto AES-GCM 0.11.1 family with its zeroize feature and default ARM64 runtime detection. Dependency review found that 0.10.3's POLYVAL 0.6.2 ARM PMULL backend has an unimplemented Drop zeroization path, and its autodetect union does not run field destructors; simply enabling the old flags is insufficient for safely retaining a cached context. AES-GCM 0.11.1 explicitly propagates zeroization to its AES/GHASH fields and exposes ZeroizeOnDrop. This reviewed stable dependency update replaces the initially considered old-version flags and avoids maintaining a cryptographic fork. Verify both its runtime-detected and forced-software backends. Reusable AEAD contexts accept caller-owned payloads and explicit nonces; no secret Debug/Clone. Clear failed output and destroy all cached key/hash state on drop or explicit clearing. Keep stateless wrappers for compatibility and reference tests.

RecordLayer caches one context, preserves checked sequence progression and exposes caller-buffer seal/open operations. Transfer established application read/write layers into independent owners; handshake state is dropped once no longer required. Existing endpoint-facing helpers remain adapters where needed. Record readers validate headers before resizing, retain partial offsets across cancellation and authenticate in owned buffers. Writers reuse final record buffers only after the prior record is completely accepted; cancellation never reseals a partial record.

### 2. Native windows and consumption measurement

Expose explicit bounded QUIC stream/send window settings, with defaults grounded in the existing decoded real Chrome reference where public flow-control fields are changed. The captured Chrome 153 values are 6MiB per stream and 15MiB aggregate; use these as the public default reference and document configurable high-BDP overrides rather than inventing a full matching Chrome profile. Server and client must use the same reviewed policy implementation; fixed stream limits remain distinct from aggregate growth. Send-window storage is accounted separately from receive commitments. Small valid budgets retain a bounded admission policy, but are not the performance target.

Make aggregate growth measure consumed bytes per elapsed time: compare the observed rate against the fraction-of-window-per-RTT criterion using the actual sample interval, rather than rejecting all intervals longer than two RTTs. Idle/slow consumption cannot grow a grant, growth is funded before advertisement, and cumulative grants are never revoked. Tests explicitly combine 50ms polling with low RTT, delayed sampling and saturation.

### 3. QUIC ingress

Represent routed input as owned receive batches with datagram metadata and shared byte ownership. Bound per-flow retained bytes and queued batches so a legal GRO batch fits; cap global fixed staging and retain the lease until the queue/socket drop. Route slices without cloning each datagram, and preserve datagram boundaries/ordering and peer/CID isolation. Supply multiple physical receive buffers when supported, bounded by the adapter's advertised segment count. Queue rejection increments anonymous dropped-datagram/byte counters and high-water observations. Never await one saturated flow from the public dispatcher. Explicitly test a burst larger than the old 16-packet limit, byte exhaustion and a concurrently healthy flow.

### 4. UDP association progress and endpoint lifetime

Use bounded pending-output state or independently owned directional tasks so a blocked QUIC/TCP carrier write cannot suspend reverse reads, control closure or the shared idle deadline. Target setup runs as bounded owned work while established targets continue. Retain exactly one in-progress encoded envelope and its offset; partial writes survive unrelated events without replay. Reuse the client endpoint across associations, with each association closing only its connection/stream and runtime shutdown closing the endpoint once. Preserve existing transport selection and error/drop semantics.

### 5. Mux work and startup

Use a deduplicated dirty-stream queue for application writes/consumption/close, a bounded blocked-credit set and a recorded participant set for each frozen output batch. Connection-wide credit wakes only blocked senders; input dispatch marks only affected streams. Keep round-robin service and finite flush barriers, including FIN/cancellation and streams that disappear while queued. Coalesce cumulative consumption updates and retain immediate updates for exhausted credit and terminal settlement.

Increase throughput-oriented mux startup windows within the configured maximum and funded connection lease. Compare startup-inclusive and warmed sustained transfers, 1/32/128 retained streams, mixed credentials and paused consumers. Do not increase padding or retry already accepted data. Pool establishment uses explicit pending ownership if lock scope is reduced; capacity reservations must include in-flight connections.

### 6. Vision buffers and raw I/O

Encode borrowed DATA directly into final owned envelopes and avoid copying owned decoded payloads again. Reuse TLS writer buffers and preserve the dedicated control slot. Raw forwarding uses bounded read-ahead/persistent offsets to read available complete records efficiently, validates each complete protected record before forwarding and retains a partial suffix. Replace per-read watch broadcasts with a shared activity clock whose timer recomputes expiry, retaining partial-read/write activity and half-close behavior. Do not interpret flush as a TCP batching primitive.

## Risks / Trade-offs

- Cached cipher state survives longer -> explicitly enable and verify dependency zeroization and clear failed output.
- Larger windows/queues increase commitments -> shared budgets fund grants and batches before ownership transfer; test last-owner release.
- Batching can delay control or confuse flush completion -> finite batch participants, reserved control capacity and cancellation tests.
- UDP task separation can leak work or replay prefixes -> one owner per writer, retained offsets, owned join/abort and explicit shutdown tests.
- Public QUIC parameters differ from old unverified defaults -> compare changed fields to raw Chrome evidence and report the exact verified scope.
- Microbenchmarks can mislead -> report workload, hardware, repeats and both startup/sustained results; verify the actual configured production paths separately.

## Migration Plan

Keep the installed 0.0.9 binaries/configs privately for rollback. Complete strict OpenSpec validation, all workspace gates including >=90% coverage, fingerprint checks and targeted parser fuzzing. Build all locally supported macOS/Linux artifacts, check version/digests and create a prerelease with exact source identity. Back up both existing service definitions/configs and binaries, stage and atomically replace executables, restart the existing services and test HTTPS via Vision/mux/native QUIC plus UDP and shutdown behavior. Restore 0.0.9 if post-deployment smoke checks fail. Remote CI limitations are reported honestly; no protected merge gate is bypassed and no old tag is rewritten.
