## Context

See proposal.md for the user-approved scope. Production TCP mux uses the duplex TLS bridge; Vision wrapped/raw and native QUIC are separate paths. A server has many independent outers but lacks process/group budgeting. The deployed client currently selects TCP Vision and QUIC UDP.

## Goals / Non-Goals

Goals: bounded resource ownership across clients, independent directional progress, adaptive credit for heterogeneous TCP mux paths, lower copying/allocation cost and measured 0.0.9 release behavior. Existing authentication, record validation and fallback contracts remain mandatory.

Non-goals: 0-RTT, account management, changes to padding distributions, kernel zero-copy claims or a guaranteed percentage improvement.

## Decisions

### Resource ownership

Use a process budget with canonical authenticated credential groups. Authentication maps the validated padded short id to an opaque group identifier; raw identifiers never enter logs. A connection owns its leases until all children and queued data are dropped. TCP, Vision and QUIC account for fixed connection/stream storage and bounded receive commitments. Receive limits and duplicate TLS/relay storage are distinct; parent/child accounting must not double count one buffer. There are global and group ceilings, and connections borrow uncommitted shared capacity. Scarce-resource admission is bounded and cancellation safe; no unauthenticated fallback response or artificial per-peer throttling is introduced.

### Adaptive mux negotiation and wire

Keep existing framing and legacy session APIs. An adaptive-capable session uses new authenticated inner commands: SETTINGS (0x0a, stream zero), CREDIT (0x0b), PROBE (0x0c, stream zero) and PROBE_ACK (0x0d, stream zero). SETTINGS has the bytes `UAF1`, followed by four big-endian u32 values: initial stream window, initial connection window, maximum stream window, maximum connection window. Settings appear once before adaptive stream traffic. They are the first frame of one write batch with configured cover padding, without advancing the normal business-write padding schedule. Limits are positive, internally ordered and bounded by 64 MiB per adaptive connection. The production client opts into adaptive mux; the server can retain legacy behavior for a peer that starts with legacy SYN/UDP. New-client/old-server failure never replays business data; paired deployment is authorized.

CREDIT is two big-endian u64 values: cumulative maximum send position and cumulative application-consumed position. Stream zero means connection totals. Both values are monotone, consumption cannot exceed bytes sent and grant cannot advertise more than the negotiated maximum window beyond consumption. DATA must fit both stream and connection credit. Consumption and expanded grants are separate counters; FIN settles cumulative positions rather than comparing against initial window. RST discards owned data and returns connection credit exactly once, including legal in-flight retired-stream DATA. New and unknown IDs never allocate state from CREDIT. Integer overflow, malformed payloads and inconsistent limits are terminal protocol errors.

PROBE and PROBE_ACK carry an eight-byte nonce. At most one probe is outstanding; matching acknowledgements provide smoothed RTT. Active traffic requests a new sample periodically. No fresh sample is needed for idle streams. Per-direction receive windows grow geometrically when application consumption uses a substantial window portion within a few RTTs, queues are being consumed and the budget can fund the increase. Small startup windows protect admission; growth stops at local/group/global limits. Cumulative advertised credit is never revoked or lent twice. Refreshes happen proactively; control writes remain possible when DATA admission is full.

### Data path

Retain persistent record/frame scratch buffers. Encode borrowed DATA directly into final frames where ownership permits. Queue owned receive chunks rather than copy every payload into a byte deque. Keep queued-byte totals incrementally and reuse scheduling scratch storage. TLS record protection uses standard AEAD in-place operations with the existing vector tests and zeroization contract. The TLS bridge owns its workers and independently progresses send/read. Relay directions run concurrently with a shared progress clock and existing half-close/cancellation behavior. Vision raw still reads a whole validated record before writing. QUIC drains available datagrams into the provided receive batch while retaining per-flow ordering and queue limits. Evaluate cipher context reuse, bridge restructuring and congestion selection against measured cost rather than changing algorithms blindly.

### Observability and evaluation

Use synthetic data and anonymous identifiers. Record payload goodput, elapsed time, CPU/byte where available, window stalls, granted versus buffered bytes and lifecycle reclamation. Compare 0.0.8 and 0.0.9 in the same environment, separately for mux, Vision and QUIC. Heterogeneous clients, slow readers, changing demand and competing credential groups must be exercised. Report unavailable metrics and limitations honestly.

## Risks / Trade-offs

- Higher RTT needs more committed memory -> bound and account before advertising; do not shrink live grants.
- More outers can amplify group consumption -> group quotas span outer connections and transports.
- A global budget can serialize traffic -> use connection-owned leases and local counters; budget coordination is a growth/admission operation.
- Protocol errors can cause replay -> keep stream ownership and fail terminally without replay.
- Mixed versions -> legacy server acceptance remains explicit; new clients require the upgraded peer for adaptive mux.
- Local microbenchmarks can hide WAN bottlenecks -> keep local and live evidence separate.

## Migration Plan

Validate specs before implementation. Build and test the exact release source, retain private installed binaries/configs, deploy server and Mac 0.0.9 together, restart and verify the real single-SOCKS routing. Exercise temporary synthetic local/live mux, Vision and QUIC traffic without changing unrelated services. Publish versioned binaries and checksums, verify deployed hashes and report results. No private endpoint or credential material is committed.

## BBR extension

### Native QUIC resource correction

The completion audit found that the initial fixed 64MiB reservation prevents any native QUIC admission under otherwise valid smaller budgets. Replace it with explicit storage, send and receive terms. Reserve 3MiB connection staging plus Quinn's existing 10,000,000-byte send limit; start aggregate receive credit at min(2,500,000, configured maximum) bytes and stream credit at min(1,250,000, aggregate/2). Account for 64KiB application storage on each accepted bidirectional stream, in addition to UDP-specific leases. Grow aggregate receive credit after demonstrated application consumption within a few RTTs, only after funding the full additional commitment. Do not revoke prior credit or change client transport parameters. Both native receive wrappers and the Quinn socket retain the growing connection lease. The 50ms local observation uses aggregate read counters; native per-stream credit remains fixed at its reviewed default maximum.

Quinn congestion selection is local sender policy, not a new ClientHello transport parameter. Add `performance.quic_congestion` with `bbr`, `cubic`, and `new-reno`; default to BBR following the user's explicit experimental preference. Apply the selection to client and server transport configs. Existing Linux TCP BBR/fq remains unchanged and governs different TCP sockets; it does not control the outer UDP flow. No kernel upgrade or global sysctl change is required. Benchmark claims must distinguish whole-version observations from causally isolated algorithm comparisons.
