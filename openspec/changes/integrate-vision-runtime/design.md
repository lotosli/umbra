## Context

See `proposal.md` for the requested outcome and `audit.md` for the verified baseline. The current TCP handshake immediately creates a detached TLS/plaintext bridge. Its caller cannot recover the raw socket or know that buffered plaintext and ciphertext have drained. The legacy Vision helper observes incomplete TLS headers and never owns this bridge.

The existing `implement-protocol-design` task 13.3 requires a separately reviewed exact wire amendment. This design and `docs/vision-runtime-wire-v2.md` are that proposed amendment; the user approved the concrete amendment on 2026-09-13.

## Goals / Non-Goals

**Goals:**

- Make outer TLS encryption measurably stop after an authenticated transition for a dedicated, eligible TCP solo stream.
- Keep the application's own end-to-end TLS intact; do not obtain its keys, terminate its TLS, or infer that a visible `0x17` verifies Finished.
- Preserve target bytes, half-close, flow control, and cleanup across fragmented or coalesced socket I/O.
- Keep the existing deployed mux configuration usable during paired endpoint migration.

**Non-Goals:**

- Raw splice on mux or QUIC, automatic application classification into a different connection pool, Linux `splice(2)`/kernel zero-copy, or changes to browser fingerprint claims.
- Automatic retry/downgrade or replay of accepted business payload. The user subsequently authorized release 0.0.7, remote push, and server/Mac deployment; active-profile switching remains unnecessary.
- A claim that structural TLS observation cryptographically authenticates an untrusted inner application.

## Decisions

### 1. Explicit opt-in and authenticated mode selection

Per the user’s subsequent simplification, use the existing `mux` setting: TCP `mux=false` selects new Vision, and `mux=true` selects existing encrypted multiplexing. Remove the old solo implementation and its helper instead of retaining duplicate paths or adding a separate `vision` option. Both endpoints must be upgraded for new solo.

An opted-in client authenticates using a version-2 REALITY token of the same size and existing authenticated binding. The server validates the version, time, short ID, and replay rules before selecting the Vision parser. New servers accept existing v1 mux/UDP sessions and reject legacy v1 solo before target setup. Old servers reject version 2 into the existing real-site fallback, so a client never sends a target or Vision control bytes to that fallback. No retry or downgrade follows.

Alternatives rejected: a magic string after the legacy target address would reach an arbitrary target on an old server; an unused v1 flag is not fail-closed because the current parser accepts arbitrary flags. Changing ALPN to a protocol-specific name would also alter the cover handshake unnecessarily.

### 2. Complete wire contract before implementation

`docs/vision-runtime-wire-v2.md` defines the authenticated target preface, capability exchange, one-envelope-per-outer-record framing, length limits, target-byte counters, four-message switch barrier, failure states, and golden byte vectors. No negotiation bytes are delivered to the target.

A supported v2 peer can decline raw capability while retaining the agreed v2 encrypted envelope transport. That is distinct from connecting to an old server: an old server does not authenticate v2 and is not automatically retried.

### 3. One transport owner, with separate read/write progress

The established TCP handshake returns an owner containing raw I/O, the outer TLS endpoint, pending handshake input, and persistent record read/write progress. Mux converts the authenticated connection into the existing bridge; new solo retains record ownership.

Vision reading and writing are polled independently so a blocked write does not stop control reads. A partially sealed record is retained with its write offset and sealed exactly once. Partial headers, bodies, authenticated envelopes, local application buffers, and timeouts are session-owned, not local variables in cancellable futures. Buffer bounds apply per session; backpressure stops reading rather than growing queues.

The raw transition consumes the owner and a permit generated only by the switch state machine. It preserves distinct peer read-ahead and local unsent inner bytes. Previously decoded wrapped data is delivered before the corresponding raw suffix. The implementation must not use `PrefixedStream::into_inner()` while it could discard unread prefix bytes. Outer traffic keys are dropped and zeroized when no longer needed. No detached TLS task may survive to touch the raw socket.

### 4. Conservative inner TLS eligibility

Reassemble complete ClientHello and ServerHello messages across arbitrary TLS records and socket reads, with fixed byte/count/time limits. Confirm the offered and selected TLS 1.3 version and cipher, the session-ID echo, extension structure, and compatible key-share selection. The first implementation declines raw for HelloRetryRequest, PSK/early-data, TLS 1.2, malformed messages, or unsupported extensions needed to establish eligibility; the wrapped byte stream still works.

Protected records must be observed in both directions after a valid negotiation, at complete record boundaries. The observer cannot decrypt Finished or authenticate the inner record tags. The trust assumption is that the local application and its TLS peer actually implement end-to-end TLS; syntactically convincing malicious plaintext cannot be distinguished by passive inspection.

After handoff, a bounded raw relay validates protected-record headers and forwards their existing bytes without another encryption layer. It closes on unexpected cleartext record types, invalid sizes, or trailing non-TLS bytes; it does not speculate that those bytes are safe to expose. This is raw userspace forwarding, not a kernel zero-copy claim.

### 5. Directional counters, one coordinated commit

The client is the only switch coordinator. It freezes client-to-server DATA at a complete protected-record boundary and sends SWITCH_REQ. The server drains its accepted DATA, freezes at its own complete boundary, and acknowledges both byte counts. The client then sends COMMIT as its final encrypted control record. The server sends and fully flushes COMMIT_ACK as its final encrypted control record before raw writes. The client enables raw writes only after authenticating that acknowledgement.

These independent directional counters share one commit barrier. This avoids a direction switching to raw too early to carry the other direction's control acknowledgement. Both endpoints reaching eligibility together does not create two coordinators or a symmetric deadlock. TCP handles transport retransmission; application control frames are not replayed.

Before SWITCH_REQ, absent shared capability or local eligibility keeps the session wrapped. A server that has not acknowledged the request may explicitly reject unavailable eligibility or a crossed FIN, with exact offsets; both peers then remain permanently wrapped. Otherwise timeout, malformed controls, counter disagreement, I/O failure, or session cancellation closes the connection. A post-commit failure never tries to restore TLS framing on the raw stream.

### 6. Observable correctness before performance claims

The integration fixture uses actual Umbra client/server runtime around an independent local inner TLS implementation. It records both the inner protected-record bytes and the outer proxy TCP bytes. The test must prove that post-boundary outer bytes equal the original inner records, that business data is exact, and that outer seal/open call counts stop increasing after the final encrypted controls.

Repeat with fragmentation, partial writes, read-ahead at the last ACK, half-close, stalled readers, and failed negotiations. Negative fixtures include non-TLS, TLS 1.2, fake `0x17`, and unsupported v2/legacy peers. Mux and QUIC retain regression coverage.

The user explicitly removed performance comparisons. Acceptance is the actual runtime byte/counter proof, with no throughput or CPU improvement percentage claimed. After the full checks, publish and deploy version 0.0.7 as explicitly requested.

## Risks / Trade-offs

- Paired endpoint requirement → opt-in defaults, authenticated version dispatch, and explicit compatibility tests.
- Extra control round trips can hurt small requests → benchmark cold and warm short requests separately; keep mux available.
- Passive TLS detection cannot prove inner encryption → state the trust assumption, conservative eligibility, and record validation after switching.
- Buffered I/O races could corrupt data or expose bytes → single ownership, bounded persistent progress, exact counters, golden vectors, adversarial partial-I/O tests, and independent review.
- User-space forwarding may remain CPU-bound → measure before adding platform-specific copy optimizations.

## Migration Plan

1. Approve the exact wire appendix and integration scope.
2. Implement and validate in this isolated worktree; preserve all existing CI gates.
3. Build both platforms and run paired local/staged verification with `mux = false` before any production activation.
4. Any later deployment upgrades the server first, then the opted-in client. Existing v1 mux sessions remain supported.
5. Rollback selects the existing mux profile. Never downgrade a partially transmitted connection or replay its payload.

The user has now requested deployment of version 0.0.7 on the Mac and server, plus remote push. Deploy only after implementation and full verification; preserve the existing usable mux entry while adding an explicitly enabled Vision solo path.
