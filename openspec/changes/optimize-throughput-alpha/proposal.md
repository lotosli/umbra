## Why

The reviewed 0.0.9 data path leaves ARM64 AES/GHASH acceleration disabled, constrains native QUIC with small fixed windows and a 16-datagram routing queue, couples UDP relay directions under backpressure, and repeatedly scans/copies stream and record state. The user approved implementing all reviewed optimization items, testing them, building version 1.0.0 alpha and deploying both existing endpoints on 2026-09-15. This proposal records that authorization before implementation.

## What Changes

- Enable runtime-detected ARM64 cryptographic acceleration in normal and distribution builds; reuse zeroizing per-direction cipher contexts and caller-owned TLS buffers.
- Tune native QUIC stream/send/aggregate windows on both endpoints, preserve explicit resource accounting, and make receive growth independent of the controller sampling interval.
- Replace per-packet QUIC routing mailboxes with bounded byte-accounted batches, retain receive metadata, use physical receive batching and expose anonymous queue saturation counters.
- Keep UDP association receive/send/target setup independently serviceable under backpressure; share the client QUIC endpoint without sharing association shutdown ownership.
- Schedule only dirty mux streams and batch participants, coalesce consumption updates, and improve funded startup windows for throughput-oriented hosts with at least 1GiB RAM.
- Remove redundant TLS and wrapped-Vision buffer copies, split application traffic-key ownership, and reduce raw-Vision read/idle-notification overhead while validating complete records before forwarding.
- Publish reproducible performance/correctness evidence, build version `1.0.0-alpha`, and deploy with private backups and verified rollback paths. Mark any public release as a prerelease.
- **BREAKING API:** internal/public record-owner construction may return errors or transfer established application keys; downstream users must adapt to explicit ownership. The existing authenticated wire framing, routing selection and no-replay behavior remain compatible.

## Capabilities

### New Capabilities

- `throughput-runtime`: extend the not-yet-archived 0.0.9 capability with accelerated record ownership, bounded batched QUIC ingress, independent UDP forwarding, work-proportional mux scheduling and verified alpha delivery.

### Modified Capabilities

- `crypto-primitives`: add reusable AEAD contexts that preserve the existing vector, constant-time authentication and secret-destruction contracts.

## Impact

Affected code includes workspace build configuration, crypto/TLS/core/inner/proto crates, runtime configuration, diagnostics, tests, distribution/release tooling and documentation. Quinn remains on the reviewed baseline; AES-GCM is updated to stable 0.11.1 for automatic ARM acceleration and complete cached-context zeroization, with its dependency/license changes audited. Native QUIC window choices are compared with the checked-in real Chrome capture; existing unverified full-fingerprint status must not be promoted without evidence. Private infrastructure details and deployment material remain outside git.

## Authorization

The user's current instruction approves all optimization areas in the preceding review, tests, an alpha version and deployment. Routine design refinement and corrective testing are within that authorization. It does not imply approval to change authentication, remove resource bounds, weaken the coverage gate, rewrite old release tags, or claim unavailable remote CI results. The two pre-existing uncommitted documentation edits are retained.
