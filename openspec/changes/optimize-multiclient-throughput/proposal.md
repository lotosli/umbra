## Why

Umbra 0.0.8 serves multiple clients, but fixed per-stream credit, repeated data copies, coupled relay directions and connection-local resource limits can restrict throughput or multiply memory use across clients. The user approved the preceding multi-client optimization design and explicitly requested complete implementation, release 0.0.9 and direct deployment/testing of both endpoints on 2026-09-15.

## What Changes

- **BREAKING for default new clients:** adaptive mux requires the upgraded peer; explicit legacy mode remains available. The Rust TLS bridge API returns an owning I/O wrapper instead of a bare duplex stream.

- Add authenticated credential-group resource accounting shared by TCP, Vision and QUIC, including connection lifetime and bounded buffer commitments.
- Add negotiated adaptive mux flow control with independent receive directions, stream and connection cumulative credit, bounded growth, RTT observation, proactive updates and correct consumption/close accounting.
- Isolate slow readers and independent relay directions; tie TLS bridge workers to the outer connection lifetime.
- Reduce record/frame allocation and intermediate payload copying; improve mux scheduling and QUIC receive batching. Retain bounded queues, fairness and authentication invariants.
- Add reproducible throughput measurements and mixed-client/backpressure validation, with results distinguished from theoretical or unmeasured improvements.
- Release and deploy 0.0.9 to the existing Mac/server pair, with private recovery files and functional/performance validation. Paired upgrades and downtime are authorized. No business data is replayed during protocol selection or recovery.

## Capabilities

### New Capabilities

- `adaptive-mux-flow-control`: negotiated cumulative flow control, autotuning and bounded memory commitments.
- `multiclient-resource-control`: credential-group identity, shared resource budgets, isolation and lifetime ownership.
- `throughput-runtime`: independent bidirectional relay, efficient record/frame transport, measurements and 0.0.9 deployment acceptance.

### Modified Capabilities

None of the three archived current specifications require changes. Existing in-flight inner-mux, orchestration and Vision specifications remain supporting context; the new capabilities explicitly define their runtime evolution.

## Impact

Affected crates: umbra-proto, umbra-crypto, umbra-tls, umbra-inner, umbra-core, umbra, testkit and xtask; fuzz targets, tests, usage/protocol documentation and package metadata. No new cryptographic construction, untrusted fallback restriction or infrastructure credentials are introduced into the repository.

Non-goals: TLS 0-RTT, pooling already-used fallback TLS connections, payload-size padding changes without fingerprint evidence, account/billing systems, and claims that all clients can simultaneously reach an independently measured peak.

## Authorization

The user approved implementation of the discussed overall design, generation and deployment of 0.0.9, and direct online testing with no active product users. This proposal transcribes that authorization before implementation; it does not claim the user reviewed artifacts generated afterward. Routine implementation details and verification will be completed within that scope without another deployment approval round.

## Approved BBR extension

The user subsequently requested an aggressive BBR trial. Add selectable Quinn BBR/Cubic/NewReno and select BBR for the 0.0.9 deployment. The Linux server already uses TCP BBR with fq; do not change unrelated host networking or claim this existing setting is a new improvement. Quinn's bundled BBR is experimental and is not represented as BBRv3. Retain an explicit Cubic fallback option and verify each direction's configuration.

The user explicitly selected the latest paired quinn 0.11.12 / quinn-proto 0.11.18 release. Update the workspace catalog and lockfiles to these reviewed patch versions before final verification.
