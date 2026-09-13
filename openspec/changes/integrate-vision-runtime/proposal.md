## Why

The production TCP solo path still sends every application byte through the outer TLS bridge. The existing Vision helper and its passing tests do not establish raw-socket ownership or removal of duplicate TLS encryption. The user requested verification and integration of real raw-stream handoff on 2026-09-13.

## What Changes

- Specify and review the exact authenticated Vision wire amendment before implementing it, satisfying the separately reserved approval in `implement-protocol-design` task 13.3.
- **BREAKING for opt-in Vision solo:** distinguish the new session before target or application bytes are sent; require upgraded client and server for the new mode. Existing v1 mux and QUIC keep their wire behavior; the user requested deleting the old solo implementation.
- Give a production solo session exclusive ownership of the outer TCP transport and TLS record state, with resumable bounded I/O and an explicit, acknowledged handoff boundary.
- Observe inner TLS 1.3 negotiation and complete protected-record boundaries without claiming to verify encrypted Finished messages. Keep noneligible streams inside outer TLS.
- Remove outer encryption, envelopes, and padding after committed handoff, while preserving bytes, half-close, cancellation, and idle cleanup.
- Prove the actual runtime transition using an independent local inner TLS peer, captured wire bytes, and outer seal/open counters; provide optimization proof without performance comparisons, as subsequently requested.

## Capabilities

### New Capabilities

- `vision-runtime-splice`: exact authenticated wire negotiation, bounded record ownership, safe production TCP solo handoff, and observable evidence that outer encryption stops.

### Modified Capabilities

No archived capability is modified. This change supplies the exact protocol amendment that is still pending in the in-flight `implement-protocol-design/specs/inner-vision/spec.md`; it does not treat that change's historical checked tasks as implementation evidence.

## Impact

- Protocol: `docs/protocol-design.md`, the new normative wire appendix, and the pending inner-Vision requirements/task references.
- Implementation after wire approval: `umbra-reality` authenticated mode selection; `umbra-proto` framing; `umbra-inner` parsing/state; `umbra-core` transport ownership, relay, and client/server integration.
- Tests: wire vectors, property/fuzz parsers, controlled partial I/O, real paired runtime, TLS 1.2/non-TLS fallback, compatibility, and optimization evidence.
- Deployment: new Vision mode needs both endpoints upgraded and a dedicated TCP solo connection. The existing deployed `mux=true` configuration does not acquire raw splice by implication. The user subsequently authorized release 0.0.7, remote push, and both-endpoint deployment.
- No new cryptographic primitives, weaker authentication, relaxed CI thresholds, new privileged networking, or claim of kernel zero-copy.

## Approval status

The user explicitly confirmed the concrete wire proposal on 2026-09-13. Implementation and validation of both endpoints are authorized. This approval does not itself establish implementation, performance improvement, or successful deployment.
