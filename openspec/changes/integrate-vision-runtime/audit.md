# Runtime verification baseline

Date: 2026-09-13. Source: `17e301e` (main, v0.0.6 source). This audit did not modify or restart the deployed server or Mac client.

## Confirmed finding

The current production TCP path has not removed duplicate outer TLS encryption. Client `VisionSolo` still runs ordinary relay through a `DuplexStream`, and the server does the same. The stream is produced by `spawn_tls_app_io`; its writer calls `endpoint.seal()` before writing every plaintext chunk as an outer TLS record. The helper `vision_relay` is not called by the core runtime and has no way to acquire the raw socket from this bridge.

Source anchors at the audited revision:

- `crates/umbra-core/src/runtime.rs:1134`: client solo preface then ordinary relay.
- `crates/umbra-core/src/runtime.rs:1236`: TCP mux selects Mux; only non-mux selects the existing solo branch.
- `crates/umbra-core/src/runtime.rs:1557`: client creates the TLS bridge after authentication.
- `crates/umbra-core/src/runtime.rs:1824`: server creates the bridge before inner-mode dispatch.
- `crates/umbra-core/src/runtime.rs:2789`: server solo also uses ordinary relay.
- `crates/umbra-core/src/tls_io.rs:50`: raw halves move into detached record tasks.
- `crates/umbra-core/src/tls_io.rs:127`: outgoing payload is always sealed.

## Existing tests run

```sh
cargo nextest run -p umbra-inner -p umbra-core \
  -E 'test(vision) | test(solo) | test(tls_app)' --run-ignored all
```

Result: **5 passed**, 222 filtered out, on the unmodified source. The five tests cover solo target addressing, the isolated helper, and TLS bridge plaintext round trips. The helper test uses synthetic record headers and a `DuplexStream`; none of these tests captures production raw handoff or proves that outer encryption stops.

## Required proof for the fix

The new fixture must run the actual opted-in client/server path with real inner TLS, compare captured bytes across the committed handoff, and show that outer seal/open counters stop after the final controls. A test that only sees `VisionPhase::Splice`, successful HTTP, or `copy_bidirectional` is insufficient. Performance results remain unmeasured at this baseline.

## Approval boundary

The concrete draft includes 11 synthetic application-plaintext vectors; their
encoded lengths, envelope kinds, C/S offsets, and rejection reason were checked
independently with Python's standard `struct` decoding. This validates the draft
layout only, not a production codec, encryption, or runtime handoff.

Independent review corrected wrapped-only version selection, explicit queue
budgets, and the FIN/SWITCH_REQ crossing. The reviewed rejection policy is
pre-ACK only, with FIN reason precedence and exact C/S accounting. No remaining
mandatory design correction was identified in that bounded review; this is not
implementation verification or a cryptographic audit.

The repository has an explicit outstanding prerequisite at `openspec/changes/implement-protocol-design/tasks.md` task 13.3: define and approve exact wire layouts and state transitions before Vision framing/splice implementation. The current work supplies that concrete amendment and does not mark it approved or implemented.
