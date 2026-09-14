## 1. Approved specification and baseline

- [x] 1.1 Transcribe the approved overall plan into proposal/design/specs before implementation; validate the change strictly.
- [x] 1.2 Preserve the installed 0.0.8 baseline and establish reproducible synthetic throughput measurements with documented conditions.

Every implementation item requires a preceding entry in `prechange-review.md` recording the current call path, benefit hypothesis, correctness constraints and validation. Candidates with inadequate benefit evidence are deferred with reasons, following the user’s latest instruction.

## 2. Efficient and independently progressing transport

- [x] 2.1 Reuse frame/record/raw relay buffers and avoid intermediate TLS/DATA copies; verify byte equality and standard AEAD vectors.
- [x] 2.2 Make relay directions independent with shared idle progress and make TLS workers owned by the outer; verify backpressure, cancellation and half-close.
- [x] 2.3 Use owned receive chunks, incremental buffering and reusable scheduling state; verify multiplexing fairness and queue limits.
- [x] 2.4 Batch QUIC receive delivery while preserving per-flow metadata and boundaries; verify mixed transport and datagram tests.

- [x] 2.5 Apply the user-requested BBR selector to both Quinn endpoints and verify supported/invalid policies and live QUIC traffic.

## 3. Shared resources and adaptive flow control

- [x] 3.1 Implement canonical credential-group identity and global/group resource leases across authenticated transports; test admission, contention and lifecycle reclamation.
- [x] 3.2 Implement bounded adaptive settings/credit/probe wire parsing with property and fuzz coverage; test malformed, overflow and legacy paths.
- [x] 3.3 Integrate stream/connection cumulative credit, proactive updates, RTT growth and FIN/RST settlement; test asymmetric windows, budget saturation and in-flight cancellation.
- [x] 3.4 Integrate configuration, production runtime and shared resource policy; verify multiple credentials, multiple outers and slow readers beside fast clients.

## 4. Measurements, tests and coverage >= 90%

- [x] 4.1 Run reproducible baseline/new-version throughput and heterogeneous-client scenarios; report measured results and remaining bottlenecks without invented gains. Completion audit added mixed_throughput.rs with simultaneous heterogeneous RTT/rate, unequal stream counts, shared credentials/link/budget, held receive payloads and per-client/group goodput. This verifies progress and resource isolation, not group scheduling fairness; that gap is tracked in completion-audit.md.
- [x] 4.2 Run fmt, clippy, nextest including required e2e, cargo deny, fingerprint verification and strict OpenSpec validation; resolve failures.
- [x] 4.3 Run cargo xtask coverage with line coverage >=90% and targeted parser fuzzing; add meaningful missing scenario/edge tests.

## 5. Release and online deployment

- [x] 5.1 Update protocol/usage docs and version 0.0.9; build supported Mac/Linux artifacts and verify versions/checksums.
- [x] 5.2 Publish exact-source release artifacts with change/test evidence and inspect remote CI status; do not claim unavailable CI passed.
- [x] 5.3 Back up privately and deploy both endpoints, verify matching versions/hashes and real TCP Vision, mux and QUIC routing plus online throughput.
- [ ] 5.4 Record sanitized verification, final service state and recovery instructions; archive completed change after final source integration.

Final service/recovery evidence is recorded in verification.md. Archive awaits source integration; current remote Actions are blocked by account billing, and no remote gate is bypassed.

## 6. Completion audit follow-up

- [x] 6.1 Resolve the mismatch between fixed 64MiB QUIC admission and valid lower memory limits; R13 reviews native credit/storage ownership. The actual 16MiB connection test failed with budget exhaustion before the change and now transfers an exact 512KiB echo; growth, limits and retained-reader ownership tests also pass. Artifact/deployment reconciliation remains under 6.3.
- [x] 6.2 Complete the original active-group scheduling and per-direction bottleneck-observation requirements: R14/R15 and their focused/runtime tests cover processing opportunities, directional pipeline I/O, credit, setup and budget pressure, with unavailable metrics explicit.
- [x] 6.2.1 Implement and verify ready-task group scheduling across authenticated TCP/Vision/QUIC/UDP paths, with cancellation-safe ownership, concurrent wake handling, idle-permit borrowing and per-group scheduler snapshots (R14).
- [x] 6.2.2 Complete data-path credit/socket/target/budget observations by group, mode and direction: opt-in anonymous pipeline registry, bounded closed history, async reporting, mux/native samples and actual TCP/QUIC runtime assertions.
- [ ] 6.3 Reconcile any further implementation with the published/deployed 0.0.9 source and artifacts, then repeat the completion audit against the full original plan.
