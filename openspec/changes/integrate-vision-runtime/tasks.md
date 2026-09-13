## 1. Verification and exact wire approval

- [x] 1.1 Trace actual client/server solo data ownership and record the continued outer encryption with source anchors in `audit.md`.
- [x] 1.2 Run the unmodified solo/Vision/TLS bridge tests and record their scope: 5 passed, with no production raw-wire proof.
- [x] 1.3 Prepare exact authenticated version, envelopes, limits, four-message commit, lifecycle rules, and golden plaintext vectors in `docs/vision-runtime-wire-v2.md`.
- [x] 1.4 User explicitly confirmed the concrete wire appendix on 2026-09-13 (reply: 确认), authorizing implementation and testing of both endpoints.

## 2. Authenticated opt-in and wire parsing

- [x] 2.1 Follow the user’s simplification: reuse `mux=false` for new solo, remove the duplicate legacy solo/helper and extra Vision switch, and test that an unowned plaintext outer cannot enter Vision.
- [x] 2.2 Add authenticated v2 discrimination with unchanged v1 behavior; verify version/time/short-ID/replay rejection and no target/control/business bytes to an old-server fallback.
- [x] 2.3 Implement exact target record and Vision envelope codec, checked counters, and limits; pass golden vector and every-header-truncation tests.
- [x] 2.4 Implement target/capability exchange and wrapped-only negotiation; verify target failure precedes SOCKS success and no envelope bytes reach the target.

## 3. Bounded observation and controlled transport ownership

- [x] 3.1 Add persistent bounded inner record/handshake observation; verify fragmented real TLS 1.3 and all specified noneligible TLS/non-TLS inputs without delaying normal payload relay.
- [x] 3.2 Add the established TCP record owner and defer legacy bridge conversion; verify retained handshake input and mux/QUIC regression behavior and deliberate legacy-solo rejection.
- [x] 3.3 Add resumable record reader/writer queues with fixed memory limits and control capacity; test cancellation at all partial offsets without reseal, lost prefixes, or duplicate bytes.
- [x] 3.4 Implement record-sized envelope padding and exact removal; verify target byte identity and actual outer record boundaries independently of socket writes.

## 4. Production raw transition

- [x] 4.1 Implement the pure client-coordinated switch state machine; cover simultaneous eligibility, counters, roles, duplicates, early controls, and total deadline failures.
- [x] 4.2 Connect both real client/server solo paths to the final-control drain and consuming raw handoff; verify ACK/raw coalescing and no detached TLS owner survives.
- [x] 4.3 Implement bounded protected-record raw forwarding and directional EOF; verify no outer framing/encryption, delayed reverse responses, invalid suffix rejection, cancellation, and cleanup.
- [x] 4.4 Run an independent real inner TLS fixture through the production runtime; assert exact target bytes, captured post-boundary wire equality, and stopped outer seal/open counters.

## 5. Tests and coverage >= 90%

- [x] 5.1 Add proptest and bounded fuzz coverage for envelopes, TLS observation, and switch transitions; run reproducible smoke checks and retain failure fixtures.
- [x] 5.2 Run `cargo fmt --all --check`, strict all-target clippy, complete workspace/ignored nextest (475 passed), cargo-deny, available fingerprint checks, and strict OpenSpec validation; investigate every failure without weakening gates.
- [x] 5.3 Run `cargo xtask coverage` and keep line coverage >=90% with all changed paths included; measured 94.77%.
- [x] 5.4 Independently review the final diff for security boundaries, compatibility, secrets, queue/cancellation ownership, and discrepancies between claims and tests.

## 6. Performance and delivery evidence

- [x] 6.1 Per user steering, omit performance comparisons; prove the optimization through captured raw record equality and stopped outer encryption counters.
- [x] 6.2 Update usage, protocol review, and implementation task references with the verified mode and paired-endpoint requirements; distinguish raw userspace forwarding from kernel zero-copy and unmeasured deployment results.
- [ ] 6.3 User explicitly requested version 0.0.7, remote push, and server/Mac deployment: bump release metadata, commit/push through the repository workflow, build both targets, deploy and verify actual Vision operation while preserving available legacy mux service.
