# Alpha throughput verification

## Baseline before implementation

Source: bc967e6, implementation 201bca9, version 0.0.9. The original two uncommitted documentation edits describe the user-approved >=1GiB server-memory assumption and remain preserved. Baseline release binaries and private deployment receipts are retained outside git.

On the local ARM64 Mac, the existing release-mode `work::tests::measure_record_work_with_and_without_group_gate` seals 4,096 16KiB AES-128-GCM payloads (64MiB), including allocation and yield overhead. Three ungated baseline samples were 1205.377, 1259.555, 1253.680Mbps (median 1253.680). In an isolated build with `--cfg aes_armv8 --cfg polyval_armv8`, samples were 5555.901, 6156.176, 6169.928Mbps (median 6156.176). Ratio 4.910; no WAN improvement is inferred. Existing release artifact fingerprints had empty rustflags. All 16 crypto primitive/vector/property tests and the in-place all-suite comparison passed under the accelerated build.

The existing release-mode mux diagnostic models a 1Gbps pipelined link and transfers 8MiB including startup/finish. Medians over three samples (fixed/adaptive Mbps): RTT0 693.104/964.709; RTT50ms 38.884/224.233; RTT100ms 20.354/117.002. These are emulator results, not physical network measurements.

## Scenario verification map

- Reusable/cleared/accelerated contexts: crypto vector/property/context tests and forced-software runs.
- Record ownership/cancellation/header/EOF: TLS record, owned_tls, tls_io and Vision tests.
- Native policy/sample cadence: resources/config/transport-parameter and quic_resources tests plus authenticated native runtime transfers.
- Batch burst/saturation: QUIC queue/adapter/routing tests and ingress diagnostic.
- UDP blocked writer/setup/endpoint sibling: UDP association state and actual TCP/QUIC runtime tests.
- Ready mux/credit/startup: mux driver/session tests and startup/warmed/mixed-stream diagnostics.
- Vision borrowed encoding/raw activity: proto envelope properties, owned record and raw relay tests.
- Alpha identity/deployment: CLI version tests, distribution checksums and private paired-deployment receipts.

Final outcomes are appended only after execution; task checkboxes are not substitutes for test evidence.
