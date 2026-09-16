# Throughput and resource policy (1.0.0-alpha)

Umbra supports multiple clients on one server. Version 1.0.0-alpha adds runtime-detected AES/PMULL acceleration, reusable TLS cipher state, ready-stream mux scheduling, shared QUIC receive batches and independent UDP progress. Quinn BBR is one QUIC-specific option; it does not replace Linux TCP congestion control or application receive credit.

Deployment assumes at least 1GiB of physical server RAM, with throughput as the primary optimization goal. Hosts with extremely small memory budgets are not an optimization target. The configurable application-commitment floor is not a physical-RAM requirement: process/group budgets manage concurrent clients, and defaults are 512MiB/256MiB. Future tuning should prioritize demonstrated high-BDP window or data-path limits rather than minimum-memory operation.

## Configuration

Both client and server accept an optional table:

```toml
[performance]
memory_mib = 512
group_memory_mib = 256
max_window_mib = 64
quic_stream_window_mib = 6
quic_send_window_mib = 32
adaptive_mux = true
diagnostics_interval_secs = 0 # server: set e.g. 10 to collect/report pipeline observations
quic_congestion = "bbr" # "cubic" or "new-reno" are also supported
```

These are bounded defaults, not allocations performed at startup and not a requirement to know the server's bandwidth. Memory limits must be positive and internally consistent (process 16–16384 MiB, group 16 MiB through the process limit). The maximum adaptive connection window is 1–64 MiB. Use a process budget appropriate to actual host/container memory, with headroom for the OS and other services.

`adaptive_mux` is the client opt-in for new TCP CONNECT mux sessions (`mux=true`). The upgraded server recognizes adaptive settings while still accepting legacy SYN/UDP sessions. A new adaptive client needs an upgraded server; setting `adaptive_mux=false` selects legacy mux explicitly. There is no automatic replay/downgrade after business data is accepted. Existing `mux=false` Vision selection and independent `udp_transport` selection remain available.

## TCP mux

An adaptive send direction obeys both per-stream and connection-wide cumulative credit. Production receivers start with 1MiB per stream and 4MiB per connection, clipped to `max_window_mib`. The library `FlowSettings::default()` retains 256KiB/1MiB for explicit callers. Rapid application consumption and measured RTT can grow windows up to 32 MiB per stream and the configured connection maximum. Growth is funded before credit is advertised. Different peers can advertise different limits; the controller does not multiply every connection by the server's NIC rate.

The driver visits changed streams, deduplicates wakes and tracks only participants in each finite output batch. Consumption updates are coalesced, with immediate low-credit and FIN/RST settlement. Pending outer establishment releases the pool lock so a healthy outer can keep accepting available work.

The first real probe reply replaces the bootstrap RTT; later replies are smoothed. The connection retains partial reads/writes and pending credit across cancellation. Expanded credit is independent of consumed-byte acknowledgement. FIN and RST settle cumulative counters; legal in-flight data for a retired stream returns aggregate credit without recreating the stream. Old fixed-window mux remains bounded by its existing stream/window contract.

SETTINGS is the first frame in one write batch with configured cover padding. The ordinary business-write padding schedule is unchanged. The feature does not modify TLS ClientHello construction.

## Shared server resources

Authenticated connections use an opaque group derived from the canonical configured credential. Multiple outers and transports using the same credential share the group ceiling; clients sharing credentials are not independently identified. There is no account or billing system and no claim of exact equal Mbps per person.

Ready authenticated task polls rotate across credential groups and then their queued tasks. The gate covers Vision relay, TCP mux drivers/targets/TLS record workers, native QUIC drivers/streams and UDP target readers. Its parallel permit count follows the Tokio worker count; one ready group can use all permits, and waiting I/O releases a permit immediately. Original Tokio tasks retain future ownership, so abort/join semantics remain available. Classification and unauthenticated fallback keep their original scheduling path. This balances processing opportunities; different poll costs, path capacities and RTTs still produce different throughput.

`ServerRuntime::scheduling_snapshot()` exposes anonymous per-group live/queued/active task counts, completed polls, cumulative ready-queue wait and wall time inside polls. Poll wall time is not a process CPU measurement. No target, credential bytes, peer address or session identifier is included. Group deques are reused while tasks remain and freed after the last task closes.

## Optional pipeline diagnostics

Set `performance.diagnostics_interval_secs` on the server to 1–3600 seconds (for example 10). Zero disables pipeline collection and reporting. `ServerRuntime::performance_snapshot()` returns the same typed observations alongside budget and scheduler snapshots. Budget refusal counts and scheduling continue to function when pipeline collection is disabled. Reports use asynchronous stderr writes and contain only numeric local observation/group identifiers, typed modes and counters.

| Observation | Meaning and limits |
|---|---|
| Transport read / write | Server-perspective outer bytes processed/accepted; includes TLS/mux/QUIC overhead and QUIC retransmissions, excludes IP/UDP headers |
| Target read / write | Business bytes read from targets / accepted by target writes; prefetched reads and queued writes do not prove remote application delivery |
| Pending polls / observed wait | Pending I/O calls and time spanning owned I/O polls, including scheduling/application delays and cancellation; raw QUIC callback wait duration is unavailable |
| Target setup | Attempt count and observed DNS/connect time, including failed or cancelled attempts |
| Mux credit | Funded receive window, queued receive/output bytes, consumption, aggregate send credit and zero-credit send attempts |
| Native QUIC credit | Funded aggregate receive window, stream-read consumption and sent/received DATA_BLOCKED or STREAM_DATA_BLOCKED frame counts; those frames can repeat |
| Budget | Current/peak logical commitments and admission/growth refusals by group; process/group cause counters may overlap |

Unavailable fields are `None`, not zero. Credit values are sampled during existing progress (mux at most every 100ms, native QUIC on its existing controller tick), with sample age reported. Native consumed bytes include the stream opening/envelope bytes read through Quinn. Vision has no mux-credit sample. CPU utilization still needs operating-system measurements; scheduler poll wall time is not CPU time.

Only active observations and the last 128 closed observations are retained. Identify observations by their local id when computing deltas: naively summing the rolling history can decrease when older entries expire. Counters for canonical configured budget/scheduler groups remain available after their flows close. These diagnostics identify pipeline pressure without exposing addresses, SNI, credentials, payloads or protocol session identifiers.

The shared pool accounts for receive commitments and separate staging allowances. Leases follow ownership through TLS workers, retained stream data, UDP target readers and queued UDP replies. Cloning a lease retains one commitment; it does not charge twice or release early. Growth leaves one eighth of the process ceiling available for initial admissions. Outstanding grants cannot be revoked or lent to another connection just because its queue is momentarily empty.

Both native QUIC endpoints start with 6MiB per-stream receive credit, 15MiB aggregate receive credit and a 32MiB send-storage ceiling. `quic_stream_window_mib` and `quic_send_window_mib` accept 1–64MiB; the stream setting is clipped to `max_window_mib`. Initial aggregate credit is clipped to the configured maximum and one eighth of the group budget; send storage is clipped to one quarter of that budget. Each connection additionally reserves 3MiB of staging, giving a default initial logical commitment of 50MiB. Application streams and UDP targets retain their separate allowances.

Aggregate credit grows from observed consumption rate and RTT after funding the increase. Delayed 50ms samples work on short-RTT paths. Quinn's fixed per-stream ceiling cannot grow after establishment; high-BDP single-stream workloads can select a larger `quic_stream_window_mib` on the receiving endpoint. Outstanding grants are never revoked. Default on-wire flow-control fields match the checked-in Chrome 153 capture; overrides change those fields, and full Chrome equivalence remains unverified.

Ingress uses shared same-flow batches and four physical receive slots, retaining datagram boundaries and metadata. Each flow is bounded by 1MiB of retained payload allocation and 64 queued batches, with at most 64 datagrams per batch. Diagnostic ingress fields report retained/peak bytes and dropped datagrams/bytes. A saturated flow never blocks dispatcher progress for its siblings.

Native QUIC clients share an endpoint per address family. Connections, retained readers and window controllers own funded commitments; closing one association leaves its siblings active. TCP and QUIC UDP carriers keep partial writes in independently polled state, while bounded target setup/send queues permit reverse traffic, control closure and idle detection to continue.

Both client and server account for native QUIC application commitments. `ServerRuntime::committed_memory()` reports logical commitments, not RSS; kernel buffers, allocator overhead and handshake work still need OS headroom.

## Data path

- TCP relay directions progress independently with a shared inactivity clock and half-close handling.
- TLS bridge I/O owns its worker tasks; resources remain owned until workers and retained data are dropped.
- TLS directions own independent application keys, drop handshake state and reuse record buffers. Zeroizing cached AEAD contexts use automatic hardware detection; in-place operations preserve nonce, content type, tag and vector behavior.
- Frame/record/raw-Vision scratch buffers are reused; borrowed DATA is encoded directly into its final owned frame.
- Mux receive queues hold owned chunks, maintain an outer-local byte total and reuse scheduling ID storage.
- QUIC fills available receive batch slots without waiting for a full batch or losing datagram boundaries.

Vision raw validates complete record prefixes in bounded 64KiB read-ahead storage, batches available records and retains partial suffixes. A shared activity clock tracks partial I/O. This remains userspace forwarding.

## BBR and TCP

The reviewed dependency pair is quinn 0.11.12 with quinn-proto 0.11.18. BBR/Cubic/NewReno selection is applied separately to each endpoint's outgoing QUIC traffic. The bundled BBR documentation labels that implementation experimental and references Google's `bbr_sender.cc`; it is not presented as BBRv3. See the [BBR API](https://docs.rs/quinn/0.11.12/quinn/congestion/struct.Bbr.html) and [paired release notes](https://github.com/quinn-rs/quinn/releases/tag/quinn-proto-0.11.18).

Linux TCP BBR applies to TCP sockets. It does not control a QUIC UDP connection. A QUIC proxy's separate server-to-target TCP connection can also use Linux BBR, on that different leg. A layer-4 frontend owns the public TCP socket; changing an application's loopback socket does not change that frontend's algorithm. No host-wide sysctl or kernel upgrade is performed by the binary.

## Evidence and limits

The change's [pre-change reviews](../openspec/changes/optimize-multiclient-throughput/prechange-review.md) identify the benefit evidence before each implementation. Reproducible synthetic measurements live in `crates/umbra-inner/tests/throughput.rs` and require explicit release-mode execution:

```sh
cargo test --release -p umbra-inner --test throughput -- --ignored --nocapture --test-threads=1
```

The diagnostic models a pipelined link with serialization and propagation delay, verifies exact payloads, and reports application goodput. It is not a physical NIC measurement. Startup/window growth is included in the reported transfer time. Live WAN results are reported separately because path capacity varied substantially during baseline collection. The earlier result does not imply a guaranteed gain for a workload already constrained by its network, target or CPU.

Validation includes asymmetric bidirectional windows, multiple real client runtimes and credentials, resource reclamation, backpressure/half-close, actual QUIC controller types, protocol properties and fuzzing. The ready-work scheduler is not a per-byte rate shaper. Cached cipher contexts are enabled with verified key destruction. The general plaintext duplex bridge remains, with independent key owners and reusable buffers; its complete replacement remains conditional on evidence. 0-RTT and fallback preconnection remain outside this release.

A later four-client shared-link diagnostic verifies different RTTs, path rates, stream counts and a paused receiver; it reports per-client/group goodput and credit/output wait time. Run it with `cargo test --release -p umbra-inner --test mixed_throughput -- --ignored --nocapture`. A live Vision profile also found low Umbra CPU use and throughput comparable to an adjacent same-endpoint SSH transfer. Full conditions and limitations are in the change's verification.md.

The final implementation includes native QUIC admission, group scheduling and opt-in pipeline observations. See the [verification record](../openspec/changes/optimize-multiclient-throughput/verification.md) for source/build identity, measured conditions, deployment checks and limitations.

Alpha measurements, exact commands and release/deployment scope are in the [alpha verification record](../openspec/changes/optimize-throughput-alpha/verification.md).
