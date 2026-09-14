# Throughput and resource policy (0.0.9)

Umbra supports multiple clients on one server. Version 0.0.9 improves TCP mux flow control, TCP/Vision data paths, and QUIC packet processing. Quinn BBR is one QUIC-specific option; it does not replace Linux TCP congestion control or application receive credit.

## Configuration

Both client and server accept an optional table:

```toml
[performance]
memory_mib = 512
group_memory_mib = 256
max_window_mib = 64
adaptive_mux = true
diagnostics_interval_secs = 0 # server: set e.g. 10 to collect/report pipeline observations
quic_congestion = "bbr" # "cubic" or "new-reno" are also supported
```

These are bounded defaults, not allocations performed at startup and not a requirement to know the server's bandwidth. Memory limits must be positive and internally consistent (process 16–16384 MiB, group 16 MiB through the process limit). The maximum adaptive connection window is 1–64 MiB. Use a process budget appropriate to actual host/container memory, with headroom for the OS and other services.

`adaptive_mux` is the client opt-in for new TCP CONNECT mux sessions (`mux=true`). The upgraded server recognizes adaptive settings while still accepting legacy SYN/UDP sessions. A new adaptive client needs an upgraded server; setting `adaptive_mux=false` selects legacy mux explicitly. There is no automatic replay/downgrade after business data is accepted. Existing `mux=false` Vision selection and independent `udp_transport` selection remain available.

## TCP mux

An adaptive send direction obeys both per-stream and connection-wide cumulative credit. Receivers start with 256 KiB per stream and 1 MiB per connection. Rapid application consumption and measured RTT can grow windows up to 32 MiB per stream and the configured connection maximum. Growth is funded before credit is advertised. Different peers can advertise different limits; the controller does not multiply every connection by the server's NIC rate.

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

The authenticated server QUIC path starts aggregate receive credit at 2,500,000 bytes (or the configured maximum, if smaller), retains Quinn's 10,000,000-byte send window, and reserves 3MiB of connection staging. Its initial commitment is about 14.92MiB, allowing a connection under the supported 16MiB minimum budget. Each accepted application stream additionally reserves 64KiB for copy/framing/task storage; UDP associations, target readers and queued replies retain their separate charges. The connection's receive credit can grow with observed consumption and RTT up to `max_window_mib`, after successfully reserving the increase. Both the socket and retained receive streams keep that commitment alive. Outstanding grants are never revoked.

Native QUIC's per-stream receive limit remains at Quinn's reviewed 1,250,000-byte default, or half the initial aggregate limit if smaller. This Quinn version exposes only an aggregate receive-window setter at runtime; aggregate growth does not eliminate a single stream's fixed-window ceiling on a high-BDP path. Resource exhaustion stops growth or rejects a newly accepted application stream without stalling other connections. Fixed listener/stream limits remain additional ceilings.

Client TCP mux and Vision use local application-resource leases. Native QUIC client transport memory continues to follow Quinn's own transport limits; the server's shared-pool number is not a claim to measure all client-side or kernel memory. `ServerRuntime::committed_memory()` reports logical application commitments, not RSS. Socket buffers, allocator overhead and handshake work require separate operating-system headroom.

## Data path

- TCP relay directions progress independently with a shared inactivity clock and half-close handling.
- TLS bridge I/O owns its worker tasks; resources remain owned until workers and retained data are dropped.
- TLS records use standard in-place AEAD operations, preserving the same nonce, content type, tag and vector behavior.
- Frame/record/raw-Vision scratch buffers are reused; borrowed DATA is encoded directly into its final owned frame.
- Mux receive queues hold owned chunks, maintain an outer-local byte total and reuse scheduling ID storage.
- QUIC fills available receive batch slots without waiting for a full batch or losing datagram boundaries.

Vision raw still validates and receives a complete protected record before forwarding; this is userspace forwarding, not kernel zero-copy.

## BBR and TCP

The reviewed dependency pair is quinn 0.11.12 with quinn-proto 0.11.18. BBR/Cubic/NewReno selection is applied separately to each endpoint's outgoing QUIC traffic. The bundled BBR documentation labels that implementation experimental and references Google's `bbr_sender.cc`; it is not presented as BBRv3. See the [BBR API](https://docs.rs/quinn/0.11.12/quinn/congestion/struct.Bbr.html) and [paired release notes](https://github.com/quinn-rs/quinn/releases/tag/quinn-proto-0.11.18).

Linux TCP BBR applies to TCP sockets. It does not control a QUIC UDP connection. A QUIC proxy's separate server-to-target TCP connection can also use Linux BBR, on that different leg. A layer-4 frontend owns the public TCP socket; changing an application's loopback socket does not change that frontend's algorithm. No host-wide sysctl or kernel upgrade is performed by the binary.

## Evidence and limits

The change's [pre-change reviews](../openspec/changes/optimize-multiclient-throughput/prechange-review.md) identify the benefit evidence before each implementation. Reproducible synthetic measurements live in `crates/umbra-inner/tests/throughput.rs` and require explicit release-mode execution:

```sh
cargo test --release -p umbra-inner --test throughput -- --ignored --nocapture --test-threads=1
```

The diagnostic models a pipelined link with serialization and propagation delay, verifies exact payloads, and reports application goodput. It is not a physical NIC measurement. Startup/window growth is included in the reported transfer time. Live WAN results are reported separately because path capacity varied substantially during baseline collection. The earlier result does not imply a guaranteed gain for a workload already constrained by its network, target or CPU.

Validation includes asymmetric bidirectional windows, multiple real client runtimes and credentials, resource reclamation, backpressure/half-close, actual QUIC controller types, protocol properties and fuzzing. The ready-work scheduler is not a per-byte rate shaper. Cached cipher contexts and a complete duplex-bridge replacement remain conditional on bottleneck evidence. 0-RTT and fallback preconnection remain outside this release.

A later four-client shared-link diagnostic verifies different RTTs, path rates, stream counts and a paused receiver; it reports per-client/group goodput and credit/output wait time. Run it with `cargo test --release -p umbra-inner --test mixed_throughput -- --ignored --nocapture`. A live Vision profile also found low Umbra CPU use and throughput comparable to an adjacent same-endpoint SSH transfer. Full conditions and limitations are in the change's verification.md.

The final implementation includes native QUIC admission, group scheduling and opt-in pipeline observations. See the [verification record](../openspec/changes/optimize-multiclient-throughput/verification.md) for source/build identity, measured conditions, deployment checks and limitations.
