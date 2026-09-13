# Vision runtime wire amendment: authenticated solo v2 / raw profile v1

Status: **approved by the user on 2026-09-13 in this task**.
Prepared for the 2026-09-13 request to remove duplicate outer TLS encryption.
This appendix is the approved normative contract for implementation. It does not
describe the currently deployed mux path or claim an already implemented optimization.

## 1. Scope, activation, and trust

For TCP, the existing client setting selects the implementation: `mux=true`
uses encrypted multiplexing; `mux=false` uses this dedicated Vision solo
protocol. No separate Vision switch is added. The old wrapped-only solo
implementation is removed at the user's request. New servers retain v1 mux
and UDP associations, but reject legacy v1 solo before connecting any target.
The server dispatches authenticated v2 exclusively to this solo protocol.
There is no raw mode on a shared mux connection or QUIC stream.

The local application and its target are assumed to run actual end-to-end TLS
1.3. Passive record observation cannot verify their encrypted Finished messages
or AEAD tags, or prove that syntactically convincing malicious payload is
ciphertext. Eligibility below is structural observation, not inner peer
authentication. The application remains responsible for target certificate and
TLS verification. Umbra never obtains the inner keys or terminates that TLS.

Raw means forwarding the existing inner TLS record bytes with **no outer TLS,
Vision envelope, or padding**. It does not mean kernel zero-copy.

## 2. Authenticated mode discrimination and old peers

The encrypted REALITY authentication plaintext retains its existing 16-byte
layout and existing key derivation, nonce derivation, and HELLO0 AAD:

```text
version:u8 || flags:u8 || timestamp:u32be || short_id:[u8;8] || reserved:[u8;2]
```

- v1 is retained for encrypted mux and its UDP associations; legacy v1 solo is rejected.
- Vision v2 uses `version=0x02`, `flags=0`, `reserved=0`.
- Unsupported versions and nonzero v2 flags/reserved fields reject local
  authentication into the existing real-site fallback. Time, short-ID, and
  replay checks apply equally to both accepted versions.
- The validated authentication version MUST reach the runtime dispatcher; it
  MUST NOT be reconstructed by inspecting target application bytes.
- A v2 client sends no target, control, or business bytes until the outer peer
  is fully classified as `UmbraTrusted`.
- An old server does not accept v2. A RealSite/Invalid result does not trigger
  an automatic v1 retry, downgrade, or replay.
- v1 mux clients never receive v2 controls. New TCP solo requires both endpoints
  on 0.0.7 or later; choosing `mux=true` keeps the supported encrypted mux mode.

This authenticated discriminator avoids appending a magic string to the legacy
target preface, where an old server would relay it to an arbitrary target.

## 3. Target and capability exchange

After outer authentication, the first client application record MUST contain
exactly one existing encoded `TargetAddr`, with no trailing bytes. The next
client application record is HELLO. The server validates the preface and HELLO,
then performs a bounded target connection. It sends HELLO_ACK only after target
success/failure is known. It does not forward envelope/control bytes to target.

Before a successful HELLO_ACK, neither endpoint sends DATA, FIN, PADDING, or
switch messages. The client returns SOCKS success only after target success.
Target failure returns the ordinary SOCKS failure and closes the session.

## 4. Envelope and record ownership

All integers are big-endian. Each subsequent outer TLS application record has
exactly one envelope as its complete application plaintext:

```text
version:u8 = 1
kind:u8
flags:u16 = 0
body_len:u16
padding_len:u16
body:[u8;body_len]
padding:[u8;padding_len]
```

The 8-byte header plus body and padding MUST equal the complete plaintext length
and MUST NOT exceed 16,384 bytes. Unknown envelope versions, kinds, flags,
wrong body sizes, trailing bytes, or an envelope spanning outer records are
terminal protocol errors. Multiple envelopes in one outer record are forbidden.
TCP reads may split or combine any number of records and MUST NOT change this
interpretation. Only declared padding is removed, exactly once.

| Kind | Direction/name | Exact body |
| --- | --- | --- |
| `01` | Client HELLO | `min_raw_ver:u8, max_raw_ver:u8, features:u16` |
| `02` | Server HELLO_ACK | `selected_raw_ver:u8, target_result:u8, features:u16` |
| `10` | Either DATA | 1..16,376 unmodified target bytes, subject to total record limit |
| `11` | Either FIN | `final_offset:u64` |
| `12` | Either PADDING | empty; padding_len must be positive |
| `20` | Client SWITCH_REQ | `switch_id:u32, c2s_boundary:u64` |
| `21` | Server SWITCH_ACK | `switch_id:u32, c2s_boundary:u64, s2c_boundary:u64` |
| `22` | Client COMMIT | same 20-byte layout as SWITCH_ACK |
| `23` | Server COMMIT_ACK | same 20-byte layout as SWITCH_ACK |
| `24` | Server SWITCH_REJECT | `switch_id:u32, c2s_boundary:u64, s2c_offset:u64, reason:u8` |

Control kinds other than PADDING MUST have `padding_len=0`. DATA may carry
padding up to the total record limit. The initial profile pads the first 16 DATA
envelopes per direction with 100..1,400 fresh random bytes, limiting each such
DATA body to 14,976 bytes so even the largest padding fits. Later DATA has no
padding. No claim of indistinguishable control lengths or packet timing follows.

For HELLO, `1 <= min_raw_ver <= max_raw_ver <= 255`; the current sender uses
`min=1,max=1,features=1`. Feature bit 0 requests TLS 1.3 raw profile v1; all
other bits are reserved and MUST be zero. The server selects version 1 only if
offered and supported with feature bit 0. Otherwise it returns version 0 and
features 0; the session permanently uses encrypted envelopes. `target_result`
is 0 for success or 1 for failure; all other values are invalid. The only valid
selection pairs are `(selected_raw_ver=0,features=0)` for wrapped-only, or
`(selected_raw_ver=1,features=1)` when version 1 and feature 1 were offered.
Version zero is the explicit exception to selecting an offered raw version;
it never authorizes raw mode. No ACK may enable an unoffered feature.

Declining a raw capability on an authenticated v2 connection is **wrapped v2**,
not a retry against a legacy peer. Future envelope formats require a separate
authenticated mode version; unknown envelope formats are never guessed.

## 5. Inner TLS observation

Observation starts at offset zero in each target stream, with no scan for later
magic or resynchronization. It runs while forwarding available bytes in DATA;
it MUST NOT wait for a complete sniffing prefix before normal relay progress.

Each direction incrementally reassembles record headers, record bodies, and
handshake messages independently of socket or DATA boundaries. Eligibility
requires all of the following:

1. A structurally valid ClientHello with exact vector/extension lengths and no
   duplicate extensions, offering TLS 1.3 via supported_versions. Its record
   legacy version may be `0301` or `0303`; the handshake legacy version is `0303`.
2. A matching complete ServerHello with handshake legacy_version `0303`,
   supported_versions `0304`, zero compression, matching session-ID echo, and
   a cipher offered by the client. The first profile accepts only `1301`,
   `1302`, and `1303`, all with 16-byte authentication tags. The selected
   key-share group must have a structurally valid offered client share.
3. No HelloRetryRequest, early_data, pre_shared_key negotiation, unsupported
   prerequisite for establishing the preceding checks, or unexpected cleartext
   handshake sequence. Such streams remain wrapped without changing their bytes.
4. After ServerHello, each direction has supplied at least one complete
   protected record: `17 03 03`, payload length 17..16,640. Merely seeing its
   header, a partial body, or `17 03 03` inside payload does not count.
5. Both selected switch offsets fall immediately after complete protected inner
   records, with no partially received record before either offset.

Compatibility CCS is recognized only as `14 03 03 00 01 01`, between the first
ClientHello and that direction's first protected record. It never contributes
to eligibility. Unexpected CCS/record structure disables raw eligibility.

TLS 1.2, non-TLS, malformed or unsupported input, and limits below permanently
select WRAPPED_ONLY before switching. The entire original byte sequence still
travels through DATA; observation must not discard or mutate it. Unknown
extensions with valid lengths that do not affect these negotiation checks may
be skipped. Unknown cipher or selected key-share semantics remain wrapped.

Protected records can contain encrypted handshake messages or alerts; this
document never equates content type `17` with verified Finished.

## 6. Limits and deadlines

| Resource | Hard bound / behavior |
| --- | --- |
| Outer TLS ciphertext payload | 16,640 bytes; validate before allocation |
| Envelope plaintext | 16,384 bytes |
| Complete protected inner record | 16,645 bytes including its header |
| Unprotected inner record payload | 16,384 bytes |
| Reassembled handshake message | 65,536 bytes including its handshake header |
| Pending outbound ciphertext | At most 2 records, at most 33,290 bytes total; reserve one queue slot for control |
| Decoded, undelivered target bytes | 32,768 bytes per direction |
| Socket raw/read-ahead buffer | 16,645 bytes; retain handshake pending input separately within 32,768 bytes |
| Total inspected bytes per direction | 262,144, then permanent WRAPPED_ONLY |
| Observation time | 5 seconds from the first target byte in either direction; no rolling reset |
| Additional local data held during switch | 32,768 bytes per direction; stop reading at capacity |
| Target preface + HELLO receive | 5 seconds from completed outer authentication |
| Initial client ACK wait | 25 seconds, covering existing bounded target connect |
| Switch transaction | 5 seconds from local send/receive of SWITCH_REQ; no phase reset |
| Switch attempts | at most one; `switch_id=1` |
| Target byte counters | checked u64; overflow closes |
| Aggregate session-owned data buffers | 524,288 bytes, excluding established cryptographic state; backpressure or fail before exceeding |

Record/handshake storage, switch-held bytes, pending ciphertext, and decoded
payload queues each have explicit bounded ownership. A full downstream queue
applies backpressure; it does not prevent polling the opposite direction where
progress can be made. Session cancellation drops/joins all owned work.

## 7. Four-message commit and exact byte accounting

Counters C and S count only target bytes carried in DATA, including inner TLS
headers. They exclude target addressing, envelope headers, controls, and padding.
The sender counts accepted DATA exactly once; the receiver verifies matching
accepted DATA at the wire boundary. Previously decoded DATA is delivered before
the corresponding raw suffix, with separate bounded queues as needed.

The client is the sole coordinator. Before sending SWITCH_REQ it must be
eligible and stop at a complete c2s record boundary C. A DATA body may split a
record, but a switch cannot leave a partial record before C or S.

| Endpoint/state | Input or decision | Required action / next state |
| --- | --- | --- |
| Client WRAPPED | raw negotiated and eligible | finish pending c2s DATA at C; send REQ(1,C); freeze c2s DATA; WAIT_ACK |
| Server WRAPPED | REQ(1,C) | validate eligibility, received count C and record boundary; drain accepted s2c DATA through complete boundary S; send ACK(1,C,S); freeze s2c DATA; WAIT_COMMIT |
| Server WRAPPED | valid REQ but local eligibility unavailable or FIN already sent | flush accepted s2c DATA; send REJECT with exact current C/S and reason; permanently WRAPPED_ONLY |
| Client WAIT_ACK | s2c DATA | receive and deliver in order; no new c2s DATA |
| Client WAIT_ACK | ACK(1,C,S) | validate exact counts/boundaries; send and fully drain COMMIT(1,C,S); WAIT_COMMIT_ACK |
| Client WAIT_ACK | REJECT(1,C,S,reason) | validate exact received counts; remain encrypted; resume queued c2s DATA/FIN; permanently WRAPPED_ONLY |
| Server WAIT_COMMIT | COMMIT(1,C,S) | authenticate/validate; send and fully drain COMMIT_ACK(1,C,S); RAW |
| Client WAIT_COMMIT_ACK | COMMIT_ACK(1,C,S) | authenticate/validate exact record end; RAW |

REJECT is permitted only before the server has sent or queued SWITCH_ACK. Its
reason is 1 for local eligibility/boundary availability or 2 for a local FIN
already queued/sent. If a local FIN is already queued or sent, reason MUST be 2;
reason 1 is permitted only otherwise. Other reasons are invalid. C must still equal the exact
received client DATA count. The server first flushes already accepted DATA
through the reported S offset, then REJECT; S need not be a protected-record
boundary because the stream remains wrapped. The client checks that its received
DATA count equals S and C matches its request. Rejection resumes encrypted
DATA/FIN only; it cannot occur after COMMIT or any raw bytes. Unknown/duplicate
requests, dishonest offsets, and malformed controls remain terminal errors.

No server-initiated request exists. Simultaneous eligibility therefore follows
the same sequence. While draining to S, the server may finish only a bounded
partially read record and already accepted DATA; it must not keep reading new
records indefinitely before ACK. A stalled partial record times out and closes.

The client's final outer TLS record is COMMIT. The server's final outer TLS
record is COMMIT_ACK. The server writes raw only after fully flushing its ACK;
the client writes raw only after authenticating that ACK. Each receiver changes
its byte interpretation exactly after the peer's final control record. TCP
read-ahead following that boundary belongs to raw input and is retained in order.

An endpoint never attempts outer decryption of post-boundary bytes and then
falls back on authentication failure. No outer close_notify, KeyUpdate,
envelope, or padding may be emitted after its final control record.

Before SWITCH_REQ, absent capability or eligibility keeps the session wrapped.
After a request, only a valid pre-ACK REJECT permits continued encrypted relay.
Otherwise mismatched counters, wrong roles, duplicates, unexpected controls/DATA, deadline expiry,
truncation, session cancellation, or failed I/O close the connection. There is
no implicit rollback to wrapped mode. TCP retransmits transport packets; the
application never replays these controls or business payload.

## 8. EOF, cancellation, and raw relay

In WRAPPED, FIN has the exact count of preceding DATA, closes only that target
direction, and follows all its DATA. No later DATA may follow FIN. The reverse
direction stays open. A connection with a sent/received FIN before REQ remains
wrapped. If a server FIN crosses a client REQ in transit, the client records
that FIN while awaiting the server's REJECT(reason=2), then completes wrapped
half-close normally. ACK/COMMIT after this FIN is invalid. The server may send
REJECT after FIN because FIN closes target DATA, not the encrypted control
channel. Unexpected outer EOF without the required FIN is truncation.

After a valid REQ, local target EOF is recorded without sending a new FIN or
closing the control channel; after successful handoff and queued payload drain,
it becomes a raw TCP half-close. A target EOF with an incomplete TLS record is
terminal. EOF on the outer connection during the barrier is terminal.

Raw forwarding retains a bounded protected-record parser. Before forwarding a
record, it validates `17 03 03` and the 17..16,640 length range; the record is
forwarded unchanged. Invalid headers, unexpected cleartext records, or trailing
non-TLS bytes close without forwarding the offending record. Inner encrypted
alerts and KeyUpdate remain protected records and pass unchanged. A complete
record boundary followed by EOF half-closes the target writer while allowing
reverse responses. Partial-record EOF is an error.

Read and write cancellation during normal scheduling preserves every byte and
offset in the session owner. A sealed-but-partially-written record is resumed
as the same ciphertext, never sealed again. Fatal cancellation closes and
cleans up; there are no detached tasks retaining or later writing the socket.
After final controls, outer traffic keys are destroyed when no longer needed.

## 9. Golden application-plaintext vectors

These synthetic vectors are **inside authenticated outer TLS**, not cleartext
wire controls. They contain no real user credentials. Offsets 256/512 test the
encoding; an integration switch also needs real eligible TLS boundary evidence.

```text
target 127.0.0.1:443
01 7f 00 00 01 01 bb

HELLO raw v1
01 01 00 00 00 04 00 00 01 01 00 01

HELLO_ACK raw v1, target success
01 02 00 00 00 04 00 00 01 00 00 01

HELLO_ACK wrapped only, target success
01 02 00 00 00 04 00 00 00 00 00 00

DATA abc, two synthetic padding bytes
01 10 00 00 00 03 00 02 61 62 63 00 00

SWITCH_REQ id=1,C=256
01 20 00 00 00 0c 00 00 00 00 00 01 00 00 00 00 00 00 01 00

SWITCH_ACK id=1,C=256,S=512
01 21 00 00 00 14 00 00 00 00 00 01 00 00 00 00 00 00 01 00 00 00 00 00 00 00 02 00

COMMIT id=1,C=256,S=512
01 22 00 00 00 14 00 00 00 00 00 01 00 00 00 00 00 00 01 00 00 00 00 00 00 00 02 00

COMMIT_ACK id=1,C=256,S=512
01 23 00 00 00 14 00 00 00 00 00 01 00 00 00 00 00 00 01 00 00 00 00 00 00 00 02 00

FIN final_offset=3
01 11 00 00 00 08 00 00 00 00 00 00 00 00 00 03

SWITCH_REJECT id=1,C=256,S=512, reason=2 (FIN already sent)
01 24 00 00 00 15 00 00 00 00 00 01 00 00 00 00 00 00 01 00 00 00 00 00 00 00 02 00 02
```

Normative negative vectors include every prefix truncation; changing flags to
1; inconsistent body/padding totals; control padding; duplicate/wrong-role
controls; id 0 or 2; C/S off by one; COMMIT_ACK before COMMIT; DATA after the
sender's boundary; unknown versions; and an application record containing two
concatenated envelopes. None authorizes raw mode.

## 10. Required acceptance evidence

1. Encode/decode matches the fixed vectors, with property and bounded fuzz tests.
2. Stateful partial reads/writes preserve exact records at every split/cancel
   point, including the final ACK coalesced with multiple raw records.
3. Actual Umbra client/server plus an independent inner TLS peer exchanges exact
   business bytes. Captured proxy TCP bytes after commit equal the original
   inner protected records. Outer seal/open counters stop after final controls.
4. Non-TLS, TLS 1.2, standalone `0x17`, HRR, early data, unsupported capability,
   malformed records, and observer limits never accidentally enable raw.
5. Both endpoints becoming eligible together, target failure, counter mismatch,
   ACK timeout, stalled reads, EOF, half-close, and cancellation terminate or
   progress exactly as specified without replay or leaked tasks.
6. Legacy v1 clients continue to work; v2 against an old server sends no target
   or business to a fallback; mux and QUIC never enter this path.
7. Formatting, strict clippy, complete workspace/ignored tests, parser fuzz
   smoke, cargo-deny, available fingerprint checks, OpenSpec strict validation,
   and line coverage >=90% pass without lowering/excluding gates.
8. Per the user’s subsequent instruction, omit performance comparisons. Report
   the actual raw-byte/counter proof without a promised speedup.

Reference: [RFC 8446 record protection](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.2).
