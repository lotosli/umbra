# Chrome 153 macOS capture evidence

- Capture date: 2026-09-14 (Asia/Shanghai).
- Actual installed browser: **Google Chrome 153.0.8010.37**, macOS. The relaunched-browser/version metadata identifies this version; none of this session's raw data is labeled Chrome 152.
- TCP method: the normal, restarted GUI Chrome was driven through CUA to a synthetic `https://fingerprint.localhost` destination. A loopback TCP listener recorded the first TLS record before sending a server response.
- QUIC method: a separate headless process from the same installed Chrome used a clean temporary profile, `--no-proxy-server`, and `--origin-to-force-quic-on=quic-capture.invalid:19443` to send QUIC to a loopback UDP listener. The listener captured two datagrams; no server handshake or HTTP request was completed.
- This is a diagnostic loopback capture with forced QUIC, not a general claim about every Chrome 153 network configuration. The TCP and QUIC captures use different synthetic names and browsing modes.
- Only the three relevant raw records/datagrams, one derived QUIC ClientHello, and decoded public handshake fields are retained here. Browser profile directories, cookies, private keys, and application traffic are not included.

## Evidence status and scope

This note adds fresh Chrome 153 evidence. It does **not** update `chrome-latest.toml` or `chrome-150-macos.toml`, and it does not change either historical Chrome 150 evidence status. There is no new production Chrome 153 profile in this change.

| Scope | Status | Available evidence |
| --- | --- | --- |
| Chrome 153 TCP ClientHello | Captured and decoded | Full first TLS record; exact extension payloads and field order. |
| Chrome 153 QUIC Initial / ClientHello | Captured, authenticated Initial decryption, and reassembled | Two complete UDP datagrams; complete CRYPTO stream ClientHello and decoded transport parameters. |
| Matching Umbra bytes to Chrome 153 | Not established | This note compares reference fields; it does not claim a production profile or byte-for-byte equivalence. |
| Server handshake, HTTP/3 settings, resumption and migration | Not captured | ClientHello/Initial-only capture. No H3 SETTINGS can be inferred from this data. |

The `.hex` files encode raw bytes in 32-byte lines without comments. Decode with `bytes.fromhex(...)`. Hashes below refer to the **decoded raw bytes**, not the text files. [Decoded fields](captures/chrome-153-macos/decoded.json) include extension payload hex, raw hashes, CRYPTO offsets, key-share hashes and comparisons against the unchanged 150 profile.

| Raw sample | Bytes | SHA-256 |
| --- | ---: | --- |
| [chrome-153-running-tcp.bin](captures/chrome-153-macos/chrome-153-running-tcp.hex) | 1929 | `f0c4224f8221184e4e43f78ac58805cc6ff375a378323e6b62b9a92ada2ba6a6` |
| [quic-after-00.bin](captures/chrome-153-macos/quic-after-00.hex) | 1250 | `1ee77f873354b2aa358481624cc22f4881dc21d7ab51578410533a4c4b881bfa` |
| [quic-after-01.bin](captures/chrome-153-macos/quic-after-01.hex) | 1250 | `01788d6f86535ccb02996b147a4ceadb49ccdd5ce5ceaec30063d08b6e201ced` |
| [chrome-153-quic-clienthello.bin](captures/chrome-153-macos/chrome-153-quic-clienthello.hex) | 1955 | `5a55989c6a731e1d18b6a818d47b90dd92e063ce82b253f921ad3280e60eecb9` |

## Decoding and cross-checks

The local scratch decoder used `umbra_transport::quic::parse_quic_initial_header` and `decrypt_quic_initial_crypto_frames`, linked to an existing workspace rlib through `rustc` without changing package dependencies. Each Initial's authentication tag verified with the public RFC 9001 Initial key derivation. CRYPTO frames were assembled by stream offset with assertions for no holes, no conflicting overlaps, and an exact TLS handshake declared length. An independent Python bounds-checked parser decoded TLS extensions and transport-parameter varints from the raw bytes. Python `hashlib` JA3/JA4 calculations agreed with `umbra_fingerprint` parsing for both samples.

Both UDP datagrams are 1250 bytes, QUIC version 1, with an 8-byte destination CID, **empty source CID**, and empty Initial token. They reassemble to one 1955-byte ClientHello. The first datagram carries offsets `0..66` and `1046..1955`; the second fills `66..1046`. Therefore a matcher must reassemble out-of-order CRYPTO ranges across datagrams; looking only at the first packet cannot recover this ClientHello. Detailed individual frame offsets and lengths are retained in the decoded JSON.

## TCP fields

The first TLS record is 1929 bytes: a 5-byte record header and a 1924-byte ClientHello handshake. The record-layer legacy version is `0x0301`; the ClientHello legacy version remains `0x0303`.

- Cipher suites: `[0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]`
- Extension order: `[0xeaea, 0x000b, 0x0010, 0x0012, 0x001b, 0x0017, 0xff01, 0x002b, 0x000a, 0x0033, 0x0000, 0xca34, 0x0005, 0x44cd, 0x002d, 0x000d, 0xfe0d, 0x0023, 0x1a1a]`
- Supported versions: `[0x2a2a, 0x0304, 0x0303]`
- Supported groups: `[0xeaea, 0x11ec, 0x001d, 0x0017, 0x0018]`
- Signature algorithms: `[0xdada, 0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]`
- ALPN: `["h2", "http/1.1"]`
- Legacy version: `0x0303`; legacy session ID: 32 bytes.
- Key shares in order: `0xeaea` (1 bytes), `0x11ec` (1216 bytes), `0x001d` (32 bytes).
- JA3: `fd7a89b5b1742416d244ac5fd401d96f`; string: `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,11-16-18-27-23-65281-43-10-51-0-51764-5-17613-45-13-65037-35,4588-29-23-24,0`.
- JA4: `t13d1517h2_8daaf6152771_cb7bf5808d99`.
- ECH outer extension: type `0`, KDF `1`, AEAD `1`, encapsulated key 32 bytes, payload 144 bytes; its configuration ID and cryptographic bytes are captured values, not fixed profile constants.

## QUIC fields

- Cipher suites: `[0x1301, 0x1302, 0x1303]`
- Extension order: `[0x0000, 0x44cd, 0x0039, 0x001b, 0xfe0d, 0x000d, 0x000a, 0xca34, 0x0033, 0x0010, 0x002b, 0x002d]`
- Supported versions: `[0x0304]`
- Supported groups: `[0x11ec, 0x001d, 0x0017, 0x0018]`
- Signature algorithms: `[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201]`
- ALPN: `["h3"]`
- Legacy version: `0x0303`; legacy session ID: 0 bytes.
- Key shares in order: `0x11ec` (1216 bytes), `0x001d` (32 bytes).
- JA3: `1ede84abc23b7736f99c952aa7cc41e3`; string: `771,4865-4866-4867,0-17613-57-27-65037-13-10-51764-51-16-43-45,4588-29-23-24,`.
- JA4: `q13d0312h3_55b375c5d22e_178839b6cec1`.
- ECH outer extension: type `0`, KDF `1`, AEAD `1`, encapsulated key 32 bytes, payload 208 bytes; its configuration ID and cryptographic bytes are captured values, not fixed profile constants.

The captured QUIC supported-version vector is **`[0x0304]`**: TLS 1.3 only, without TLS-version GREASE in this sample. TCP offers `[0x2a2a, 0x0304, 0x0303]`. This directly corroborates removing TLS 1.2 from the QUIC offer. RFC 9001 requires QUIC clients to exclude TLS versions below 1.3; legal GREASE is an interoperability allowance, not an assertion that this particular Chrome QUIC sample emitted GREASE. [RFC 9001 §4.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-4.2)

Transport parameters below appear in actual wire order. Integer values are decoded QUIC varints; other payloads remain raw hex. Unknown/vendor IDs are deliberately not assigned unverified meanings.

| ID | Meaning | Payload bytes | Value |
| --- | --- | ---: | --- |
| `0x1` | max_idle_timeout | 4 | 30000 |
| `0x11` | version_information | 12 | `00000001000000012a3ada9a` |
| `0x8` | initial_max_streams_bidi | 2 | 100 |
| `0x7` | initial_max_stream_data_uni | 4 | 6291456 |
| `0x4` | initial_max_data | 4 | 15728640 |
| `0x12776213df91fcf5` | reserved GREASE-shaped ID (`31 × N + 27`) | 9 | `22baff946c9976af5a` |
| `0xf` | initial_source_connection_id | 0 | empty |
| `0x3` | max_udp_payload_size | 2 | 1472 |
| `0x3128` | unclassified in this evidence note | 4 | `4f524947` |
| `0x20` | max_datagram_frame_size | 4 | 65536 |
| `0x9` | initial_max_streams_uni | 2 | 103 |
| `0x5` | initial_max_stream_data_bidi_local | 4 | 6291456 |
| `0x6` | initial_max_stream_data_bidi_remote | 4 | 6291456 |

The `version_information` bytes decode as chosen version `0x00000001`, followed by available versions `0x00000001` and `0x2a3ada9a`; the latter is a reserved QUIC version. Parameter `0x12776213df91fcf5` has the reserved `31 × N + 27` form. Its random identifier/value are sample data, not persistent settings.

## Hybrid key-share layout

Both captures offer group `0x11ec` with **1216 bytes**. Interpreting bytes `0..1184` as an ML-KEM-768 encapsulation key passes the independent encoded-coefficient modulus check: all 768 packed 12-bit coefficients in its first 1152 bytes are below 3329. Interpreting the reversed layout's bytes `32..1216` as that key fails the same check in both samples. The observed layout therefore agrees with **ML-KEM public key (1184) followed by X25519 public key (32)**, as specified by [RFC 10024 §4.1](https://www.rfc-editor.org/rfc/rfc10024.html#section-4.1). This capture does not contain a ServerHello or shared secret; server-share and combined-secret layouts cannot be established from these client bytes alone.

**The hybrid X25519 tail differs from the separately offered classic X25519 key in both Chrome samples.** The two groups need not reuse the same ephemeral key. Umbra's deliberate classic/hybrid-share consistency requirement serves its authentication design; equality must not be described as Chrome fingerprint parity. No private key or shared secret is present in these captured ClientHellos.

## Differences from the unchanged Chrome 150 profile

- The normal GUI TCP sample has 19 extensions including two GREASE entries, versus 18 in the historical 150 transcription. It adds extension `0xca34` (186 payload bytes in this sample), whose semantics are not assigned here, and a GREASE signature algorithm `0xdada`. Extension order and GREASE values differ. A single captured permutation is not a stable ordering promise across Chrome connections.
- After removing GREASE, the TCP cipher suites, supported groups, signature algorithms and ALPN match the recorded 150 lists. The version vector matches the recorded `[GREASE, TLS 1.3, TLS 1.2]` shape. JA4 changes from `t13d1516h2_8daaf6152771_806a8c22fdea` to `t13d1517h2_8daaf6152771_cb7bf5808d99`; JA3 also changes because extension order is part of JA3.
- The 153 TCP record is 1929 bytes rather than the historically reported 1757. Hostname lengths, random ECH GREASE payload lengths, evolving extensions and connection-dependent data prevent assigning that size difference to a single version feature.
- Actual QUIC uses only the three TLS 1.3 ciphers, 12 extensions, an empty session ID, an empty source CID, no TLS-version/group/cipher GREASE in this sample, and the captured QUIC-specific ALPN/signature lists. The current TCP-derived Umbra QUIC profile and inherited seed transport-parameter list therefore do not establish Chrome 153 parity.
- The actual QUIC transport-parameter order and values differ from the 150 profile's unverified seed list; it contains a reserved `31 × N + 27` parameter rather than the seeded fixed TLS-GREASE-shaped carrier. QUIC Initial fragmentation and CRYPTO ordering are also captured behavior requiring separate transport-level comparison.
- The Chrome ECH payloads are nonempty and variable: TCP encapsulated key/payload lengths are 32/144 bytes, QUIC 32/208. A syntactically valid Umbra GREASE implementation is not evidence of exact Chrome ECH payload/length parity.

TLS randoms, public keys, GREASE choices, ECH payloads and connection IDs are expected to vary. These raw samples are reference evidence, not deterministic fixtures to be copied as live cryptographic material. No claim of byte-for-byte equality with Chrome 150, Chrome 153, or every Chrome connection is made.
