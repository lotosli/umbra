# Chrome 150 macOS Fingerprint Capture

- Capture date: 2026-07-08
- Browser: Google Chrome 150.0.7871.47
- Platform: macOS local Chrome
- Method: Chrome extension-controlled local browser navigated to `https://localhost:<ephemeral-port>/`; a local TCP listener captured the first TLS record before any server response.
- Captured TLS record bytes: 1757
- JA3 string: `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-51-27-5-17613-11-10-35-65037-18-43-65281-23-13-45-16,4588-29-23-24,0`
- JA3 hash: `fc513d165de2da9e593e11eddc48906e`
- Standard TCP JA4 reconstructed from the recorded fields: `t13d1516h2_8daaf6152771_806a8c22fdea` (not a raw-capture verification).
- The previous `t771c15e16g4_...` identifier was an Umbra-only self-check, not standard JA4, and is superseded.

## Evidence Status

Both `chrome-150-macos.toml` and its `chrome-latest.toml` alias require an `[evidence]` table:

| Scope | Status | What is available |
| --- | --- | --- |
| `parsed_tls` | `recorded` | Historical parsed-field transcription below, including extension order, offered versions, and JA3. Not freshly re-decoded. |
| `full_tls_payload` | `unverified` | The historical 1757-byte record/full extension payload is not present in the repository evidence inspected for this remediation. |
| `quic` | `unverified` | Inherited seed parameters only; no matching decoded Chrome QUIC Initial capture. |

The repository was searched for `.pcap`, `.pcapng`, `.cap`, `.bin`, `.hex`, and capture/ClientHello-named files, excluding build output (`target`), Git internals, and dependency directories. Only this capture note, source code, and the parser fuzz target were found; no raw browser capture was located. This is a statement about available repository evidence, not proof that the historical capture never existed elsewhere. No new browser/network capture was performed.

Generated profile fixtures encode JA3/JA4 inputs only. They are not browser captures and cannot promote either unverified status. In particular, a matching JA4 says nothing about ECH bytes, padding payload/placement, compression payload parity, or QUIC transport parameters. Existing extension-order, JA3, and version checks remain necessary and are retained.

## Parsed TLS Fields

- Ciphers: `[43690, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53]`
- Extensions: `[19018, 0, 51, 27, 5, 17613, 11, 10, 35, 65037, 18, 43, 65281, 23, 13, 45, 16, 64250]`
- GREASE extension slots: `[0, 17]`
- Supported groups: `[43690, 4588, 29, 23, 24]`
- Supported versions: `[10794, 772, 771]`
- Key share groups: `[43690, 4588, 29]`
- Signature algorithms: `[2308, 2309, 2310, 1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537]`
- ALPN: `["h2", "http/1.1"]`
- Application settings payload for extension `17613`: `0003026832`

## Pinned JA4 Definition and Independent Checks

- Authority: FoxIO-LLC/ja4, commit `d3dedafd6d3ac27a37107183533fc7274c5f4ea9`, resolved and read through GitHub's API using `gh` before implementing normalization.
- Definition: [technical_details/JA4.md](https://github.com/FoxIO-LLC/ja4/blob/d3dedafd6d3ac27a37107183533fc7274c5f4ea9/technical_details/JA4.md).
- License checked: [LICENSE-JA4](https://github.com/FoxIO-LLC/ja4/blob/d3dedafd6d3ac27a37107183533fc7274c5f4ea9/LICENSE-JA4) is BSD 3-Clause for **JA4 TLS client fingerprinting only**. The [licensing FAQ](https://github.com/FoxIO-LLC/ja4/blob/d3dedafd6d3ac27a37107183533fc7274c5f4ea9/License%20FAQ.md) distinguishes the other JA4+ methods under FoxIO License 1.1. Umbra independently implements the JA4 definition; no FoxIO implementation code or other JA4+ logic was copied or added as a dependency.
- The published detailed example has fixed expected JA4 `t13d1516h2_8daaf6152771_e5627efa2ab1`. Tests reconstruct its listed fields independently of the profile fixture builder and assert this literal. Its separately published no-signature extension hash `6d807ffa2a79` is also asserted.
- Normative corner cases covered: explicit TCP `t` versus QUIC `q` (not record framing); highest non-GREASE supported version, falling back to ClientHello legacy version only when supported_versions is absent; unknown version `00`; SNI presence `d`/`i`; non-GREASE counts capped at 99; ASCII-alphanumeric ALPN endpoint bytes, otherwise endpoint hex digits; sorted four-digit lowercase hexadecimal ciphers/extensions; SNI and ALPN counted but excluded from extension hash; signature algorithms remain ordered; GREASE signatures removed; no trailing underscore for absent signatures; empty hash lists produce twelve zeros. Empty ALPN input normalizes to `00`, but malformed empty network ALPN vectors are rejected at parsing.

For this Chrome profile, the canonical hash inputs were transcribed from the fields above and hashed separately using Python's `hashlib.sha256(value.encode('ascii')).hexdigest()[:12]`, not Umbra's JA4 implementation:

```text
JA4_b input:
002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9
JA4_b = 8daaf6152771

JA4_c input:
0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601
JA4_c = 806a8c22fdea
```

The prefix is `t13d1516h2`: TCP, TLS 1.3, SNI present, 15 ciphers and 16 extensions after GREASE removal, first ALPN `h2`. This validates a field-derived expectation, not the unavailable full record. Callers must use `ja3_ja4_with_transport(..., Ja4Transport::Quic)` (or `ja4_with_transport`) for QUIC; the default APIs remain TCP. QUIC wiring and gate reporting are separate from this profile/JA4 remediation.

## Limitations

- QUIC transport parameter data was not recaptured in this pass. The profile keeps the previous seed QUIC values until a QUIC Initial capture is provided and decoded.
- The current TLS builder can represent extension order and known extension payloads, including Chrome 150 application settings extension `17613`, but full ECH GREASE payload parity for extension `65037` remains a future profile-schema task.
