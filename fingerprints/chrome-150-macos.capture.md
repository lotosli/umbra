# Chrome 150 macOS Fingerprint Capture

- Capture date: 2026-07-08
- Browser: Google Chrome 150.0.7871.47
- Platform: macOS local Chrome
- Method: Chrome extension-controlled local browser navigated to `https://localhost:<ephemeral-port>/`; a local TCP listener captured the first TLS record before any server response.
- Captured TLS record bytes: 1757
- JA3 string: `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-51-27-5-17613-11-10-35-65037-18-43-65281-23-13-45-16,4588-29-23-24,0`
- JA3 hash: `fc513d165de2da9e593e11eddc48906e`
- JA4 self-check: `t771c15e16g4_57acf744df56_95821207fdf2_fefd5cd8f1da`

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

## Limitations

- QUIC transport parameter data was not recaptured in this pass. The profile keeps the previous seed QUIC values until a QUIC Initial capture is provided and decoded.
- The current TLS builder can represent extension order and known extension payloads, including Chrome 150 application settings extension `17613`, but full ECH GREASE payload parity for extension `65037` remains a future profile-schema task.
