# Umbra User Guide

> Umbra is a privacy transport whose outer connection is designed to look and behave like a real TLS 1.3 or QUIC connection to a real destination site. Unauthenticated or probing traffic is forwarded to the configured destination instead of receiving a proxy-shaped failure.

This guide covers installation, configuration, and operation. For protocol internals see [protocol-design.md](protocol-design.md); for architecture see [architecture.md](architecture.md).

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Server Configuration](#server-configuration)
- [Client Configuration](#client-configuration)
- [Transport Modes](#transport-modes)
- [Padding Schemes](#padding-schemes)
- [TCP Evasion](#tcp-evasion)
- [Fingerprint Profiles](#fingerprint-profiles)
- [Choosing a Destination Site](#choosing-a-destination-site)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)

---

## Installation

### Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/lotosli/umbra/releases). Binaries are provided for:

| Platform | Architecture | Asset Name |
|---|---|---|
| macOS | Apple Silicon | `umbra-aarch64-apple-darwin` |
| macOS | Intel | `umbra-x86_64-apple-darwin` |
| Linux | x86_64 | `umbra-x86_64-unknown-linux-gnu` |
| Linux | aarch64 | `umbra-aarch64-unknown-linux-gnu` |
| Windows | x86_64 | `umbra-x86_64-pc-windows-msvc.exe` |

After downloading, make the binary executable and place it in your PATH:

```bash
chmod +x umbra-*
sudo mv umbra-x86_64-unknown-linux-gnu /usr/local/bin/umbra
```

### Build from Source

Requires Rust 1.96.1+ (specified in `rust-toolchain.toml`).

```bash
git clone https://github.com/lotosli/umbra.git
cd umbra
cargo build --release
# Binary at target/release/umbra
```

---

## Quick Start

### 1. Generate Keys

```bash
umbra keygen
```

Output:

```
x25519_private=<base64>
x25519_public=<base64>
mldsa_seed=<base64>
mldsa_verify=<base64>
```

- `x25519_private` and `mldsa_seed` are **server secrets** -- keep them confidential.
- `x25519_public`, `mldsa_verify`, and a `short_id` (see below) are shared with clients.

### 2. Configure the Server

Create `server.toml`:

```toml
listen        = "0.0.0.0:443"
private_key   = "<x25519_private from keygen>"
short_ids     = ["", "0123456789abcdef"]
dest          = "www.microsoft.com:443"
server_names  = ["www.microsoft.com"]
max_time_diff = "120s"
mldsa_seed    = "<mldsa_seed from keygen>"
```

**Field notes:**

- `short_ids`: a list of hex strings (0-8 bytes each). An empty string `""` is a valid short id. Clients pick one.
- `dest`: the real site whose identity the server borrows. See [Choosing a Destination Site](#choosing-a-destination-site).
- `server_names`: SNI values the server accepts. Must include the `dest` domain.

### 3. Start the Server

```bash
umbra server -c server.toml
```

The server probes `dest` on startup to learn its TLS parameters and certificate profile. If the probe fails, the server exits. Once running, it listens on the configured address and waits for connections. Press Ctrl-C to shut down.

### 4. Configure the Client

Create `client.toml`:

```toml
server       = "<YOUR_SERVER_IP>:443"
transport    = "tcp"
public_key   = "<x25519_public from keygen>"
short_id     = "0123456789abcdef"
server_name  = "www.microsoft.com"
fingerprint  = "chrome-latest"
mldsa_verify = "<mldsa_verify from keygen>"
socks_listen = "127.0.0.1:1080"
```

**Field notes:**

- `server`: your server's public IP and port.
- `public_key`: the X25519 public key -- treat as a shared secret.
- `short_id`: must match one of the server's `short_ids`.
- `server_name`: must match one of the server's `server_names`.
- `socks_listen`: local SOCKS5 proxy address. Point your applications here.

### 5. Start the Client

```bash
umbra client -c client.toml
```

The client starts a local SOCKS5 proxy on `socks_listen`. Configure your browser or system proxy to use `127.0.0.1:1080` (SOCKS5).

### 6. Optional: Enable QUIC

Add `udp_listen` to `server.toml`:

```toml
udp_listen = "0.0.0.0:443"
```

Set `transport = "quic"` in `client.toml`. QUIC uses UDP and offers better resistance to TCP RST injection.

---

## CLI Reference

```
umbra <SUBCOMMAND>
```

### `umbra server`

Run an Umbra server.

```
umbra server [OPTIONS]
```

| Flag | Description |
|---|---|
| `-c, --config <PATH>` | Path to `server.toml` |
| `--listen <ADDR>` | TCP listener address (e.g. `0.0.0.0:443`) |
| `--udp-listen <ADDR>` | UDP listener address for QUIC |
| `--private-key <B64>` | Base64 X25519 private key |
| `--short-ids <HEX,...>` | Comma-separated accepted short ids (hex) |
| `--dest <HOST:PORT>` | Fallback destination |
| `--server-names <NAME,...>` | Comma-separated accepted SNI names |
| `--max-time-diff <DUR>` | Maximum REALITY timestamp skew (e.g. `120s`) |
| `--mldsa-seed <B64>` | Base64 32-byte ML-DSA seed |
| `--prebuild <BOOL>` | Enable periodic destination refresh |
| `--padding-scheme <SCHEME>` | Inner padding scheme |
| `--tcp-evasion <POLICY>` | TCP evasion policy |

CLI flags override values from the config file. All fields are optional on the command line when provided in the config.

### `umbra client`

Run an Umbra client.

```
umbra client [OPTIONS]
```

| Flag | Description |
|---|---|
| `-c, --config <PATH>` | Path to `client.toml` |
| `--server <HOST:PORT>` | Umbra server address |
| `--transport <tcp\|quic>` | Outer transport |
| `--public-key <B64>` | Base64 X25519 server public key |
| `--short-id <HEX>` | Selected short id (hex) |
| `--server-name <NAME>` | SNI for the outer ClientHello |
| `--fingerprint <NAME>` | Fingerprint profile name |
| `--mldsa-verify <B64>` | Base64 ML-DSA verification key |
| `--spider-path <PATH>` | Browser-like path for RealSite spider mode |
| `--socks-listen <ADDR>` | Local SOCKS5 listener address |
| `--mux <BOOL>` | Enable inner mux mode |
| `--padding-scheme <SCHEME>` | Inner padding scheme |
| `--tcp-evasion <POLICY>` | TCP evasion policy |

### `umbra keygen`

Generate X25519 and ML-DSA key material. No options. Prints four base64 values to stdout.

---

## Server Configuration

Full `server.toml` reference:

```toml
# Required fields

listen        = "0.0.0.0:443"         # TCP listener address
private_key   = "BASE64"              # X25519 32-byte private key (from keygen)
short_ids     = ["", "cafebabedeadbeef"]  # Accepted short ids (hex, 0-8 bytes each)
dest          = "www.microsoft.com:443"   # Fallback destination host:port
server_names  = ["www.microsoft.com"]     # Accepted SNI values
max_time_diff = "120s"                # Maximum REALITY timestamp skew
mldsa_seed    = "BASE64"              # ML-DSA-65 32-byte seed (from keygen)

# Optional fields (defaults shown)

udp_listen     = "0.0.0.0:443"        # QUIC UDP listener (omit to disable QUIC)
prebuild       = true                  # Periodic destination profile refresh
padding_scheme = "default"            # Inner padding scheme
tcp_evasion    = "segment"            # TCP evasion policy
```

### Field Details

| Field | Required | Type | Default | Description |
|---|---|---|---|---|
| `listen` | yes | `host:port` | -- | TCP listener bind address |
| `udp_listen` | no | `host:port` | -- | UDP listener for QUIC. Omit to disable QUIC |
| `private_key` | yes | base64 (32 bytes) | -- | X25519 private key from `umbra keygen` |
| `short_ids` | yes | array of hex strings | -- | Accepted REALITY short ids. At least one required. Each 0-8 bytes hex-encoded |
| `dest` | yes | `host:port` | -- | Real destination site the server borrows identity from |
| `server_names` | yes | array of strings | -- | Accepted SNI values. Must be valid DNS names |
| `max_time_diff` | yes | duration string | -- | Maximum clock skew for REALITY timestamps. Minimum 1 second. Supports `ms`, `s`, `m`, `h` suffixes |
| `mldsa_seed` | yes | base64 (32 bytes) | -- | ML-DSA-65 signing seed from `umbra keygen` |
| `prebuild` | no | boolean | `true` | Whether to periodically refresh the destination profile (every 1 hour). Startup probe always runs |
| `padding_scheme` | no | string | `"default"` | Inner padding scheme. See [Padding Schemes](#padding-schemes) |
| `tcp_evasion` | no | string | `"segment"` | TCP evasion policy. See [TCP Evasion](#tcp-evasion) |

---

## Client Configuration

Full `client.toml` reference:

```toml
# Required fields

server       = "198.51.100.10:443"    # Umbra server address
transport    = "tcp"                  # Outer transport: "tcp" or "quic"
public_key   = "BASE64"              # X25519 32-byte server public key
short_id     = "cafebabedeadbeef"    # Selected short id (hex)
server_name  = "www.microsoft.com"   # SNI for the outer ClientHello
fingerprint  = "chrome-latest"       # Fingerprint profile name
mldsa_verify = "BASE64"              # ML-DSA-65 verification key
socks_listen = "127.0.0.1:1080"     # Local SOCKS5 proxy address

# Optional fields (defaults shown)

spider_path   = "/"                   # Path for RealSite spider mode
mux           = true                  # Enable inner mux mode
padding_scheme = "default"           # Inner padding scheme
tcp_evasion   = "segment"            # TCP evasion policy
```

### Field Details

| Field | Required | Type | Default | Description |
|---|---|---|---|---|
| `server` | yes | `host:port` | -- | Umbra server address (public IP and port) |
| `transport` | yes | `"tcp"` or `"quic"` | -- | Outer transport protocol |
| `public_key` | yes | base64 (32 bytes) | -- | X25519 public key from server's `umbra keygen` |
| `short_id` | yes | hex string | -- | Must match one of the server's `short_ids` (0-8 bytes hex) |
| `server_name` | yes | string | -- | SNI for the outer ClientHello. Must match one of the server's `server_names` |
| `fingerprint` | yes | string | -- | Chrome fingerprint profile name. See [Fingerprint Profiles](#fingerprint-profiles) |
| `mldsa_verify` | yes | base64 | -- | ML-DSA-65 verification key from server's `umbra keygen` |
| `socks_listen` | yes | `host:port` | -- | Local SOCKS5 proxy bind address |
| `spider_path` | no | string | `"/"` | HTTP path used when the server is detected as a real site (not authenticated). Must start with `/` |
| `mux` | no | boolean | `true` | Enable inner multiplexing. When `false`, uses solo/Vision mode |
| `padding_scheme` | no | string | `"default"` | Inner padding scheme. See [Padding Schemes](#padding-schemes) |
| `tcp_evasion` | no | string | `"segment"` | TCP evasion policy. See [TCP Evasion](#tcp-evasion) |

---

## Transport Modes

Umbra supports two outer transports:

### TCP (default)

```toml
transport = "tcp"
```

- Standard TLS 1.3 over TCP.
- Works through most firewalls since port 443 TCP is rarely blocked.
- Use with `tcp_evasion = "segment"` for conservative TCP segmentation.


#### TCP Vision solo (0.0.7)

Set `transport = "tcp"` and `mux = false` to use dedicated Vision connections. Upgrade both client and server to 0.0.7. After an authenticated boundary exchange on eligible inner TLS 1.3 traffic, the runtime forwards the original protected records without outer TLS encryption or extra framing. Non-TLS and unsupported TLS remain encrypted. The legacy solo implementation was removed; `mux = true` continues to provide encrypted multiplexing. No extra Vision flag is needed. Raw forwarding is userspace I/O, not a claim of kernel zero-copy or a measured speed increase.

Successful sessions log `umbra vision splice active` and, on completion, raw byte counts plus `outer_records_unchanged=true`, without targets or credentials.

#### TCP mux capacity and recovery (current source)

With `mux = true`, the client reuses up to four accepting outer connections and reserves real stream capacity before choosing one. The default 256 KiB per-stream window and 8 MiB per-outer receive budget allow 32 streams per outer, or up to 128 across accepting outers. Pool admission has a separate limit of 128 waiters. Four additional retirement slots allow draining outers to keep existing streams, with a hard limit of eight outers in total. If a new accepting outer is needed at that limit, only the oldest draining outer is retired; its remaining streams fail, and business requests or payloads are never replayed.

Server TCP target setup gives DNS up to 5 seconds within a 14-second total budget, then races up to four resolved addresses at a time with a 250 ms stagger and bounded candidate rotation. The client distinguishes pool admission, SYN transmission, and target acknowledgement failures; its target-acknowledgement wait is 25 seconds to cover the server deadline and feedback. Failed TCP mux setup returns a standard SOCKS failure reply. Suspected stalled outers stop accepting new streams, allowing replacements while the retirement budget permits. Unreachable targets still return a bounded failure.

### QUIC

```toml
transport = "quic"
```

- TLS 1.3 over UDP (HTTP/3 style).
- No head-of-line blocking at the transport layer.
- More resistant to TCP RST injection since there is no TCP state to corrupt.
- Requires `udp_listen` on the server.
- The server must open the UDP port (typically 443).

**When to use QUIC:** If the censor performs TCP-level RST injection and QUIC/UDP is not blocked, switching to QUIC is the simplest countermeasure.

---

## Padding Schemes

The `padding_scheme` setting controls adaptive padding injected into inner-layer records to defeat TLS-in-TLS detection.

| Value | Behavior |
|---|---|
| `"default"` | First 16 records per direction get random padding (100-1400 bytes); then one padding frame every 32 records |
| `"none"` | No padding injected |
| `"early=N,min=N,max=N,later=N"` | Custom: `early` = number of early padded records, `min`/`max` = padding length range, `later` = frequency after early phase |

**Recommendation:** Keep `"default"` unless you have a specific reason. Disabling padding (`"none"`) makes inner TLS handshake patterns visible to traffic classifiers.

---

## TCP Evasion

The `tcp_evasion` setting controls how the ClientHello is written to the TCP stream.

| Value | Behavior |
|---|---|
| `"segment"` | (default) Writes the ClientHello in small segments (first 32 bytes, then the rest), making it harder for middleboxes to match the full handshake in a single TCP segment |
| `"off"` | Ordinary single write. Use if `segment` causes connectivity issues |
| `"segment:threshold=N,first=M"` | Custom segmentation parameters |

Geneva DSL strategies (e.g. `geneva:fragment{tcp}`) are **not yet implemented** and will be rejected at config validation.

---

## Fingerprint Profiles

The `fingerprint` setting selects which Chrome version's TLS fingerprint to mimic. Built-in profiles:

| Name | Description |
|---|---|
| `"chrome-latest"` | Tracks the latest captured Chrome profile (currently Chrome 150 on macOS) |
| `"chrome-150-macos"` | Chrome 150.0.7871.47 on macOS, captured 2026-07-08 |

Both profiles currently produce identical fingerprints:
- JA3: `fc513d165de2da9e593e11eddc48906e`
- JA4: `t13d1516h2_8daaf6152771_806a8c22fdea`

**Recommendation:** Use `"chrome-latest"` -- it will be updated as new Chrome versions are captured.

---

## Choosing a Destination Site

The `dest` (server) and `server_name` (client) determine which real site's identity the server borrows. Good choices:

**Required:**
- A site outside the censor's jurisdiction
- Supports TLS 1.3
- Supports HTTP/2 or HTTP/3
- Domain must not redirect to another domain

**Preferred:**
- IP address geographically close to your VPS (lower latency, more believable)
- Encrypts post-ServerHello messages (e.g. `www.microsoft.com`, `dl.google.com`)
- Supports OCSP stapling
- Does not serve content back to the server's country

**Tips:**
- `server_names` on the server should include the `dest` domain
- `server_name` on the client must match one of the server's `server_names`
- Popular choices: `www.microsoft.com`, `dl.google.com`, `www.apple.com`, `cloudflare.com`
- Avoid sites that might be blocked independently (which would also block your server)

---

## Deployment

### systemd Service

Create `/etc/systemd/system/umbra-server.service`:

```ini
[Unit]
Description=Umbra Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/umbra server -c /etc/umbra/server.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now umbra-server
```

### System Tuning

```bash
# Increase file descriptor limit
ulimit -n 65535

# Enable BBR congestion control (Linux)
sudo modprobe tcp_bbr
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
```

### Firewall

Open the listening ports:

```bash
# TCP (required)
sudo ufw allow 443/tcp

# UDP (if using QUIC)
sudo ufw allow 443/udp
```

### Logging

Umbra produces minimal output by design. On error, it prints to stderr with context like `umbra server TCP session error: ...`. Normal operation is silent. Use journald to capture logs:

```bash
sudo journalctl -u umbra-server -f
```

---

## Troubleshooting

### Server exits immediately with an error

- **Destination probe failed:** The server could not connect to `dest` or the TLS parameters were unexpected. Check that `dest` is reachable from your VPS and supports TLS 1.3.
- **Config parse error:** Check TOML syntax. The error message includes line and column but never reveals secret values.

### Client cannot connect

- **Check `server` address:** Must be the server's public IP and port.
- **Check `public_key`:** Must match the server's `x25519_public` from `keygen`.
- **Check `short_id`:** Must match one of the server's `short_ids`.
- **Check `server_name`:** Must match one of the server's `server_names`.
- **Check firewall:** Port 443 (TCP) must be open. Port 443 (UDP) if using QUIC.

### SOCKS5 proxy works but pages load slowly

- Try switching `transport = "quic"` if available.
- Check if `mux = true` helps (default) -- multiplexing reduces connection setup overhead.
- Verify `padding_scheme = "default"` -- `"none"` may trigger traffic shaping.

### Connection drops intermittently

- Increase `max_time_diff` if server and client clocks are not well synchronized.
- Check if the destination site is still accessible from the server.
- Consider enabling QUIC as a more resilient transport.

### `openssl s_client` shows a real certificate

This is **expected behavior** for unauthenticated connections. The server forwards unknown connections to the real `dest`, so probing tools see the genuine site certificate. Only authenticated clients (with the correct `public_key` and `short_id`) receive the temporary trusted certificate.

---

## Security Notes

### Secret Management

| Material | Where | Sensitivity |
|---|---|---|
| `x25519_private` | Server only | **Secret** -- never share |
| `mldsa_seed` | Server only | **Secret** -- never share |
| `x25519_public` | Client config | Shared secret -- distribute securely |
| `mldsa_verify` | Client config | Public -- but distribute with config |
| `short_id` | Both configs | Shared secret -- distribute securely |

Leaking `x25519_private` or `mldsa_seed` allows anyone to impersonate your server. Leaking `x25519_public` allows censors to craft targeted probes.

### What Umbra Does Not Log

Umbra does not log destination addresses, traffic content, keys, or session identifiers. Error messages use redacted placeholders for secret fields.

### Constant-Time Operations

All MAC/tag comparisons and certificate binding checks use constant-time verification to prevent timing side channels.

### Replay Protection

The server maintains a bounded replay cache (default capacity: 65,536 entries). Entries expire after `timestamp + max_time_diff`. When the cache is full, new authentications are rejected (connection falls through to the real destination).

### Compliance

Umbra is intended for privacy protection and access to the open internet where lawful. Do not use it for illegal activity.
