# Umbra 用户手册

> Umbra 是一个隐私传输工具，其外层连接被设计为与通往真实目标站点的 TLS 1.3 或 QUIC 连接在外观和行为上完全一致。未认证或探测流量会被原样转发到配置的目标站点，而不会返回代理特征响应。

本手册涵盖安装、配置和运维。协议细节见 [protocol-design.md](protocol-design.md)；架构见 [architecture.md](architecture.md)。

---

## 目录

- [安装](#安装)
- [快速开始](#快速开始)
- [CLI 参考](#cli-参考)
- [服务端配置](#服务端配置)
- [客户端配置](#客户端配置)
- [传输模式](#传输模式)
- [填充策略](#填充策略)
- [TCP 规避](#tcp-规避)
- [指纹档案](#指纹档案)
- [选择目标站点（dest）](#选择目标站点dest)
- [部署](#部署)
- [故障排查](#故障排查)
- [安全说明](#安全说明)

---

## 安装

### 预编译二进制

从 [GitHub Releases](https://github.com/lotosli/umbra/releases) 下载最新版本。提供以下平台的二进制：

| 平台 | 架构 | 文件名 |
|---|---|---|
| macOS | Apple Silicon | `umbra-aarch64-apple-darwin` |
| macOS | Intel | `umbra-x86_64-apple-darwin` |
| Linux | x86_64 | `umbra-x86_64-unknown-linux-gnu` |
| Linux | aarch64 | `umbra-aarch64-unknown-linux-gnu` |
| Windows | x86_64 | `umbra-x86_64-pc-windows-msvc.exe` |

下载后赋予执行权限并放入 PATH：

```bash
chmod +x umbra-*
sudo mv umbra-x86_64-unknown-linux-gnu /usr/local/bin/umbra
```

### 从源码构建

需要 Rust 1.96.1+（版本锁定在 `rust-toolchain.toml`）。

```bash
git clone https://github.com/lotosli/umbra.git
cd umbra
cargo build --release
# 二进制位于 target/release/umbra
```

---

## 快速开始

### 1. 生成密钥

```bash
umbra keygen
```

输出：

```
x25519_private=<base64>
x25519_public=<base64>
mldsa_seed=<base64>
mldsa_verify=<base64>
```

- `x25519_private` 和 `mldsa_seed` 是**服务端密钥**，务必保密。
- `x25519_public`、`mldsa_verify` 和一个 `short_id`（见下文）分发给客户端。

### 2. 配置服务端

创建 `server.toml`：

```toml
listen        = "0.0.0.0:443"
private_key   = "<keygen 输出的 x25519_private>"
short_ids     = ["", "0123456789abcdef"]
dest          = "www.microsoft.com:443"
server_names  = ["www.microsoft.com"]
max_time_diff = "120s"
mldsa_seed    = "<keygen 输出的 mldsa_seed>"
```

**字段说明：**

- `short_ids`：十六进制字符串列表，每个 0-8 字节。空字符串 `""` 也是合法的 short id。客户端从中选一个。
- `dest`：服务端借用的真实目标站点。详见[选择目标站点](#选择目标站点dest)。
- `server_names`：服务端接受的 SNI 值，必须包含 `dest` 的域名。

### 3. 启动服务端

```bash
umbra server -c server.toml
```

服务端启动时会探测 `dest` 以获取其 TLS 参数和证书特征。探测失败则退出。启动成功后监听配置地址，等待连接。按 Ctrl-C 停止。

### 4. 配置客户端

创建 `client.toml`：

```toml
server       = "<你的服务器公网IP>:443"
transport    = "tcp"
public_key   = "<keygen 输出的 x25519_public>"
short_id     = "0123456789abcdef"
server_name  = "www.microsoft.com"
fingerprint  = "chrome-latest"
mldsa_verify = "<keygen 输出的 mldsa_verify>"
socks_listen = "127.0.0.1:1080"
```

**字段说明：**

- `server`：你服务器的公网 IP 和端口。
- `public_key`：X25519 公钥——视为共享秘密。
- `short_id`：必须匹配服务端 `short_ids` 中的一个。
- `server_name`：必须匹配服务端 `server_names` 中的一个。
- `socks_listen`：本地 SOCKS5 代理地址。将应用指向此处。

### 5. 启动客户端

```bash
umbra client -c client.toml
```

客户端在 `socks_listen` 启动本地 SOCKS5 代理。将浏览器或系统代理设置为 `127.0.0.1:1080`（SOCKS5）。

### 6. 可选：启用 QUIC

在 `server.toml` 中添加：

```toml
udp_listen = "0.0.0.0:443"
```

在 `client.toml` 中设置 `transport = "quic"`。QUIC 使用 UDP，对 TCP RST 注入有更好的抵抗力。

若要一个客户端同时采用 TCP/Vision 和 QUIC UDP，则保留 `transport = "tcp"`，另外设置 `udp_transport = "quic"`、`mux = false`，详见[单实例说明](#单实例-tcp-vision--quic-udp)。服务端仍只启动一次 `umbra server -c server.toml`；TCP 和 UDP 可以使用相同端口号。

启用 QUIC 时，`dest` 也需提供可用的真实 QUIC/HTTP3 回落服务；只有 TCP HTTPS 的目标不能替代这一要求。如果由 Caddy 与 QUIC 分流模块统一承接公网443，可把 Umbra 的两个监听绑定到回环地址，由 Caddy 透传，内部端口无需在公网防火墙开放。

### 7. Clash 单节点配置

```yaml
proxies:
  - name: Umbra
    type: socks5
    server: 127.0.0.1
    port: 1080
    udp: true
```

`udp: true` 表示节点允许 UDP 请求。Clash 对 TCP 使用 SOCKS CONNECT，对 UDP 使用 UDP ASSOCIATE；外层采用 TCP 还是 QUIC，由 Umbra 的 `transport` 和 `udp_transport` 决定。

---

## CLI 参考

```
umbra <子命令>
```

### `umbra server`

运行 Umbra 服务端。

```
umbra server [选项]
```

| 参数 | 说明 |
|---|---|
| `-c, --config <路径>` | `server.toml` 配置文件路径 |
| `--listen <地址>` | TCP 监听地址（如 `0.0.0.0:443`） |
| `--udp-listen <地址>` | QUIC 的 UDP 监听地址 |
| `--private-key <B64>` | Base64 编码的 X25519 私钥 |
| `--short-ids <HEX,...>` | 逗号分隔的 short id 列表（十六进制） |
| `--dest <HOST:PORT>` | 回退目标站点 |
| `--server-names <NAME,...>` | 逗号分隔的 SNI 列表 |
| `--max-time-diff <时长>` | REALITY 时间戳最大偏差（如 `120s`） |
| `--mldsa-seed <B64>` | Base64 编码的 32 字节 ML-DSA 种子 |
| `--prebuild <BOOL>` | 是否启用周期性目标刷新 |
| `--padding-scheme <策略>` | 内层填充策略 |
| `--tcp-evasion <策略>` | TCP 规避策略 |

命令行参数会覆盖配置文件中的对应值。通过配置文件提供时，所有命令行参数均为可选。

### `umbra client`

运行 Umbra 客户端。

```
umbra client [选项]
```

| 参数 | 说明 |
|---|---|
| `-c, --config <路径>` | `client.toml` 配置文件路径 |
| `--server <HOST:PORT>` | Umbra 服务端地址 |
| `--transport <tcp\|quic>` | 外层传输协议 |
| `--udp-transport <tcp\|quic>` | UDP 关联的外层传输；省略时跟随主传输 |
| `--public-key <B64>` | Base64 编码的 X25519 服务端公钥 |
| `--short-id <HEX>` | 选定的 short id（十六进制） |
| `--server-name <NAME>` | 外层 ClientHello 的 SNI |
| `--fingerprint <名称>` | 指纹档案名称 |
| `--mldsa-verify <B64>` | Base64 编码的 ML-DSA 验签密钥 |
| `--spider-path <路径>` | RealSite 爬虫模式的浏览器风格路径 |
| `--socks-listen <地址>` | 本地 SOCKS5 监听地址 |
| `--mux <BOOL>` | 是否启用内层多路复用 |
| `--padding-scheme <策略>` | 内层填充策略 |
| `--tcp-evasion <策略>` | TCP 规避策略 |

### `umbra keygen`

生成 X25519 和 ML-DSA 密钥材料。无参数。向标准输出打印四个 base64 值。

---

## 服务端配置

完整 `server.toml` 参考：

```toml
# 必填字段

listen        = "0.0.0.0:443"              # TCP 监听地址
private_key   = "BASE64"                   # X25519 32 字节私钥（来自 keygen）
short_ids     = ["", "cafebabedeadbeef"]   # 接受的 short id 列表（十六进制，每个 0-8 字节）
dest          = "www.microsoft.com:443"    # 回退目标站点 host:port
server_names  = ["www.microsoft.com"]      # 接受的 SNI 值
max_time_diff = "120s"                     # REALITY 时间戳最大偏差
mldsa_seed    = "BASE64"                   # ML-DSA-65 32 字节种子（来自 keygen）

# 可选字段（显示默认值）

udp_listen     = "0.0.0.0:443"            # QUIC UDP 监听（省略则禁用 QUIC）
prebuild       = true                      # 周期性目标档案刷新
padding_scheme = "default"                 # 内层填充策略
tcp_evasion    = "segment"                 # TCP 规避策略
```

### 字段详情

| 字段 | 必填 | 类型 | 默认值 | 说明 |
|---|---|---|---|---|
| `listen` | 是 | `host:port` | -- | TCP 监听绑定地址 |
| `udp_listen` | 否 | `host:port` | -- | QUIC 的 UDP 监听地址。省略则禁用 QUIC |
| `private_key` | 是 | base64（32 字节） | -- | `umbra keygen` 生成的 X25519 私钥 |
| `short_ids` | 是 | 十六进制字符串数组 | -- | 接受的 REALITY short id。至少一个。每个 0-8 字节，十六进制编码 |
| `dest` | 是 | `host:port` | -- | 服务端借用身份的真实目标站点 |
| `server_names` | 是 | 字符串数组 | -- | 接受的 SNI 值。必须是合法域名 |
| `max_time_diff` | 是 | 时长字符串 | -- | REALITY 时间戳最大偏差。最小 1 秒。支持 `ms`、`s`、`m`、`h` 后缀 |
| `mldsa_seed` | 是 | base64（32 字节） | -- | `umbra keygen` 生成的 ML-DSA-65 签名种子 |
| `prebuild` | 否 | 布尔值 | `true` | 是否周期性刷新目标档案（每 1 小时）。启动探测始终执行 |
| `padding_scheme` | 否 | 字符串 | `"default"` | 内层填充策略。见[填充策略](#填充策略) |
| `tcp_evasion` | 否 | 字符串 | `"segment"` | TCP 规避策略。见[TCP 规避](#tcp-规避) |

---

## 客户端配置

完整 `client.toml` 参考：

```toml
# 必填字段

server       = "198.51.100.10:443"         # Umbra 服务端地址
transport    = "tcp"                       # 外层传输："tcp" 或 "quic"
public_key   = "BASE64"                   # X25519 32 字节服务端公钥
short_id     = "cafebabedeadbeef"         # 选定的 short id（十六进制）
server_name  = "www.microsoft.com"        # 外层 ClientHello 的 SNI
fingerprint  = "chrome-latest"            # 指纹档案名称
mldsa_verify = "BASE64"                   # ML-DSA-65 验签密钥
socks_listen = "127.0.0.1:1080"          # 本地 SOCKS5 代理地址

# 可选字段（显示默认值）

spider_path   = "/"                        # RealSite 爬虫模式路径
mux           = true                       # 启用内层多路复用
padding_scheme = "default"                # 内层填充策略
tcp_evasion   = "segment"                  # TCP 规避策略
```

### 字段详情

| 字段 | 必填 | 类型 | 默认值 | 说明 |
|---|---|---|---|---|
| `server` | 是 | `host:port` | -- | Umbra 服务端地址（公网 IP 和端口） |
| `transport` | 是 | `"tcp"` 或 `"quic"` | -- | 外层传输协议 |
| `udp_transport` | 否 | `"tcp"` 或 `"quic"` | 跟随 `transport` | 单独选择 UDP 关联的外层传输，TCP 请求仍使用主传输 |
| `public_key` | 是 | base64（32 字节） | -- | 服务端 `umbra keygen` 输出的 X25519 公钥 |
| `short_id` | 是 | 十六进制字符串 | -- | 必须匹配服务端 `short_ids` 之一（0-8 字节十六进制） |
| `server_name` | 是 | 字符串 | -- | 外层 ClientHello 的 SNI。必须匹配服务端 `server_names` 之一 |
| `fingerprint` | 是 | 字符串 | -- | Chrome 指纹档案名称。见[指纹档案](#指纹档案) |
| `mldsa_verify` | 是 | base64 | -- | 服务端 `umbra keygen` 输出的 ML-DSA-65 验签密钥 |
| `socks_listen` | 是 | `host:port` | -- | 本地 SOCKS5 代理绑定地址 |
| `spider_path` | 否 | 字符串 | `"/"` | 服务端被检测为真实站点（未认证）时使用的 HTTP 路径。必须以 `/` 开头 |
| `mux` | 否 | 布尔值 | `true` | 启用内层多路复用。设为 `false` 则使用 solo/Vision 模式 |
| `padding_scheme` | 否 | 字符串 | `"default"` | 内层填充策略。见[填充策略](#填充策略) |
| `tcp_evasion` | 否 | 字符串 | `"segment"` | TCP 规避策略。见[TCP 规避](#tcp-规避) |

---

## 传输模式

### 1.0.0-alpha 吞吐优化

建议同时升级服务端与客户端。`mux=true` 的新连接默认启用自适应流控；`mux=false` 继续使用Vision。QUIC默认选择BBR，可在 `[performance]` 中将 `quic_congestion` 设置为 `cubic` 或 `new-reno`。这不改变Linux TCP的拥塞算法。

可选配置包括 `memory_mib=512`、`group_memory_mib=256`、`max_window_mib=64`、`quic_stream_window_mib=6`、`quic_send_window_mib=32` 和客户端 `adaptive_mux=true`。窗口按消费和RTT自动增长，部署者不需填写带宽；内存上限需要给系统留出余量。详见[吞吐与配置说明](performance.md)。

需要定位服务端瓶颈时，可在 `[performance]` 中设置 `diagnostics_interval_secs=10`；默认0关闭，开启间隔支持1–3600秒。报告按匿名凭据组和模式区分传输/目标字节、I/O等待、信用、队列与预算拒绝，不包含地址、凭据、SNI或载荷。传输字节包含协议开销，目标读取字节可能尚未交付客户端，不能直接当作有效吞吐；具体含义见性能说明。

### 0.0.8 升级说明

0.0.8 修正 X25519MLKEM768 的标准字段与共享秘密顺序，并移除 QUIC 握手中的 TLS 1.2 版本声明。
客户端和服务端必须同时升级；不保留早期混合握手的错误格式兼容。已有身份密钥、short ID、SNI 和 SOCKS 配置可以沿用。
TCP Vision 与 mux 的选择方式不变，QUIC 仍通过 `transport = "quic"` 选择。此次标准互通修复不代表已验证完整 Chrome 指纹一致性，也不保证测速提升。

Umbra 支持两种外层传输：

### 单实例 TCP Vision + QUIC UDP

在同一份客户端配置中设置：

```toml
transport = "tcp"
udp_transport = "quic"
mux = false
socks_listen = "127.0.0.1:1080"
```

一个客户端实例即可在同一 SOCKS 入口接收 TCP 和 UDP 请求。TCP CONNECT 使用 TCP/Vision，UDP ASSOCIATE 使用 QUIC；二者连接同一个 `server` 地址，该服务端入口需同时支持 TCP 和 QUIC。
Clash 只需配置一个 `type: socks5`、`server: 127.0.0.1`、`port: 1080`、`udp: true` 节点。1080 是 SOCKS 控制入口；UDP 数据中继地址通过标准 SOCKS 协商返回，不要求固定绑定 UDP1080。
省略 `udp_transport` 时，UDP 跟随文件与 CLI 合并后的主 `transport`；`--udp-transport` 优先于文件设置。服务端原本就能用一个实例同时配置 `listen` 和 `udp_listen`。

### TCP（默认）

```toml
transport = "tcp"
```

- 标准 TLS 1.3 over TCP。
- 适用于大多数防火墙，因为 443 端口 TCP 很少被封。
- 配合 `tcp_evasion = "segment"` 进行保守的 TCP 分段。


#### TCP Vision solo（0.0.7）

使用 `transport = "tcp"`、`mux = false` 即可选择独占连接的 Vision；当前请将客户端和服务端统一升级到 1.0.0-alpha。符合条件的内层 TLS 1.3 流量经过双方确认切换边界后，原始受保护记录不再增加外层 TLS 加密或帧封装。非 TLS 和不符合条件的 TLS 仍加密传输。旧 solo 实现已删除，`mux = true` 继续提供加密多路复用；不需要额外 Vision 开关。原始转发使用用户态 I/O，不宣称内核零拷贝或未经测量的速度提升。

成功切换会记录 `umbra vision splice active`；连接完成后记录原始字节数及 `outer_records_unchanged=true`，不包含目标地址或凭据。

#### TCP mux 容量与恢复（当前源码）

`mux = true` 时，客户端保留复用，最多使用4条接收新流的外层连接，并在选择连接前预留实际流容量。自适应模式每条outer最多128条流，受共享连接信用和内存预算约束。`adaptive_mux=false` 的旧模式使用每流256KiB、每outer 8MiB预算，每outer最多32条流；连接池另限制最多128个准入等待者。额外4个退休槽位用于保留draining连接上的旧流，所有outer总数最多8条。总预算已满且需要新建接收连接时，只退役最早进入draining的outer；其剩余旧流终止并报错，不重放业务请求或数据。

服务端TCP目标连接的DNS等待最多5秒，计入14秒总预算；对解析得到的地址最多4路并发竞速，以250 ms间隔启动，并有界轮换候选。客户端区分连接池准入、SYN发送和目标确认阶段的错误，目标确认等待25秒以覆盖服务端期限及反馈余量；TCP mux建立失败会返回标准SOCKS失败回复。疑似停滞的outer停止接收新流，在退休预算允许时建立替代连接。不可达目标仍会在有界时间内失败。

### QUIC

```toml
transport = "quic"
```

- TLS 1.3 over UDP（HTTP/3 风格）。
- 传输层无队头阻塞。
- 对 TCP RST 注入更有抵抗力，因为没有可破坏的 TCP 状态。
- 需要服务端配置 `udp_listen`。
- 服务端必须开放 UDP 端口（通常为 443）。

**何时使用 QUIC：** 如果审查者进行 TCP 层面的 RST 注入且 QUIC/UDP 未被封锁，切换到 QUIC 是最简单的对策。

---

## 填充策略

`padding_scheme` 设置控制注入到内层记录的自适应填充，用于对抗 TLS-in-TLS 检测。

| 值 | 行为 |
|---|---|
| `"default"` | 每方向前 16 条记录注入随机填充（100-1400 字节）；之后每 32 条记录注入一次填充帧 |
| `"none"` | 不注入填充 |
| `"early=N,min=N,max=N,later=N"` | 自定义：`early` = 早期填充记录数，`min`/`max` = 填充长度范围，`later` = 早期阶段后的频率 |

**建议：** 除非有特殊原因，保持 `"default"`。禁用填充（`"none"`）会使内层 TLS 握手模式对流量分类器可见。

---

## TCP 规避

`tcp_evasion` 设置控制 ClientHello 写入 TCP 流的方式。

| 值 | 行为 |
|---|---|
| `"segment"` | （默认）分段写入 ClientHello（先写 32 字节，再写剩余部分），使中间设备更难在单个 TCP 段中匹配完整握手 |
| `"off"` | 普通单次写入。如果 `segment` 导致连接问题则使用 |
| `"segment:threshold=N,first=M"` | 自定义分段参数 |

Geneva DSL 策略（如 `geneva:fragment{tcp}`）**尚未实现**，会在配置校验时被拒绝。

---

## 指纹档案

`fingerprint` 设置选择模拟哪个 Chrome 版本的 TLS 指纹。内置档案：

| 名称 | 说明 |
|---|---|
| `"chrome-latest"` | 跟踪最新抓取的 Chrome 档案（当前为 Chrome 150 macOS） |
| `"chrome-150-macos"` | Chrome 150.0.7871.47 macOS，2026-07-08 抓取 |

两个档案当前产生相同的指纹：
- JA3: `fc513d165de2da9e593e11eddc48906e`
- JA4: `t13d1516h2_8daaf6152771_806a8c22fdea`

**建议：** 使用 `"chrome-latest"`——随着新 Chrome 版本被抓取，该档案会更新。

---

## 选择目标站点（dest）

`dest`（服务端）和 `server_name`（客户端）决定服务端借用哪个真实站点的身份。好的选择：

**必要条件：**
- 位于审查者管辖范围外的站点
- 支持 TLS 1.3
- 支持 HTTP/2 或 HTTP/3
- 域名不能是跳转域名

**优先条件：**
- IP 地址与你的 VPS 地理位置相近（延迟更低、更可信）
- ServerHello 之后的握手消息加密（如 `www.microsoft.com`、`dl.google.com`）
- 支持 OCSP stapling
- 不会向服务端所在国家回传内容

**提示：**
- 服务端的 `server_names` 应包含 `dest` 域名
- 客户端的 `server_name` 必须匹配服务端的 `server_names` 之一
- 常见选择：`www.microsoft.com`、`dl.google.com`、`www.apple.com`、`cloudflare.com`
- 避免可能被独立封锁的站点（否则会连带封锁你的服务器）

---

## 部署

### systemd 服务

创建 `/etc/systemd/system/umbra-server.service`：

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

### 系统调优

```bash
# 增加文件描述符限制
ulimit -n 65535

# 启用 BBR 拥塞控制（Linux）
sudo modprobe tcp_bbr
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
```

### 防火墙

开放监听端口：

```bash
# TCP（必需）
sudo ufw allow 443/tcp

# UDP（如果使用 QUIC）
sudo ufw allow 443/udp
```

### 日志

Umbra 设计上输出极少。出错时向 stderr 打印上下文信息，如 `umbra server TCP session error: ...`。正常运行时无输出。使用 journald 捕获日志：

```bash
sudo journalctl -u umbra-server -f
```

---

## 故障排查

### 服务端立即退出并报错

- **目标探测失败：** 服务端无法连接 `dest` 或 TLS 参数异常。检查 `dest` 从你的 VPS 是否可达且支持 TLS 1.3。
- **配置解析错误：** 检查 TOML 语法。错误信息包含行列号但不会泄露密钥值。

### 客户端无法连接

- **检查 `server` 地址：** 必须是服务端的公网 IP 和端口。
- **检查 `public_key`：** 必须匹配 `keygen` 输出的 `x25519_public`。
- **检查 `short_id`：** 必须匹配服务端 `short_ids` 之一。
- **检查 `server_name`：** 必须匹配服务端 `server_names` 之一。
- **检查防火墙：** 443 端口（TCP）必须开放。使用 QUIC 时 443 端口（UDP）也需开放。

### SOCKS5 代理可用但页面加载慢

- 如有条件，尝试切换 `transport = "quic"`。
- 检查 `mux = true`（默认值）是否有帮助——多路复用减少连接建立开销。
- 确认 `padding_scheme = "default"`——`"none"` 可能触发流量整形。

### 连接间歇性断开

- 如果服务端和客户端时钟不同步，增大 `max_time_diff`。
- 检查目标站点从服务端是否仍可访问。
- 考虑启用 QUIC 作为更稳定的传输方式。

### `openssl s_client` 显示真实证书

这是**预期行为**。服务端将未认证连接转发到真实的 `dest`，因此探测工具看到的是真实站点证书。只有持有正确 `public_key` 和 `short_id` 的认证客户端才会收到临时可信证书。

---

## 安全说明

### 密钥管理

| 材料 | 位置 | 敏感性 |
|---|---|---|
| `x25519_private` | 仅服务端 | **机密** —— 绝不外泄 |
| `mldsa_seed` | 仅服务端 | **机密** —— 绝不外泄 |
| `x25519_public` | 客户端配置 | 共享秘密 —— 安全分发 |
| `mldsa_verify` | 客户端配置 | 公开 —— 但随配置分发 |
| `short_id` | 双方配置 | 共享秘密 —— 安全分发 |

泄露 `x25519_private` 或 `mldsa_seed` 将允许任何人冒充你的服务端。泄露 `x25519_public` 将使审查者能够构造针对性探测。

### Umbra 不记录什么

Umbra 不记录目标地址、流量内容、密钥或会话标识。错误信息对密钥字段使用脱敏占位符。

### 常量时间操作

所有 MAC/标签比较和证书绑定检查使用常量时间验证，以防止计时侧信道攻击。

### 重放保护

服务端维护有界的反重放缓存（默认容量：65,536 条）。条目在 `时间戳 + max_time_diff` 后过期。缓存满时，新认证被拒绝（连接回退到真实目标站点）。

### 合规声明

Umbra 用于隐私保护和在法律允许范围内访问开放互联网。请勿用于非法用途。
