//! Configuration parsing, validation, CLI override merging, and redacted debug output.

use std::{fmt, fs, net::SocketAddr, path::Path, str::FromStr, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use umbra_crypto::{secret::Secret, x25519};
use umbra_inner::padding::{parse_pad_scheme, PadScheme};
use umbra_transport::evasion::{parse_tcp_evasion, TcpEvasionPolicy};

use crate::{dispatch, CoreError};

/// Effective server configuration after file parsing, CLI overrides, and validation.
pub struct ServerCfg {
    /// Shared application memory and adaptive window policy.
    pub performance: crate::resources::PerformanceCfg,
    /// TCP listener address.
    pub listen: SocketAddr,
    /// Optional UDP listener address used for QUIC.
    pub udp_listen: Option<SocketAddr>,
    /// Server X25519 private key.
    pub private_key: x25519::PrivateKey,
    /// Accepted REALITY short identifiers as raw bytes.
    pub short_ids: Vec<Vec<u8>>,
    /// Fixed fallback destination `host:port`.
    pub dest: String,
    /// Accepted SNI values.
    pub server_names: Vec<String>,
    /// Maximum accepted REALITY timestamp skew.
    pub max_time_diff: Duration,
    /// ML-DSA seed used for certificate binding.
    pub mldsa_seed: Secret<32>,
    /// Whether periodic destination prebuild refresh is enabled after the mandatory startup probe.
    pub prebuild: bool,
    /// Inner padding policy.
    pub padding_scheme: PadScheme,
    /// TCP evasion policy.
    pub tcp_evasion: TcpEvasionPolicy,
}

impl ServerCfg {
    /// Parse and validate a server TOML document.
    pub fn from_toml_str(input: &str) -> Result<Self, CoreError> {
        Self::from_toml_str_with_overrides(input, ServerConfigOverrides::default())
    }

    /// Parse a server TOML document, merge CLI-style overrides, then validate.
    pub fn from_toml_str_with_overrides(
        input: &str,
        overrides: ServerConfigOverrides,
    ) -> Result<Self, CoreError> {
        let mut raw: RawServerCfg =
            toml::from_str(input).map_err(|err| sanitized_parse_error(input, &err))?;
        overrides.apply_to(&mut raw);
        server_from_raw(raw)
    }

    /// Read, parse, merge overrides, and validate a server TOML file.
    pub fn from_file_with_overrides(
        path: impl AsRef<Path>,
        overrides: ServerConfigOverrides,
    ) -> Result<Self, CoreError> {
        let input = fs::read_to_string(path)?;
        Self::from_toml_str_with_overrides(&input, overrides)
    }

    /// Consume this config and return the lower-level dispatch configuration.
    pub fn into_dispatch_cfg(self) -> dispatch::ServerCfg {
        dispatch::ServerCfg {
            private_key: self.private_key,
            short_ids: self.short_ids,
            server_names: self.server_names,
            dest: self.dest,
            max_time_diff: self.max_time_diff.as_secs(),
            mldsa_seed: self.mldsa_seed,
            hello_limits: dispatch::HelloReadLimits::default(),
        }
    }
}

impl fmt::Debug for ServerCfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerCfg")
            .field("performance", &self.performance)
            .field("listen", &self.listen)
            .field("udp_listen", &self.udp_listen)
            .field("private_key", &Redacted)
            .field("short_ids", &RedactedCount(self.short_ids.len()))
            .field("dest", &Redacted)
            .field("server_names", &self.server_names)
            .field("max_time_diff", &self.max_time_diff)
            .field("mldsa_seed", &Redacted)
            .field("prebuild", &self.prebuild)
            .field("padding_scheme", &self.padding_scheme)
            .field("tcp_evasion", &self.tcp_evasion)
            .finish()
    }
}

/// Effective client configuration after file parsing, CLI overrides, and validation.
pub struct ClientCfg {
    /// Local application memory and adaptive window policy.
    pub performance: crate::resources::PerformanceCfg,
    /// Umbra server `host:port`.
    pub server: String,
    /// Outer transport for TCP CONNECT and for UDP when no override is set.
    pub transport: TransportKind,
    /// Optional UDP association transport; omitted values inherit `transport`.
    pub udp_transport: Option<TransportKind>,
    /// Server X25519 public key bytes.
    pub public_key: x25519::PublicKeyBytes,
    /// Selected REALITY short id bytes.
    pub short_id: Vec<u8>,
    /// SNI used in the outer ClientHello.
    pub server_name: String,
    /// Fingerprint profile name.
    pub fingerprint: String,
    /// ML-DSA verify key bytes.
    pub mldsa_verify: Vec<u8>,
    /// Browser-like path used when RealSite is detected.
    pub spider_path: String,
    /// Local SOCKS5 listener address.
    pub socks_listen: SocketAddr,
    /// Whether inner mux mode is enabled.
    pub mux: bool,
    /// Inner padding policy.
    pub padding_scheme: PadScheme,
    /// TCP evasion policy.
    pub tcp_evasion: TcpEvasionPolicy,
}

impl ClientCfg {
    /// Return the UDP transport after configuration and CLI overrides have been merged.
    #[must_use]
    pub fn effective_udp_transport(&self) -> TransportKind {
        self.udp_transport.unwrap_or(self.transport)
    }

    /// Parse and validate a client TOML document.
    pub fn from_toml_str(input: &str) -> Result<Self, CoreError> {
        Self::from_toml_str_with_overrides(input, ClientConfigOverrides::default())
    }

    /// Parse a client TOML document, merge CLI-style overrides, then validate.
    pub fn from_toml_str_with_overrides(
        input: &str,
        overrides: ClientConfigOverrides,
    ) -> Result<Self, CoreError> {
        let mut raw: RawClientCfg =
            toml::from_str(input).map_err(|err| sanitized_parse_error(input, &err))?;
        overrides.apply_to(&mut raw);
        client_from_raw(raw)
    }

    /// Read, parse, merge overrides, and validate a client TOML file.
    pub fn from_file_with_overrides(
        path: impl AsRef<Path>,
        overrides: ClientConfigOverrides,
    ) -> Result<Self, CoreError> {
        let input = fs::read_to_string(path)?;
        Self::from_toml_str_with_overrides(&input, overrides)
    }
}

impl fmt::Debug for ClientCfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCfg")
            .field("performance", &self.performance)
            .field("server", &Redacted)
            .field("transport", &self.transport)
            .field("udp_transport", &self.udp_transport)
            .field("public_key", &Redacted)
            .field("short_id", &Redacted)
            .field("server_name", &self.server_name)
            .field("fingerprint", &self.fingerprint)
            .field("mldsa_verify", &Redacted)
            .field("spider_path", &self.spider_path)
            .field("socks_listen", &self.socks_listen)
            .field("mux", &self.mux)
            .field("padding_scheme", &self.padding_scheme)
            .field("tcp_evasion", &self.tcp_evasion)
            .finish()
    }
}

/// Outer transport selected by the client configuration.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TransportKind {
    /// TCP outer transport.
    Tcp,
    /// QUIC outer transport.
    Quic,
}

impl FromStr for TransportKind {
    type Err = CoreError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "tcp" => Ok(Self::Tcp),
            "quic" => Ok(Self::Quic),
            _ => Err(CoreError::InvalidConfig("unsupported transport")),
        }
    }
}

/// CLI-style server overrides. `None` means keep the value loaded from TOML.
#[derive(Clone, Default)]
pub struct ServerConfigOverrides {
    /// Override `listen`.
    pub listen: Option<String>,
    /// Override `udp_listen`.
    pub udp_listen: Option<String>,
    /// Override `private_key`.
    pub private_key: Option<String>,
    /// Override `short_ids`.
    pub short_ids: Option<Vec<String>>,
    /// Override `dest`.
    pub dest: Option<String>,
    /// Override `server_names`.
    pub server_names: Option<Vec<String>>,
    /// Override `max_time_diff`.
    pub max_time_diff: Option<String>,
    /// Override `mldsa_seed`.
    pub mldsa_seed: Option<String>,
    /// Override `prebuild`.
    pub prebuild: Option<bool>,
    /// Override `padding_scheme`.
    pub padding_scheme: Option<String>,
    /// Override `tcp_evasion`.
    pub tcp_evasion: Option<String>,
}

impl fmt::Debug for ServerConfigOverrides {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfigOverrides")
            .field("listen", &self.listen)
            .field("udp_listen", &self.udp_listen)
            .field("private_key", &self.private_key.as_ref().map(|_| Redacted))
            .field(
                "short_ids",
                &self.short_ids.as_ref().map(|ids| RedactedCount(ids.len())),
            )
            .field("dest", &self.dest.as_ref().map(|_| Redacted))
            .field("server_names", &self.server_names)
            .field("max_time_diff", &self.max_time_diff)
            .field("mldsa_seed", &self.mldsa_seed.as_ref().map(|_| Redacted))
            .field("prebuild", &self.prebuild)
            .field("padding_scheme", &self.padding_scheme)
            .field("tcp_evasion", &self.tcp_evasion)
            .finish()
    }
}

impl ServerConfigOverrides {
    fn apply_to(self, raw: &mut RawServerCfg) {
        if let Some(value) = self.listen {
            raw.listen = Some(value);
        }
        if let Some(value) = self.udp_listen {
            raw.udp_listen = Some(value);
        }
        if let Some(value) = self.private_key {
            raw.private_key = Some(value);
        }
        if let Some(value) = self.short_ids {
            raw.short_ids = Some(value);
        }
        if let Some(value) = self.dest {
            raw.dest = Some(value);
        }
        if let Some(value) = self.server_names {
            raw.server_names = Some(value);
        }
        if let Some(value) = self.max_time_diff {
            raw.max_time_diff = Some(value);
        }
        if let Some(value) = self.mldsa_seed {
            raw.mldsa_seed = Some(value);
        }
        if let Some(value) = self.prebuild {
            raw.prebuild = Some(value);
        }
        if let Some(value) = self.padding_scheme {
            raw.padding_scheme = Some(value);
        }
        if let Some(value) = self.tcp_evasion {
            raw.tcp_evasion = Some(value);
        }
    }
}

/// CLI-style client overrides. `None` means keep the value loaded from TOML.
#[derive(Clone, Default)]
pub struct ClientConfigOverrides {
    /// Override `server`.
    pub server: Option<String>,
    /// Override `transport`.
    pub transport: Option<String>,
    /// Override the UDP association transport.
    pub udp_transport: Option<String>,
    /// Override `public_key`.
    pub public_key: Option<String>,
    /// Override `short_id`.
    pub short_id: Option<String>,
    /// Override `server_name`.
    pub server_name: Option<String>,
    /// Override `fingerprint`.
    pub fingerprint: Option<String>,
    /// Override `mldsa_verify`.
    pub mldsa_verify: Option<String>,
    /// Override `spider_path`.
    pub spider_path: Option<String>,
    /// Override `socks_listen`.
    pub socks_listen: Option<String>,
    /// Override `mux`.
    pub mux: Option<bool>,
    /// Override `padding_scheme`.
    pub padding_scheme: Option<String>,
    /// Override `tcp_evasion`.
    pub tcp_evasion: Option<String>,
}

impl fmt::Debug for ClientConfigOverrides {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfigOverrides")
            .field("server", &self.server.as_ref().map(|_| Redacted))
            .field("transport", &self.transport)
            .field("udp_transport", &self.udp_transport)
            .field("public_key", &self.public_key.as_ref().map(|_| Redacted))
            .field("short_id", &self.short_id.as_ref().map(|_| Redacted))
            .field("server_name", &self.server_name)
            .field("fingerprint", &self.fingerprint)
            .field(
                "mldsa_verify",
                &self.mldsa_verify.as_ref().map(|_| Redacted),
            )
            .field("spider_path", &self.spider_path)
            .field("socks_listen", &self.socks_listen)
            .field("mux", &self.mux)
            .field("padding_scheme", &self.padding_scheme)
            .field("tcp_evasion", &self.tcp_evasion)
            .finish()
    }
}

impl ClientConfigOverrides {
    fn apply_to(self, raw: &mut RawClientCfg) {
        if let Some(value) = self.server {
            raw.server = Some(value);
        }
        if let Some(value) = self.transport {
            raw.transport = Some(value);
        }
        if let Some(value) = self.udp_transport {
            raw.udp_transport = Some(value);
        }
        if let Some(value) = self.public_key {
            raw.public_key = Some(value);
        }
        if let Some(value) = self.short_id {
            raw.short_id = Some(value);
        }
        if let Some(value) = self.server_name {
            raw.server_name = Some(value);
        }
        if let Some(value) = self.fingerprint {
            raw.fingerprint = Some(value);
        }
        if let Some(value) = self.mldsa_verify {
            raw.mldsa_verify = Some(value);
        }
        if let Some(value) = self.spider_path {
            raw.spider_path = Some(value);
        }
        if let Some(value) = self.socks_listen {
            raw.socks_listen = Some(value);
        }
        if let Some(value) = self.mux {
            raw.mux = Some(value);
        }
        if let Some(value) = self.padding_scheme {
            raw.padding_scheme = Some(value);
        }
        if let Some(value) = self.tcp_evasion {
            raw.tcp_evasion = Some(value);
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawServerCfg {
    performance: crate::resources::PerformanceCfg,
    listen: Option<String>,
    udp_listen: Option<String>,
    private_key: Option<String>,
    short_ids: Option<Vec<String>>,
    dest: Option<String>,
    server_names: Option<Vec<String>>,
    max_time_diff: Option<String>,
    mldsa_seed: Option<String>,
    prebuild: Option<bool>,
    padding_scheme: Option<String>,
    tcp_evasion: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawClientCfg {
    performance: crate::resources::PerformanceCfg,
    server: Option<String>,
    transport: Option<String>,
    udp_transport: Option<String>,
    public_key: Option<String>,
    short_id: Option<String>,
    server_name: Option<String>,
    fingerprint: Option<String>,
    mldsa_verify: Option<String>,
    spider_path: Option<String>,
    socks_listen: Option<String>,
    mux: Option<bool>,
    padding_scheme: Option<String>,
    tcp_evasion: Option<String>,
}

fn server_from_raw(raw: RawServerCfg) -> Result<ServerCfg, CoreError> {
    let listen_raw = required(raw.listen, "listen is required")?;
    let listen = parse_socket_addr(&listen_raw)?;
    let udp_listen = raw
        .udp_listen
        .map(|addr| parse_socket_addr(&addr))
        .transpose()?;
    let private_key_raw = required(raw.private_key, "private_key is required")?;
    let private_key = Secret::new(decode_base64_array(
        &private_key_raw,
        "private_key must be base64-encoded 32 bytes",
    )?);
    let short_ids_raw = required(raw.short_ids, "short_ids is required")?;
    let short_ids = decode_short_id_list(&short_ids_raw)?;
    let dest = required(raw.dest, "dest is required")?;
    validate_host_port(&dest)?;
    let server_names =
        validate_server_names(required(raw.server_names, "server_names is required")?)?;
    let max_time_diff_raw = required(raw.max_time_diff, "max_time_diff is required")?;
    let max_time_diff = parse_duration(&max_time_diff_raw)?;
    if max_time_diff.as_secs() == 0 {
        return Err(CoreError::InvalidConfig(
            "max_time_diff must be at least one second",
        ));
    }
    let mldsa_seed_raw = required(raw.mldsa_seed, "mldsa_seed is required")?;
    let mldsa_seed = Secret::new(decode_base64_array(
        &mldsa_seed_raw,
        "mldsa_seed must be base64-encoded 32 bytes",
    )?);
    let padding_scheme =
        parse_pad_scheme(&raw.padding_scheme.unwrap_or_else(|| "default".to_owned()))?;
    let tcp_evasion = parse_tcp_evasion(&raw.tcp_evasion.unwrap_or_else(|| "segment".to_owned()))?;

    Ok(ServerCfg {
        performance: raw.performance.validate()?,
        listen,
        udp_listen,
        private_key,
        short_ids,
        dest,
        server_names,
        max_time_diff,
        mldsa_seed,
        prebuild: raw.prebuild.unwrap_or(true),
        padding_scheme,
        tcp_evasion,
    })
}

fn client_from_raw(raw: RawClientCfg) -> Result<ClientCfg, CoreError> {
    let server = required(raw.server, "server is required")?;
    validate_host_port(&server)?;
    let transport = TransportKind::from_str(&required(raw.transport, "transport is required")?)?;
    let udp_transport = raw
        .udp_transport
        .map(|value| TransportKind::from_str(&value))
        .transpose()?;
    let public_key_raw = required(raw.public_key, "public_key is required")?;
    let public_key = x25519::PublicKeyBytes::new(decode_base64_array(
        &public_key_raw,
        "public_key must be base64-encoded 32 bytes",
    )?);
    let short_id = decode_short_id(&required(raw.short_id, "short_id is required")?)?;
    let server_name = required(raw.server_name, "server_name is required")?;
    validate_server_name(&server_name)?;
    let fingerprint = required(raw.fingerprint, "fingerprint is required")?;
    if fingerprint.trim().is_empty() {
        return Err(CoreError::InvalidConfig("fingerprint is empty"));
    }
    let mldsa_verify_raw = required(raw.mldsa_verify, "mldsa_verify is required")?;
    let mldsa_verify = decode_base64_vec(&mldsa_verify_raw, "mldsa_verify must be base64")?;
    if mldsa_verify.is_empty() {
        return Err(CoreError::InvalidConfig("mldsa_verify is empty"));
    }
    let spider_path = raw.spider_path.unwrap_or_else(|| "/".to_owned());
    validate_spider_path(&spider_path)?;
    let socks_listen_raw = required(raw.socks_listen, "socks_listen is required")?;
    let socks_listen = parse_socket_addr(&socks_listen_raw)?;
    let padding_scheme =
        parse_pad_scheme(&raw.padding_scheme.unwrap_or_else(|| "default".to_owned()))?;
    let tcp_evasion = parse_tcp_evasion(&raw.tcp_evasion.unwrap_or_else(|| "segment".to_owned()))?;

    Ok(ClientCfg {
        performance: raw.performance.validate()?,
        server,
        transport,
        udp_transport,
        public_key,
        short_id,
        server_name,
        fingerprint,
        mldsa_verify,
        spider_path,
        socks_listen,
        mux: raw.mux.unwrap_or(true),
        padding_scheme,
        tcp_evasion,
    })
}

// TOML's message and source excerpt can both contain secrets, including values
// nested in arrays. Retain only a static error category and a numeric location;
// never attach the original error as a source.
fn sanitized_parse_error(input: &str, error: &toml::de::Error) -> CoreError {
    let Some(span) = error.span() else {
        return CoreError::ConfigParse("invalid TOML syntax or type".to_owned());
    };
    let (line, column) = input
        .char_indices()
        .take_while(|(offset, _)| *offset < span.start)
        .fold((1_usize, 1_usize), |(line, column), (_, ch)| {
            if ch == '\n' {
                (line + 1, 1)
            } else {
                (line, column + 1)
            }
        });
    CoreError::ConfigParse(format!(
        "invalid TOML syntax or type at line {line}, column {column}"
    ))
}

fn required<T>(value: Option<T>, message: &'static str) -> Result<T, CoreError> {
    value.ok_or(CoreError::InvalidConfig(message))
}

fn parse_socket_addr(input: &str) -> Result<SocketAddr, CoreError> {
    input
        .parse()
        .map_err(|_| CoreError::InvalidConfig("socket address is invalid"))
}

fn decode_base64_array<const N: usize>(
    input: &str,
    message: &'static str,
) -> Result<[u8; N], CoreError> {
    let bytes = decode_base64_vec(input, message)?;
    bytes
        .try_into()
        .map_err(|_| CoreError::InvalidConfig(message))
}

fn decode_base64_vec(input: &str, message: &'static str) -> Result<Vec<u8>, CoreError> {
    STANDARD
        .decode(input)
        .map_err(|_| CoreError::InvalidConfig(message))
}

fn decode_short_id_list(values: &[String]) -> Result<Vec<Vec<u8>>, CoreError> {
    if values.is_empty() {
        return Err(CoreError::InvalidConfig(
            "at least one short id is required",
        ));
    }
    values.iter().map(|value| decode_short_id(value)).collect()
}

fn decode_short_id(input: &str) -> Result<Vec<u8>, CoreError> {
    if input.len() > 16 || !input.len().is_multiple_of(2) {
        return Err(CoreError::InvalidConfig(
            "short id must be 0-8 bytes encoded as hex",
        ));
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for pair in input.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, CoreError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(CoreError::InvalidConfig("short id contains non-hex byte")),
    }
}

fn validate_host_port(input: &str) -> Result<(), CoreError> {
    let (host, port) = input.rsplit_once(':').ok_or(CoreError::InvalidConfig(
        "address must include host and port",
    ))?;
    if host.is_empty() || port.is_empty() {
        return Err(CoreError::InvalidConfig("address host or port is empty"));
    }
    let parsed_port = port
        .parse::<u16>()
        .map_err(|_| CoreError::InvalidConfig("address port is invalid"))?;
    if parsed_port == 0 {
        return Err(CoreError::InvalidConfig("address port must be nonzero"));
    }
    Ok(())
}

fn validate_server_names(values: Vec<String>) -> Result<Vec<String>, CoreError> {
    if values.is_empty() {
        return Err(CoreError::InvalidConfig(
            "at least one server name is required",
        ));
    }
    for value in &values {
        validate_server_name(value)?;
    }
    Ok(values)
}

fn validate_server_name(input: &str) -> Result<(), CoreError> {
    if input.is_empty()
        || input.len() > 253
        || !input.is_ascii()
        || input.as_bytes().iter().any(u8::is_ascii_whitespace)
    {
        return Err(CoreError::InvalidConfig("server name is invalid"));
    }
    Ok(())
}

fn validate_spider_path(input: &str) -> Result<(), CoreError> {
    if !input.starts_with('/') {
        return Err(CoreError::InvalidConfig("spider_path must start with '/'"));
    }
    if input
        .as_bytes()
        .iter()
        .any(|byte| matches!(*byte, b'\r' | b'\n'))
    {
        return Err(CoreError::InvalidConfig(
            "spider_path must not contain CR or LF",
        ));
    }
    Ok(())
}

fn parse_duration(input: &str) -> Result<Duration, CoreError> {
    let trimmed = input.trim();
    if let Some(ms) = trimmed.strip_suffix("ms") {
        return parse_duration_value(ms, DurationUnit::Millis);
    }
    if let Some(seconds) = trimmed.strip_suffix('s') {
        return parse_duration_value(seconds, DurationUnit::Seconds);
    }
    if let Some(minutes) = trimmed.strip_suffix('m') {
        return parse_duration_value(minutes, DurationUnit::Minutes);
    }
    if let Some(hours) = trimmed.strip_suffix('h') {
        return parse_duration_value(hours, DurationUnit::Hours);
    }
    parse_duration_value(trimmed, DurationUnit::Seconds)
}

#[derive(Clone, Copy)]
enum DurationUnit {
    Millis,
    Seconds,
    Minutes,
    Hours,
}

fn parse_duration_value(input: &str, unit: DurationUnit) -> Result<Duration, CoreError> {
    let value = input
        .parse::<u64>()
        .map_err(|_| CoreError::InvalidConfig("duration is invalid"))?;
    match unit {
        DurationUnit::Millis => Ok(Duration::from_millis(value)),
        DurationUnit::Seconds => Ok(Duration::from_secs(value)),
        DurationUnit::Minutes => value
            .checked_mul(60)
            .map(Duration::from_secs)
            .ok_or(CoreError::InvalidConfig("duration overflows")),
        DurationUnit::Hours => value
            .checked_mul(60 * 60)
            .map(Duration::from_secs)
            .ok_or(CoreError::InvalidConfig("duration overflows")),
    }
}

struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

struct RedactedCount(usize);

impl fmt::Debug for RedactedCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} redacted>", self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    const FAKE_SECRET: &str = "SYNTHETIC_PRIVATE_KEY_SEED_SHORT_ID";

    #[test]
    fn syntax_errors_omit_secret_lines_and_retain_location() {
        for field in ["private_key", "mldsa_seed", "short_ids"] {
            let input = format!("# synthetic fixture\n{field} = [\"{FAKE_SECRET}\" trailing]");
            assert_safe_parse_error(&ServerCfg::from_toml_str(&input).expect_err("syntax error"));
        }
        for field in ["public_key", "mldsa_verify", "short_id"] {
            let input = format!("# synthetic fixture\n{field} = [\"{FAKE_SECRET}\" trailing]");
            assert_safe_parse_error(&ClientCfg::from_toml_str(&input).expect_err("syntax error"));
        }
    }

    #[test]
    fn type_errors_omit_secret_values_including_nested_arrays() {
        for field in ["private_key", "mldsa_seed", "short_ids", "prebuild"] {
            for value in [
                format!("[\"{FAKE_SECRET}\", \"cafebabedeadbeef\"]"),
                format!("[[\"{FAKE_SECRET}\", \"cafebabedeadbeef\"]]"),
                format!("{{ value = \"{FAKE_SECRET}\" }}"),
            ] {
                // A string array is the correct type for short_ids; use nested arrays there.
                if field == "short_ids" && value.starts_with("[\"") {
                    continue;
                }
                let input = format!("# synthetic fixture\n{field} = {value}");
                assert_safe_parse_error(&ServerCfg::from_toml_str(&input).expect_err("type error"));
            }
        }
        for field in ["public_key", "mldsa_verify", "short_id", "mux"] {
            let input = format!(
                "# synthetic fixture\n{field} = [[\"{FAKE_SECRET}\", \"cafebabedeadbeef\"]]"
            );
            assert_safe_parse_error(&ClientCfg::from_toml_str(&input).expect_err("type error"));
        }
        for input in [
            format!("# synthetic fixture\nprebuild = \"{FAKE_SECRET}\""),
            format!("# synthetic fixture\n{FAKE_SECRET} = true"),
        ] {
            assert_safe_parse_error(
                &ServerCfg::from_toml_str(&input).expect_err("invalid field or type"),
            );
        }
    }

    #[test]
    fn sanitized_error_handles_unicode_eof_and_missing_span() {
        let input = "private_key = \"é\" trailing";
        let error = ServerCfg::from_toml_str(input).expect_err("trailing content");
        assert_eq!(
            error.to_string(),
            "configuration parse failed: invalid TOML syntax or type at line 1, column 19"
        );
        let input = format!("# synthetic fixture\nprivate_key = \"{FAKE_SECRET}");
        assert_safe_parse_error(
            &ServerCfg::from_toml_str(&input).expect_err("unterminated string"),
        );

        let original: toml::de::Error = serde::de::Error::custom(FAKE_SECRET);
        let error = sanitized_parse_error("", &original);
        assert_eq!(
            error.to_string(),
            "configuration parse failed: invalid TOML syntax or type"
        );
        assert!(error.source().is_none());
        assert!(!format!("{error:?}").contains(FAKE_SECRET));
    }

    #[test]
    fn validation_errors_omit_secret_values() {
        for field in ["private_key", "mldsa_seed", "short_ids"] {
            let value = if field == "short_ids" {
                format!("[\"{FAKE_SECRET}\"]")
            } else {
                format!("\"{FAKE_SECRET}\"")
            };
            let input = replace_field(&server_toml(), field, &value);
            let error = ServerCfg::from_toml_str(&input).expect_err("invalid secret format");
            assert!(matches!(error, CoreError::InvalidConfig(_)));
            assert!(!format!("{error} {error:?}").contains(FAKE_SECRET));
            assert!(error.source().is_none());
        }
        for field in ["public_key", "mldsa_verify", "short_id"] {
            let input = replace_field(&client_toml(), field, &format!("\"{FAKE_SECRET}\""));
            let error = ClientCfg::from_toml_str(&input).expect_err("invalid secret format");
            assert!(matches!(error, CoreError::InvalidConfig(_)));
            assert!(!format!("{error} {error:?}").contains(FAKE_SECRET));
            assert!(error.source().is_none());
        }
    }

    #[test]
    fn geneva_is_rejected_in_file_values_and_cli_overrides() {
        for strategy in [
            "geneva:",
            "geneva:fragment{tcp}",
            "geneva:SYNTHETIC_PRIVATE_KEY_SEED_SHORT_ID",
        ] {
            let server = format!("{}\ntcp_evasion = \"{strategy}\"", server_toml());
            let client = format!("{}\ntcp_evasion = \"{strategy}\"", client_toml());
            assert_unsupported_geneva(&ServerCfg::from_toml_str(&server).expect_err("unsupported"));
            assert_unsupported_geneva(&ClientCfg::from_toml_str(&client).expect_err("unsupported"));
            assert_unsupported_geneva(
                &ServerCfg::from_toml_str_with_overrides(
                    &format!("{}\ntcp_evasion = \"off\"", server_toml()),
                    ServerConfigOverrides {
                        tcp_evasion: Some(strategy.to_owned()),
                        ..Default::default()
                    },
                )
                .expect_err("unsupported override"),
            );
            assert_unsupported_geneva(
                &ClientCfg::from_toml_str_with_overrides(
                    &format!("{}\ntcp_evasion = \"segment\"", client_toml()),
                    ClientConfigOverrides {
                        tcp_evasion: Some(strategy.to_owned()),
                        ..Default::default()
                    },
                )
                .expect_err("unsupported override"),
            );

            // Validation applies to the effective merged value, not the discarded file value.
            let server = ServerCfg::from_toml_str_with_overrides(
                &server,
                ServerConfigOverrides {
                    tcp_evasion: Some("off".to_owned()),
                    ..Default::default()
                },
            )
            .expect("implemented override replaces unsupported file value");
            assert!(server.tcp_evasion.is_off());
            let client = ClientCfg::from_toml_str_with_overrides(
                &client,
                ClientConfigOverrides {
                    tcp_evasion: Some("segment".to_owned()),
                    ..Default::default()
                },
            )
            .expect("implemented override replaces unsupported file value");
            assert!(matches!(
                client.tcp_evasion,
                TcpEvasionPolicy::Segment { .. }
            ));
        }
    }

    fn assert_safe_parse_error(error: &CoreError) {
        let CoreError::ConfigParse(message) = error else {
            panic!("expected a parse error")
        };
        let location = message
            .strip_prefix("invalid TOML syntax or type at line 2, column ")
            .expect("safe category and line number");
        assert!(location.parse::<usize>().expect("numeric column only") > 0);
        assert!(error.source().is_none());
        for value in [FAKE_SECRET, "cafebabedeadbeef", "synthetic fixture"] {
            assert!(!format!("{error} {error:?} {error:#?}").contains(value));
        }
    }

    fn assert_unsupported_geneva(error: &CoreError) {
        assert!(matches!(
            error,
            CoreError::Transport(umbra_transport::TransportError::InvalidEvasionStrategy(_))
        ));
        assert_eq!(
            error.to_string(),
            "invalid TCP evasion strategy: unsupported Geneva strategy: sender unavailable"
        );
        assert!(!format!("{error:?}").contains(FAKE_SECRET));
        assert!(error.source().is_none());
    }

    fn replace_field(input: &str, field: &str, value: &str) -> String {
        input
            .lines()
            .map(|line| {
                if line.starts_with(&format!("{field} =")) {
                    format!("{field} = {value}")
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn server_toml() -> String {
        format!(
            r#"listen = "127.0.0.1:0"
private_key = "{}"
short_ids = ["cafebabedeadbeef"]
dest = "localhost:443"
server_names = ["example.test"]
max_time_diff = "120s"
mldsa_seed = "{}""#,
            STANDARD.encode([1_u8; 32]),
            STANDARD.encode([2_u8; 32])
        )
    }

    fn client_toml() -> String {
        format!(
            r#"server = "localhost:443"
transport = "tcp"
public_key = "{}"
short_id = "cafebabedeadbeef"
server_name = "example.test"
fingerprint = "chrome-latest"
mldsa_verify = "{}"
socks_listen = "127.0.0.1:0""#,
            STANDARD.encode([1_u8; 32]),
            STANDARD.encode([2_u8; 32])
        )
    }
}
