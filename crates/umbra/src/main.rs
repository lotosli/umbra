//! Umbra command line interface.

use std::{fs, path::PathBuf};

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Args, Parser, Subcommand};
use umbra_core::{
    config::{ClientCfg, ClientConfigOverrides, ServerCfg, ServerConfigOverrides},
    runtime::{run_client, run_server},
};
use umbra_crypto::{mldsa, x25519};

/// Umbra privacy transport CLI.
#[derive(Debug, Parser)]
#[command(name = "umbra", version, about = "Umbra client/server/keygen CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Umbra subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Run an Umbra server.
    Server(ServerArgs),
    /// Run an Umbra client.
    Client(ClientArgs),
    /// Generate X25519 and ML-DSA key material.
    Keygen,
}

/// Server command arguments.
#[derive(Debug, Args)]
struct ServerArgs {
    /// Path to `server.toml`.
    #[arg(long, short)]
    config: Option<PathBuf>,
    /// TCP listener address.
    #[arg(long)]
    listen: Option<String>,
    /// UDP listener address for QUIC.
    #[arg(long = "udp-listen")]
    udp_listen: Option<String>,
    /// Base64 X25519 private key.
    #[arg(long = "private-key")]
    private_key: Option<String>,
    /// Accepted short ids as hex strings. Repeat or pass comma-separated values.
    #[arg(long = "short-ids", value_delimiter = ',')]
    short_ids: Vec<String>,
    /// Fixed fallback destination `host:port`.
    #[arg(long)]
    dest: Option<String>,
    /// Accepted SNI names. Repeat or pass comma-separated values.
    #[arg(long = "server-names", value_delimiter = ',')]
    server_names: Vec<String>,
    /// Maximum REALITY timestamp skew, such as `120s`.
    #[arg(long = "max-time-diff")]
    max_time_diff: Option<String>,
    /// Base64 32-byte ML-DSA seed.
    #[arg(long = "mldsa-seed")]
    mldsa_seed: Option<String>,
    /// Whether destination prebuild probing is enabled.
    #[arg(long)]
    prebuild: Option<bool>,
    /// Inner padding scheme.
    #[arg(long = "padding-scheme")]
    padding_scheme: Option<String>,
    /// TCP evasion policy.
    #[arg(long = "tcp-evasion")]
    tcp_evasion: Option<String>,
}

/// Client command arguments.
#[derive(Debug, Args)]
struct ClientArgs {
    /// Path to `client.toml`.
    #[arg(long, short)]
    config: Option<PathBuf>,
    /// Umbra server `host:port`.
    #[arg(long)]
    server: Option<String>,
    /// Outer transport: `tcp` or `quic`.
    #[arg(long)]
    transport: Option<String>,
    /// Base64 X25519 server public key.
    #[arg(long = "public-key")]
    public_key: Option<String>,
    /// Selected short id as a hex string.
    #[arg(long = "short-id")]
    short_id: Option<String>,
    /// SNI used in the outer ClientHello.
    #[arg(long = "server-name")]
    server_name: Option<String>,
    /// Fingerprint profile name.
    #[arg(long)]
    fingerprint: Option<String>,
    /// Base64 ML-DSA verification key.
    #[arg(long = "mldsa-verify")]
    mldsa_verify: Option<String>,
    /// Browser-like path used for RealSite spider mode.
    #[arg(long = "spider-path")]
    spider_path: Option<String>,
    /// Local SOCKS5 listener address.
    #[arg(long = "socks-listen")]
    socks_listen: Option<String>,
    /// Whether inner mux mode is enabled.
    #[arg(long)]
    mux: Option<bool>,
    /// Inner padding scheme.
    #[arg(long = "padding-scheme")]
    padding_scheme: Option<String>,
    /// TCP evasion policy.
    #[arg(long = "tcp-evasion")]
    tcp_evasion: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Server(args) => run_server(resolve_server_cfg(&args)?).await?,
        Command::Client(args) => run_client(resolve_client_cfg(&args)?).await?,
        Command::Keygen => run_keygen(),
    }
    Ok(())
}

fn resolve_server_cfg(args: &ServerArgs) -> anyhow::Result<ServerCfg> {
    let input = read_optional_config(args.config.as_ref())?;
    ServerCfg::from_toml_str_with_overrides(&input, server_overrides(args))
        .context("server configuration is invalid")
}

fn resolve_client_cfg(args: &ClientArgs) -> anyhow::Result<ClientCfg> {
    let input = read_optional_config(args.config.as_ref())?;
    ClientCfg::from_toml_str_with_overrides(&input, client_overrides(args))
        .context("client configuration is invalid")
}

fn read_optional_config(path: Option<&PathBuf>) -> anyhow::Result<String> {
    path.map_or_else(
        || Ok(String::new()),
        |path| {
            fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
        },
    )
}

fn server_overrides(args: &ServerArgs) -> ServerConfigOverrides {
    ServerConfigOverrides {
        listen: args.listen.clone(),
        udp_listen: args.udp_listen.clone(),
        private_key: args.private_key.clone(),
        short_ids: non_empty_vec(&args.short_ids),
        dest: args.dest.clone(),
        server_names: non_empty_vec(&args.server_names),
        max_time_diff: args.max_time_diff.clone(),
        mldsa_seed: args.mldsa_seed.clone(),
        prebuild: args.prebuild,
        padding_scheme: args.padding_scheme.clone(),
        tcp_evasion: args.tcp_evasion.clone(),
    }
}

fn client_overrides(args: &ClientArgs) -> ClientConfigOverrides {
    ClientConfigOverrides {
        server: args.server.clone(),
        transport: args.transport.clone(),
        public_key: args.public_key.clone(),
        short_id: args.short_id.clone(),
        server_name: args.server_name.clone(),
        fingerprint: args.fingerprint.clone(),
        mldsa_verify: args.mldsa_verify.clone(),
        spider_path: args.spider_path.clone(),
        socks_listen: args.socks_listen.clone(),
        mux: args.mux,
        padding_scheme: args.padding_scheme.clone(),
        tcp_evasion: args.tcp_evasion.clone(),
    }
}

fn non_empty_vec(values: &[String]) -> Option<Vec<String>> {
    if values.is_empty() {
        None
    } else {
        Some(values.to_vec())
    }
}

/// Print X25519 and ML-DSA key material for Umbra configuration files.
pub fn run_keygen() {
    let x25519 = x25519::generate_keypair();
    let mldsa = mldsa::mldsa_keygen();
    println!(
        "x25519_private={}\nx25519_public={}\nmldsa_seed={}\nmldsa_verify={}",
        STANDARD.encode(x25519.private.expose_secret()),
        STANDARD.encode(x25519.public.as_bytes()),
        STANDARD.encode(mldsa.signing_seed.expose_secret()),
        STANDARD.encode(&mldsa.verifying_key),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    #[test]
    fn scenario_server_flags_override_config() {
        let args = ServerArgs {
            config: None,
            listen: Some("127.0.0.1:9443".to_owned()),
            udp_listen: Some("127.0.0.1:9444".to_owned()),
            private_key: Some(b64(1)),
            short_ids: vec!["aa".to_owned(), "bb".to_owned()],
            dest: Some("override.example:443".to_owned()),
            server_names: vec!["override.example".to_owned()],
            max_time_diff: Some("120s".to_owned()),
            mldsa_seed: Some(b64(2)),
            prebuild: Some(false),
            padding_scheme: Some("none".to_owned()),
            tcp_evasion: Some("off".to_owned()),
        };

        let cfg = resolve_server_cfg(&args).expect("server flags resolve");

        assert_eq!(cfg.listen.to_string(), "127.0.0.1:9443");
        assert_eq!(cfg.udp_listen.expect("udp").to_string(), "127.0.0.1:9444");
        assert_eq!(cfg.short_ids, vec![vec![0xaa], vec![0xbb]]);
        assert_eq!(cfg.dest, "override.example:443");
        assert_eq!(cfg.server_names, vec!["override.example"]);
        assert!(!cfg.prebuild);
    }

    #[test]
    fn scenario_client_flags_override_config() {
        let args = ClientArgs {
            config: None,
            server: Some("198.51.100.10:443".to_owned()),
            transport: Some("tcp".to_owned()),
            public_key: Some(b64(3)),
            short_id: Some("aa".to_owned()),
            server_name: Some("server.example".to_owned()),
            fingerprint: Some("chrome-latest".to_owned()),
            mldsa_verify: Some(b64(4)),
            spider_path: Some("/spider".to_owned()),
            socks_listen: Some("127.0.0.1:1081".to_owned()),
            mux: Some(false),
            padding_scheme: Some("none".to_owned()),
            tcp_evasion: Some("off".to_owned()),
        };

        let cfg = resolve_client_cfg(&args).expect("client flags resolve");

        assert_eq!(cfg.server, "198.51.100.10:443");
        assert_eq!(cfg.short_id, vec![0xaa]);
        assert_eq!(cfg.server_name, "server.example");
        assert_eq!(cfg.spider_path, "/spider");
        assert!(!cfg.mux);
    }

    #[test]
    fn scenario_invalid_transport_exits_before_runtime_startup() {
        let args = ClientArgs {
            config: None,
            server: Some("198.51.100.10:443".to_owned()),
            transport: Some("invalid".to_owned()),
            public_key: Some(b64(3)),
            short_id: Some("aa".to_owned()),
            server_name: Some("server.example".to_owned()),
            fingerprint: Some("chrome-latest".to_owned()),
            mldsa_verify: Some(b64(4)),
            spider_path: Some("/spider".to_owned()),
            socks_listen: Some("127.0.0.1:1081".to_owned()),
            mux: Some(true),
            padding_scheme: Some("none".to_owned()),
            tcp_evasion: Some("off".to_owned()),
        };

        assert!(resolve_client_cfg(&args).is_err());
    }

    fn b64(byte: u8) -> String {
        STANDARD.encode([byte; 32])
    }
}
