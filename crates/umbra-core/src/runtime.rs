//! Server and client runtime orchestration.

use std::{
    future::Future,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use rand::{rngs::OsRng, RngCore};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream, UdpSocket},
};
use umbra_crypto::x25519;
use umbra_fingerprint::load_profile;
use umbra_inner::{mux::MuxSession, padding::PadScheme, spider::spider, vision::send_solo_preface};
use umbra_proto::addr::TargetAddr;
use umbra_reality::{auth::try_seal_session_id, prebuild::DestProfile, replay::ReplayCache};
use umbra_tls::clienthello::hello0;
use umbra_transport::{
    evasion::TcpEvasionPolicy,
    tcp::{build_tcp_client_hello, tcp_connect_and_send, TcpClientHelloConfig},
};

use crate::{
    config::{ClientCfg, ServerCfg as RuntimeServerCfg, TransportKind},
    dispatch::{dispatch_with_connector_and_timing, DispatchOutcome, HelloReadLimits},
    probe::ProbeResistancePolicy,
    socks::{
        negotiate_no_auth, read_connect_request, write_success_reply,
        write_unsupported_command_reply, SocksConnect,
    },
    CoreError,
};

const DEFAULT_REPLAY_CAPACITY: usize = 65_536;
const PLACEHOLDER_MLKEM_KEY_EXCHANGE_LEN: usize = 32;

/// Bound server runtime with listeners, replay cache, and active destination profile.
pub struct ServerRuntime {
    tcp_listener: TcpListener,
    udp_socket: Option<UdpSocket>,
    dispatch_cfg: crate::dispatch::ServerCfg,
    profile: DestProfile,
    replay: ReplayCache,
    probe_policy: ProbeResistancePolicy,
    padding_scheme: PadScheme,
    tcp_evasion: TcpEvasionPolicy,
    prebuild: bool,
}

impl ServerRuntime {
    /// Bind configured listeners using an already-collected destination profile.
    pub async fn bind_with_profile(
        cfg: RuntimeServerCfg,
        profile: DestProfile,
        probe_policy: ProbeResistancePolicy,
    ) -> Result<Self, CoreError> {
        probe_policy.validate()?;
        let RuntimeServerCfg {
            listen,
            udp_listen,
            private_key,
            short_ids,
            dest,
            server_names,
            max_time_diff,
            mldsa_seed,
            prebuild,
            padding_scheme,
            tcp_evasion,
        } = cfg;

        let tcp_listener = TcpListener::bind(listen).await?;
        let udp_socket = match udp_listen {
            Some(addr) => Some(UdpSocket::bind(addr).await?),
            None => None,
        };
        let replay = ReplayCache::new(DEFAULT_REPLAY_CAPACITY, max_time_diff.as_secs())?;
        let hello_limits = HelloReadLimits {
            max_useless_records: probe_policy.useless_records.max_useless_records,
            ..HelloReadLimits::default()
        };
        let dispatch_cfg = crate::dispatch::ServerCfg {
            private_key,
            short_ids,
            server_names,
            dest,
            max_time_diff: max_time_diff.as_secs(),
            mldsa_seed,
            hello_limits,
        };

        Ok(Self {
            tcp_listener,
            udp_socket,
            dispatch_cfg,
            profile,
            replay,
            probe_policy,
            padding_scheme,
            tcp_evasion,
            prebuild,
        })
    }

    /// Return the bound TCP listener address.
    pub fn local_addr(&self) -> Result<SocketAddr, CoreError> {
        self.tcp_listener.local_addr().map_err(CoreError::from)
    }

    /// Return the bound UDP listener address, when QUIC is enabled.
    pub fn udp_local_addr(&self) -> Result<Option<SocketAddr>, CoreError> {
        self.udp_socket
            .as_ref()
            .map(UdpSocket::local_addr)
            .transpose()
            .map_err(CoreError::from)
    }

    /// Return how many listener tasks this runtime needs.
    #[must_use]
    pub const fn listener_count(&self) -> usize {
        if self.udp_socket.is_some() {
            2
        } else {
            1
        }
    }

    /// Return the configured inner padding scheme.
    #[must_use]
    pub const fn padding_scheme(&self) -> &PadScheme {
        &self.padding_scheme
    }

    /// Return the configured TCP evasion policy.
    #[must_use]
    pub const fn tcp_evasion(&self) -> &TcpEvasionPolicy {
        &self.tcp_evasion
    }

    /// Return whether this runtime was configured for destination prebuild.
    #[must_use]
    pub const fn prebuild_enabled(&self) -> bool {
        self.prebuild
    }

    /// Accept one TCP connection and dispatch it using an injected destination connector.
    pub async fn accept_one_with_connector<D, Connect, ConnectFuture>(
        &self,
        connect_dest: Connect,
    ) -> Result<AcceptedServerSession, CoreError>
    where
        D: AsyncRead + AsyncWrite + Unpin,
        Connect: FnOnce(String) -> ConnectFuture,
        ConnectFuture: Future<Output = Result<D, std::io::Error>>,
    {
        let (stream, peer) = self.tcp_listener.accept().await?;
        let outcome = dispatch_with_connector_and_timing(
            stream,
            &self.dispatch_cfg,
            &self.profile,
            &self.replay,
            current_unix_time()?,
            connect_dest,
            self.probe_policy.timing,
        )
        .await?;
        Ok(AcceptedServerSession { peer, outcome })
    }

    /// Accept and dispatch TCP sessions until shutdown resolves.
    pub async fn run_until_shutdown<S>(&self, shutdown: S) -> Result<(), CoreError>
    where
        S: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => return Ok(()),
                accepted = self.accept_one_with_connector(TcpStream::connect) => {
                    accepted?;
                }
            }
        }
    }
}

/// One accepted server-side session result.
#[derive(Debug)]
pub struct AcceptedServerSession {
    /// TCP peer address.
    pub peer: SocketAddr,
    /// Dispatch result.
    pub outcome: DispatchOutcome,
}

/// Client-side runtime bound to a SOCKS5 listener.
pub struct ClientRuntime {
    listener: TcpListener,
    cfg: ClientCfg,
}

impl ClientRuntime {
    /// Bind the configured SOCKS5 listener.
    pub async fn bind(cfg: ClientCfg) -> Result<Self, CoreError> {
        let listener = TcpListener::bind(cfg.socks_listen).await?;
        Ok(Self { listener, cfg })
    }

    /// Return the local SOCKS5 listener address.
    pub fn local_addr(&self) -> Result<SocketAddr, CoreError> {
        self.listener.local_addr().map_err(CoreError::from)
    }

    /// Accept one SOCKS request and open the selected outer transport with an injected opener.
    pub async fn accept_one_with_outer<Outer, Open, OpenFuture>(
        &self,
        open_outer: Open,
    ) -> Result<ClientSessionOutcome, CoreError>
    where
        Outer: AsyncRead + AsyncWrite + Unpin,
        Open: FnOnce(ClientConnectPlan) -> OpenFuture,
        OpenFuture: Future<Output = Result<Outer, CoreError>>,
    {
        let (mut socks, _) = self.listener.accept().await?;
        client_session_with_outer(&self.cfg, &mut socks, open_outer).await
    }

    /// Run the SOCKS listener until shutdown resolves.
    pub async fn run_until_shutdown<S>(&self, shutdown: S) -> Result<(), CoreError>
    where
        S: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => return Ok(()),
                accepted = self.accept_one_with_outer(|plan| async move {
                    open_outer_from_config(&self.cfg, &plan).await
                }) => {
                    accepted?;
                }
            }
        }
    }
}

/// Planned client outer connection for one SOCKS CONNECT target.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientConnectPlan {
    /// Requested target.
    pub target: TargetAddr,
    /// Configured Umbra server address.
    pub server: String,
    /// Selected outer transport.
    pub transport: TransportKind,
    /// Selected inner mode.
    pub mode: ClientInnerMode,
    /// SNI used for the outer connection.
    pub server_name: String,
}

/// Inner mode selected for one client session.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ClientInnerMode {
    /// Mux stream over the authenticated outer connection.
    Mux,
    /// Solo mode with Vision preface.
    VisionSolo,
}

/// Result of one accepted client-side SOCKS session.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientSessionOutcome {
    /// Target requested by the local SOCKS client.
    pub target: TargetAddr,
    /// Transport used for the outer connection.
    pub transport: TransportKind,
    /// Inner mode used for the stream.
    pub mode: ClientInnerMode,
}

/// Drive one SOCKS stream through selected outer connection and inner mode.
pub async fn client_session_with_outer<S, Outer, Open, OpenFuture>(
    cfg: &ClientCfg,
    socks: &mut S,
    open_outer: Open,
) -> Result<ClientSessionOutcome, CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Outer: AsyncRead + AsyncWrite + Unpin,
    Open: FnOnce(ClientConnectPlan) -> OpenFuture,
    OpenFuture: Future<Output = Result<Outer, CoreError>>,
{
    negotiate_no_auth(socks).await?;
    let SocksConnect { target } = match read_connect_request(socks).await {
        Ok(request) => request,
        Err(CoreError::Socks("unsupported SOCKS command")) => {
            write_unsupported_command_reply(socks).await?;
            return Err(CoreError::Socks("unsupported SOCKS command"));
        }
        Err(err) => return Err(err),
    };
    let mode = if cfg.mux {
        ClientInnerMode::Mux
    } else {
        ClientInnerMode::VisionSolo
    };
    let plan = ClientConnectPlan {
        target: target.clone(),
        server: cfg.server.clone(),
        transport: cfg.transport,
        mode,
        server_name: cfg.server_name.clone(),
    };
    let mut outer = open_outer(plan).await?;
    match mode {
        ClientInnerMode::Mux => {
            let mut mux = MuxSession::client(outer, &cfg.padding_scheme)?;
            let _stream = mux.open(&target).await?;
        }
        ClientInnerMode::VisionSolo => {
            send_solo_preface(&mut outer, &target).await?;
        }
    }
    write_success_reply(socks).await?;
    Ok(ClientSessionOutcome {
        target,
        transport: cfg.transport,
        mode,
    })
}

/// Open the configured TCP outer transport for a client plan.
pub async fn open_outer_from_config(
    cfg: &ClientCfg,
    plan: &ClientConnectPlan,
) -> Result<TcpStream, CoreError> {
    match plan.transport {
        TransportKind::Tcp => open_tcp_outer(cfg).await,
        TransportKind::Quic => Err(CoreError::InvalidConfig(
            "network QUIC outer transport requires QUIC runtime support",
        )),
    }
}

/// Run a server until Ctrl-C after probing the configured destination.
pub async fn run_server(cfg: RuntimeServerCfg) -> Result<(), CoreError> {
    let dest = cfg.dest.clone();
    let profile = umbra_reality::prebuild::probe_dest(&dest).await?;
    let runtime =
        ServerRuntime::bind_with_profile(cfg, profile, ProbeResistancePolicy::default()).await?;
    runtime.run_until_shutdown(shutdown_on_ctrl_c()).await
}

/// Run a client until Ctrl-C.
pub async fn run_client(cfg: ClientCfg) -> Result<(), CoreError> {
    let runtime = ClientRuntime::bind(cfg).await?;
    runtime.run_until_shutdown(shutdown_on_ctrl_c()).await
}

/// Run RealSite spider mode after a RealSite certificate classification.
pub async fn run_realsite_spider<IO>(io: IO, spider_path: &str) -> Result<(), CoreError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    spider(io, spider_path).await.map_err(CoreError::from)
}

async fn open_tcp_outer(cfg: &ClientCfg) -> Result<TcpStream, CoreError> {
    let profile = load_profile(&cfg.fingerprint)?;
    let keypair = x25519::generate_keypair();
    let shared = x25519::agree(&keypair.private, cfg.public_key.as_bytes())?;
    let mut random = [0_u8; 32];
    OsRng.fill_bytes(&mut random);

    let zero_hello = build_tcp_client_hello(tcp_hello_config(
        cfg,
        &keypair,
        [0_u8; 32],
        profile.clone(),
        random,
    ))?;
    let aad = hello0(&zero_hello)?;
    let session_id = try_seal_session_id(
        shared.expose_secret(),
        &cfg.short_id,
        &aad,
        current_unix_time()?,
    )?;
    let client_hello =
        build_tcp_client_hello(tcp_hello_config(cfg, &keypair, session_id, profile, random))?;
    let (stream, _report) =
        tcp_connect_and_send(&cfg.server, &client_hello, &cfg.tcp_evasion).await?;
    Ok(stream)
}

fn tcp_hello_config(
    cfg: &ClientCfg,
    keypair: &x25519::Keypair,
    session_id: [u8; 32],
    profile: umbra_fingerprint::FingerprintProfile,
    random: [u8; 32],
) -> TcpClientHelloConfig {
    TcpClientHelloConfig {
        sni: cfg.server_name.clone(),
        session_id,
        x25519_priv: *keypair.private.expose_secret(),
        x25519_pub: *keypair.public.as_bytes(),
        mlkem_key_exchange: vec![0x42; PLACEHOLDER_MLKEM_KEY_EXCHANGE_LEN],
        profile,
        random,
    }
}

fn current_unix_time() -> Result<u64, CoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoreError::InvalidConfig("system clock is before Unix epoch"))
        .map(|duration| duration.as_secs())
}

async fn shutdown_on_ctrl_c() {
    let _ = tokio::signal::ctrl_c().await;
}
