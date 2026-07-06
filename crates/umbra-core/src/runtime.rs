//! Server and client runtime orchestration.

use std::{
    future::Future,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use rand::{rngs::OsRng, RngCore};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
use umbra_crypto::{mlkem::mlkem_keygen, x25519};
use umbra_fingerprint::load_profile;
use umbra_inner::{
    mux::{MuxEvent, MuxSession, MuxStream},
    padding::PadScheme,
    spider::spider,
    vision::send_solo_preface,
};
use umbra_proto::addr::TargetAddr;
use umbra_reality::{
    auth::try_seal_session_id,
    cert::{classify_peer_certificate, PeerKind as RealityPeerKind},
    prebuild::DestProfile,
    replay::ReplayCache,
};
use umbra_tls::{
    clienthello::{hello0, ClientHelloParams, MlkemShare},
    handshake::{CertVerify, PeerKind as TlsPeerKind, Tls13Client},
};
use umbra_transport::{
    evasion::TcpEvasionPolicy,
    tcp::{build_tcp_client_hello, tcp_connect_and_send, TcpClientHelloConfig},
};

use crate::{
    config::{ClientCfg, ServerCfg as RuntimeServerCfg, TransportKind},
    dispatch::{
        classify_client_hello, read_client_hello_raw, write_fallback_prefix, DispatchContext,
        DispatchDecision, DispatchOutcome, HelloReadLimits,
    },
    probe::ProbeResistancePolicy,
    socks::{
        negotiate_no_auth, read_connect_request, write_success_reply,
        write_unsupported_command_reply, SocksConnect,
    },
    tls_io::{read_tls_record, spawn_tls_app_io, TlsAppEndpoint},
    CoreError,
};

const DEFAULT_REPLAY_CAPACITY: usize = 65_536;

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
        let outcome = dispatch_runtime_with_connector(
            stream,
            &self.dispatch_cfg,
            &self.profile,
            &self.replay,
            current_unix_time()?,
            connect_dest,
            self.probe_policy.timing,
            &self.padding_scheme,
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
    let outer = open_outer(plan).await?;
    match mode {
        ClientInnerMode::Mux => {
            let mut mux = MuxSession::client(outer, &cfg.padding_scheme)?;
            let stream = mux.open(&target).await?;
            write_success_reply(socks).await?;
            relay_mux_client_stream(socks, mux, stream).await?;
        }
        ClientInnerMode::VisionSolo => {
            let mut outer = outer;
            send_solo_preface(&mut outer, &target).await?;
            write_success_reply(socks).await?;
            tokio::io::copy_bidirectional(socks, &mut outer).await?;
        }
    }
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
) -> Result<tokio::io::DuplexStream, CoreError> {
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
    Box::pin(runtime.run_until_shutdown(shutdown_on_ctrl_c())).await
}

/// Run a client until Ctrl-C.
pub async fn run_client(cfg: ClientCfg) -> Result<(), CoreError> {
    let runtime = ClientRuntime::bind(cfg).await?;
    Box::pin(runtime.run_until_shutdown(shutdown_on_ctrl_c())).await
}

/// Run RealSite spider mode after a RealSite certificate classification.
pub async fn run_realsite_spider<IO>(io: IO, spider_path: &str) -> Result<(), CoreError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    spider(io, spider_path).await.map_err(CoreError::from)
}

async fn open_tcp_outer(cfg: &ClientCfg) -> Result<tokio::io::DuplexStream, CoreError> {
    let profile = load_profile(&cfg.fingerprint)?;
    let keypair = x25519::generate_keypair();
    let shared = x25519::agree(&keypair.private, cfg.public_key.as_bytes())?;
    let mut random = [0_u8; 32];
    OsRng.fill_bytes(&mut random);
    let mlkem_key_exchange = hybrid_mlkem_key_exchange(keypair.public.as_bytes());

    let zero_hello = build_tcp_client_hello(tcp_hello_config(
        cfg,
        &keypair,
        [0_u8; 32],
        profile.clone(),
        random,
        mlkem_key_exchange.clone(),
    ))?;
    let aad = hello0(&zero_hello)?;
    let session_id = try_seal_session_id(
        shared.expose_secret(),
        &cfg.short_id,
        &aad,
        current_unix_time()?,
    )?;
    let tls_params = tls_client_hello_params(
        cfg,
        &keypair,
        session_id,
        profile,
        random,
        mlkem_key_exchange,
    );
    let (mut tls_client, client_hello) = Tls13Client::start(tls_params)?;
    let (mut stream, _report) =
        tcp_connect_and_send(&cfg.server, &client_hello, &cfg.tcp_evasion).await?;
    let mut server_flight = read_required_tls_record(&mut stream).await?;
    server_flight.extend_from_slice(&read_required_tls_record(&mut stream).await?);
    let verifier = RealityCertVerifier {
        shared: *shared.expose_secret(),
        session_id,
        mldsa_verify: cfg.mldsa_verify.clone(),
    };
    let out = tls_client.drive(&server_flight, &verifier)?;
    stream.write_all(&out.outbound).await?;
    stream.flush().await?;
    match out.peer_kind {
        Some(TlsPeerKind::UmbraTrusted) => {
            Ok(spawn_tls_app_io(stream, TlsAppEndpoint::Client(tls_client)))
        }
        Some(TlsPeerKind::RealSite) => {
            let tls_io = spawn_tls_app_io(stream, TlsAppEndpoint::Client(tls_client));
            run_realsite_spider(tls_io, &cfg.spider_path).await?;
            Err(CoreError::InvalidConfig("peer is real site"))
        }
        Some(TlsPeerKind::Invalid) | None => Err(CoreError::InvalidConfig(
            "peer certificate was not Umbra trusted",
        )),
    }
}

fn tcp_hello_config(
    cfg: &ClientCfg,
    keypair: &x25519::Keypair,
    session_id: [u8; 32],
    profile: umbra_fingerprint::FingerprintProfile,
    random: [u8; 32],
    mlkem_key_exchange: Vec<u8>,
) -> TcpClientHelloConfig {
    TcpClientHelloConfig {
        sni: cfg.server_name.clone(),
        session_id,
        x25519_priv: *keypair.private.expose_secret(),
        x25519_pub: *keypair.public.as_bytes(),
        mlkem_key_exchange,
        profile,
        random,
    }
}

fn tls_client_hello_params(
    cfg: &ClientCfg,
    keypair: &x25519::Keypair,
    session_id: [u8; 32],
    profile: umbra_fingerprint::FingerprintProfile,
    random: [u8; 32],
    mlkem_key_exchange: Vec<u8>,
) -> ClientHelloParams {
    ClientHelloParams {
        sni: cfg.server_name.clone(),
        session_id,
        x25519_priv: *keypair.private.expose_secret(),
        x25519_pub: *keypair.public.as_bytes(),
        mlkem: MlkemShare::x25519_mlkem768(mlkem_key_exchange),
        profile,
        random,
    }
}

fn hybrid_mlkem_key_exchange(x25519_public: &[u8; 32]) -> Vec<u8> {
    let mlkem = mlkem_keygen();
    let mut key_exchange = Vec::with_capacity(x25519_public.len() + mlkem.encapsulation_key.len());
    key_exchange.extend_from_slice(x25519_public);
    key_exchange.extend_from_slice(&mlkem.encapsulation_key);
    key_exchange
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

struct RealityCertVerifier {
    shared: [u8; 32],
    session_id: [u8; 32],
    mldsa_verify: Vec<u8>,
}

impl CertVerify for RealityCertVerifier {
    fn verify(&self, leaf_der: &[u8], _chain: &[Vec<u8>]) -> TlsPeerKind {
        match classify_peer_certificate(
            leaf_der,
            &self.shared,
            &self.session_id,
            &self.mldsa_verify,
            true,
        ) {
            RealityPeerKind::UmbraTrusted => TlsPeerKind::UmbraTrusted,
            RealityPeerKind::RealSite => TlsPeerKind::RealSite,
            RealityPeerKind::Invalid => TlsPeerKind::Invalid,
        }
    }
}

async fn dispatch_runtime_with_connector<C, D, Connect, ConnectFuture>(
    mut conn: C,
    cfg: &crate::dispatch::ServerCfg,
    profile: &DestProfile,
    replay: &ReplayCache,
    now_unix: u64,
    connect_dest_or_target: Connect,
    timing: crate::probe::TimingAlignment,
    padding_scheme: &PadScheme,
) -> Result<DispatchOutcome, CoreError>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    D: AsyncRead + AsyncWrite + Unpin,
    Connect: FnOnce(String) -> ConnectFuture,
    ConnectFuture: Future<Output = Result<D, std::io::Error>>,
{
    let started_at = tokio::time::Instant::now();
    let chello_raw = read_client_hello_raw(&mut conn, cfg.hello_limits).await?;
    match classify_client_hello(
        chello_raw,
        DispatchContext {
            cfg,
            profile,
            replay,
            now_unix,
        },
    )? {
        DispatchDecision::Authenticated(mut authenticated) => {
            timing.wait_started_at(started_at, profile).await;
            conn.write_all(&authenticated.server_flight).await?;
            conn.flush().await?;
            let client_finished = read_required_tls_record(&mut conn).await?;
            authenticated.tls_server.drive(&client_finished)?;
            let tls_io = spawn_tls_app_io(conn, TlsAppEndpoint::Server(authenticated.tls_server));
            let server_flight_len = authenticated.server_flight.len();
            relay_one_server_inner_stream(tls_io, connect_dest_or_target, padding_scheme).await?;
            Ok(DispatchOutcome::Authenticated {
                sni: authenticated.sni,
                server_flight_len,
            })
        }
        DispatchDecision::Fallback { reason, chello_raw } => {
            let mut dest = connect_dest_or_target(cfg.dest.clone()).await?;
            write_fallback_prefix(&mut dest, &chello_raw).await?;
            let (client_to_dest, dest_to_client) =
                tokio::io::copy_bidirectional(&mut conn, &mut dest).await?;
            Ok(DispatchOutcome::Forwarded {
                reason,
                client_to_dest,
                dest_to_client,
            })
        }
    }
}

async fn relay_one_server_inner_stream<D, Connect, ConnectFuture>(
    tls_io: tokio::io::DuplexStream,
    connect_target: Connect,
    padding_scheme: &PadScheme,
) -> Result<(), CoreError>
where
    D: AsyncRead + AsyncWrite + Unpin,
    Connect: FnOnce(String) -> ConnectFuture,
    ConnectFuture: Future<Output = Result<D, std::io::Error>>,
{
    let mut mux = MuxSession::server(tls_io, padding_scheme)?;
    let (stream, target) = mux.accept().await?;
    let mut target_io = connect_target(target_to_host_port(&target)).await?;
    Box::pin(relay_mux_server_stream(&mut target_io, mux, stream)).await
}

async fn relay_mux_client_stream<S, IO>(
    socks: &mut S,
    mut mux: MuxSession<IO>,
    mut stream: MuxStream,
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut socks_open = true;
    let mut peer_open = true;
    let mut buf = [0_u8; 16 * 1024];
    while socks_open || peer_open {
        tokio::select! {
            read = socks.read(&mut buf), if socks_open => {
                let read = read?;
                if read == 0 {
                    socks_open = false;
                    finish_stream_best_effort(&mut mux, stream.stream_id).await?;
                } else {
                    mux.send_data_wait_window(&mut stream, &buf[..read]).await?;
                }
            }
            event = mux.receive_next(), if peer_open => {
                match event? {
                    MuxEvent::Data { stream_id, payload } if stream_id == stream.stream_id => {
                        socks.write_all(&payload).await?;
                        let increment = u32::try_from(payload.len())
                            .map_err(|_| CoreError::InvalidConfig("mux payload too large"))?;
                        send_window_update_best_effort(&mut mux, stream_id, increment).await?;
                    }
                    MuxEvent::Fin { stream_id } if stream_id == stream.stream_id => {
                        peer_open = false;
                        socks.shutdown().await?;
                    }
                    MuxEvent::Rst { stream_id } if stream_id == stream.stream_id => {
                        return Err(CoreError::InvalidConfig("mux stream reset"));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

async fn relay_mux_server_stream<T, IO>(
    target: &mut T,
    mut mux: MuxSession<IO>,
    mut stream: MuxStream,
) -> Result<(), CoreError>
where
    T: AsyncRead + AsyncWrite + Unpin,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut target_open = true;
    let mut peer_open = true;
    let mut buf = [0_u8; 16 * 1024];
    while target_open || peer_open {
        tokio::select! {
            read = target.read(&mut buf), if target_open => {
                let read = read?;
                if read == 0 {
                    target_open = false;
                    finish_stream_best_effort(&mut mux, stream.stream_id).await?;
                } else {
                    mux.send_data_wait_window(&mut stream, &buf[..read]).await?;
                }
            }
            event = mux.receive_next(), if peer_open => {
                match event? {
                    MuxEvent::Data { stream_id, payload } if stream_id == stream.stream_id => {
                        target.write_all(&payload).await?;
                        let increment = u32::try_from(payload.len())
                            .map_err(|_| CoreError::InvalidConfig("mux payload too large"))?;
                        send_window_update_best_effort(&mut mux, stream_id, increment).await?;
                    }
                    MuxEvent::Fin { stream_id } if stream_id == stream.stream_id => {
                        peer_open = false;
                        target.shutdown().await?;
                    }
                    MuxEvent::Rst { stream_id } if stream_id == stream.stream_id => {
                        return Err(CoreError::InvalidConfig("mux stream reset"));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

async fn read_required_tls_record<R>(reader: &mut R) -> Result<Vec<u8>, CoreError>
where
    R: AsyncRead + Unpin,
{
    read_tls_record(reader)
        .await?
        .ok_or(CoreError::InvalidClientHello("unexpected TLS EOF"))
}

fn target_to_host_port(target: &TargetAddr) -> String {
    match target {
        TargetAddr::Ipv4(addr, port) => format!("{addr}:{port}"),
        TargetAddr::Domain(domain, port) => format!("{domain}:{port}"),
        TargetAddr::Ipv6(addr, port) => format!("[{addr}]:{port}"),
    }
}

async fn finish_stream_best_effort<IO>(
    mux: &mut MuxSession<IO>,
    stream_id: u32,
) -> Result<(), CoreError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    match mux.finish_stream(stream_id).await {
        Ok(()) => Ok(()),
        Err(umbra_inner::InnerError::Io(err)) if err.kind() == std::io::ErrorKind::BrokenPipe => {
            Ok(())
        }
        Err(err) => Err(CoreError::from(err)),
    }
}

async fn send_window_update_best_effort<IO>(
    mux: &mut MuxSession<IO>,
    stream_id: u32,
    increment: u32,
) -> Result<(), CoreError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    match mux.send_window_update(stream_id, increment).await {
        Ok(()) => Ok(()),
        Err(umbra_inner::InnerError::Io(err)) if err.kind() == std::io::ErrorKind::BrokenPipe => {
            Ok(())
        }
        Err(err) => Err(CoreError::from(err)),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use tokio::io::AsyncWriteExt;

    use super::*;

    #[test]
    fn scenario_target_to_host_port_formats_all_address_kinds() {
        assert_eq!(
            target_to_host_port(&TargetAddr::Ipv4(Ipv4Addr::new(192, 0, 2, 1), 443)),
            "192.0.2.1:443"
        );
        assert_eq!(
            target_to_host_port(&TargetAddr::domain("example.com", 8443).expect("domain")),
            "example.com:8443"
        );
        assert_eq!(
            target_to_host_port(&TargetAddr::Ipv6(Ipv6Addr::LOCALHOST, 443)),
            "[::1]:443"
        );
    }

    #[tokio::test]
    async fn scenario_required_tls_record_rejects_eof() {
        let (writer, mut reader) = tokio::io::duplex(32);
        drop(writer);

        assert!(matches!(
            read_required_tls_record(&mut reader).await,
            Err(CoreError::InvalidClientHello("unexpected TLS EOF"))
        ));
    }

    #[tokio::test]
    async fn scenario_mux_close_ack_helpers_ignore_broken_pipe() {
        let (client, server) = tokio::io::duplex(64);
        drop(server);
        let pad = PadScheme::none();
        let mut mux = MuxSession::client(client, &pad).expect("mux creates");

        finish_stream_best_effort(&mut mux, 1)
            .await
            .expect("broken pipe during FIN is ignored");
        send_window_update_best_effort(&mut mux, 1, 1)
            .await
            .expect("broken pipe during WINDOW_UPDATE is ignored");
    }

    #[tokio::test]
    async fn scenario_required_tls_record_reads_complete_record() {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        writer
            .write_all(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x42])
            .await
            .expect("write record");

        assert_eq!(
            read_required_tls_record(&mut reader)
                .await
                .expect("record reads"),
            [0x17, 0x03, 0x03, 0x00, 0x01, 0x42]
        );
    }
}
