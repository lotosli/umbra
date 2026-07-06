//! Server and client runtime orchestration.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rand::{rngs::OsRng, RngCore};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
use umbra_crypto::{mlkem::mlkem_keygen, secret::SecretBytes, x25519};
use umbra_fingerprint::load_profile;
use umbra_inner::{
    mux::{MuxEvent, MuxSession, MuxStream},
    padding::PadScheme,
    spider::spider,
    vision::{read_solo_preface, send_solo_preface, vision_relay},
};
use umbra_proto::{addr::TargetAddr, consts::MUX_VERSION, frame::MuxCommand};
use umbra_reality::{
    auth::try_seal_session_id,
    cert::{classify_peer_certificate, PeerKind as RealityPeerKind},
    prebuild::DestProfile,
    replay::ReplayCache,
};
use umbra_tls::{
    clienthello::{
        build_client_hello_handshake, hello0, quic_hello0, ClientHelloParams,
        ClientQuicTransportParameter, MlkemShare, EXT_QUIC_TRANSPORT_PARAMETERS,
    },
    handshake::{CertVerify, PeerKind as TlsPeerKind, Tls13Client},
};
use umbra_transport::{
    evasion::TcpEvasionPolicy,
    quic::{
        build_quic_initial_crypto_packet, decrypt_quic_initial_crypto_frames,
        parse_quic_initial_header, read_target_stream, write_target_stream, QuicCryptoFrame,
    },
    tcp::{build_tcp_client_hello, tcp_connect_and_send, TcpClientHelloConfig},
};

use crate::{
    config::{ClientCfg, ServerCfg as RuntimeServerCfg, TransportKind},
    dispatch::{
        classify_client_hello, classify_quic_client_hello, read_client_hello_raw,
        write_fallback_prefix, DispatchContext, DispatchDecision, DispatchOutcome, FallbackReason,
        HelloReadLimits, QuicDispatchDecision,
    },
    prefixed::PrefixedStream,
    probe::ProbeResistancePolicy,
    quic_crypto,
    socks::{
        negotiate_no_auth, read_connect_request, write_success_reply,
        write_unsupported_command_reply, SocksConnect,
    },
    tls_io::{read_tls_record, spawn_tls_app_io, TlsAppEndpoint},
    CoreError,
};

const DEFAULT_REPLAY_CAPACITY: usize = 65_536;
const DEFAULT_QUIC_FALLBACK_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const QUIC_PREFETCH_MAX_DATAGRAMS: usize = 16;
const QUIC_PREFETCH_MAX_CRYPTO_BYTES: usize = 64 * 1024;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_PADDING: u16 = 0x0015;
const MUX_OPENING_PREFIX_LEN: usize = 7;

/// Bound server runtime with listeners, replay cache, and active destination profile.
pub struct ServerRuntime {
    tcp_listener: TcpListener,
    udp_socket: Option<QuicServerSocket>,
    dispatch_cfg: crate::dispatch::ServerCfg,
    profile: DestProfile,
    replay: ReplayCache,
    probe_policy: ProbeResistancePolicy,
    padding_scheme: PadScheme,
    tcp_evasion: TcpEvasionPolicy,
    prebuild: bool,
}

struct QuicServerSocket {
    dispatch: Arc<UdpSocket>,
    endpoint: StdUdpSocket,
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
            Some(addr) => {
                let std_socket = StdUdpSocket::bind(addr)?;
                std_socket.set_nonblocking(true)?;
                let endpoint = std_socket.try_clone()?;
                let dispatch = Arc::new(UdpSocket::from_std(std_socket)?);
                Some(QuicServerSocket { dispatch, endpoint })
            }
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
            .map(|socket| socket.dispatch.local_addr())
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

    /// Accept one UDP datagram and dispatch it as a QUIC Initial.
    pub async fn accept_one_quic_with_idle_timeout(
        &self,
        idle_timeout: Duration,
    ) -> Result<AcceptedQuicSession, CoreError> {
        let socket = self
            .udp_socket
            .as_ref()
            .ok_or(CoreError::InvalidConfig("UDP listener is not configured"))?;
        let mut buf = vec![0_u8; 65_535];
        let (read, peer) = socket.dispatch.recv_from(&mut buf).await?;
        let datagram = buf[..read].to_vec();
        let outcome = dispatch_quic_runtime(
            datagram,
            QuicRuntimeDispatch {
                client_socket: &socket.dispatch,
                endpoint_socket: socket.endpoint.try_clone()?,
                client_peer: peer,
                cfg: &self.dispatch_cfg,
                profile: &self.profile,
                replay: &self.replay,
                now_unix: current_unix_time()?,
                timing: self.probe_policy.timing,
                idle_timeout,
            },
        )
        .await?;
        Ok(AcceptedQuicSession { peer, outcome })
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
                accepted = self.accept_one_quic_with_idle_timeout(DEFAULT_QUIC_FALLBACK_IDLE_TIMEOUT), if self.udp_socket.is_some() => {
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

/// One accepted server-side QUIC result.
#[derive(Debug)]
pub struct AcceptedQuicSession {
    /// UDP peer address.
    pub peer: SocketAddr,
    /// QUIC dispatch result.
    pub outcome: QuicRuntimeOutcome,
}

/// Observable result of server-side QUIC dispatch.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum QuicRuntimeOutcome {
    /// The local Umbra QUIC path accepted the Initial.
    Authenticated {
        /// Accepted SNI.
        sni: String,
        /// Recovered raw ClientHello length.
        client_hello_len: usize,
    },
    /// The datagram flow was relayed to the configured destination QUIC service.
    Forwarded {
        /// Why the local path was rejected.
        reason: FallbackReason,
        /// Bytes forwarded from client to destination.
        client_to_dest: u64,
        /// Bytes forwarded from destination to client.
        dest_to_client: u64,
    },
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
                accepted = self.accept_one_from_config() => {
                    accepted?;
                }
            }
        }
    }

    /// Accept one SOCKS request and open the configured outer transport.
    pub async fn accept_one_from_config(&self) -> Result<ClientSessionOutcome, CoreError> {
        let (mut socks, _) = self.listener.accept().await?;
        Box::pin(client_session_from_config(&self.cfg, &mut socks)).await
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
    /// Direct QUIC bidirectional stream carrying the target prefix.
    QuicStream,
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

/// Client-side QUIC first flight built from runtime configuration.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QuicClientInitial {
    /// Protected UDP datagram containing the QUIC Initial packet.
    pub datagram: Vec<u8>,
    /// Raw ClientHello handshake bytes carried in the CRYPTO frame.
    pub client_hello: Vec<u8>,
    /// Client-chosen destination connection id used for Initial keys.
    pub dcid: Vec<u8>,
    /// Client source connection id.
    pub scid: Vec<u8>,
    /// REALITY token placed in the QUIC GREASE transport parameter.
    pub auth_token: [u8; 32],
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
    let mode = selected_client_inner_mode(cfg);
    let plan = ClientConnectPlan {
        target: target.clone(),
        server: cfg.server.clone(),
        transport: cfg.transport,
        mode,
        server_name: cfg.server_name.clone(),
    };
    let outer = open_outer(plan).await?;
    client_stream_over_outer(cfg, socks, &target, mode, outer).await?;
    Ok(ClientSessionOutcome {
        target,
        transport: cfg.transport,
        mode,
    })
}

/// Drive one SOCKS stream through the outer transport configured in `ClientCfg`.
pub async fn client_session_from_config<S>(
    cfg: &ClientCfg,
    socks: &mut S,
) -> Result<ClientSessionOutcome, CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
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
    let mode = selected_client_inner_mode(cfg);
    match cfg.transport {
        TransportKind::Tcp => {
            let plan = ClientConnectPlan {
                target: target.clone(),
                server: cfg.server.clone(),
                transport: cfg.transport,
                mode,
                server_name: cfg.server_name.clone(),
            };
            let outer = open_outer_from_config(cfg, &plan).await?;
            Box::pin(client_stream_over_outer(cfg, socks, &target, mode, outer)).await?;
        }
        TransportKind::Quic => {
            client_quic_stream_session(cfg, socks, &target).await?;
        }
    }
    Ok(ClientSessionOutcome {
        target,
        transport: cfg.transport,
        mode,
    })
}

async fn client_stream_over_outer<S, Outer>(
    cfg: &ClientCfg,
    socks: &mut S,
    target: &TargetAddr,
    mode: ClientInnerMode,
    outer: Outer,
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Outer: AsyncRead + AsyncWrite + Unpin,
{
    match mode {
        ClientInnerMode::Mux => {
            let mut mux = MuxSession::client(outer, &cfg.padding_scheme)?;
            let stream = mux.open(target).await?;
            write_success_reply(socks).await?;
            relay_mux_client_stream(socks, mux, stream).await?;
        }
        ClientInnerMode::VisionSolo => {
            let mut outer = outer;
            send_solo_preface(&mut outer, target).await?;
            write_success_reply(socks).await?;
            tokio::io::copy_bidirectional(socks, &mut outer).await?;
        }
        ClientInnerMode::QuicStream => {
            return Err(CoreError::InvalidConfig(
                "QUIC stream mode requires QUIC runtime",
            ));
        }
    }
    Ok(())
}

/// Open the configured TCP outer transport for a client plan.
pub async fn open_outer_from_config(
    cfg: &ClientCfg,
    plan: &ClientConnectPlan,
) -> Result<tokio::io::DuplexStream, CoreError> {
    match plan.transport {
        TransportKind::Tcp => open_tcp_outer(cfg).await,
        TransportKind::Quic => Err(CoreError::InvalidConfig(
            "QUIC direct stream is not a byte-stream outer",
        )),
    }
}

fn selected_client_inner_mode(cfg: &ClientCfg) -> ClientInnerMode {
    if cfg.transport == TransportKind::Quic {
        ClientInnerMode::QuicStream
    } else if cfg.mux {
        ClientInnerMode::Mux
    } else {
        ClientInnerMode::VisionSolo
    }
}

async fn client_quic_stream_session<S>(
    cfg: &ClientCfg,
    socks: &mut S,
    target: &TargetAddr,
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let server_addr = resolve_server_addr(&cfg.server).await?;
    let bind_addr: SocketAddr = if server_addr.is_ipv6() {
        "[::]:0"
            .parse()
            .map_err(|_| CoreError::InvalidConfig("invalid QUIC IPv6 bind address"))?
    } else {
        "0.0.0.0:0"
            .parse()
            .map_err(|_| CoreError::InvalidConfig("invalid QUIC IPv4 bind address"))?
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr).map_err(quic_error)?;
    endpoint.set_default_client_config(quic_crypto::client_config(cfg)?);
    let connection = endpoint
        .connect(server_addr, &cfg.server_name)
        .map_err(quic_error)?
        .await
        .map_err(quic_error)?;
    let (mut send, mut recv) = connection.open_bi().await.map_err(quic_error)?;
    write_target_stream(&mut send, target, &[]).await?;
    write_success_reply(socks).await?;
    let (mut socks_read, mut socks_write) = tokio::io::split(socks);
    let client_to_server = async {
        tokio::io::copy(&mut socks_read, &mut send).await?;
        send.shutdown().await
    };
    let server_to_client = async {
        tokio::io::copy(&mut recv, &mut socks_write).await?;
        socks_write.shutdown().await
    };
    let _ = tokio::try_join!(client_to_server, server_to_client)?;
    connection.close(0_u32.into(), b"");
    endpoint.close(0_u32.into(), b"");
    Ok(())
}

async fn resolve_server_addr(server: &str) -> Result<SocketAddr, CoreError> {
    tokio::net::lookup_host(server)
        .await?
        .next()
        .ok_or(CoreError::InvalidConfig(
            "QUIC server address did not resolve",
        ))
}

fn quic_error(err: impl std::fmt::Display) -> CoreError {
    CoreError::Quic(err.to_string())
}

/// Build the configured QUIC first flight without starting stream relay.
///
/// This is the client-side half of component G up to the protected Initial
/// datagram. Full QUIC stream relay still requires the QUIC-TLS stream engine.
pub fn build_quic_client_initial(cfg: &ClientCfg) -> Result<QuicClientInitial, CoreError> {
    let profile = load_profile(&cfg.fingerprint)?;
    let cid_len = validate_quic_cid_len(profile.quic.scid_len)?;
    let keypair = x25519::generate_keypair();
    let mut random = [0_u8; 32];
    OsRng.fill_bytes(&mut random);
    let mut dcid = vec![0_u8; cid_len];
    OsRng.fill_bytes(&mut dcid);
    let mut scid = vec![0_u8; cid_len];
    OsRng.fill_bytes(&mut scid);
    build_quic_client_initial_with_material(
        cfg,
        QuicInitialMaterial {
            profile,
            keypair,
            random,
            dcid,
            scid,
            now_unix: current_unix_time()?,
        },
    )
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
    let mlkem = hybrid_mlkem_key_exchange(keypair.public.as_bytes());

    let zero_hello = build_tcp_client_hello(tcp_hello_config(
        cfg,
        &keypair,
        [0_u8; 32],
        profile.clone(),
        random,
        mlkem.key_exchange.clone(),
    ))?;
    let aad = hello0(&zero_hello)?;
    let session_id = try_seal_session_id(
        shared.expose_secret(),
        &cfg.short_id,
        &aad,
        current_unix_time()?,
    )?;
    let tls_params = tls_client_hello_params(cfg, &keypair, session_id, profile, random, mlkem);
    let (mut tls_client, client_hello) = Tls13Client::start(tls_params)?;
    let (mut stream, _report) =
        tcp_connect_and_send(&cfg.server, &client_hello, &cfg.tcp_evasion).await?;
    stream
        .write_all(&Tls13Client::dummy_change_cipher_spec())
        .await?;
    stream.flush().await?;
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
    mlkem: HybridMlkemMaterial,
) -> ClientHelloParams {
    ClientHelloParams {
        sni: cfg.server_name.clone(),
        session_id: session_id.to_vec(),
        x25519_priv: *keypair.private.expose_secret(),
        x25519_pub: *keypair.public.as_bytes(),
        mlkem: MlkemShare::x25519_mlkem768_with_decapsulation_key(
            mlkem.key_exchange,
            mlkem.decapsulation_key,
        ),
        profile,
        random,
        quic_transport_parameters: Vec::new(),
    }
}

struct QuicInitialMaterial {
    profile: umbra_fingerprint::FingerprintProfile,
    keypair: x25519::Keypair,
    random: [u8; 32],
    dcid: Vec<u8>,
    scid: Vec<u8>,
    now_unix: u64,
}

fn build_quic_client_initial_with_material(
    cfg: &ClientCfg,
    material: QuicInitialMaterial,
) -> Result<QuicClientInitial, CoreError> {
    let QuicInitialMaterial {
        profile,
        keypair,
        random,
        dcid,
        scid,
        now_unix,
    } = material;
    let (profile, grease_parameter) = quic_client_profile(profile)?;
    let mlkem = hybrid_mlkem_key_exchange(keypair.public.as_bytes());
    let shared = x25519::agree(&keypair.private, cfg.public_key.as_bytes())?;
    let zero_hello = build_client_hello_handshake(&quic_client_hello_params(
        cfg,
        &keypair,
        [0_u8; 32],
        profile.clone(),
        random,
        MlkemShare::x25519_mlkem768(mlkem.key_exchange.clone()),
        grease_parameter,
    ))?;
    let aad = quic_hello0(&zero_hello, grease_parameter)?;
    let auth_token = try_seal_session_id(shared.expose_secret(), &cfg.short_id, &aad, now_unix)?;
    let client_hello = build_client_hello_handshake(&quic_client_hello_params(
        cfg,
        &keypair,
        auth_token,
        profile,
        random,
        MlkemShare::x25519_mlkem768_with_decapsulation_key(
            mlkem.key_exchange,
            mlkem.decapsulation_key,
        ),
        grease_parameter,
    ))?;
    let datagram = build_quic_initial_crypto_packet(&client_hello, &dcid, &scid, &[])?;
    Ok(QuicClientInitial {
        datagram,
        client_hello,
        dcid,
        scid,
        auth_token,
    })
}

fn quic_client_hello_params(
    cfg: &ClientCfg,
    keypair: &x25519::Keypair,
    auth_token: [u8; 32],
    profile: umbra_fingerprint::FingerprintProfile,
    random: [u8; 32],
    mlkem: MlkemShare,
    grease_parameter: u64,
) -> ClientHelloParams {
    ClientHelloParams {
        sni: cfg.server_name.clone(),
        session_id: Vec::new(),
        x25519_priv: *keypair.private.expose_secret(),
        x25519_pub: *keypair.public.as_bytes(),
        mlkem,
        profile,
        random,
        quic_transport_parameters: vec![ClientQuicTransportParameter {
            id: grease_parameter,
            value: auth_token.to_vec(),
        }],
    }
}

fn quic_client_profile(
    mut profile: umbra_fingerprint::FingerprintProfile,
) -> Result<(umbra_fingerprint::FingerprintProfile, u64), CoreError> {
    if profile.quic.alpn != "h3" {
        return Err(CoreError::InvalidConfig("QUIC ALPN must be h3"));
    }
    validate_quic_cid_len(profile.quic.scid_len)?;
    let grease_parameter = profile.quic.grease_parameter;
    profile.alpn = vec![profile.quic.alpn.clone()];
    if !profile
        .extension_order
        .contains(&EXT_QUIC_TRANSPORT_PARAMETERS)
    {
        let insert_at = profile
            .extension_order
            .iter()
            .position(|ext| *ext == EXT_PADDING)
            .unwrap_or(profile.extension_order.len());
        profile
            .extension_order
            .insert(insert_at, EXT_QUIC_TRANSPORT_PARAMETERS);
    }
    Ok((profile, grease_parameter))
}

fn validate_quic_cid_len(len: usize) -> Result<usize, CoreError> {
    if !(8..=20).contains(&len) {
        return Err(CoreError::InvalidConfig(
            "QUIC connection id length must be between 8 and 20 bytes",
        ));
    }
    Ok(len)
}

struct HybridMlkemMaterial {
    key_exchange: Vec<u8>,
    decapsulation_key: SecretBytes,
}

fn hybrid_mlkem_key_exchange(x25519_public: &[u8; 32]) -> HybridMlkemMaterial {
    let mlkem = mlkem_keygen();
    let mut key_exchange = Vec::with_capacity(x25519_public.len() + mlkem.encapsulation_key.len());
    key_exchange.extend_from_slice(x25519_public);
    key_exchange.extend_from_slice(&mlkem.encapsulation_key);
    HybridMlkemMaterial {
        key_exchange,
        decapsulation_key: mlkem.decapsulation_key,
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
            let client_finished = read_required_non_ccs_tls_record(&mut conn).await?;
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

struct QuicRuntimeDispatch<'a> {
    client_socket: &'a UdpSocket,
    endpoint_socket: StdUdpSocket,
    client_peer: SocketAddr,
    cfg: &'a crate::dispatch::ServerCfg,
    profile: &'a DestProfile,
    replay: &'a ReplayCache,
    now_unix: u64,
    timing: crate::probe::TimingAlignment,
    idle_timeout: Duration,
}

struct QuicPrefetchedClientHello {
    datagrams: Vec<Vec<u8>>,
    client_hello: Vec<u8>,
    scid: Vec<u8>,
    dcid_len: usize,
}

enum QuicPrefetchOutcome {
    Complete(QuicPrefetchedClientHello),
    Fallback {
        reason: FallbackReason,
        datagrams: Vec<Vec<u8>>,
    },
}

async fn dispatch_quic_runtime(
    datagram: Vec<u8>,
    ctx: QuicRuntimeDispatch<'_>,
) -> Result<QuicRuntimeOutcome, CoreError> {
    let started_at = tokio::time::Instant::now();
    let prefetched = prefetch_quic_client_hello(
        datagram,
        ctx.client_socket,
        ctx.client_peer,
        ctx.idle_timeout,
    )
    .await?;
    let prefetched = match prefetched {
        QuicPrefetchOutcome::Complete(prefetched) => prefetched,
        QuicPrefetchOutcome::Fallback { reason, datagrams } => {
            let (client_to_dest, dest_to_client) = relay_quic_fallback_until_idle(
                ctx.client_socket,
                ctx.client_peer,
                datagrams,
                &ctx.cfg.dest,
                ctx.idle_timeout,
            )
            .await?;
            return Ok(QuicRuntimeOutcome::Forwarded {
                reason,
                client_to_dest,
                dest_to_client,
            });
        }
    };
    let first_datagram = prefetched
        .datagrams
        .first()
        .cloned()
        .ok_or(CoreError::InvalidConfig(
            "QUIC prefetch did not retain initial datagram",
        ))?;
    match classify_quic_client_hello(
        first_datagram,
        prefetched.client_hello,
        &prefetched.scid,
        DispatchContext {
            cfg: ctx.cfg,
            profile: ctx.profile,
            replay: ctx.replay,
            now_unix: ctx.now_unix,
        },
    )? {
        QuicDispatchDecision::Authenticated(authenticated) => {
            ctx.timing.wait_started_at(started_at, ctx.profile).await;
            let client_hello_len = authenticated.client_hello.len();
            let sni = authenticated.sni.clone();
            run_authenticated_quic_stream(
                ctx.endpoint_socket,
                ctx.client_peer,
                prefetched.datagrams,
                prefetched.dcid_len,
                ctx.idle_timeout,
                AuthenticatedQuicRuntime {
                    sni: authenticated.sni,
                    session_id: authenticated.session_id,
                    shared_secret: authenticated.shared_secret.into_inner(),
                    client_hello: authenticated.client_hello,
                    profile: ctx.profile.clone(),
                    mldsa_seed: *ctx.cfg.mldsa_seed.expose_secret(),
                },
            )
            .await?;
            Ok(QuicRuntimeOutcome::Authenticated {
                sni,
                client_hello_len,
            })
        }
        QuicDispatchDecision::Fallback { reason, datagram } => {
            let datagrams = if prefetched.datagrams.is_empty() {
                vec![datagram]
            } else {
                prefetched.datagrams
            };
            let (client_to_dest, dest_to_client) = relay_quic_fallback_until_idle(
                ctx.client_socket,
                ctx.client_peer,
                datagrams,
                &ctx.cfg.dest,
                ctx.idle_timeout,
            )
            .await?;
            Ok(QuicRuntimeOutcome::Forwarded {
                reason,
                client_to_dest,
                dest_to_client,
            })
        }
    }
}

async fn prefetch_quic_client_hello(
    first_datagram: Vec<u8>,
    client_socket: &UdpSocket,
    client_peer: SocketAddr,
    idle_timeout: Duration,
) -> Result<QuicPrefetchOutcome, CoreError> {
    let Ok(header) = parse_quic_initial_header(&first_datagram) else {
        return Ok(QuicPrefetchOutcome::Fallback {
            reason: FallbackReason::MalformedClientHello,
            datagrams: vec![first_datagram],
        });
    };
    let mut datagrams = vec![first_datagram];
    let scid = header.scid;
    let dcid_len = header.dcid.len();
    let mut frames = BTreeMap::new();
    if collect_quic_crypto_datagram(&mut frames, &datagrams[0]).is_err() {
        return Ok(QuicPrefetchOutcome::Fallback {
            reason: FallbackReason::MalformedClientHello,
            datagrams,
        });
    }
    if let Some(client_hello) = complete_prefetched_quic_client_hello(&frames)? {
        return Ok(QuicPrefetchOutcome::Complete(QuicPrefetchedClientHello {
            datagrams,
            client_hello,
            scid,
            dcid_len,
        }));
    }

    let mut buf = vec![0_u8; 65_535];
    while datagrams.len() < QUIC_PREFETCH_MAX_DATAGRAMS {
        let received = tokio::time::timeout(idle_timeout, client_socket.recv_from(&mut buf)).await;
        let Ok(received) = received else {
            return Ok(QuicPrefetchOutcome::Fallback {
                reason: FallbackReason::MalformedClientHello,
                datagrams,
            });
        };
        let (read, peer) = received?;
        if peer != client_peer {
            continue;
        }
        datagrams.push(buf[..read].to_vec());
        let last = datagrams
            .last()
            .ok_or(CoreError::InvalidConfig("QUIC datagram prefetch failed"))?;
        if collect_quic_crypto_datagram(&mut frames, last).is_err() {
            return Ok(QuicPrefetchOutcome::Fallback {
                reason: FallbackReason::MalformedClientHello,
                datagrams,
            });
        }
        if let Some(client_hello) = complete_prefetched_quic_client_hello(&frames)? {
            return Ok(QuicPrefetchOutcome::Complete(QuicPrefetchedClientHello {
                datagrams,
                client_hello,
                scid,
                dcid_len,
            }));
        }
    }

    Ok(QuicPrefetchOutcome::Fallback {
        reason: FallbackReason::MalformedClientHello,
        datagrams,
    })
}

fn collect_quic_crypto_datagram(
    frames: &mut BTreeMap<usize, Vec<u8>>,
    datagram: &[u8],
) -> Result<(), CoreError> {
    let chunks = decrypt_quic_initial_crypto_frames(datagram)
        .map_err(|_| CoreError::InvalidClientHello("invalid QUIC Initial CRYPTO"))?;
    for chunk in chunks {
        insert_quic_crypto_frame(frames, chunk)?;
    }
    Ok(())
}

fn insert_quic_crypto_frame(
    frames: &mut BTreeMap<usize, Vec<u8>>,
    frame: QuicCryptoFrame,
) -> Result<(), CoreError> {
    let frame_end = frame
        .offset
        .checked_add(frame.bytes.len())
        .ok_or(CoreError::ClientHelloTooLarge)?;
    if frame_end > QUIC_PREFETCH_MAX_CRYPTO_BYTES {
        return Err(CoreError::ClientHelloTooLarge);
    }
    if let Some(existing) = frames.get(&frame.offset) {
        if existing != &frame.bytes {
            return Err(CoreError::InvalidClientHello(
                "conflicting QUIC CRYPTO retransmission",
            ));
        }
        return Ok(());
    }
    frames.insert(frame.offset, frame.bytes);
    Ok(())
}

fn complete_prefetched_quic_client_hello(
    frames: &BTreeMap<usize, Vec<u8>>,
) -> Result<Option<Vec<u8>>, CoreError> {
    let crypto = contiguous_quic_crypto_prefix(frames)?;
    if crypto.len() < 4 {
        return Ok(None);
    }
    if crypto[0] != TLS_HANDSHAKE_CLIENT_HELLO {
        return Err(CoreError::InvalidClientHello("not a QUIC ClientHello"));
    }
    let declared = read_quic_u24(&crypto[1..4])?;
    let needed = 4_usize
        .checked_add(declared)
        .ok_or(CoreError::ClientHelloTooLarge)?;
    if needed > QUIC_PREFETCH_MAX_CRYPTO_BYTES {
        return Err(CoreError::ClientHelloTooLarge);
    }
    if crypto.len() < needed {
        return Ok(None);
    }
    Ok(Some(crypto[..needed].to_vec()))
}

fn contiguous_quic_crypto_prefix(frames: &BTreeMap<usize, Vec<u8>>) -> Result<Vec<u8>, CoreError> {
    let mut out = Vec::new();
    for (offset, bytes) in frames {
        if *offset > out.len() {
            break;
        }
        let overlap = out.len() - *offset;
        if overlap > 0 {
            let covered = overlap.min(bytes.len());
            let overlap_end = offset
                .checked_add(covered)
                .ok_or(CoreError::ClientHelloTooLarge)?;
            if out[*offset..overlap_end] != bytes[..covered] {
                return Err(CoreError::InvalidClientHello(
                    "overlapping QUIC CRYPTO data changed",
                ));
            }
        }
        if overlap >= bytes.len() {
            continue;
        }
        out.extend_from_slice(&bytes[overlap..]);
        if out.len() > QUIC_PREFETCH_MAX_CRYPTO_BYTES {
            return Err(CoreError::ClientHelloTooLarge);
        }
    }
    Ok(out)
}

fn read_quic_u24(input: &[u8]) -> Result<usize, CoreError> {
    if input.len() != 3 {
        return Err(CoreError::InvalidClientHello("bad QUIC uint24"));
    }
    Ok((usize::from(input[0]) << 16) | (usize::from(input[1]) << 8) | usize::from(input[2]))
}

struct AuthenticatedQuicRuntime {
    sni: String,
    session_id: [u8; 32],
    shared_secret: [u8; 32],
    client_hello: Vec<u8>,
    profile: DestProfile,
    mldsa_seed: [u8; 32],
}

async fn run_authenticated_quic_stream(
    endpoint_socket: StdUdpSocket,
    client_peer: SocketAddr,
    initial_datagrams: Vec<Vec<u8>>,
    local_cid_len: usize,
    drain_timeout: Duration,
    authenticated: AuthenticatedQuicRuntime,
) -> Result<(), CoreError> {
    let runtime = quinn::default_runtime()
        .ok_or_else(|| CoreError::Quic("no async runtime available for QUIC".to_owned()))?;
    let inner = runtime
        .wrap_udp_socket(endpoint_socket)
        .map_err(quic_error)?;
    let pending = initial_datagrams
        .into_iter()
        .map(|bytes| PrefetchedDatagram {
            bytes,
            peer: client_peer,
        })
        .collect();
    let socket = Arc::new(PrefetchedUdpSocket {
        inner,
        pending: Mutex::new(pending),
    });
    let server_config = quic_crypto::server_config(quic_crypto::AuthenticatedServerCrypto {
        sni: authenticated.sni,
        session_id: authenticated.session_id,
        shared_secret: authenticated.shared_secret,
        client_hello: authenticated.client_hello,
        profile: authenticated.profile,
        mldsa_seed: authenticated.mldsa_seed,
    });
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.cid_generator(move || {
        Box::new(quinn_proto::RandomConnectionIdGenerator::new(
            local_cid_len.max(1),
        ))
    });
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        endpoint_config,
        Some(server_config),
        socket,
        runtime,
    )
    .map_err(quic_error)?;
    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| CoreError::Quic("QUIC endpoint closed before accept".to_owned()))?;
    let connection = incoming.await.map_err(quic_error)?;
    let (send, mut recv) = connection.accept_bi().await.map_err(quic_error)?;
    let target = read_target_stream(&mut recv).await?;
    let target_io = TcpStream::connect(target_to_host_port(&target)).await?;
    relay_quic_server_stream(target_io, send, recv).await?;
    let _ = tokio::time::timeout(drain_timeout, connection.closed()).await;
    endpoint.close(0_u32.into(), b"");
    Ok(())
}

async fn relay_quic_server_stream(
    target: TcpStream,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), CoreError> {
    let (mut target_read, mut target_write) = tokio::io::split(target);
    let client_to_target = async {
        tokio::io::copy(&mut recv, &mut target_write).await?;
        target_write.shutdown().await
    };
    let target_to_client = async {
        tokio::io::copy(&mut target_read, &mut send).await?;
        send.shutdown().await
    };
    let _ = tokio::try_join!(client_to_target, target_to_client)?;
    Ok(())
}

#[derive(Debug)]
struct PrefetchedDatagram {
    bytes: Vec<u8>,
    peer: SocketAddr,
}

struct PrefetchedUdpSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    pending: Mutex<VecDeque<PrefetchedDatagram>>,
}

impl fmt::Debug for PrefetchedUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrefetchedUdpSocket")
            .finish_non_exhaustive()
    }
}

impl quinn::AsyncUdpSocket for PrefetchedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let pending = match self.pending.lock() {
            Ok(mut guard) => guard.pop_front(),
            Err(_) => {
                return Poll::Ready(Err(io::Error::other(
                    "prefetched QUIC datagram lock poisoned",
                )))
            }
        };
        if let Some(datagram) = pending {
            let Some(buf) = bufs.first_mut() else {
                return Poll::Ready(Err(io::Error::other("QUIC receive buffer missing")));
            };
            let Some(meta) = meta.first_mut() else {
                return Poll::Ready(Err(io::Error::other("QUIC receive metadata missing")));
            };
            if buf.len() < datagram.bytes.len() {
                return Poll::Ready(Err(io::Error::other(
                    "prefetched QUIC datagram buffer too small",
                )));
            }
            buf[..datagram.bytes.len()].copy_from_slice(&datagram.bytes);
            *meta = quinn::udp::RecvMeta {
                addr: datagram.peer,
                len: datagram.bytes.len(),
                stride: datagram.bytes.len(),
                ecn: None,
                dst_ip: None,
            };
            return Poll::Ready(Ok(1));
        }
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

async fn relay_quic_fallback_until_idle(
    client_socket: &UdpSocket,
    client_peer: SocketAddr,
    initial_datagrams: Vec<Vec<u8>>,
    dest: &str,
    idle_timeout: Duration,
) -> Result<(u64, u64), CoreError> {
    if initial_datagrams.is_empty() {
        return Err(CoreError::InvalidConfig(
            "QUIC fallback requires at least one datagram",
        ));
    }
    let upstream = UdpSocket::bind("0.0.0.0:0").await?;
    upstream.connect(dest).await?;
    let mut client_to_dest = 0_u64;
    for datagram in initial_datagrams {
        upstream.send(&datagram).await?;
        client_to_dest = add_quic_byte_count(client_to_dest, datagram.len())?;
    }
    let mut dest_to_client = 0_u64;
    let mut client_buf = vec![0_u8; 65_535];
    let mut upstream_buf = vec![0_u8; 65_535];

    loop {
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            () = &mut idle => return Ok((client_to_dest, dest_to_client)),
            received = client_socket.recv_from(&mut client_buf) => {
                let (read, peer) = received?;
                if peer == client_peer {
                    upstream.send(&client_buf[..read]).await?;
                    client_to_dest = add_quic_byte_count(client_to_dest, read)?;
                }
            }
            received = upstream.recv(&mut upstream_buf) => {
                let read = received?;
                client_socket.send_to(&upstream_buf[..read], client_peer).await?;
                dest_to_client = add_quic_byte_count(dest_to_client, read)?;
            }
        }
    }
}

fn add_quic_byte_count(total: u64, increment: usize) -> Result<u64, CoreError> {
    total
        .checked_add(
            u64::try_from(increment)
                .map_err(|_| CoreError::InvalidConfig("QUIC datagram length is too large"))?,
        )
        .ok_or(CoreError::InvalidConfig("QUIC byte count overflows"))
}

async fn relay_one_server_inner_stream<D, Connect, ConnectFuture>(
    mut tls_io: tokio::io::DuplexStream,
    connect_target: Connect,
    padding_scheme: &PadScheme,
) -> Result<(), CoreError>
where
    D: AsyncRead + AsyncWrite + Unpin,
    Connect: FnOnce(String) -> ConnectFuture,
    ConnectFuture: Future<Output = Result<D, std::io::Error>>,
{
    let (mode, prefix) = read_inner_opening_mode(&mut tls_io).await?;
    let tls_io = PrefixedStream::new(prefix, tls_io);
    match mode {
        ServerInnerMode::Mux => {
            let mut mux = MuxSession::server(tls_io, padding_scheme)?;
            let (stream, target) = mux.accept().await?;
            let mut target_io = connect_target(target_to_host_port(&target)).await?;
            Box::pin(relay_mux_server_stream(&mut target_io, mux, stream)).await
        }
        ServerInnerMode::VisionSolo => {
            let mut solo = tls_io;
            let target = read_solo_preface(&mut solo).await?;
            let target_io = connect_target(target_to_host_port(&target)).await?;
            vision_relay(solo, target_io).await?;
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ServerInnerMode {
    Mux,
    VisionSolo,
}

async fn read_inner_opening_mode<IO>(io: &mut IO) -> Result<(ServerInnerMode, Vec<u8>), CoreError>
where
    IO: AsyncRead + Unpin,
{
    let mut first = [0_u8; 1];
    io.read_exact(&mut first).await?;
    let mut prefix = vec![first[0]];
    if first[0] != MUX_VERSION {
        return Ok((ServerInnerMode::VisionSolo, prefix));
    }

    let mut rest = [0_u8; MUX_OPENING_PREFIX_LEN - 1];
    io.read_exact(&mut rest).await?;
    prefix.extend_from_slice(&rest);
    if looks_like_mux_opening_prefix(&prefix) {
        Ok((ServerInnerMode::Mux, prefix))
    } else {
        Ok((ServerInnerMode::VisionSolo, prefix))
    }
}

fn looks_like_mux_opening_prefix(prefix: &[u8]) -> bool {
    if prefix.len() != MUX_OPENING_PREFIX_LEN || prefix[0] != MUX_VERSION {
        return false;
    }
    let stream_id = u32::from_be_bytes([prefix[2], prefix[3], prefix[4], prefix[5]]);
    match MuxCommand::try_from(prefix[1]) {
        Ok(MuxCommand::Syn) => stream_id == 1 && prefix[6] <= 1,
        Ok(MuxCommand::Padding) => stream_id == 0,
        Ok(_) | Err(_) => false,
    }
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

async fn read_required_non_ccs_tls_record<R>(reader: &mut R) -> Result<Vec<u8>, CoreError>
where
    R: AsyncRead + Unpin,
{
    loop {
        let record = read_required_tls_record(reader).await?;
        if record.as_slice() == Tls13Client::dummy_change_cipher_spec() {
            continue;
        }
        return Ok(record);
    }
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

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::{timeout, Duration},
    };

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
    async fn scenario_server_inner_stream_accepts_vision_solo_preface() {
        let (mut client, server) = tokio::io::duplex(4096);
        let (target_io, mut target_peer) = tokio::io::duplex(4096);
        let target = TargetAddr::domain("solo.example", 443).expect("target");
        let server_task = tokio::spawn(async move {
            relay_one_server_inner_stream(
                server,
                |dest| async move {
                    assert_eq!(dest, "solo.example:443");
                    Ok::<_, std::io::Error>(target_io)
                },
                &PadScheme::none(),
            )
            .await
        });

        send_solo_preface(&mut client, &target)
            .await
            .expect("send solo preface");
        client.write_all(b"ping").await.expect("write request");
        client.shutdown().await.expect("close client write half");

        let mut observed = [0_u8; 4];
        target_peer
            .read_exact(&mut observed)
            .await
            .expect("target receives request");
        assert_eq!(&observed, b"ping");
        target_peer
            .write_all(b"pong")
            .await
            .expect("write response");
        target_peer
            .shutdown()
            .await
            .expect("close target write half");

        let mut response = [0_u8; 4];
        client
            .read_exact(&mut response)
            .await
            .expect("client receives response");
        assert_eq!(&response, b"pong");

        timeout(Duration::from_secs(1), server_task)
            .await
            .expect("server task completes")
            .expect("server task joins")
            .expect("server relay succeeds");
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

    #[test]
    fn scenario_quic_crypto_prefetch_assembles_split_and_overlap() {
        let full = b"\x01\x00\x00\x05hello".to_vec();
        let mut frames = BTreeMap::new();

        insert_quic_crypto_frame(&mut frames, quic_frame(0, &full[..6])).expect("first chunk");
        insert_quic_crypto_frame(&mut frames, quic_frame(6, &full[6..])).expect("second chunk");
        insert_quic_crypto_frame(&mut frames, quic_frame(0, &full[..6])).expect("retransmit");

        assert_eq!(
            complete_prefetched_quic_client_hello(&frames)
                .expect("complete")
                .expect("client hello"),
            full
        );

        let mut overlapping = BTreeMap::new();
        insert_quic_crypto_frame(&mut overlapping, quic_frame(0, &full[..6]))
            .expect("first overlap chunk");
        insert_quic_crypto_frame(&mut overlapping, quic_frame(4, &full[4..]))
            .expect("second overlap chunk");
        assert_eq!(
            contiguous_quic_crypto_prefix(&overlapping).expect("overlap assembles"),
            full
        );
    }

    #[test]
    fn scenario_quic_crypto_prefetch_rejects_bad_fragments() {
        let mut frames = BTreeMap::new();
        insert_quic_crypto_frame(&mut frames, quic_frame(0, b"\x01\x00\x00\x01a"))
            .expect("insert first");
        assert!(
            insert_quic_crypto_frame(&mut frames, quic_frame(0, b"\x01\x00\x00\x01b")).is_err()
        );

        let mut changed_overlap = BTreeMap::new();
        insert_quic_crypto_frame(&mut changed_overlap, quic_frame(0, b"\x01\x00\x00\x02ab"))
            .expect("insert base");
        insert_quic_crypto_frame(&mut changed_overlap, quic_frame(4, b"xb"))
            .expect("insert overlap");
        assert!(contiguous_quic_crypto_prefix(&changed_overlap).is_err());

        let mut not_hello = BTreeMap::new();
        insert_quic_crypto_frame(&mut not_hello, quic_frame(0, b"\x02\x00\x00\x00"))
            .expect("insert not hello");
        assert!(complete_prefetched_quic_client_hello(&not_hello).is_err());

        assert!(insert_quic_crypto_frame(
            &mut BTreeMap::new(),
            quic_frame(QUIC_PREFETCH_MAX_CRYPTO_BYTES, b"x"),
        )
        .is_err());
        assert!(read_quic_u24(&[0, 1]).is_err());
    }

    fn quic_frame(offset: usize, bytes: &[u8]) -> QuicCryptoFrame {
        QuicCryptoFrame {
            offset,
            bytes: bytes.to_vec(),
        }
    }
}
