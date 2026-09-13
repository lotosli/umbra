//! Server and client runtime orchestration.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rand::{rngs::OsRng, RngCore};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
};
use umbra_crypto::{
    mlkem::mlkem_keygen,
    secret::{Secret, SecretBytes},
    x25519,
};
use umbra_fingerprint::load_profile;
use umbra_inner::{
    mux::{MuxEvent, MuxSession},
    padding::PadScheme,
    spider::spider,
    vision::{read_solo_preface, send_solo_preface},
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
        parse_quic_initial_header, read_target_stream, write_target_stream,
        write_udp_association_marker, write_udp_envelope_stream, QuicCryptoFrame,
        QUIC_UDP_ASSOCIATE_MARKER,
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
        decode_udp_packet, encode_udp_response_packets, negotiate_no_auth, read_request,
        write_bound_success_reply, write_failure_reply, write_success_reply,
        write_unsupported_command_reply, SocksConnect, SocksRequest, SocksUdpReassembler,
        DEFAULT_RESPONSE_FRAGMENT_PAYLOAD,
    },
    tls_io::{read_tls_record, spawn_tls_app_io, TlsAppEndpoint},
    CoreError,
};

const DEFAULT_REPLAY_CAPACITY: usize = 65_536;
const DEFAULT_OUTER_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_MUX_POOL_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MUX_TARGET_TIMEOUT: Duration = Duration::from_secs(25);
const MAX_MUX_OUTERS: usize = 4;
const MAX_MUX_DRAINING_SPARE: usize = 4;
const MAX_MUX_TOTAL_OUTERS: usize = MAX_MUX_OUTERS + MAX_MUX_DRAINING_SPARE;
const MAX_MUX_QUEUED_OPENS: usize = 128;
const DEFAULT_SESSION_IDLE_TIMEOUT: Duration = Duration::from_mins(5);
const DEFAULT_PROFILE_REFRESH_INTERVAL: Duration = Duration::from_hours(1);
const DEFAULT_QUIC_FALLBACK_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const QUIC_PREFETCH_MAX_DATAGRAMS: usize = 16;
const QUIC_PREFETCH_MAX_CRYPTO_BYTES: usize = 64 * 1024;
const QUIC_MAX_FLOWS: usize = 64;
const QUIC_FLOW_QUEUE_CAPACITY: usize = 16;
const QUIC_FLOW_MAX_CIDS: usize = 64;
const QUIC_MAX_STREAMS: usize = 128;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_PADDING: u16 = 0x0015;
const MUX_OPENING_PREFIX_LEN: usize = 7;
const UDP_RELAY_BUF_LEN: usize = 65_535;
const MAX_UDP_TARGETS_PER_ASSOCIATION: usize = 256;
const UDP_RELAY_CHANNEL_CAPACITY: usize = 256;

/// Bound server runtime with listeners, replay cache, and active destination profile.
pub struct ServerRuntime {
    tcp_listener: TcpListener,
    udp_socket: Option<QuicServerSocket>,
    dispatch_cfg: Arc<crate::dispatch::ServerCfg>,
    // Watch's short synchronous borrow is used only to clone an immutable snapshot.
    profile: tokio::sync::watch::Sender<Arc<DestProfile>>,
    // JoinSet aborts the worker if the runtime is dropped without explicit shutdown.
    profile_refresh: Mutex<JoinSet<()>>,
    replay: Arc<ReplayCache>,
    probe_policy: ProbeResistancePolicy,
    padding_scheme: PadScheme,
    tcp_evasion: TcpEvasionPolicy,
    prebuild: bool,
}

struct QuicServerSocket {
    dispatch: Arc<UdpSocket>,
    // Only the listener polls this wrapper for receives. Flow wrappers use sends only.
    send: Arc<dyn quinn::AsyncUdpSocket>,
    receiver: tokio::sync::Mutex<()>,
}

impl ServerRuntime {
    /// Bind configured listeners using an already-validated destination profile.
    ///
    /// When prebuild is enabled, refresh independently until shutdown or drop.
    pub async fn bind_with_profile(
        cfg: RuntimeServerCfg,
        profile: DestProfile,
        probe_policy: ProbeResistancePolicy,
    ) -> Result<Self, CoreError> {
        Self::bind_with_refresh(cfg, profile, probe_policy, |active, dest| async move {
            refresh_profiles(
                active,
                dest,
                |dest: String| async move { umbra_reality::prebuild::probe_dest(&dest).await },
                profile_refresh_interval(),
            )
            .await;
        })
        .await
    }

    async fn bind_with_probe<F>(
        cfg: RuntimeServerCfg,
        probe: impl FnOnce(String) -> F,
    ) -> Result<Self, CoreError>
    where
        F: Future<Output = Result<DestProfile, umbra_reality::RealityError>>,
    {
        // Both prebuild modes must obtain a validated profile before binding listeners.
        let profile = probe(cfg.dest.clone()).await?;
        Self::bind_with_profile(cfg, profile, ProbeResistancePolicy::default()).await
    }

    async fn bind_with_refresh<F>(
        cfg: RuntimeServerCfg,
        profile: DestProfile,
        probe_policy: ProbeResistancePolicy,
        refresh: impl FnOnce(tokio::sync::watch::Sender<Arc<DestProfile>>, String) -> F,
    ) -> Result<Self, CoreError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
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
                let runtime = quinn::default_runtime()
                    .ok_or_else(|| CoreError::Quic("no QUIC runtime".to_owned()))?;
                let send = runtime.wrap_udp_socket(std_socket.try_clone()?)?;
                let dispatch = Arc::new(UdpSocket::from_std(std_socket)?);
                Some(QuicServerSocket {
                    dispatch,
                    send,
                    receiver: tokio::sync::Mutex::new(()),
                })
            }
            None => None,
        };
        let replay = Arc::new(ReplayCache::new(
            DEFAULT_REPLAY_CAPACITY,
            max_time_diff.as_secs(),
        )?);
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
        let (profile, _) = tokio::sync::watch::channel(Arc::new(profile));
        let mut profile_refresh = JoinSet::new();
        if prebuild {
            profile_refresh.spawn(refresh(profile.clone(), dispatch_cfg.dest.clone()));
        }

        Ok(Self {
            tcp_listener,
            udp_socket,
            dispatch_cfg: Arc::new(dispatch_cfg),
            profile,
            profile_refresh: Mutex::new(profile_refresh),
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

    fn profile_snapshot(&self) -> Arc<DestProfile> {
        Arc::clone(&self.profile.borrow())
    }

    async fn stop_profile_refresh(&self) {
        // No lock survives the await. Moving the task set cannot poison its contents.
        let mut tasks = std::mem::take(
            &mut *self
                .profile_refresh
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        abort_all(&mut tasks).await;
    }

    /// Accept one TCP connection and dispatch it using an injected destination connector.
    pub async fn accept_one_with_connector<D, Connect, ConnectFuture>(
        &self,
        connect_dest: Connect,
    ) -> Result<AcceptedServerSession, CoreError>
    where
        D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        Connect: FnMut(String) -> ConnectFuture + Send,
        ConnectFuture: Future<Output = Result<D, std::io::Error>> + Send + 'static,
    {
        let (stream, peer) = self.tcp_listener.accept().await?;
        let profile = self.profile_snapshot();
        let outcome = dispatch_runtime_with_connector(
            stream,
            self.dispatch_cfg.as_ref(),
            profile.as_ref(),
            self.replay.as_ref(),
            current_unix_time()?,
            connect_dest,
            self.probe_policy.timing,
            &self.padding_scheme,
        )
        .await?;
        Ok(AcceptedServerSession { peer, outcome })
    }

    /// Run the UDP supervisor until one flow completes, then stop and join other flows.
    pub async fn accept_one_quic_with_idle_timeout(
        &self,
        idle_timeout: Duration,
    ) -> Result<AcceptedQuicSession, CoreError> {
        self.run_quic_listener(idle_timeout, true, std::future::pending())
            .await?
            .ok_or(CoreError::InvalidConfig(
                "QUIC listener stopped before an outcome",
            ))
    }

    async fn run_quic_listener<S>(
        &self,
        idle_timeout: Duration,
        one_outcome: bool,
        shutdown: S,
    ) -> Result<Option<AcceptedQuicSession>, CoreError>
    where
        S: Future<Output = ()>,
    {
        let socket = self
            .udp_socket
            .as_ref()
            .ok_or(CoreError::InvalidConfig("UDP listener is not configured"))?;
        tokio::pin!(shutdown);
        // Public convenience calls must not introduce another physical receiver.
        let _receiver = tokio::select! {
            () = &mut shutdown => return Ok(None),
            receiver = socket.receiver.lock() => receiver,
        };
        let mut flows: JoinSet<Result<AcceptedQuicSession, CoreError>> = JoinSet::new();
        let (stop_flows, stopping) = tokio::sync::watch::channel(false);
        let mut routes = HashMap::new();
        let mut buf = vec![0_u8; UDP_RELAY_BUF_LEN];
        let result = loop {
            tokio::select! {
                () = &mut shutdown => break Ok(None),
                joined = flows.join_next_with_id(), if !flows.is_empty() => {
                    match joined {
                        Some(Ok((id, outcome))) => {
                            routes.remove(&id);
                            if one_outcome {
                                break outcome.map(Some);
                            }
                            report_session_result("server QUIC", Some(Ok(outcome)));
                        }
                        Some(Err(err)) => {
                            routes.remove(&err.id());
                            report_session_result::<AcceptedQuicSession>("server QUIC", Some(Err(err)));
                        }
                        None => {}
                    }
                }
                received = receive_quic_datagrams(socket.send.as_ref(), &mut buf) => {
                    let (meta, read) = match received {
                        Ok(received) => received,
                        Err(err) => break Err(err.into()),
                    };
                    let peer = meta.addr;
                    let datagrams = buf[..read].chunks(meta.stride.max(1))
                        .chain((read == 0).then_some(&buf[..0]));
                    for datagram in datagrams {
                        match route_quic_datagram(&routes, peer, datagram) {
                            QuicRouteMatch::Existing(sender) => {
                                // Never block unrelated peers on a saturated UDP queue.
                                let _ = sender.try_send(datagram.to_vec());
                            }
                            QuicRouteMatch::New if routes.len() < QUIC_MAX_FLOWS => {
                                let (route, inbox) = QuicFlowRoute::new(peer, datagram);
                                let task = flows.spawn(self.quic_flow(
                                    socket,
                                    datagram.to_vec(),
                                    inbox,
                                    idle_timeout,
                                    stopping.clone(),
                                ));
                                routes.insert(task.id(), route);
                            }
                            QuicRouteMatch::New | QuicRouteMatch::Ambiguous => {}
                        }
                    }
                }
            }
        };
        let _ = stop_flows.send(true);
        routes.clear();
        while flows.join_next().await.is_some() {}
        result
    }

    fn quic_flow(
        &self,
        socket: &QuicServerSocket,
        datagram: Vec<u8>,
        inbox: QuicFlowInbox,
        idle_timeout: Duration,
        mut stopping: tokio::sync::watch::Receiver<bool>,
    ) -> impl Future<Output = Result<AcceptedQuicSession, CoreError>> + Send + 'static {
        let cfg = Arc::clone(&self.dispatch_cfg);
        let profile = self.profile_snapshot();
        let replay = Arc::clone(&self.replay);
        let client_socket = Arc::clone(&socket.dispatch);
        let endpoint_socket = Arc::clone(&socket.send);
        let timing = self.probe_policy.timing;
        async move {
            let peer = inbox.peer;
            let mut streams = JoinSet::new();
            let outcome = tokio::select! {
                _ = stopping.changed() => Err(CoreError::Quic("listener stopped".to_owned())),
                outcome = Box::pin(dispatch_quic_runtime(
                    datagram,
                    inbox,
                    QuicRuntimeDispatch {
                        client_socket: &client_socket,
                        endpoint_socket,
                        cfg: cfg.as_ref(),
                        profile: profile.as_ref(),
                        replay: replay.as_ref(),
                        now_unix: current_unix_time()?,
                        timing,
                        idle_timeout,
                    },
                    &mut streams,
                )) => outcome,
            };
            abort_all(&mut streams).await;
            outcome.map(|outcome| AcceptedQuicSession { peer, outcome })
        }
    }

    /// Accept and dispatch sessions until shutdown, then stop and join profile refresh.
    pub async fn run_until_shutdown<S>(&self, shutdown: S) -> Result<(), CoreError>
    where
        S: Future<Output = ()>,
    {
        let result = self.run_accept_loops(shutdown).await;
        self.stop_profile_refresh().await;
        result
    }

    async fn run_accept_loops<S>(&self, shutdown: S) -> Result<(), CoreError>
    where
        S: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        let (quic_stop, quic_stopped) = tokio::sync::oneshot::channel();
        let quic_listener =
            self.run_quic_listener(DEFAULT_QUIC_FALLBACK_IDLE_TIMEOUT, false, async {
                let _ = quic_stopped.await;
            });
        tokio::pin!(quic_listener);
        let mut tcp_sessions = JoinSet::new();
        loop {
            tokio::select! {
                () = &mut shutdown => {
                    let _ = quic_stop.send(());
                    if self.udp_socket.is_some() {
                        quic_listener.await?;
                    }
                    abort_all(&mut tcp_sessions).await;
                    return Ok(());
                }
                joined = tcp_sessions.join_next(), if !tcp_sessions.is_empty() => {
                    report_session_result("server TCP", joined);
                }
                accepted = self.tcp_listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(err) => {
                            let _ = quic_stop.send(());
                            if self.udp_socket.is_some() {
                                let _ = quic_listener.await;
                            }
                            abort_all(&mut tcp_sessions).await;
                            return Err(err.into());
                        }
                    };
                    let cfg = Arc::clone(&self.dispatch_cfg);
                    let profile = self.profile_snapshot();
                    let replay = Arc::clone(&self.replay);
                    let timing = self.probe_policy.timing;
                    let padding_scheme = self.padding_scheme.clone();
                    tcp_sessions.spawn(async move {
                        let outcome = Box::pin(dispatch_runtime_with_connector(
                            stream,
                            cfg.as_ref(),
                            profile.as_ref(),
                            replay.as_ref(),
                            current_unix_time()?,
                            crate::target_connect::connect_tcp_target,
                            timing,
                            &padding_scheme,
                        ))
                        .await?;
                        Ok::<_, CoreError>(AcceptedServerSession { peer, outcome })
                    });
                }
                result = &mut quic_listener, if self.udp_socket.is_some() => {
                    abort_all(&mut tcp_sessions).await;
                    return result.map(|_| ());
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
    cfg: Arc<ClientCfg>,
    connections: Arc<ClientConnections>,
}

struct ClientConnections {
    quic: tokio::sync::Mutex<Option<QuicClientConnection>>,
    mux: tokio::sync::Mutex<Vec<(crate::mux_io::MuxDriver, crate::mux_io::ClientMux)>>,
    mux_changed: Arc<tokio::sync::Notify>,
    stopped: tokio::sync::Notify,
    closed: AtomicBool,
    mux_waiters: tokio::sync::Semaphore,
}

impl Default for ClientConnections {
    fn default() -> Self {
        Self {
            quic: tokio::sync::Mutex::new(None),
            mux: tokio::sync::Mutex::new(Vec::new()),
            mux_changed: Arc::new(tokio::sync::Notify::new()),
            stopped: tokio::sync::Notify::new(),
            closed: AtomicBool::new(false),
            mux_waiters: tokio::sync::Semaphore::new(MAX_MUX_QUEUED_OPENS),
        }
    }
}

impl ClientConnections {
    async fn open_mux(
        &self,
        cfg: &ClientCfg,
        target: TargetAddr,
    ) -> Result<crate::mux_io::MuxIo, CoreError> {
        let reservation = self
            .reserve_mux(|| async {
                let outer = open_tcp_outer(cfg).await?;
                MuxSession::client(outer, &cfg.padding_scheme).map_err(CoreError::from)
            })
            .await?;
        reservation
            .open(
                target,
                DEFAULT_OUTER_CONNECT_TIMEOUT,
                DEFAULT_MUX_TARGET_TIMEOUT,
            )
            .await
            .map_err(CoreError::from)
    }

    async fn reserve_mux<IO, Open, Opening>(
        &self,
        open: Open,
    ) -> Result<crate::mux_io::MuxReservation, CoreError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        Open: FnMut() -> Opening,
        Opening: Future<Output = Result<MuxSession<IO>, CoreError>>,
    {
        self.reserve_mux_with_timeout(open, DEFAULT_MUX_POOL_TIMEOUT)
            .await
    }

    async fn reserve_mux_with_timeout<IO, Open, Opening>(
        &self,
        open: Open,
        wait_timeout: Duration,
    ) -> Result<crate::mux_io::MuxReservation, CoreError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        Open: FnMut() -> Opening,
        Opening: Future<Output = Result<MuxSession<IO>, CoreError>>,
    {
        let _waiting = self.mux_waiters.try_acquire().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "mux pool admission queue is full",
            )
        })?;
        tokio::time::timeout(wait_timeout, self.reserve_mux_inner(open))
            .await
            .map_err(|_| CoreError::IdleTimeout("mux pool admission"))?
    }

    async fn reserve_mux_inner<IO, Open, Opening>(
        &self,
        mut open: Open,
    ) -> Result<crate::mux_io::MuxReservation, CoreError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        Open: FnMut() -> Opening,
        Opening: Future<Output = Result<MuxSession<IO>, CoreError>>,
    {
        loop {
            // Register before inspecting slots so their last release cannot be lost.
            let changed = self.mux_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let mut active = self.mux.lock().await;
            if self.closed.load(Ordering::Acquire) {
                return Err(CoreError::InvalidConfig("client runtime is shutting down"));
            }
            let mut index = 0;
            while index < active.len() {
                let handle = &active[index].1;
                if !handle.is_healthy() || (!handle.is_accepting() && handle.live_streams() == 0) {
                    let (driver, _) = active.remove(index);
                    driver.shutdown().await;
                } else {
                    index += 1;
                }
            }
            for (_, handle) in active.iter() {
                if let Some(reserved) = handle.try_reserve() {
                    return Ok(reserved);
                }
            }
            let can_create = active
                .iter()
                .filter(|(_, handle)| handle.is_accepting())
                .count()
                < MAX_MUX_OUTERS;
            if can_create && active.len() == MAX_MUX_TOTAL_OUTERS {
                // Preserve old streams while spare slots exist. At the hard
                // total bound, retire only the oldest draining outer: its old
                // operations fail terminally and are never replayed elsewhere.
                if let Some(index) = oldest_draining_outer(&active) {
                    let (driver, _) = active.remove(index);
                    driver.shutdown().await;
                }
            }
            if can_create && active.len() < MAX_MUX_TOTAL_OUTERS {
                let stopped = self.stopped.notified();
                tokio::pin!(stopped);
                stopped.as_mut().enable();
                if self.closed.load(Ordering::Acquire) {
                    return Err(CoreError::InvalidConfig("client runtime is shutting down"));
                }
                // The pool lock coordinates establishment. It never guards stream I/O.
                let session = tokio::select! {
                    () = &mut stopped => return Err(CoreError::InvalidConfig("client runtime is shutting down")),
                    result = open() => result?,
                };
                let (driver, handle) =
                    crate::mux_io::start_client_with_notifier(session, self.mux_changed.clone())?;
                let reservation = handle.try_reserve();
                active.push((driver, handle));
                if let Some(reservation) = reservation {
                    return Ok(reservation);
                }
            } else {
                drop(active);
                changed.await;
            }
        }
    }

    async fn quic(&self, cfg: &ClientCfg) -> Result<quinn::Connection, CoreError> {
        let mut active = self.quic.lock().await;
        if let Some(outer) = active.as_ref() {
            if outer.connection.close_reason().is_none() {
                return Ok(outer.connection.clone());
            }
        }
        active.take();
        let outer = QuicClientConnection::connect(cfg).await?;
        let connection = outer.connection.clone();
        *active = Some(outer);
        Ok(connection)
    }

    async fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        self.stopped.notify_waiters();
        self.mux_changed.notify_waiters();
        let active = std::mem::take(&mut *self.mux.lock().await);
        for (driver, _) in active {
            driver.shutdown().await;
        }
        if let Some(outer) = self.quic.lock().await.take() {
            outer.endpoint.close(0_u32.into(), b"");
            let _ = tokio::time::timeout(DEFAULT_OUTER_CONNECT_TIMEOUT, outer.endpoint.wait_idle())
                .await;
        }
    }
}

fn oldest_draining_outer(
    outers: &[(crate::mux_io::MuxDriver, crate::mux_io::ClientMux)],
) -> Option<usize> {
    outers
        .iter()
        .enumerate()
        .filter(|(_, (_, handle))| !handle.is_accepting())
        .filter_map(|(index, (_, handle))| handle.draining_since().map(|since| (index, since)))
        .min_by_key(|(_, since)| *since)
        .map(|(index, _)| index)
}

struct QuicClientConnection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

impl QuicClientConnection {
    async fn connect(cfg: &ClientCfg) -> Result<Self, CoreError> {
        tokio::time::timeout(DEFAULT_OUTER_CONNECT_TIMEOUT, Self::connect_inner(cfg))
            .await
            .map_err(|_| CoreError::IdleTimeout("outer QUIC connection setup"))?
    }

    async fn connect_inner(cfg: &ClientCfg) -> Result<Self, CoreError> {
        let server_addr = resolve_server_addr(&cfg.server).await?;
        let bind_ip = if server_addr.is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let mut endpoint =
            quinn::Endpoint::client(SocketAddr::new(bind_ip, 0)).map_err(quic_error)?;
        endpoint.set_default_client_config(quic_crypto::client_config(cfg)?);
        let connection = endpoint
            .connect(server_addr, &cfg.server_name)
            .map_err(quic_error)?
            .await
            .map_err(quic_error)?;
        Ok(Self {
            endpoint,
            connection,
        })
    }
}

impl Drop for QuicClientConnection {
    fn drop(&mut self) {
        self.endpoint.close(0_u32.into(), b"");
    }
}

impl ClientRuntime {
    /// Bind the configured SOCKS5 listener.
    pub async fn bind(cfg: ClientCfg) -> Result<Self, CoreError> {
        let listener = TcpListener::bind(cfg.socks_listen).await?;
        Ok(Self {
            listener,
            cfg: Arc::new(cfg),
            connections: Arc::new(ClientConnections::default()),
        })
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
        Outer: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        Open: FnOnce(ClientConnectPlan) -> OpenFuture,
        OpenFuture: Future<Output = Result<Outer, CoreError>>,
    {
        let (mut socks, _) = self.listener.accept().await?;
        client_session_with_outer(self.cfg.as_ref(), &mut socks, open_outer).await
    }

    /// Run the SOCKS listener until shutdown resolves.
    pub async fn run_until_shutdown<S>(&self, shutdown: S) -> Result<(), CoreError>
    where
        S: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        let mut sessions = JoinSet::new();
        let result = loop {
            tokio::select! {
                () = &mut shutdown => break Ok(()),
                joined = sessions.join_next(), if !sessions.is_empty() => {
                    report_session_result("client SOCKS", joined);
                }
                accepted = self.listener.accept() => {
                    let (mut socks, _peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => break Err(error.into()),
                    };
                    let cfg = Arc::clone(&self.cfg);
                    let connections = Arc::clone(&self.connections);
                    sessions.spawn(async move {
                        Box::pin(client_session_with_connections(
                            cfg.as_ref(), &mut socks, &connections,
                        )).await
                    });
                }
            }
        };
        abort_all(&mut sessions).await;
        self.connections.shutdown().await;
        result
    }

    /// Accept one SOCKS request and open the configured outer transport.
    pub async fn accept_one_from_config(&self) -> Result<ClientSessionOutcome, CoreError> {
        let (mut socks, _) = self.listener.accept().await?;
        Box::pin(client_session_with_connections(
            self.cfg.as_ref(),
            &mut socks,
            &self.connections,
        ))
        .await
    }
}

async fn abort_all<T: 'static>(tasks: &mut JoinSet<T>) {
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

fn report_session_result<T>(
    context: &str,
    joined: Option<Result<Result<T, CoreError>, tokio::task::JoinError>>,
) {
    match joined {
        Some(Ok(Ok(_))) | None => {}
        Some(Ok(Err(error))) => eprintln!("umbra {context} session error: {error}"),
        Some(Err(error)) => eprintln!("umbra {context} task error: {error}"),
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
    Outer: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Open: FnOnce(ClientConnectPlan) -> OpenFuture,
    OpenFuture: Future<Output = Result<Outer, CoreError>>,
{
    negotiate_no_auth(socks).await?;
    let request = match read_request(socks).await {
        Ok(request) => request,
        Err(CoreError::Socks("unsupported SOCKS command")) => {
            write_unsupported_command_reply(socks).await?;
            return Err(CoreError::Socks("unsupported SOCKS command"));
        }
        Err(err) => return Err(err),
    };
    let SocksRequest::Connect(SocksConnect { target }) = request else {
        let SocksRequest::UdpAssociate(associate) = request else {
            return Err(CoreError::Socks("unsupported SOCKS command"));
        };
        if cfg.transport == TransportKind::Quic {
            return Err(CoreError::InvalidConfig(
                "QUIC UDP association requires configured QUIC runtime",
            ));
        }
        let mode = ClientInnerMode::Mux;
        let plan = ClientConnectPlan {
            target: associate.client_addr.clone(),
            server: cfg.server.clone(),
            transport: cfg.transport,
            mode,
            server_name: cfg.server_name.clone(),
        };
        let outer = open_outer(plan).await?;
        client_udp_association_over_tcp_outer(cfg, socks, outer).await?;
        return Ok(ClientSessionOutcome {
            target: associate.client_addr,
            transport: cfg.transport,
            mode,
        });
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
    let connections = ClientConnections::default();
    let result = client_session_with_connections(cfg, socks, &connections).await;
    connections.shutdown().await;
    result
}

async fn client_session_with_connections<S>(
    cfg: &ClientCfg,
    socks: &mut S,
    connections: &ClientConnections,
) -> Result<ClientSessionOutcome, CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_no_auth(socks).await?;
    let request = match read_request(socks).await {
        Ok(request) => request,
        Err(CoreError::Socks("unsupported SOCKS command")) => {
            write_unsupported_command_reply(socks).await?;
            return Err(CoreError::Socks("unsupported SOCKS command"));
        }
        Err(err) => return Err(err),
    };
    let SocksRequest::Connect(SocksConnect { target }) = request else {
        let SocksRequest::UdpAssociate(associate) = request else {
            return Err(CoreError::Socks("unsupported SOCKS command"));
        };
        let mode = match cfg.transport {
            TransportKind::Tcp => ClientInnerMode::Mux,
            TransportKind::Quic => ClientInnerMode::QuicStream,
        };
        match cfg.transport {
            TransportKind::Tcp => {
                let outer = open_tcp_outer(cfg).await?;
                client_udp_association_over_tcp_outer(cfg, socks, outer).await?;
            }
            TransportKind::Quic => {
                client_quic_udp_association(cfg, socks).await?;
            }
        }
        return Ok(ClientSessionOutcome {
            target: associate.client_addr,
            transport: cfg.transport,
            mode,
        });
    };
    let mode = selected_client_inner_mode(cfg);
    match cfg.transport {
        TransportKind::Tcp if mode == ClientInnerMode::Mux => {
            let mut stream = match connections.open_mux(cfg, target.clone()).await {
                Ok(stream) => stream,
                Err(error) => {
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), write_failure_reply(socks))
                            .await;
                    return Err(error);
                }
            };
            write_success_reply(socks).await?;
            relay_bidirectional_until_idle(socks, &mut stream, DEFAULT_SESSION_IDLE_TIMEOUT)
                .await?;
        }
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
            let connection = connections.quic(cfg).await?;
            Box::pin(client_quic_stream_session(&connection, socks, &target)).await?;
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
    Outer: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match mode {
        ClientInnerMode::Mux => {
            let mux = MuxSession::client(outer, &cfg.padding_scheme)?;
            let (driver, handle) = crate::mux_io::start_client(mux)?;
            let result = async {
                let mut stream = handle.open(target.clone()).await?;
                write_success_reply(socks).await?;
                relay_bidirectional_until_idle(socks, &mut stream, DEFAULT_SESSION_IDLE_TIMEOUT)
                    .await?;
                Ok::<(), CoreError>(())
            }
            .await;
            driver.shutdown().await;
            result?;
        }
        ClientInnerMode::VisionSolo => {
            let mut outer = outer;
            send_solo_preface(&mut outer, target).await?;
            write_success_reply(socks).await?;
            Box::pin(relay_bidirectional_until_idle(
                socks,
                &mut outer,
                DEFAULT_SESSION_IDLE_TIMEOUT,
            ))
            .await?;
        }
        ClientInnerMode::QuicStream => {
            return Err(CoreError::InvalidConfig(
                "QUIC stream mode requires QUIC runtime",
            ));
        }
    }
    Ok(())
}

async fn client_udp_association_over_tcp_outer<S, Outer>(
    cfg: &ClientCfg,
    control: &mut S,
    outer: Outer,
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Outer: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let udp = bind_socks_udp_relay(cfg).await?;
    let bound = udp.local_addr()?;
    write_bound_success_reply(control, bound).await?;
    let mut mux = MuxSession::client(outer, &cfg.padding_scheme)?;
    let mut reassembler = SocksUdpReassembler::default();
    let mut client_peer = None;
    let mut control_buf = [0_u8; 1];
    let mut udp_buf = vec![0_u8; UDP_RELAY_BUF_LEN];

    loop {
        let idle = tokio::time::sleep(DEFAULT_SESSION_IDLE_TIMEOUT);
        tokio::pin!(idle);
        tokio::select! {
            () = &mut idle => return Err(CoreError::IdleTimeout("client UDP association")),
            read = control.read(&mut control_buf) => {
                if read? == 0 {
                    return Ok(());
                }
            }
            received = udp.recv_from(&mut udp_buf) => {
                let (read, peer) = received?;
                if let Some(expected) = client_peer {
                    if expected != peer {
                        continue;
                    }
                }
                let Ok(packet) = decode_udp_packet(&udp_buf[..read]) else {
                    continue;
                };
                if client_peer.is_none() {
                    client_peer = Some(peer);
                }
                if let Some(payload) = reassembler.process(packet, Instant::now())? {
                    mux.send_udp_datagram(&payload.target, &payload.payload).await?;
                }
            }
            event = mux.receive_next() => {
                let event = match event {
                    Ok(event) => event,
                    Err(umbra_inner::InnerError::Io(err))
                        if is_association_closed_io(&err) => return Ok(()),
                    Err(err) => return Err(err.into()),
                };
                if let MuxEvent::UdpDatagram { target, payload } = event {
                    let Some(peer) = client_peer else {
                        continue;
                    };
                    for packet in encode_udp_response_packets(
                        &target,
                        &payload,
                        DEFAULT_RESPONSE_FRAGMENT_PAYLOAD,
                    )? {
                        udp.send_to(&packet, peer).await?;
                    }
                }
            }
        }
    }
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
    connection: &quinn::Connection,
    socks: &mut S,
    target: &TargetAddr,
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut send, mut recv) = connection.open_bi().await.map_err(quic_error)?;
    write_target_stream(&mut send, target, &[]).await?;
    write_success_reply(socks).await?;
    let (mut socks_read, mut socks_write) = tokio::io::split(socks);
    let client_to_server = async {
        Box::pin(copy_until_idle(
            &mut socks_read,
            &mut send,
            DEFAULT_SESSION_IDLE_TIMEOUT,
        ))
        .await?;
        send.shutdown().await?;
        Ok::<(), CoreError>(())
    };
    let server_to_client = async {
        Box::pin(copy_until_idle(
            &mut recv,
            &mut socks_write,
            DEFAULT_SESSION_IDLE_TIMEOUT,
        ))
        .await?;
        socks_write.shutdown().await?;
        Ok::<(), CoreError>(())
    };
    let _ = tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

async fn client_quic_udp_association<S>(cfg: &ClientCfg, control: &mut S) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let udp = bind_socks_udp_relay(cfg).await?;
    let bound = udp.local_addr()?;
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
    write_udp_association_marker(&mut send).await?;
    write_bound_success_reply(control, bound).await?;
    let mut envelope_reader = umbra_transport::quic::UdpEnvelopeReader::default();

    let mut reassembler = SocksUdpReassembler::default();
    let mut client_peer = None;
    let mut control_buf = [0_u8; 1];
    let mut udp_buf = vec![0_u8; UDP_RELAY_BUF_LEN];

    loop {
        let idle = tokio::time::sleep(DEFAULT_SESSION_IDLE_TIMEOUT);
        tokio::pin!(idle);
        tokio::select! {
            () = &mut idle => {
                connection.close(0_u32.into(), b"");
                endpoint.close(0_u32.into(), b"");
                return Err(CoreError::IdleTimeout("client QUIC UDP association"));
            }
            read = control.read(&mut control_buf) => {
                if read? == 0 {
                    connection.close(0_u32.into(), b"");
                    endpoint.close(0_u32.into(), b"");
                    return Ok(());
                }
            }
            received = udp.recv_from(&mut udp_buf) => {
                let (read, peer) = received?;
                if let Some(expected) = client_peer {
                    if expected != peer {
                        continue;
                    }
                }
                let Ok(packet) = decode_udp_packet(&udp_buf[..read]) else {
                    continue;
                };
                if client_peer.is_none() {
                    client_peer = Some(peer);
                }
                if let Some(payload) = reassembler.process(packet, Instant::now())? {
                    write_udp_envelope_stream(&mut send, &payload.target, &payload.payload).await?;
                }
            }
            envelope = envelope_reader.read_next(&mut recv) => {
                let envelope = match envelope {
                    Ok(envelope) => envelope,
                    Err(umbra_transport::TransportError::Io(err))
                        if is_association_closed_io(&err) => return Ok(()),
                    Err(err) => return Err(err.into()),
                };
                let Some(peer) = client_peer else {
                    continue;
                };
                for packet in encode_udp_response_packets(
                    &envelope.target,
                    &envelope.payload,
                    DEFAULT_RESPONSE_FRAGMENT_PAYLOAD,
                )? {
                    udp.send_to(&packet, peer).await?;
                }
            }
        }
    }
}

async fn resolve_server_addr(server: &str) -> Result<SocketAddr, CoreError> {
    tokio::net::lookup_host(server)
        .await?
        .next()
        .ok_or(CoreError::InvalidConfig(
            "QUIC server address did not resolve",
        ))
}

async fn bind_socks_udp_relay(cfg: &ClientCfg) -> Result<UdpSocket, CoreError> {
    UdpSocket::bind(socks_udp_bind_addr(cfg))
        .await
        .map_err(CoreError::from)
}

fn socks_udp_bind_addr(cfg: &ClientCfg) -> SocketAddr {
    let ip = match cfg.socks_listen.ip() {
        IpAddr::V4(addr) if addr.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(addr) if addr.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        concrete => concrete,
    };
    SocketAddr::new(ip, 0)
}

fn is_association_closed_io(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::NotConnected | io::ErrorKind::ConnectionReset
    )
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

fn profile_refresh_interval() -> tokio::time::Interval {
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + DEFAULT_PROFILE_REFRESH_INTERVAL,
        DEFAULT_PROFILE_REFRESH_INTERVAL,
    );
    // Never burst stale scheduled probes after a slow probe or executor pause.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval
}

trait ProfileRefreshClock: Send {
    fn tick(&mut self) -> impl Future<Output = ()> + Send;
}

impl ProfileRefreshClock for tokio::time::Interval {
    async fn tick(&mut self) {
        self.tick().await;
    }
}

async fn refresh_profiles<F>(
    active: tokio::sync::watch::Sender<Arc<DestProfile>>,
    dest: String,
    mut probe: impl FnMut(String) -> F + Send,
    mut clock: impl ProfileRefreshClock,
) where
    F: Future<Output = Result<DestProfile, umbra_reality::RealityError>> + Send,
{
    loop {
        clock.tick().await;
        // Sequential awaits allow only one in-flight probe. The backend already
        // bounds blocking workers and enforces a total deadline.
        if let Ok(profile) = probe(dest.clone()).await {
            active.send_replace(Arc::new(profile));
        }
        // Retain the last good value on failure; do not log destinations or errors.
    }
}

/// Run a server until Ctrl-C after probing the configured destination.
pub async fn run_server(cfg: RuntimeServerCfg) -> Result<(), CoreError> {
    let runtime = ServerRuntime::bind_with_probe(cfg, |dest: String| async move {
        umbra_reality::prebuild::probe_dest(&dest).await
    })
    .await?;
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

fn require_http1_spider(alpn: Option<&[u8]>) -> Result<(), CoreError> {
    if alpn.is_none_or(|protocol| protocol == b"http/1.1") {
        Ok(())
    } else {
        Err(CoreError::InvalidConfig(
            "RealSite negotiated unsupported spider protocol",
        ))
    }
}

async fn open_tcp_outer(cfg: &ClientCfg) -> Result<tokio::io::DuplexStream, CoreError> {
    tokio::time::timeout(DEFAULT_OUTER_CONNECT_TIMEOUT, open_tcp_outer_inner(cfg))
        .await
        .map_err(|_| CoreError::IdleTimeout("outer TCP connection setup"))?
}

async fn open_tcp_outer_inner(cfg: &ClientCfg) -> Result<tokio::io::DuplexStream, CoreError> {
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
    let verifier = RealityCertVerifier {
        shared,
        session_id,
        mldsa_verify: cfg.mldsa_verify.clone(),
        server_name: cfg.server_name.clone(),
    };
    let out = loop {
        let record = read_required_tls_record(&mut stream).await?;
        let out = tls_client.drive(&record, &verifier)?;
        if out.complete {
            break out;
        }
    };
    stream.write_all(&out.outbound).await?;
    stream.flush().await?;
    match out.peer_kind {
        Some(TlsPeerKind::UmbraTrusted) => Ok(spawn_tls_app_io(
            stream,
            TlsAppEndpoint::Client(Box::new(tls_client)),
        )),
        Some(TlsPeerKind::RealSite) => {
            require_http1_spider(tls_client.negotiated_alpn())?;
            let tls_io = spawn_tls_app_io(stream, TlsAppEndpoint::Client(Box::new(tls_client)));
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

/// Deterministic inputs used by tests and the runtime to build one QUIC Initial.
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

/// Hybrid X25519 plus ML-KEM material needed to later decapsulate TLS secrets.
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

/// Certificate verifier used by the TCP outer runtime after REALITY auth.
struct RealityCertVerifier {
    shared: Secret<32>,
    session_id: [u8; 32],
    mldsa_verify: Vec<u8>,
    server_name: String,
}

impl CertVerify for RealityCertVerifier {
    fn verify(&self, leaf_der: &[u8], chain: &[Vec<u8>]) -> TlsPeerKind {
        match classify_peer_certificate(
            leaf_der,
            self.shared.expose_secret(),
            &self.session_id,
            &self.mldsa_verify,
            true,
        ) {
            RealityPeerKind::UmbraTrusted => TlsPeerKind::UmbraTrusted,
            RealityPeerKind::RealSite
                if umbra_reality::cert::verify_site_certificate(
                    leaf_der,
                    chain,
                    &self.server_name,
                ) =>
            {
                TlsPeerKind::RealSite
            }
            RealityPeerKind::RealSite | RealityPeerKind::Invalid => TlsPeerKind::Invalid,
        }
    }
}

async fn dispatch_runtime_with_connector<C, D, Connect, ConnectFuture>(
    mut conn: C,
    cfg: &crate::dispatch::ServerCfg,
    profile: &DestProfile,
    replay: &ReplayCache,
    now_unix: u64,
    mut connect_dest_or_target: Connect,
    timing: crate::probe::TimingAlignment,
    padding_scheme: &PadScheme,
) -> Result<DispatchOutcome, CoreError>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Connect: FnMut(String) -> ConnectFuture + Send,
    ConnectFuture: Future<Output = Result<D, std::io::Error>> + Send + 'static,
{
    let chello_raw = read_client_hello_raw(&mut conn, cfg.hello_limits).await?;
    let started_at = tokio::time::Instant::now();
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
            let tls_io = spawn_tls_app_io(
                conn,
                TlsAppEndpoint::Server(Box::new(authenticated.tls_server)),
            );
            let server_flight_len = authenticated.server_flight.len();
            relay_one_server_inner_stream(
                tls_io,
                connect_dest_or_target,
                padding_scheme,
                DEFAULT_SESSION_IDLE_TIMEOUT,
            )
            .await?;
            Ok(DispatchOutcome::Authenticated {
                sni: authenticated.sni,
                server_flight_len,
            })
        }
        DispatchDecision::Fallback { reason, chello_raw } => {
            let mut dest = connect_dest_or_target(cfg.dest.clone()).await?;
            write_fallback_prefix(&mut dest, &chello_raw).await?;
            let (client_to_dest, dest_to_client) = Box::pin(relay_bidirectional_until_idle(
                &mut conn,
                &mut dest,
                DEFAULT_SESSION_IDLE_TIMEOUT,
            ))
            .await?;
            Ok(DispatchOutcome::Forwarded {
                reason,
                client_to_dest,
                dest_to_client,
            })
        }
    }
}

/// Receive one kernel batch while retaining the datagram stride (UDP GRO).
async fn receive_quic_datagrams(
    socket: &dyn quinn::AsyncUdpSocket,
    buf: &mut [u8],
) -> io::Result<(quinn::udp::RecvMeta, usize)> {
    let mut meta = [quinn::udp::RecvMeta::default()];
    std::future::poll_fn(|cx| socket.poll_recv(cx, &mut [IoSliceMut::new(buf)], &mut meta)).await?;
    Ok((meta[0], meta[0].len))
}

/// CID aliases have a fixed lifetime (the flow) and a fixed storage budget.
#[derive(Default)]
struct QuicFlowCids {
    values: Mutex<Vec<Vec<u8>>>,
    exhausted: tokio::sync::Notify,
    fallback: std::sync::atomic::AtomicBool,
}

impl QuicFlowCids {
    fn register(&self, cid: &[u8]) -> bool {
        let Ok(mut values) = self.values.lock() else {
            return false;
        };
        if values.iter().any(|known| known == cid) {
            return true;
        }
        if cid.len() > 20 || values.len() == QUIC_FLOW_MAX_CIDS {
            return false;
        }
        values.push(cid.to_vec());
        true
    }
}

struct QuicFlowRoute {
    peer: SocketAddr,
    original: Option<Vec<u8>>,
    cids: Arc<QuicFlowCids>,
    sender: mpsc::Sender<Vec<u8>>,
}

struct QuicFlowInbox {
    peer: SocketAddr,
    receiver: mpsc::Receiver<Vec<u8>>,
    cids: Arc<QuicFlowCids>,
}

impl QuicFlowRoute {
    fn new(peer: SocketAddr, datagram: &[u8]) -> (Self, QuicFlowInbox) {
        let (sender, receiver) = mpsc::channel(QUIC_FLOW_QUEUE_CAPACITY);
        let cids = Arc::new(QuicFlowCids::default());
        let original = quic_long_header_cids(datagram).map(|(dcid, _)| dcid.to_vec());
        if let Some(cid) = &original {
            cids.register(cid);
        }
        (
            Self {
                peer,
                original,
                cids: Arc::clone(&cids),
                sender,
            },
            QuicFlowInbox {
                peer,
                receiver,
                cids,
            },
        )
    }
}

enum QuicRouteMatch<'a> {
    Existing(&'a mpsc::Sender<Vec<u8>>),
    New,
    Ambiguous,
}

// Only inspect invariant long-header fields; malformed bytes still enter fallback.
fn quic_long_header_cids(datagram: &[u8]) -> Option<(&[u8], &[u8])> {
    if datagram.first()? & 0x80 == 0 {
        return None;
    }
    let dcid_len = usize::from(*datagram.get(5)?);
    if dcid_len > 20 {
        return None;
    }
    let dcid = datagram.get(6..6 + dcid_len)?;
    let scid_len = usize::from(*datagram.get(6 + dcid_len)?);
    if scid_len > 20 {
        return None;
    }
    Some((dcid, datagram.get(7 + dcid_len..7 + dcid_len + scid_len)?))
}

fn route_quic_datagram<'a>(
    routes: &'a HashMap<tokio::task::Id, QuicFlowRoute>,
    peer: SocketAddr,
    datagram: &[u8],
) -> QuicRouteMatch<'a> {
    let long = quic_long_header_cids(datagram);
    let short = datagram.first().is_some_and(|byte| byte & 0x80 == 0);
    let mut matched = None;
    let mut opaque = None;
    let mut fallback = None;
    let mut peer_flows = 0;
    for route in routes.values().filter(|route| route.peer == peer) {
        peer_flows += 1;
        if route
            .cids
            .fallback
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            fallback = Some(&route.sender);
        }
        let Ok(cids) = route.cids.values.lock() else {
            return QuicRouteMatch::Ambiguous;
        };
        let owns_cid = cids.iter().any(|cid| match long {
            Some((dcid, _)) => cid == dcid,
            None => short && !cid.is_empty() && datagram[1..].starts_with(cid),
        });
        if owns_cid {
            if matched.is_some() {
                return QuicRouteMatch::Ambiguous;
            }
            matched = Some(&route.sender);
        }
        if route.original.is_none() {
            opaque = Some(&route.sender);
        }
    }
    if let Some(sender) = matched {
        return QuicRouteMatch::Existing(sender);
    }
    if long.is_none() {
        // Upstream NEW_CONNECTION_ID frames are encrypted in fallback. A sole
        // fallback flow can retain peer routing; never guess between flows.
        if peer_flows == 1 {
            if let Some(sender) = opaque.or(if short { fallback } else { None }) {
                return QuicRouteMatch::Existing(sender);
            }
        }
        // No address migration or rebinding is inferred from CID ownership.
        if short && peer_flows > 0 || opaque.is_some() {
            return QuicRouteMatch::Ambiguous;
        }
    }
    QuicRouteMatch::New
}

/// Register every randomly issued CID before Quinn can transmit it. Retain aliases
/// until flow exit; close an authenticated connection if the finite budget fills.
struct RoutedCidGenerator {
    inner: quinn_proto::RandomConnectionIdGenerator,
    cids: Arc<QuicFlowCids>,
}

impl quinn_proto::ConnectionIdGenerator for RoutedCidGenerator {
    fn generate_cid(&mut self) -> quinn_proto::ConnectionId {
        let cid = self.inner.generate_cid();
        if !self.cids.register(&cid) {
            self.cids.exhausted.notify_one();
        }
        cid
    }

    fn cid_len(&self) -> usize {
        self.inner.cid_len()
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

/// Context kept together while dispatching one server-side QUIC flow.
struct QuicRuntimeDispatch<'a> {
    client_socket: &'a UdpSocket,
    endpoint_socket: Arc<dyn quinn::AsyncUdpSocket>,
    cfg: &'a crate::dispatch::ServerCfg,
    profile: &'a DestProfile,
    replay: &'a ReplayCache,
    now_unix: u64,
    timing: crate::probe::TimingAlignment,
    idle_timeout: Duration,
}

/// Buffered QUIC datagrams plus the contiguous ClientHello recovered from CRYPTO frames.
struct QuicPrefetchedClientHello {
    datagrams: Vec<Vec<u8>>,
    client_hello: Vec<u8>,
    scid: Vec<u8>,
    dcid_len: usize,
}

/// Result of prefetching enough QUIC Initial data for local authentication.
enum QuicPrefetchOutcome {
    Complete(QuicPrefetchedClientHello),
    Fallback {
        reason: FallbackReason,
        datagrams: Vec<Vec<u8>>,
    },
}

async fn dispatch_quic_runtime(
    datagram: Vec<u8>,
    mut inbox: QuicFlowInbox,
    ctx: QuicRuntimeDispatch<'_>,
    streams: &mut JoinSet<Result<(), CoreError>>,
) -> Result<QuicRuntimeOutcome, CoreError> {
    let started_at = tokio::time::Instant::now();
    let prefetched =
        prefetch_quic_client_hello(datagram, &mut inbox.receiver, ctx.idle_timeout).await;
    let prefetched = match prefetched {
        QuicPrefetchOutcome::Complete(prefetched) => prefetched,
        QuicPrefetchOutcome::Fallback { reason, datagrams } => {
            let (client_to_dest, dest_to_client) = relay_quic_fallback_until_idle(
                ctx.client_socket,
                &mut inbox,
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
            Box::pin(run_authenticated_quic_stream(
                ctx.endpoint_socket,
                inbox,
                prefetched.datagrams,
                prefetched.dcid_len,
                ctx.idle_timeout,
                AuthenticatedQuicRuntime {
                    sni: authenticated.sni,
                    session_id: authenticated.session_id,
                    shared_secret: authenticated.shared_secret,
                    client_hello: authenticated.client_hello,
                    profile: ctx.profile.clone(),
                    mldsa_seed: Secret::new(*ctx.cfg.mldsa_seed.expose_secret()),
                },
                streams,
            ))
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
                &mut inbox,
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
    receiver: &mut mpsc::Receiver<Vec<u8>>,
    idle_timeout: Duration,
) -> QuicPrefetchOutcome {
    let header = parse_quic_initial_header(&first_datagram);
    let mut datagrams = vec![first_datagram];
    let mut frames = BTreeMap::new();
    // A total classification deadline prevents slow fragment trickles from
    // retaining pre-authentication state indefinitely.
    let deadline = tokio::time::Instant::now() + idle_timeout;
    if let Ok(header) = header {
        while let Some(last) = datagrams.last() {
            if collect_quic_crypto_datagram(&mut frames, last).is_err() {
                break;
            }
            match complete_prefetched_quic_client_hello(&frames) {
                Ok(Some(client_hello)) => {
                    return QuicPrefetchOutcome::Complete(QuicPrefetchedClientHello {
                        datagrams,
                        client_hello,
                        scid: header.scid,
                        dcid_len: header.dcid.len(),
                    });
                }
                Ok(None) => {}
                // Conflicting overlaps, bad handshake types and oversize
                // declarations must retain bytes for transparent forwarding.
                Err(_) => break,
            }
            if datagrams.len() == QUIC_PREFETCH_MAX_DATAGRAMS {
                break;
            }
            match tokio::time::timeout_at(deadline, receiver.recv()).await {
                Ok(Some(datagram)) => datagrams.push(datagram),
                Ok(None) | Err(_) => break,
            }
        }
    }
    QuicPrefetchOutcome::Fallback {
        reason: FallbackReason::MalformedClientHello,
        datagrams,
    }
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

/// Authenticated QUIC values passed from dispatch into the quinn server runtime.
struct AuthenticatedQuicRuntime {
    sni: String,
    session_id: [u8; 32],
    shared_secret: Secret<32>,
    client_hello: Vec<u8>,
    profile: DestProfile,
    mldsa_seed: Secret<32>,
}

async fn run_authenticated_quic_stream(
    endpoint_socket: Arc<dyn quinn::AsyncUdpSocket>,
    inbox: QuicFlowInbox,
    initial_datagrams: Vec<Vec<u8>>,
    local_cid_len: usize,
    drain_timeout: Duration,
    authenticated: AuthenticatedQuicRuntime,
    streams: &mut JoinSet<Result<(), CoreError>>,
) -> Result<(), CoreError> {
    let runtime = quinn::default_runtime()
        .ok_or_else(|| CoreError::Quic("no async runtime available for QUIC".to_owned()))?;
    let cids = Arc::clone(&inbox.cids);
    let socket = Arc::new(PrefetchedUdpSocket {
        inner: endpoint_socket,
        peer: inbox.peer,
        pending: Mutex::new(QuicSocketQueue {
            prefetched: initial_datagrams.into(),
            receiver: inbox.receiver,
        }),
    });
    let mut server_config = quic_crypto::server_config(quic_crypto::AuthenticatedServerCrypto {
        sni: authenticated.sni,
        session_id: authenticated.session_id,
        shared_secret: authenticated.shared_secret,
        client_hello: authenticated.client_hello,
        profile: authenticated.profile,
        mldsa_seed: authenticated.mldsa_seed,
    });
    server_config.migration(false);
    let mut endpoint_config = quinn::EndpointConfig::default();
    let issued_cids = Arc::clone(&cids);
    endpoint_config.cid_generator(move || {
        Box::new(RoutedCidGenerator {
            inner: quinn_proto::RandomConnectionIdGenerator::new(local_cid_len.max(8)),
            cids: Arc::clone(&issued_cids),
        })
    });
    let endpoint = QuicEndpointGuard(
        quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            socket,
            runtime,
        )
        .map_err(quic_error)?,
    );
    let connection = tokio::time::timeout(drain_timeout, async {
        let incoming = endpoint
            .0
            .accept()
            .await
            .ok_or_else(|| CoreError::Quic("QUIC endpoint closed before accept".to_owned()))?;
        incoming.await.map_err(quic_error)
    })
    .await
    .map_err(|_| CoreError::IdleTimeout("server QUIC handshake"))??;
    loop {
        tokio::select! {
            () = cids.exhausted.notified() => {
                return Err(CoreError::Quic("QUIC CID budget exhausted".to_owned()));
            }
            _ = connection.closed() => break,
            joined = streams.join_next(), if !streams.is_empty() => {
                // One failed target must not terminate other streams or associations.
                report_session_result("server QUIC stream", joined);
            }
            accepted = connection.accept_bi(), if streams.len() < QUIC_MAX_STREAMS => {
                let Ok((send, recv)) = accepted else { break };
                streams.spawn(async move {
                    Box::pin(run_quic_accepted_bi_stream(send, recv, drain_timeout)).await
                });
            }
        }
    }
    Ok(())
}

// Quinn spawns its own driver: close explicitly even when dispatch is cancelled.
struct QuicEndpointGuard(quinn::Endpoint);

impl Drop for QuicEndpointGuard {
    fn drop(&mut self) {
        self.0.close(0_u32.into(), b"");
    }
}

async fn run_quic_accepted_bi_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    drain_timeout: Duration,
) -> Result<(), CoreError> {
    let mut first = [0_u8; 1];
    tokio::time::timeout(
        drain_timeout,
        AsyncReadExt::read_exact(&mut recv, &mut first),
    )
    .await
    .map_err(|_| CoreError::IdleTimeout("server QUIC stream opening"))??;
    if first[0] == QUIC_UDP_ASSOCIATE_MARKER {
        Box::pin(relay_quic_server_udp_association(send, recv, drain_timeout)).await?;
    } else {
        let mut recv = PrefixedStream::new(vec![first[0]], recv);
        let target = tokio::time::timeout(drain_timeout, read_target_stream(&mut recv))
            .await
            .map_err(|_| CoreError::IdleTimeout("server QUIC target header"))??;
        let target_io = tokio::time::timeout(
            DEFAULT_OUTER_CONNECT_TIMEOUT,
            crate::target_connect::connect_tcp_target(target_to_host_port(&target)),
        )
        .await
        .map_err(|_| CoreError::IdleTimeout("server QUIC target connect"))??;
        Box::pin(relay_quic_server_stream(target_io, send, recv)).await?;
    }
    Ok(())
}

async fn relay_quic_server_stream(
    target: TcpStream,
    mut send: quinn::SendStream,
    mut recv: impl AsyncRead + Unpin,
) -> Result<(), CoreError> {
    let (mut target_read, mut target_write) = tokio::io::split(target);
    let client_to_target = async {
        Box::pin(copy_until_idle(
            &mut recv,
            &mut target_write,
            DEFAULT_SESSION_IDLE_TIMEOUT,
        ))
        .await?;
        target_write.shutdown().await?;
        Ok::<(), CoreError>(())
    };
    let target_to_client = async {
        Box::pin(copy_until_idle(
            &mut target_read,
            &mut send,
            DEFAULT_SESSION_IDLE_TIMEOUT,
        ))
        .await?;
        send.shutdown().await?;
        Ok::<(), CoreError>(())
    };
    let _ = tokio::try_join!(client_to_target, target_to_client)?;
    Ok(())
}

async fn relay_quic_server_udp_association(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    idle_timeout: Duration,
) -> Result<(), CoreError> {
    let (tx, mut rx) = mpsc::channel(UDP_RELAY_CHANNEL_CAPACITY);
    let mut targets = HashMap::new();
    let mut envelopes = umbra_transport::quic::UdpEnvelopeReader::default();

    loop {
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            () = &mut idle => return Err(CoreError::IdleTimeout("server QUIC UDP association")),
            envelope = envelopes.read_next(&mut recv) => {
                let envelope = match envelope {
                    Ok(envelope) => envelope,
                    Err(umbra_transport::TransportError::Io(err))
                        if is_association_closed_io(&err) => return Ok(()),
                    Err(err) => return Err(err.into()),
                };
                send_udp_to_target(
                    &mut targets,
                    &tx,
                    UdpRelayDatagram {
                        target: envelope.target,
                        payload: envelope.payload,
                    },
                )
                .await?;
            }
            reply = rx.recv() => {
                let Some(reply) = reply else {
                    return Ok(());
                };
                write_udp_envelope_stream(&mut send, &reply.target, &reply.payload).await?;
            }
        }
    }
}

async fn relay_bidirectional_until_idle<A, B>(
    left: &mut A,
    right: &mut B,
    idle_timeout: Duration,
) -> Result<(u64, u64), CoreError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut left_open = true;
    let mut right_open = true;
    let mut left_to_right = 0_u64;
    let mut right_to_left = 0_u64;
    let mut left_buf = vec![0_u8; 16 * 1024];
    let mut right_buf = vec![0_u8; 16 * 1024];

    while left_open || right_open {
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            () = &mut idle => return Err(CoreError::IdleTimeout("bidirectional relay")),
            read = left.read(&mut left_buf), if left_open => {
                let read = read?;
                if read == 0 {
                    left_open = false;
                    timeout_write_shutdown(right, idle_timeout).await?;
                } else {
                    timeout_write_all(right, &left_buf[..read], idle_timeout).await?;
                    left_to_right = add_io_byte_count(left_to_right, read)?;
                }
            }
            read = right.read(&mut right_buf), if right_open => {
                let read = read?;
                if read == 0 {
                    right_open = false;
                    timeout_write_shutdown(left, idle_timeout).await?;
                } else {
                    timeout_write_all(left, &right_buf[..read], idle_timeout).await?;
                    right_to_left = add_io_byte_count(right_to_left, read)?;
                }
            }
        }
    }

    Ok((left_to_right, right_to_left))
}

async fn copy_until_idle<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle_timeout: Duration,
) -> Result<u64, CoreError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut copied = 0_u64;
    let mut buf = vec![0_u8; 16 * 1024];
    loop {
        let read = tokio::time::timeout(idle_timeout, reader.read(&mut buf))
            .await
            .map_err(|_| CoreError::IdleTimeout("copy read"))??;
        if read == 0 {
            return Ok(copied);
        }
        timeout_write_all(writer, &buf[..read], idle_timeout).await?;
        copied = add_io_byte_count(copied, read)?;
    }
}

async fn timeout_write_all<W>(
    writer: &mut W,
    buf: &[u8],
    idle_timeout: Duration,
) -> Result<(), CoreError>
where
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout(idle_timeout, writer.write_all(buf))
        .await
        .map_err(|_| CoreError::IdleTimeout("relay write"))??;
    Ok(())
}

async fn timeout_write_shutdown<W>(writer: &mut W, idle_timeout: Duration) -> Result<(), CoreError>
where
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout(idle_timeout, writer.shutdown())
        .await
        .map_err(|_| CoreError::IdleTimeout("relay shutdown"))??;
    Ok(())
}

fn add_io_byte_count(total: u64, increment: usize) -> Result<u64, CoreError> {
    total
        .checked_add(
            u64::try_from(increment)
                .map_err(|_| CoreError::InvalidConfig("relay byte count is too large"))?,
        )
        .ok_or(CoreError::InvalidConfig("relay byte count overflows"))
}

struct QuicSocketQueue {
    prefetched: VecDeque<Vec<u8>>,
    receiver: mpsc::Receiver<Vec<u8>>,
}

/// Quinn receives only replayed datagrams and its bounded per-flow queue.
/// The physical socket wrapper delegates sends, never receives.
struct PrefetchedUdpSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    peer: SocketAddr,
    pending: Mutex<QuicSocketQueue>,
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
        let Some(buf) = bufs.first_mut() else {
            return Poll::Ready(Err(io::Error::other("QUIC receive buffer missing")));
        };
        let Some(meta) = meta.first_mut() else {
            return Poll::Ready(Err(io::Error::other("QUIC receive metadata missing")));
        };
        let datagram = match self.pending.lock() {
            Ok(mut queue) => match queue.prefetched.pop_front() {
                Some(datagram) => datagram,
                None => match queue.receiver.poll_recv(cx) {
                    Poll::Ready(Some(datagram)) => datagram,
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "QUIC flow queue closed",
                        )));
                    }
                },
            },
            Err(_) => return Poll::Ready(Err(io::Error::other("QUIC queue lock poisoned"))),
        };
        if buf.len() < datagram.len() {
            return Poll::Ready(Err(io::Error::other("QUIC datagram buffer too small")));
        }
        buf[..datagram.len()].copy_from_slice(&datagram);
        *meta = quinn::udp::RecvMeta {
            addr: self.peer,
            len: datagram.len(),
            stride: datagram.len(),
            ecn: None,
            dst_ip: None,
        };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

async fn relay_quic_fallback_until_idle(
    client_socket: &UdpSocket,
    inbox: &mut QuicFlowInbox,
    initial_datagrams: Vec<Vec<u8>>,
    dest: &str,
    idle_timeout: Duration,
) -> Result<(u64, u64), CoreError> {
    if initial_datagrams.is_empty() {
        return Err(CoreError::InvalidConfig(
            "QUIC fallback requires at least one datagram",
        ));
    }
    inbox
        .cids
        .fallback
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let dest = tokio::time::timeout(idle_timeout, tokio::net::lookup_host(dest))
        .await
        .map_err(|_| CoreError::IdleTimeout("QUIC fallback resolution"))??
        .next()
        .ok_or(CoreError::InvalidConfig("QUIC destination did not resolve"))?;
    let bind = if dest.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let upstream = UdpSocket::bind(bind).await?;
    upstream.connect(dest).await?;
    let mut client_to_dest = 0_u64;
    for datagram in initial_datagrams {
        upstream.send(&datagram).await?;
        client_to_dest = add_quic_byte_count(client_to_dest, datagram.len())?;
    }
    let mut dest_to_client = 0_u64;
    let mut upstream_buf = vec![0_u8; 65_535];

    loop {
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            () = &mut idle => return Ok((client_to_dest, dest_to_client)),
            received = inbox.receiver.recv() => {
                let Some(datagram) = received else {
                    return Ok((client_to_dest, dest_to_client));
                };
                upstream.send(&datagram).await?;
                client_to_dest = add_quic_byte_count(client_to_dest, datagram.len())?;
            }
            received = upstream.recv(&mut upstream_buf) => {
                let read = received?;
                if let Some((_, scid)) = quic_long_header_cids(&upstream_buf[..read]) {
                    // Learn cleartext upstream CIDs before forwarding the response.
                    // Encrypted NEW_CONNECTION_ID cannot be inspected in fallback;
                    // unknown/ambiguous CIDs must never select a different flow.
                    inbox.cids.register(scid);
                }
                client_socket.send_to(&upstream_buf[..read], inbox.peer).await?;
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
    mut connect_target: Connect,
    padding_scheme: &PadScheme,
    idle_timeout: Duration,
) -> Result<(), CoreError>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Connect: FnMut(String) -> ConnectFuture + Send,
    ConnectFuture: Future<Output = Result<D, std::io::Error>> + Send + 'static,
{
    let (mode, prefix) = read_inner_opening_mode(&mut tls_io).await?;
    let tls_io = PrefixedStream::new(prefix, tls_io);
    match mode {
        ServerInnerMode::Mux => {
            let mut mux = MuxSession::server(tls_io, padding_scheme)?;
            match mux.receive_next().await? {
                MuxEvent::Syn { stream_id, target } => {
                    let (driver, incoming) =
                        crate::mux_io::start_server_after_syn(mux, stream_id, target)?;
                    relay_mux_targets(driver, incoming, connect_target, idle_timeout).await
                }
                MuxEvent::UdpDatagram { target, payload } => {
                    Box::pin(relay_mux_server_udp_association(
                        mux,
                        Some(UdpRelayDatagram { target, payload }),
                        idle_timeout,
                    ))
                    .await
                }
                _ => Err(CoreError::InvalidConfig("unexpected mux opening frame")),
            }
        }
        ServerInnerMode::VisionSolo => {
            let mut solo = tls_io;
            let target = read_solo_preface(&mut solo).await?;
            let target_io = connect_target(target_to_host_port(&target)).await?;
            let mut solo = solo;
            let mut target_io = target_io;
            Box::pin(relay_bidirectional_until_idle(
                &mut solo,
                &mut target_io,
                idle_timeout,
            ))
            .await?;
            Ok(())
        }
    }
}

async fn relay_mux_targets<D, Connect, ConnectFuture>(
    driver: crate::mux_io::MuxDriver,
    mut incoming: crate::mux_io::ServerMux,
    mut connect_target: Connect,
    idle_timeout: Duration,
) -> Result<(), CoreError>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Connect: FnMut(String) -> ConnectFuture + Send,
    ConnectFuture: Future<Output = Result<D, io::Error>> + Send + 'static,
{
    let mut streams = JoinSet::new();
    let result = loop {
        tokio::select! {
            () = tokio::time::sleep(idle_timeout), if streams.is_empty() => {
                break Err(CoreError::IdleTimeout("server mux connection"));
            }
            joined = streams.join_next(), if !streams.is_empty() => {
                report_session_result("server mux", joined);
            }
            pending = incoming.accept(), if streams.len() < umbra_inner::mux::MAX_STREAMS => {
                let Ok(pending) = pending else {
                    break Ok(());
                };
                let connect = connect_target(target_to_host_port(&pending.target));
                streams.spawn(async move {
                    let mut target = match tokio::time::timeout(DEFAULT_OUTER_CONNECT_TIMEOUT, connect).await {
                        Ok(Ok(target)) => target,
                        Ok(Err(error)) => {
                            pending.reject();
                            return Err(CoreError::from(error));
                        }
                        Err(_) => {
                            pending.reject();
                            return Err(CoreError::IdleTimeout("mux target setup"));
                        }
                    };
                    let mut stream = pending.accept().await?;
                    relay_bidirectional_until_idle(&mut target, &mut stream, idle_timeout).await?;
                    Ok(())
                });
            }
        }
    };
    abort_all(&mut streams).await;
    driver.shutdown().await;
    result
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
/// Opening mode selected after sniffing the first authenticated inner bytes.
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
        Ok(MuxCommand::Padding | MuxCommand::UdpDatagram) => stream_id == 0,
        Ok(_) | Err(_) => false,
    }
}

#[derive(Debug, Clone)]
struct UdpRelayDatagram {
    target: TargetAddr,
    payload: Vec<u8>,
}

/// Per-target UDP socket task that is aborted when the association drops.
struct UdpTargetState {
    socket: Arc<UdpSocket>,
    task: JoinHandle<()>,
}

impl Drop for UdpTargetState {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn relay_mux_server_udp_association<IO>(
    mut mux: MuxSession<IO>,
    first: Option<UdpRelayDatagram>,
    idle_timeout: Duration,
) -> Result<(), CoreError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let (tx, mut rx) = mpsc::channel(UDP_RELAY_CHANNEL_CAPACITY);
    let mut targets = HashMap::new();
    if let Some(datagram) = first {
        send_udp_to_target(&mut targets, &tx, datagram).await?;
    }

    loop {
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            () = &mut idle => return Err(CoreError::IdleTimeout("server mux UDP association")),
            event = mux.receive_next() => {
                let event = match event {
                    Ok(event) => event,
                    Err(umbra_inner::InnerError::Io(err))
                        if is_association_closed_io(&err) => return Ok(()),
                    Err(err) => return Err(err.into()),
                };
                match event {
                    MuxEvent::UdpDatagram { target, payload } => {
                        send_udp_to_target(
                            &mut targets,
                            &tx,
                            UdpRelayDatagram { target, payload },
                        )
                        .await?;
                    }
                    MuxEvent::Fin { .. } | MuxEvent::Rst { .. } => return Ok(()),
                    _ => {}
                }
            }
            reply = rx.recv() => {
                let Some(reply) = reply else {
                    return Ok(());
                };
                mux.send_udp_datagram(&reply.target, &reply.payload).await?;
            }
        }
    }
}

async fn send_udp_to_target(
    targets: &mut HashMap<TargetAddr, UdpTargetState>,
    tx: &mpsc::Sender<UdpRelayDatagram>,
    datagram: UdpRelayDatagram,
) -> Result<(), CoreError> {
    if !targets.contains_key(&datagram.target) {
        if targets.len() >= MAX_UDP_TARGETS_PER_ASSOCIATION {
            return Ok(());
        }
        let state = connect_udp_target(datagram.target.clone(), tx.clone()).await?;
        targets.insert(datagram.target.clone(), state);
    }
    if let Some(state) = targets.get(&datagram.target) {
        state.socket.send(&datagram.payload).await?;
    }
    Ok(())
}

async fn connect_udp_target(
    target: TargetAddr,
    tx: mpsc::Sender<UdpRelayDatagram>,
) -> Result<UdpTargetState, CoreError> {
    let resolved = resolve_target_socket_addr(&target).await?;
    let bind_addr = if resolved.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    socket.connect(resolved).await?;
    let reader = Arc::clone(&socket);
    let task = tokio::spawn(async move {
        let mut buf = vec![0_u8; UDP_RELAY_BUF_LEN];
        while let Ok(read) = reader.recv(&mut buf).await {
            let datagram = UdpRelayDatagram {
                target: target.clone(),
                payload: buf[..read].to_vec(),
            };
            if tx.send(datagram).await.is_err() {
                break;
            }
        }
    });
    Ok(UdpTargetState { socket, task })
}

async fn resolve_target_socket_addr(target: &TargetAddr) -> Result<SocketAddr, CoreError> {
    match target {
        TargetAddr::Ipv4(addr, port) => Ok(SocketAddr::new(IpAddr::V4(*addr), *port)),
        TargetAddr::Ipv6(addr, port) => Ok(SocketAddr::new(IpAddr::V6(*addr), *port)),
        TargetAddr::Domain(domain, port) => tokio::net::lookup_host((domain.as_str(), *port))
            .await?
            .next()
            .ok_or(CoreError::InvalidConfig("UDP target did not resolve")),
    }
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::{timeout, Duration},
    };

    use super::*;

    mod profile_refresh {
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::sync::{mpsc, oneshot};
        use umbra_reality::{prebuild::CertTemplate, RealityError};

        const TEST_TIMEOUT: Duration = Duration::from_secs(5);
        type ProbeReply = oneshot::Sender<Result<DestProfile, RealityError>>;

        struct ManualClock {
            ticks: mpsc::UnboundedReceiver<()>,
            waiting: mpsc::UnboundedSender<()>,
        }

        impl ProfileRefreshClock for ManualClock {
            async fn tick(&mut self) {
                self.waiting.send(()).expect("clock observed");
                self.ticks.recv().await.expect("clock remains owned");
            }
        }

        struct Control {
            ticks: mpsc::UnboundedSender<()>,
            waiting: mpsc::UnboundedReceiver<()>,
            probes: mpsc::UnboundedReceiver<ProbeReply>,
        }

        impl Control {
            async fn idle(&mut self) {
                receive(&mut self.waiting).await;
            }

            async fn probe(&mut self) -> ProbeReply {
                self.ticks.send(()).expect("advance clock");
                receive(&mut self.probes).await
            }
        }

        async fn receive<T>(receiver: &mut mpsc::UnboundedReceiver<T>) -> T {
            timeout(TEST_TIMEOUT, receiver.recv())
                .await
                .expect("bounded notification")
                .expect("sender alive")
        }

        fn config(prebuild: bool) -> RuntimeServerCfg {
            RuntimeServerCfg {
                listen: "127.0.0.1:0".parse().expect("loopback TCP"),
                udp_listen: Some("127.0.0.1:0".parse().expect("loopback UDP")),
                private_key: x25519::generate_keypair().private,
                short_ids: vec![vec![1]],
                dest: "127.0.0.1:9".to_owned(),
                server_names: vec!["refresh.example".to_owned()],
                max_time_diff: Duration::from_mins(2),
                mldsa_seed: Secret::new([3; 32]),
                prebuild,
                padding_scheme: PadScheme::none(),
                tcp_evasion: TcpEvasionPolicy::Off,
            }
        }

        fn profile(dest: String, generation: u8) -> DestProfile {
            DestProfile {
                dest,
                tls_ver: 0x0304,
                cipher: 0x1301,
                group: 0x001d,
                alpn: vec![b"h2".to_vec()],
                ee_exts: vec![0x0010],
                leaf_template: CertTemplate {
                    subject: "CN=refresh.example".to_owned(),
                    issuer: "CN=Local Fixture".to_owned(),
                    not_before_unix: 1_700_000_000,
                    not_after_unix: 2_000_000_000,
                    san_dns: vec!["refresh.example".to_owned()],
                    sct: Vec::new(),
                    signature_algorithm: "ecdsa-with-SHA256".to_owned(),
                    leaf_der: Vec::new(),
                },
                ocsp: Some(vec![generation]),
                rtt: Duration::from_millis(u64::from(generation)),
            }
        }

        async fn controlled(cfg: RuntimeServerCfg) -> (Arc<ServerRuntime>, Control) {
            let (ticks, tick_rx) = mpsc::unbounded_channel();
            let (waiting, wait_rx) = mpsc::unbounded_channel();
            let (probes, probe_rx) = mpsc::unbounded_channel();
            let initial = profile(cfg.dest.clone(), 1);
            let runtime = ServerRuntime::bind_with_refresh(
                cfg,
                initial,
                ProbeResistancePolicy::default(),
                move |active, dest| {
                    let expected_dest = dest.clone();
                    refresh_profiles(
                        active,
                        dest,
                        move |dest| {
                            assert_eq!(dest, expected_dest);
                            let (reply, result) = oneshot::channel();
                            probes.send(reply).expect("probe observed");
                            async move { result.await.expect("probe result supplied") }
                        },
                        ManualClock {
                            ticks: tick_rx,
                            waiting,
                        },
                    )
                },
            )
            .await
            .expect("bind controlled runtime");
            (
                Arc::new(runtime),
                Control {
                    ticks,
                    waiting: wait_rx,
                    probes: probe_rx,
                },
            )
        }

        fn start(runtime: &Arc<ServerRuntime>) -> (oneshot::Sender<()>, JoinHandle<()>) {
            let (stop, stopped) = oneshot::channel();
            let runtime = Arc::clone(runtime);
            let task = tokio::spawn(async move {
                runtime
                    .run_until_shutdown(async {
                        let _ = stopped.await;
                    })
                    .await
                    .expect("runtime shutdown");
            });
            (stop, task)
        }

        async fn stop(stop: oneshot::Sender<()>, task: JoinHandle<()>) {
            stop.send(()).expect("signal shutdown");
            timeout(TEST_TIMEOUT, task)
                .await
                .expect("bounded shutdown")
                .expect("join runtime");
        }

        async fn wait_for_refs(profile: &Arc<DestProfile>, expected: usize) {
            timeout(TEST_TIMEOUT, async {
                while Arc::strong_count(profile) != expected {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("session captures profile");
        }

        #[tokio::test]
        async fn startup_probe_failure_prevents_binding_in_both_modes() {
            for enabled in [false, true] {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("occupied port");
                let mut cfg = config(enabled);
                cfg.listen = listener.local_addr().expect("local address");
                let dest = cfg.dest.clone();
                let calls = AtomicUsize::new(0);
                let result = ServerRuntime::bind_with_probe(cfg, |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Err(RealityError::ProbeFailed("controlled startup failure")))
                })
                .await;
                let Err(err) = result else {
                    panic!("startup must fail");
                };
                assert!(matches!(
                    err,
                    CoreError::Reality(RealityError::ProbeFailed(_))
                ));
                assert!(!err.to_string().contains(&dest));
                assert_eq!(calls.load(Ordering::SeqCst), 1);
            }
        }

        #[tokio::test]
        async fn run_server_rejects_local_failed_tls_probe() {
            let upstream = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("local probe target");
            let mut cfg = config(false);
            cfg.dest = upstream.local_addr().expect("target address").to_string();
            let target = tokio::spawn(async move {
                let (stream, _) = upstream.accept().await.expect("startup probe connects");
                drop(stream);
            });
            let result = timeout(TEST_TIMEOUT, run_server(cfg))
                .await
                .expect("startup bounded");
            assert!(matches!(
                result,
                Err(CoreError::Reality(RealityError::ProbeFailed(_)))
            ));
            target.await.expect("local target joined");
        }

        #[tokio::test]
        async fn disabled_keeps_successful_startup_profile_without_periodic_work() {
            let calls = AtomicUsize::new(0);
            let runtime = ServerRuntime::bind_with_probe(config(false), |dest| {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(profile(dest, 1)))
            })
            .await
            .expect("startup succeeds");
            let initial = runtime.profile_snapshot();
            assert!(!runtime.prebuild_enabled());
            assert!(runtime.profile_refresh.lock().expect("tasks").is_empty());
            runtime
                .run_until_shutdown(async {})
                .await
                .expect("shutdown");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(Arc::ptr_eq(&initial, &runtime.profile_snapshot()));

            let (runtime, mut control) = controlled(config(false)).await;
            assert!(
                control.ticks.send(()).is_err(),
                "no periodic clock retained"
            );
            assert!(
                control.probes.recv().await.is_none(),
                "no periodic probe retained"
            );
            assert!(runtime.profile_refresh.lock().expect("tasks").is_empty());
        }

        #[tokio::test]
        async fn hourly_schedule_delays_first_tick_and_skips_missed_ticks() {
            let mut interval = profile_refresh_interval();
            assert_eq!(interval.period(), Duration::from_hours(1));
            assert_eq!(
                interval.missed_tick_behavior(),
                tokio::time::MissedTickBehavior::Skip
            );
            let pending =
                std::future::poll_fn(|cx| Poll::Ready(interval.poll_tick(cx).is_pending())).await;
            assert!(
                pending,
                "startup profile must not trigger an immediate second probe"
            );
            let mut immediate = tokio::time::interval(DEFAULT_PROFILE_REFRESH_INTERVAL);
            timeout(TEST_TIMEOUT, ProfileRefreshClock::tick(&mut immediate))
                .await
                .expect("production clock implementation ticks");
        }

        #[tokio::test]
        async fn refresh_replaces_future_tcp_and_quic_snapshots_only() {
            let (runtime, mut control) = controlled(config(true)).await;
            control.idle().await;
            assert!(matches!(
                control.probes.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            let old = runtime.profile_snapshot();
            let (shutdown, task) = start(&runtime);
            let tcp = TcpStream::connect(runtime.local_addr().expect("TCP address"))
                .await
                .expect("first TCP handshake");
            wait_for_refs(&old, 3).await;
            let socket = runtime.udp_socket.as_ref().expect("QUIC enabled");
            let (_, inbox) = QuicFlowRoute::new("127.0.0.1:1234".parse().expect("peer"), b"");
            let (_stop_flow, stopping) = tokio::sync::watch::channel(false);
            let quic = runtime.quic_flow(socket, Vec::new(), inbox, TEST_TIMEOUT, stopping);
            assert_eq!(Arc::strong_count(&old), 4, "QUIC snapshots before polling");

            let refreshed = profile(old.dest.clone(), 2);
            control
                .probe()
                .await
                .send(Ok(refreshed.clone()))
                .expect("successful refresh");
            control.idle().await;
            let new = runtime.profile_snapshot();
            assert_eq!(*new, refreshed);
            assert!(!Arc::ptr_eq(&old, &new));
            assert_eq!(old.ocsp, Some(vec![1]));
            assert_eq!(
                Arc::strong_count(&old),
                3,
                "existing sessions retain old profile"
            );
            let tcp_after = TcpStream::connect(runtime.local_addr().expect("TCP address"))
                .await
                .expect("next TCP handshake");
            wait_for_refs(&new, 3).await;
            let (_, inbox) = QuicFlowRoute::new("127.0.0.1:1235".parse().expect("peer"), b"");
            let (_stop_flow_after, stopping) = tokio::sync::watch::channel(false);
            let quic_after = runtime.quic_flow(socket, Vec::new(), inbox, TEST_TIMEOUT, stopping);
            assert_eq!(
                Arc::strong_count(&new),
                4,
                "future QUIC flow takes new profile"
            );
            drop((quic, quic_after));
            stop(shutdown, task).await;
            drop((tcp, tcp_after));
            assert_eq!(Arc::strong_count(&old), 1);
            assert_eq!(Arc::strong_count(&new), 2);
            assert!(control.ticks.send(()).is_err(), "shutdown releases clock");
        }

        #[tokio::test]
        async fn convenience_tcp_accept_keeps_snapshot_during_refresh() {
            let (runtime, mut control) = controlled(config(true)).await;
            control.idle().await;
            let old = runtime.profile_snapshot();
            let accepting = Arc::clone(&runtime);
            let task = tokio::spawn(async move {
                accepting
                    .accept_one_with_connector(|_| {
                        std::future::ready(Err::<tokio::io::DuplexStream, _>(io::Error::other(
                            "unused test connector",
                        )))
                    })
                    .await
            });
            let client = TcpStream::connect(runtime.local_addr().expect("TCP address"))
                .await
                .expect("TCP connects");
            wait_for_refs(&old, 3).await;
            control
                .probe()
                .await
                .send(Ok(profile(old.dest.clone(), 2)))
                .expect("refresh succeeds without supervisor");
            control.idle().await;
            assert_eq!(
                Arc::strong_count(&old),
                2,
                "in-flight accept retains snapshot"
            );
            assert_eq!(runtime.profile_snapshot().ocsp, Some(vec![2]));
            task.abort();
            assert!(task.await.expect_err("accept cancelled").is_cancelled());
            assert_eq!(Arc::strong_count(&old), 1);
            drop(client);
            runtime
                .run_until_shutdown(async {})
                .await
                .expect("shutdown");
        }

        #[tokio::test]
        async fn failed_refresh_retains_last_good_and_next_success_recovers() {
            let (runtime, mut control) = controlled(config(true)).await;
            control.idle().await;
            let old = runtime.profile_snapshot();
            control
                .probe()
                .await
                .send(Err(RealityError::ProbeFailed("controlled failure")))
                .expect("failed result supplied");
            control.idle().await;
            assert!(Arc::ptr_eq(&old, &runtime.profile_snapshot()));
            let replacement = profile(old.dest.clone(), 3);
            control
                .probe()
                .await
                .send(Ok(replacement.clone()))
                .expect("recovery supplied");
            control.idle().await;
            assert_eq!(*runtime.profile_snapshot(), replacement);
            assert_eq!(old.ocsp, Some(vec![1]));
            runtime
                .run_until_shutdown(async {})
                .await
                .expect("shutdown");
            assert!(control.ticks.send(()).is_err());
        }

        #[tokio::test]
        async fn stalled_refresh_is_single_flight_accepts_progress_and_shutdown_cancels_it() {
            let upstream = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("loopback target");
            let udp_upstream = UdpSocket::bind(upstream.local_addr().expect("target address"))
                .await
                .expect("loopback QUIC target");
            let mut cfg = config(true);
            cfg.dest = upstream.local_addr().expect("target address").to_string();
            let (runtime, mut control) = controlled(cfg).await;
            control.idle().await;
            let pending = control.probe().await;
            control.ticks.send(()).expect("queue another interval");
            let (shutdown, task) = start(&runtime);
            timeout(TEST_TIMEOUT, async {
                let client = async {
                    let mut stream = TcpStream::connect(runtime.local_addr().expect("address"))
                        .await
                        .expect("accept remains responsive");
                    stream.write_all(b"not TLS").await.expect("send fallback");
                    stream.shutdown().await.expect("client half close");
                    let mut reply = Vec::new();
                    stream
                        .read_to_end(&mut reply)
                        .await
                        .expect("fallback reply");
                    assert_eq!(reply, b"local reply");
                };
                let target = async {
                    let (mut stream, _) = upstream.accept().await.expect("fallback target");
                    let mut request = Vec::new();
                    stream
                        .read_to_end(&mut request)
                        .await
                        .expect("fallback request");
                    assert_eq!(request, b"not TLS");
                    stream
                        .write_all(b"local reply")
                        .await
                        .expect("target reply");
                };
                tokio::join!(client, target);
                let udp = UdpSocket::bind("127.0.0.1:0").await.expect("UDP client");
                udp.connect(
                    runtime
                        .udp_local_addr()
                        .expect("UDP address")
                        .expect("QUIC enabled"),
                )
                .await
                .expect("UDP connects");
                udp.send(b"opaque QUIC").await.expect("UDP request");
                let mut buf = [0; 64];
                let (len, peer) = udp_upstream
                    .recv_from(&mut buf)
                    .await
                    .expect("UDP forwarded");
                assert_eq!(&buf[..len], b"opaque QUIC");
                udp_upstream
                    .send_to(b"UDP reply", peer)
                    .await
                    .expect("UDP target reply");
                let len = udp.recv(&mut buf).await.expect("UDP response forwarded");
                assert_eq!(&buf[..len], b"UDP reply");
            })
            .await
            .expect("accepts progress while refresh stalls");
            assert!(matches!(
                control.probes.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                control.waiting.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            stop(shutdown, task).await;
            assert!(
                pending.is_closed(),
                "shutdown joined cancelled probe future"
            );
            assert!(control.ticks.send(()).is_err(), "no worker after shutdown");
            assert!(control.probes.recv().await.is_none());
            assert!(runtime.profile_refresh.lock().expect("tasks").is_empty());
            assert_eq!(runtime.profile_snapshot().ocsp, Some(vec![1]));
        }

        #[tokio::test]
        async fn dropping_bound_runtime_aborts_refresh_without_accept_loop() {
            let (runtime, mut control) = controlled(config(true)).await;
            control.idle().await;
            let mut pending = control.probe().await;
            drop(runtime);
            timeout(TEST_TIMEOUT, pending.closed())
                .await
                .expect("drop cancels owned task");
            assert!(control.ticks.send(()).is_err());
            assert!(control.probes.recv().await.is_none());
        }
    }

    struct MuxPoolFixture {
        created: std::sync::atomic::AtomicUsize,
        silent_outers: usize,
        drivers: Mutex<Vec<crate::mux_io::MuxDriver>>,
        tasks: Mutex<Vec<JoinHandle<()>>>,
        accepted: mpsc::UnboundedSender<crate::mux_io::MuxIo>,
        peers: tokio::sync::Mutex<mpsc::UnboundedReceiver<crate::mux_io::MuxIo>>,
    }

    impl MuxPoolFixture {
        fn new(silence_first: bool) -> Self {
            Self::with_silent_outers(usize::from(silence_first))
        }

        fn with_silent_outers(silent_outers: usize) -> Self {
            let (accepted, peers) = mpsc::unbounded_channel();
            Self {
                created: std::sync::atomic::AtomicUsize::new(0),
                silent_outers,
                drivers: Mutex::new(Vec::new()),
                tasks: Mutex::new(Vec::new()),
                accepted,
                peers: tokio::sync::Mutex::new(peers),
            }
        }

        async fn session(&self) -> Result<MuxSession<tokio::io::DuplexStream>, CoreError> {
            let index = self.created.fetch_add(1, Ordering::SeqCst);
            // Exercise contention while an outer is being established, before publication.
            tokio::task::yield_now().await;
            let (local, peer) = tokio::io::duplex(1024 * 1024);
            let mut session = MuxSession::server(peer, &PadScheme::none())?;
            let task = if index < self.silent_outers {
                tokio::spawn(async move {
                    let MuxEvent::Syn { stream_id, .. } = session.receive_next().await.unwrap()
                    else {
                        panic!("expected first SYN");
                    };
                    session.queue_accept(stream_id).unwrap();
                    session.flush_pending().await.unwrap();
                    std::future::pending::<()>().await;
                    drop(session);
                })
            } else {
                let (driver, mut incoming) = crate::mux_io::start_server(session)?;
                self.drivers.lock().unwrap().push(driver);
                let accepted = self.accepted.clone();
                tokio::spawn(async move {
                    let mut delayed = Vec::new();
                    while let Ok(pending) = incoming.accept().await {
                        if pending.target == mux_test_target(2) {
                            pending.reject();
                        } else if pending.target == mux_test_target(3) {
                            delayed.push(pending);
                        } else if let Ok(stream) = pending.accept().await {
                            let _ = accepted.send(stream);
                        }
                    }
                })
            };
            self.tasks.lock().unwrap().push(task);
            MuxSession::client(local, &PadScheme::none()).map_err(CoreError::from)
        }

        async fn peer(&self) -> crate::mux_io::MuxIo {
            self.peers.lock().await.recv().await.unwrap()
        }
    }

    impl Drop for MuxPoolFixture {
        fn drop(&mut self) {
            for task in self.tasks.get_mut().unwrap().iter() {
                task.abort();
            }
        }
    }

    fn mux_test_target(port: u16) -> TargetAddr {
        TargetAddr::Ipv4(Ipv4Addr::LOCALHOST, port)
    }

    async fn pool_test_open(
        pool: &ClientConnections,
        fixture: &MuxPoolFixture,
        port: u16,
    ) -> Result<crate::mux_io::MuxIo, CoreError> {
        pool.reserve_mux(|| fixture.session())
            .await?
            .open(
                mux_test_target(port),
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .await
            .map_err(CoreError::from)
    }

    async fn retain_one_draining_stream(
        pool: &ClientConnections,
        fixture: &MuxPoolFixture,
    ) -> (crate::mux_io::MuxIo, crate::mux_io::ClientMux) {
        let held = pool_test_open(pool, fixture, 1).await.unwrap();
        let handle = pool.mux.lock().await.last().unwrap().1.clone();
        let reservation = pool.reserve_mux(|| fixture.session()).await.unwrap();
        let error = reservation
            .open(
                mux_test_target(1),
                Duration::from_secs(1),
                Duration::from_millis(20),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(handle.is_healthy());
        assert!(!handle.is_accepting());
        assert!(handle.draining_since().is_some());
        (held, handle)
    }

    #[tokio::test]
    async fn scenario_four_draining_outers_with_one_stream_each_allow_recovery() {
        timeout(Duration::from_secs(5), async {
            let pool = ClientConnections::default();
            let fixture = MuxPoolFixture::with_silent_outers(4);
            let mut held = Vec::new();
            for _ in 0..4 {
                held.push(retain_one_draining_stream(&pool, &fixture).await);
            }
            assert_eq!(pool.mux.lock().await.len(), 4);
            let _new = pool_test_open(&pool, &fixture, 1).await.unwrap();
            assert_eq!(fixture.created.load(Ordering::SeqCst), 5);
            assert_eq!(pool.mux.lock().await.len(), 5);
            assert_eq!(
                pool.mux
                    .lock()
                    .await
                    .iter()
                    .filter(|(_, handle)| handle.is_accepting())
                    .count(),
                1
            );
            assert!(
                held.iter().all(|(_, handle)| handle.is_healthy()),
                "spare retirement slots preserve old streams"
            );
            pool.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn scenario_full_retirement_budget_evicts_only_oldest_draining_outer() {
        timeout(Duration::from_secs(5), async {
            let pool = ClientConnections::default();
            let fixture = MuxPoolFixture::with_silent_outers(4);
            let mut old = Vec::new();
            for _ in 0..4 {
                old.push(retain_one_draining_stream(&pool, &fixture).await);
            }
            let mut healthy = Vec::new();
            for _ in 0..127 {
                healthy.push(pool_test_open(&pool, &fixture, 1).await.unwrap());
            }
            let last_slot = pool.reserve_mux(|| fixture.session()).await.unwrap();
            assert_eq!(fixture.created.load(Ordering::SeqCst), MAX_MUX_TOTAL_OUTERS);
            let handles = pool.mux.lock().await;
            assert_eq!(handles.len(), MAX_MUX_TOTAL_OUTERS);
            assert_eq!(
                handles
                    .iter()
                    .filter(|(_, handle)| handle.is_accepting())
                    .count(),
                MAX_MUX_OUTERS
            );
            let newer = handles.last().unwrap().1.clone();
            drop(handles);
            let error = pool
                .reserve_mux_with_timeout(|| fixture.session(), Duration::from_millis(10))
                .await
                .err()
                .unwrap();
            assert!(matches!(
                error,
                CoreError::IdleTimeout("mux pool admission")
            ));
            assert!(old.iter().all(|(_, handle)| handle.is_healthy()));
            // Stop admission on one newer outer. The remaining three accepting
            // outers are full, so recovery now needs a slot at the total bound.
            assert!(last_slot
                .open(
                    mux_test_target(3),
                    Duration::from_secs(1),
                    Duration::from_millis(30),
                )
                .await
                .is_err());
            assert!(!newer.is_accepting());
            let _replacement = pool_test_open(&pool, &fixture, 1).await.unwrap();
            assert_eq!(
                fixture.created.load(Ordering::SeqCst),
                MAX_MUX_TOTAL_OUTERS + 1
            );
            assert_eq!(pool.mux.lock().await.len(), MAX_MUX_TOTAL_OUTERS);
            assert_eq!(
                pool.mux
                    .lock()
                    .await
                    .iter()
                    .filter(|(_, handle)| handle.is_accepting())
                    .count(),
                MAX_MUX_OUTERS
            );
            assert!(!old[0].1.is_healthy());
            assert!(old[0].0.write(b"must not replay").await.is_err());
            assert!(old[1..].iter().all(|(_, handle)| handle.is_healthy()));
            assert!(
                newer.is_healthy(),
                "newer draining streams retain their owner"
            );
            healthy[0].write_all(b"live").await.unwrap();
            let mut peer = fixture.peer().await;
            let mut bytes = [0; 4];
            peer.read_exact(&mut bytes).await.unwrap();
            assert_eq!(
                &bytes, b"live",
                "healthy accepting siblings survive retirement"
            );
            pool.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn scenario_tcp_mux_pool_reserves_capacity_and_deduplicates_concurrent_setup() {
        timeout(Duration::from_secs(5), async {
            let pool = Arc::new(ClientConnections::default());
            let fixture = Arc::new(MuxPoolFixture::new(false));
            let mut requests = JoinSet::new();
            for _ in 0..40 {
                let pool = pool.clone();
                let fixture = fixture.clone();
                requests.spawn(async move { pool_test_open(&pool, &fixture, 1).await.unwrap() });
            }
            let mut held = Vec::new();
            while let Some(stream) = requests.join_next().await {
                held.push(stream.unwrap());
            }
            assert_eq!(held.len(), 40);
            assert_eq!(fixture.created.load(Ordering::SeqCst), 2);
            assert_eq!(pool.mux.lock().await.len(), 2);
            let mut peer = fixture.peer().await;
            peer.write_all(b"response").await.unwrap();
            // All forty SYN_ACKs completed without waiting for any held stream to close.
            pool.shutdown().await;
            assert!(pool.mux.lock().await.is_empty());
            for mut stream in held {
                assert!(stream.write(b"closed").await.is_err());
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn scenario_tcp_mux_pool_target_failure_preserves_sibling_and_reuse() {
        timeout(Duration::from_secs(5), async {
            let pool = ClientConnections::default();
            let fixture = MuxPoolFixture::new(false);
            let mut sibling = pool_test_open(&pool, &fixture, 1).await.unwrap();
            let mut peer = fixture.peer().await;
            assert!(pool_test_open(&pool, &fixture, 2).await.is_err());
            let handles = pool.mux.lock().await;
            assert_eq!(handles.len(), 1);
            assert!(handles[0].1.is_accepting());
            drop(handles);
            sibling.write_all(b"live").await.unwrap();
            let mut received = [0; 4];
            peer.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"live");
            let _later = pool_test_open(&pool, &fixture, 1).await.unwrap();
            assert_eq!(fixture.created.load(Ordering::SeqCst), 1);
            pool.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn scenario_tcp_mux_pool_stalled_outer_drains_without_aborting_sibling() {
        timeout(Duration::from_secs(5), async {
            let pool = ClientConnections::default();
            let fixture = MuxPoolFixture::new(true);
            let sibling = pool_test_open(&pool, &fixture, 1).await.unwrap();
            let old = pool.mux.lock().await[0].1.clone();
            let reservation = pool.reserve_mux(|| fixture.session()).await.unwrap();
            let error = reservation
                .open(
                    mux_test_target(1),
                    Duration::from_secs(1),
                    Duration::from_millis(30),
                )
                .await
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(error.to_string().contains("acknowledgement"));
            assert!(old.is_healthy());
            assert!(!old.is_accepting());
            let _replacement = pool_test_open(&pool, &fixture, 1).await.unwrap();
            assert_eq!(fixture.created.load(Ordering::SeqCst), 2);
            assert!(
                old.is_healthy(),
                "existing sibling is not aborted by replacement"
            );
            drop(sibling);
            let _next = pool_test_open(&pool, &fixture, 1).await.unwrap();
            assert!(!old.is_healthy(), "idle draining outer is now reclaimed");
            assert_eq!(pool.mux.lock().await.len(), 1);
            pool.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn scenario_tcp_mux_pool_replaces_closed_outer_without_replaying_payload() {
        timeout(Duration::from_secs(5), async {
            let pool = ClientConnections::default();
            let fixture = MuxPoolFixture::new(false);
            let mut first = pool_test_open(&pool, &fixture, 1).await.unwrap();
            let mut first_peer = fixture.peer().await;
            first.write_all(b"before").await.unwrap();
            let mut before = [0; 6];
            first_peer.read_exact(&mut before).await.unwrap();
            assert_eq!(&before, b"before");
            let old = pool.mux.lock().await[0].1.clone();
            let server = fixture.drivers.lock().unwrap().pop().unwrap();
            server.shutdown().await;
            while old.is_healthy() {
                tokio::task::yield_now().await;
            }
            assert!(first.write(b"not replayed").await.is_err());
            let mut next = pool_test_open(&pool, &fixture, 1).await.unwrap();
            let mut next_peer = fixture.peer().await;
            next.write_all(b"after").await.unwrap();
            let mut after = [0; 5];
            next_peer.read_exact(&mut after).await.unwrap();
            assert_eq!(&after, b"after");
            assert_eq!(fixture.created.load(Ordering::SeqCst), 2);
            assert_eq!(pool.mux.lock().await.len(), 1);
            pool.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn scenario_tcp_mux_pool_shutdown_wakes_capacity_and_establishment_waiters() {
        timeout(Duration::from_secs(5), async {
            let pool = Arc::new(ClientConnections::default());
            let fixture = Arc::new(MuxPoolFixture::new(false));
            let mut reservations = Vec::new();
            for _ in 0..128 {
                reservations.push(pool.reserve_mux(|| fixture.session()).await.unwrap());
            }
            assert_eq!(fixture.created.load(Ordering::SeqCst), MAX_MUX_OUTERS);
            let waiting_pool = pool.clone();
            let waiting_fixture = fixture.clone();
            let waiter = tokio::spawn(async move {
                waiting_pool.reserve_mux(|| waiting_fixture.session()).await
            });
            tokio::task::yield_now().await;
            assert!(!waiter.is_finished());
            pool.shutdown().await;
            assert!(waiter.await.unwrap().is_err());
            assert!(pool.mux.lock().await.is_empty());
            drop(reservations);

            let pool = Arc::new(ClientConnections::default());
            let (started, ready) = tokio::sync::oneshot::channel();
            let opening_pool = pool.clone();
            let pending = tokio::spawn(async move {
                let mut started = Some(started);
                opening_pool.reserve_mux(|| {
                    started.take().unwrap().send(()).unwrap();
                    std::future::pending::<Result<MuxSession<tokio::io::DuplexStream>, CoreError>>()
                }).await
            });
            ready.await.unwrap();
            pool.shutdown().await;
            assert!(pending.await.unwrap().is_err());
            assert!(pool.mux.lock().await.is_empty());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn scenario_mux_setup_failure_returns_a_socks_failure_reply() {
        timeout(Duration::from_secs(5), async {
            let (mut cfg, _server) = pooled_client_fixture().await;
            cfg.transport = TransportKind::Tcp;
            cfg.mux = true;
            cfg.server = "127.0.0.1:invalid".to_owned();
            let (mut client, mut socks) = tokio::io::duplex(64);
            let task =
                tokio::spawn(async move { client_session_from_config(&cfg, &mut socks).await });
            client.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            client
                .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
            assert!(task.await.unwrap().is_err());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn scenario_tcp_mux_pool_has_a_bounded_admission_queue() {
        timeout(Duration::from_secs(5), async {
            let pool = Arc::new(ClientConnections::default());
            let fixture = Arc::new(MuxPoolFixture::new(false));
            let mut held = Vec::new();
            for _ in 0..128 {
                held.push(pool.reserve_mux(|| fixture.session()).await.unwrap());
            }
            let capacity_error = pool
                .reserve_mux_with_timeout(|| fixture.session(), Duration::from_millis(10))
                .await
                .err()
                .unwrap();
            assert!(matches!(
                capacity_error,
                CoreError::IdleTimeout("mux pool admission")
            ));
            assert!(pool
                .mux
                .lock()
                .await
                .iter()
                .all(|(_, handle)| handle.is_accepting()));
            let mut waiting = JoinSet::new();
            for _ in 0..MAX_MUX_QUEUED_OPENS {
                let pool = pool.clone();
                let fixture = fixture.clone();
                waiting.spawn(async move { pool.reserve_mux(|| fixture.session()).await });
            }
            while pool.mux_waiters.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
            let error = pool.reserve_mux(|| fixture.session()).await.err().unwrap();
            assert!(
                matches!(error, CoreError::Io(error) if error.kind() == io::ErrorKind::WouldBlock)
            );
            assert_eq!(fixture.created.load(Ordering::SeqCst), MAX_MUX_OUTERS);
            pool.shutdown().await;
            while let Some(result) = waiting.join_next().await {
                assert!(result.unwrap().is_err());
            }
            assert_eq!(pool.mux_waiters.available_permits(), MAX_MUX_QUEUED_OPENS);
            drop(held);
        })
        .await
        .unwrap();
    }

    async fn pooled_client_fixture() -> (ClientCfg, ServerRuntime) {
        let key = x25519::generate_keypair();
        let seed = [0x4c; 32];
        let signing = umbra_crypto::mldsa::mldsa_keygen_from_seed(&seed);
        let mut cfg = ClientCfg {
            server: String::new(),
            transport: TransportKind::Quic,
            public_key: key.public,
            short_id: vec![1],
            server_name: "pool.example".to_owned(),
            fingerprint: "chrome-latest".to_owned(),
            mldsa_verify: signing.verifying_key,
            spider_path: "/".to_owned(),
            socks_listen: "127.0.0.1:0".parse().expect("loopback"),
            mux: true,
            padding_scheme: PadScheme::none(),
            tcp_evasion: TcpEvasionPolicy::Off,
        };
        let server_cfg = RuntimeServerCfg {
            listen: cfg.socks_listen,
            udp_listen: Some(cfg.socks_listen),
            private_key: key.private,
            short_ids: vec![cfg.short_id.clone()],
            dest: "pool.example:443".to_owned(),
            server_names: vec![cfg.server_name.clone()],
            max_time_diff: Duration::from_mins(2),
            mldsa_seed: Secret::new(seed),
            prebuild: false,
            padding_scheme: PadScheme::none(),
            tcp_evasion: TcpEvasionPolicy::Off,
        };
        let profile = DestProfile {
            dest: server_cfg.dest.clone(),
            tls_ver: 0x0304,
            cipher: 0x1301,
            group: 0x001d,
            alpn: vec![b"h2".to_vec()],
            ee_exts: vec![0x0010],
            leaf_template: umbra_reality::prebuild::CertTemplate {
                subject: "CN=pool.example".to_owned(),
                issuer: "CN=Synthetic Test CA".to_owned(),
                not_before_unix: 1_700_000_000,
                not_after_unix: 1_900_000_000,
                san_dns: vec![cfg.server_name.clone()],
                sct: Vec::new(),
                signature_algorithm: "ecdsa-with-SHA256".to_owned(),
                leaf_der: Vec::new(),
            },
            ocsp: None,
            rtt: Duration::ZERO,
        };
        let server =
            ServerRuntime::bind_with_profile(server_cfg, profile, ProbeResistancePolicy::default())
                .await
                .expect("server binds");
        cfg.server = server
            .udp_local_addr()
            .expect("UDP address")
            .expect("UDP listener")
            .to_string();
        (cfg, server)
    }

    #[tokio::test]
    async fn scenario_quic_pool_shares_establishment_and_replaces_only_closed_outer() {
        let (cfg, server) = pooled_client_fixture().await;
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            server
                .run_until_shutdown(async {
                    let _ = stopped.await;
                })
                .await
        });
        let pool = ClientConnections::default();
        let (first, second, third) = timeout(Duration::from_secs(5), async {
            tokio::try_join!(pool.quic(&cfg), pool.quic(&cfg), pool.quic(&cfg))
        })
        .await
        .expect("concurrent setup completes")
        .expect("authenticated connections");
        assert_eq!(first.stable_id(), second.stable_id());
        assert_eq!(first.stable_id(), third.stable_id());
        first.close(0_u32.into(), b"");
        assert!(second.close_reason().is_some());
        let replacement = timeout(Duration::from_secs(5), pool.quic(&cfg))
            .await
            .expect("replacement completes")
            .expect("new authenticated connection");
        assert_ne!(replacement.stable_id(), first.stable_id());
        let again = pool.quic(&cfg).await.expect("reuse replacement");
        assert_eq!(again.stable_id(), replacement.stable_id());
        pool.shutdown().await;
        assert!(replacement.close_reason().is_some());
        assert!(pool.quic.lock().await.is_none());
        stop.send(()).expect("stop server");
        timeout(Duration::from_secs(5), server)
            .await
            .expect("server stopped")
            .expect("server joins")
            .expect("server shutdown succeeds");
    }

    #[tokio::test]
    async fn scenario_quic_pool_failed_setup_does_not_publish_connection() {
        let (mut cfg, _server) = pooled_client_fixture().await;
        cfg.server = "127.0.0.1:invalid".to_owned();
        let pool = ClientConnections::default();
        assert!(pool.quic(&cfg).await.is_err());
        assert!(pool.quic.lock().await.is_none());
        pool.shutdown().await;
    }

    #[test]
    fn scenario_realsite_spider_requires_compatible_http_alpn() {
        assert!(require_http1_spider(None).is_ok());
        assert!(require_http1_spider(Some(b"http/1.1")).is_ok());
        for protocol in [b"h2".as_slice(), b"h3", b"", b"unknown"] {
            assert!(require_http1_spider(Some(protocol)).is_err());
        }
    }

    #[test]
    fn scenario_tcp_verifier_rejects_untrusted_ordinary_certificate() {
        let cert = rcgen::generate_simple_self_signed(vec!["site.example".to_owned()])
            .expect("synthetic certificate");
        let verifier = RealityCertVerifier {
            shared: Secret::new([1; 32]),
            session_id: [2; 32],
            mldsa_verify: Vec::new(),
            server_name: "site.example".to_owned(),
        };
        assert_eq!(verifier.verify(cert.cert.der(), &[]), TlsPeerKind::Invalid);
        assert_eq!(verifier.verify(b"bad DER", &[]), TlsPeerKind::Invalid);
    }

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
    async fn scenario_mux_driver_reports_closed_outer_to_new_opens() {
        let (client, server) = tokio::io::duplex(64);
        drop(server);
        let mux = MuxSession::client(client, &PadScheme::none()).expect("mux creates");
        let (driver, handle) = crate::mux_io::start_client(mux).expect("driver starts");
        assert!(timeout(
            Duration::from_secs(1),
            handle.open(TargetAddr::Ipv4(Ipv4Addr::LOCALHOST, 443),)
        )
        .await
        .expect("open wakes")
        .is_err());
        assert!(!handle.is_healthy());
        driver.shutdown().await;
    }

    #[tokio::test]
    async fn scenario_relay_bidirectional_reclaims_idle_connections() {
        let (mut left, _left_peer) = tokio::io::duplex(64);
        let (mut right, _right_peer) = tokio::io::duplex(64);

        let err = relay_bidirectional_until_idle(&mut left, &mut right, Duration::from_millis(10))
            .await
            .expect_err("idle relay times out");
        assert!(matches!(err, CoreError::IdleTimeout("bidirectional relay")));
    }

    #[tokio::test]
    async fn scenario_relay_bidirectional_timeout_is_idle_not_total_duration() {
        let (mut left, mut left_peer) = tokio::io::duplex(64);
        let (mut right, mut right_peer) = tokio::io::duplex(64);

        let relay = tokio::spawn(async move {
            relay_bidirectional_until_idle(&mut left, &mut right, Duration::from_millis(80)).await
        });
        left_peer
            .write_all(b"one")
            .await
            .expect("write first chunk");
        let mut observed = [0_u8; 3];
        right_peer
            .read_exact(&mut observed)
            .await
            .expect("read first chunk");
        assert_eq!(&observed, b"one");
        tokio::time::sleep(Duration::from_millis(40)).await;
        left_peer
            .write_all(b"two")
            .await
            .expect("write second chunk before idle timeout");
        right_peer
            .read_exact(&mut observed)
            .await
            .expect("read second chunk");
        assert_eq!(&observed, b"two");
        drop(left_peer);
        drop(right_peer);

        let (left_to_right, right_to_left) = timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay finishes")
            .expect("join relay")
            .expect("relay succeeds");
        assert_eq!(left_to_right, 6);
        assert_eq!(right_to_left, 0);
    }

    #[tokio::test]
    async fn scenario_server_inner_stream_accepts_vision_solo_preface() {
        let (mut client, server) = tokio::io::duplex(4096);
        let (target_io, mut target_peer) = tokio::io::duplex(4096);
        let target = TargetAddr::domain("solo.example", 443).expect("target");
        let server_task = tokio::spawn(async move {
            let mut target_io = Some(target_io);
            relay_one_server_inner_stream(
                server,
                |dest| {
                    assert_eq!(dest, "solo.example:443");
                    let io = target_io.take().expect("one solo target");
                    async move { Ok::<_, std::io::Error>(io) }
                },
                &PadScheme::none(),
                DEFAULT_SESSION_IDLE_TIMEOUT,
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
    async fn scenario_server_udp_multiple_targets_are_isolated() {
        let target_one_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind first UDP target");
        let target_two_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind second UDP target");
        let target_one = target_addr_from_udp_socket(&target_one_socket);
        let target_two = target_addr_from_udp_socket(&target_two_socket);
        let (tx, mut rx) = mpsc::channel(4);
        let mut targets = HashMap::new();

        send_udp_to_target(
            &mut targets,
            &tx,
            UdpRelayDatagram {
                target: target_one.clone(),
                payload: b"one".to_vec(),
            },
        )
        .await
        .expect("send first target datagram");
        let mut observed = [0_u8; 16];
        let (read, peer) = target_one_socket
            .recv_from(&mut observed)
            .await
            .expect("first target receives");
        assert_eq!(&observed[..read], b"one");
        target_one_socket
            .send_to(b"answer-one", peer)
            .await
            .expect("first target replies");
        let reply = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("receive first reply")
            .expect("first reply present");
        assert_eq!(reply.target, target_one);
        assert_eq!(reply.payload, b"answer-one");

        send_udp_to_target(
            &mut targets,
            &tx,
            UdpRelayDatagram {
                target: target_two.clone(),
                payload: b"two".to_vec(),
            },
        )
        .await
        .expect("send second target datagram");
        let (read, peer) = target_two_socket
            .recv_from(&mut observed)
            .await
            .expect("second target receives");
        assert_eq!(&observed[..read], b"two");
        target_two_socket
            .send_to(b"answer-two", peer)
            .await
            .expect("second target replies");
        let reply = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("receive second reply")
            .expect("second reply present");
        assert_eq!(reply.target, target_two);
        assert_eq!(reply.payload, b"answer-two");
        assert_eq!(targets.len(), 2);
    }

    #[tokio::test]
    async fn scenario_server_udp_target_limit_is_enforced() {
        let shared_socket = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind shared UDP socket"),
        );
        let (tx, _rx) = mpsc::channel(1);
        let mut targets = HashMap::new();
        for index in 0..MAX_UDP_TARGETS_PER_ASSOCIATION {
            let port = u16::try_from(index + 1).expect("target index fits port");
            let task = tokio::spawn(async {});
            targets.insert(
                TargetAddr::Ipv4(Ipv4Addr::LOCALHOST, port),
                UdpTargetState {
                    socket: Arc::clone(&shared_socket),
                    task,
                },
            );
        }
        let overflow_target = TargetAddr::Ipv4(Ipv4Addr::LOCALHOST, u16::MAX);

        send_udp_to_target(
            &mut targets,
            &tx,
            UdpRelayDatagram {
                target: overflow_target.clone(),
                payload: b"drop".to_vec(),
            },
        )
        .await
        .expect("overflow target is dropped cleanly");

        assert_eq!(targets.len(), MAX_UDP_TARGETS_PER_ASSOCIATION);
        assert!(!targets.contains_key(&overflow_target));
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

    mod quic_lifecycle {
        use super::*;
        use quinn::AsyncUdpSocket;
        use quinn_proto::ConnectionIdGenerator;
        use umbra_crypto::{mldsa::mldsa_keygen_from_seed, secret::Secret};
        use umbra_reality::prebuild::CertTemplate;

        const TEST_TIMEOUT: Duration = Duration::from_secs(5);

        async fn server(dest: SocketAddr) -> (Arc<ServerRuntime>, ClientCfg) {
            let key = x25519::generate_keypair();
            let public_key = key.public;
            let signing = mldsa_keygen_from_seed(&[3; 32]);
            let cfg = RuntimeServerCfg {
                listen: "127.0.0.1:0".parse().expect("TCP bind"),
                udp_listen: Some("127.0.0.1:0".parse().expect("UDP bind")),
                private_key: key.private,
                short_ids: vec![vec![1, 2, 3]],
                dest: dest.to_string(),
                server_names: vec!["quic.example".to_owned()],
                max_time_diff: Duration::from_mins(2),
                mldsa_seed: Secret::new([3; 32]),
                prebuild: false,
                padding_scheme: PadScheme::none(),
                tcp_evasion: TcpEvasionPolicy::Off,
            };
            let profile = DestProfile {
                dest: dest.to_string(),
                tls_ver: 0x0304,
                cipher: 0x1301,
                group: 0x001d,
                alpn: vec![b"h3".to_vec()],
                ee_exts: vec![0x0010],
                leaf_template: CertTemplate {
                    subject: "CN=quic.example".to_owned(),
                    issuer: "CN=Loopback CA".to_owned(),
                    not_before_unix: 1_700_000_000,
                    not_after_unix: 2_000_000_000,
                    san_dns: vec!["quic.example".to_owned()],
                    sct: Vec::new(),
                    signature_algorithm: "ecdsa-with-SHA256".to_owned(),
                    leaf_der: Vec::new(),
                },
                ocsp: None,
                rtt: Duration::ZERO,
            };
            let runtime = Arc::new(
                ServerRuntime::bind_with_profile(cfg, profile, ProbeResistancePolicy::default())
                    .await
                    .expect("bind runtime"),
            );
            let cfg = ClientCfg {
                server: runtime
                    .udp_local_addr()
                    .expect("address")
                    .expect("UDP")
                    .to_string(),
                transport: TransportKind::Quic,
                public_key,
                short_id: vec![1, 2, 3],
                server_name: "quic.example".to_owned(),
                fingerprint: "chrome-latest".to_owned(),
                mldsa_verify: signing.verifying_key,
                spider_path: "/".to_owned(),
                socks_listen: "127.0.0.1:0".parse().expect("SOCKS address"),
                mux: false,
                padding_scheme: PadScheme::none(),
                tcp_evasion: TcpEvasionPolicy::Off,
            };
            (runtime, cfg)
        }

        fn start(
            runtime: &Arc<ServerRuntime>,
        ) -> (tokio::sync::oneshot::Sender<()>, JoinHandle<()>) {
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let runtime = Arc::clone(runtime);
            let task = tokio::spawn(async move {
                runtime
                    .run_until_shutdown(async {
                        let _ = stopped.await;
                    })
                    .await
                    .expect("runtime stops");
            });
            (stop, task)
        }

        async fn client(runtime: &ServerRuntime) -> UdpSocket {
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
            client
                .connect(runtime.udp_local_addr().expect("address").expect("UDP"))
                .await
                .expect("client connect");
            client
        }

        async fn authenticated_connection(cfg: &ClientCfg) -> (quinn::Endpoint, quinn::Connection) {
            let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("bind"))
                .expect("client endpoint");
            endpoint.set_default_client_config(quic_crypto::client_config(cfg).expect("crypto"));
            let connection = endpoint
                .connect(cfg.server.parse().expect("server"), &cfg.server_name)
                .expect("connect")
                .await
                .expect("authenticated handshake");
            (endpoint, connection)
        }

        async fn open_tcp_target_stream(
            connection: &quinn::Connection,
            request: &[u8],
        ) -> (quinn::SendStream, quinn::RecvStream, TcpListener) {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("target");
            let target = TargetAddr::Ipv4(
                Ipv4Addr::LOCALHOST,
                listener.local_addr().expect("address").port(),
            );
            let (mut send, recv) = connection.open_bi().await.expect("target stream");
            write_target_stream(&mut send, &target, &[])
                .await
                .expect("target header");
            send.write_all(request).await.expect("target request");
            (send, recv, listener)
        }

        async fn closed_tcp_port() -> u16 {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("unused port");
            let port = listener.local_addr().expect("address").port();
            drop(listener);
            port
        }

        fn assert_released(runtime: &ServerRuntime) {
            let socket = runtime.udp_socket.as_ref().expect("QUIC socket");
            assert!(socket.receiver.try_lock().is_ok(), "receive lease released");
            assert_eq!(
                Arc::strong_count(&socket.dispatch),
                1,
                "flow send handles released"
            );
            assert_eq!(
                Arc::strong_count(&runtime.dispatch_cfg),
                1,
                "flow contexts released"
            );
        }

        fn initial(offset: u8, crypto: &[u8], dcid: [u8; 8]) -> Vec<u8> {
            assert!(offset < 64 && crypto.len() < 64);
            let keys = umbra_transport::quic::derive_initial_quinn_packet_keys(
                1,
                &dcid,
                quinn_proto::Side::Client,
            )
            .expect("Initial keys");
            let mut packet = vec![0xc3, 0, 0, 0, 1, 8];
            packet.extend_from_slice(&dcid);
            packet.push(8);
            packet.extend_from_slice(&[9; 8]);
            packet.push(0); // Empty token.
            let payload_len = u16::try_from(1200 - packet.len() - 2).expect("payload length");
            packet.extend_from_slice(&(0x4000 | payload_len).to_be_bytes());
            let pn_offset = packet.len();
            packet.extend_from_slice(&u32::from(offset).to_be_bytes());
            let header_len = packet.len();
            packet.extend_from_slice(&[
                6,
                offset,
                u8::try_from(crypto.len()).expect("CRYPTO length"),
            ]);
            packet.extend_from_slice(crypto);
            packet.resize(1200, 0);
            keys.packet
                .local
                .encrypt(u64::from(offset), &mut packet, header_len);
            keys.header.local.encrypt(pn_offset, &mut packet);
            packet
        }

        #[tokio::test]
        async fn simultaneous_fallback_peers_preserve_bytes_and_shutdown() {
            timeout(TEST_TIMEOUT, async {
                let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("upstream");
                let (runtime, _) = server(upstream.local_addr().expect("address")).await;
                let (stop, task) = start(&runtime);
                let first = client(&runtime).await;
                let second = client(&runtime).await;
                let mut peers = Vec::new();
                for round in 0..2 {
                    let a = vec![0, 1, round, 0xff, 0];
                    let b = vec![0, 2, round, 0xfe, 0];
                    first.send(&a).await.expect("first sends");
                    second.send(&b).await.expect("second sends");
                    let mut observed = Vec::new();
                    for _ in 0..2 {
                        let mut buf = [0; 64];
                        let (len, peer) = upstream
                            .recv_from(&mut buf)
                            .await
                            .expect("upstream receives");
                        observed.push(buf[..len].to_vec());
                        if round == 0 {
                            peers.push(peer);
                        }
                        upstream
                            .send_to(&buf[..len], peer)
                            .await
                            .expect("upstream replies");
                    }
                    observed.sort();
                    assert_eq!(observed, vec![a.clone(), b.clone()]);
                    let mut buf = [0; 64];
                    let len = first.recv(&mut buf).await.expect("first reply");
                    assert_eq!(&buf[..len], a);
                    let len = second.recv(&mut buf).await.expect("second reply");
                    assert_eq!(&buf[..len], b);
                }
                assert_ne!(peers[0], peers[1], "fallback upstreams are isolated");
                stop.send(()).expect("stop");
                task.await.expect("join");
                assert_released(&runtime);
            })
            .await
            .expect("bounded fallback test");
        }

        #[tokio::test]
        async fn same_peer_fallback_flows_route_upstream_issued_cids() {
            timeout(TEST_TIMEOUT, async {
                let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("destination");
                let (runtime, _) = server(upstream.local_addr().expect("address")).await;
                let (stop, task) = start(&runtime);
                let client = client(&runtime).await;
                let mut upstream_peers = Vec::new();
                let mut buf = [0; 2048];
                for cid in [1_u8, 2] {
                    let request = initial(0, b"\x01\x00\x00\x00", [cid; 8]);
                    client.send(&request).await.expect("Initial");
                    let (len, peer) = upstream
                        .recv_from(&mut buf)
                        .await
                        .expect("Initial forwarded");
                    assert_eq!(&buf[..len], request);
                    upstream_peers.push(peer);
                    let mut reply = vec![0xc0, 0, 0, 0, 1, 8];
                    reply.extend_from_slice(&[9; 8]);
                    reply.push(8);
                    reply.extend_from_slice(&[cid + 2; 8]);
                    upstream
                        .send_to(&reply, peer)
                        .await
                        .expect("issued source CID");
                    let len = client.recv(&mut buf).await.expect("Initial response");
                    assert_eq!(&buf[..len], reply);
                }
                assert_ne!(upstream_peers[0], upstream_peers[1]);
                for (index, cid) in [3_u8, 4].into_iter().enumerate() {
                    let mut short = vec![0x40];
                    short.extend_from_slice(&[cid; 8]);
                    short.extend_from_slice(b"application packet");
                    client.send(&short).await.expect("short header");
                    let (len, peer) = upstream
                        .recv_from(&mut buf)
                        .await
                        .expect("routed short header");
                    assert_eq!(&buf[..len], short);
                    assert_eq!(peer, upstream_peers[index]);
                }
                stop.send(()).expect("stop");
                task.await.expect("join");
                assert_released(&runtime);
            })
            .await
            .expect("bounded same-peer flow test");
        }

        #[tokio::test]
        async fn listener_flow_budget_preserves_existing_flows() {
            timeout(TEST_TIMEOUT, async {
                let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("destination");
                let (runtime, _) = server(upstream.local_addr().expect("address")).await;
                let (stop, task) = start(&runtime);
                let mut clients = Vec::new();
                let mut buf = [0; 32];
                for _ in 0..QUIC_MAX_FLOWS {
                    let client = client(&runtime).await;
                    client.send(b"occupy").await.expect("new flow");
                    let (len, _) = upstream.recv_from(&mut buf).await.expect("flow admitted");
                    assert_eq!(&buf[..len], b"occupy");
                    clients.push(client);
                }
                assert_eq!(Arc::strong_count(&runtime.dispatch_cfg), QUIC_MAX_FLOWS + 1);
                let overflow = client(&runtime).await;
                overflow.send(b"overflow").await.expect("over capacity");
                clients[0].send(b"existing").await.expect("existing flow");
                let (len, peer) = upstream
                    .recv_from(&mut buf)
                    .await
                    .expect("existing still relays");
                assert_eq!(&buf[..len], b"existing");
                upstream.send_to(b"alive", peer).await.expect("reply");
                let len = clients[0].recv(&mut buf).await.expect("existing reply");
                assert_eq!(&buf[..len], b"alive");
                assert!(
                    timeout(Duration::from_millis(20), upstream.recv_from(&mut buf))
                        .await
                        .is_err()
                );
                assert_eq!(Arc::strong_count(&runtime.dispatch_cfg), QUIC_MAX_FLOWS + 1);
                stop.send(()).expect("stop all flows");
                task.await.expect("join all flows");
                assert_released(&runtime);
            })
            .await
            .expect("bounded admission test");
        }

        #[tokio::test]
        async fn fragmented_initial_and_duplicates_survive_tcp_accepts() {
            timeout(TEST_TIMEOUT, async {
                let tcp = TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("TCP destination");
                let udp = UdpSocket::bind(tcp.local_addr().expect("address"))
                    .await
                    .expect("UDP destination");
                let (runtime, _) = server(udp.local_addr().expect("address")).await;
                let (stop, task) = start(&runtime);
                let quic = client(&runtime).await;
                let prefix = initial(0, b"\x01\x00\x00\x05he", [4; 8]);
                let suffix = initial(6, b"llo", [4; 8]);
                quic.send(&prefix).await.expect("fragment");
                quic.send(&prefix).await.expect("retransmit");
                // A second peer's fallback response is a receive-loop barrier.
                let other = client(&runtime).await;
                other.send(b"barrier").await.expect("other peer");
                let mut buf = [0; 2048];
                let (len, peer) = udp.recv_from(&mut buf).await.expect("other fallback");
                assert_eq!(&buf[..len], b"barrier");
                udp.send_to(b"ready", peer).await.expect("barrier reply");
                assert_eq!(other.recv(&mut buf).await.expect("barrier received"), 5);
                for _ in 0..3 {
                    let mut incoming =
                        TcpStream::connect(runtime.local_addr().expect("TCP address"))
                            .await
                            .expect("TCP client");
                    incoming
                        .write_all(&[0; 5])
                        .await
                        .expect("malformed TCP prefix");
                    incoming.shutdown().await.expect("TCP half-close");
                    let (mut forwarded, _) =
                        tcp.accept().await.expect("TCP accepted and dispatched");
                    let mut prefix = Vec::new();
                    forwarded
                        .read_to_end(&mut prefix)
                        .await
                        .expect("TCP prefix");
                    assert_eq!(prefix, [0; 5]);
                }
                quic.send(&suffix).await.expect("complete Initial");
                for expected in [&prefix, &prefix, &suffix] {
                    let (len, _) = udp.recv_from(&mut buf).await.expect("retained Initial");
                    assert_eq!(&buf[..len], expected);
                }
                stop.send(()).expect("stop");
                task.await.expect("join");
                assert_released(&runtime);
            })
            .await
            .expect("bounded interleaving test");
        }

        #[tokio::test]
        async fn authenticated_streams_and_udp_are_independent_and_joined() {
            timeout(TEST_TIMEOUT, async {
                let udp = UdpSocket::bind("127.0.0.1:0").await.expect("UDP target");
                let (runtime, cfg) = server(udp.local_addr().expect("address")).await;
                let (stop, task) = start(&runtime);
                let (endpoint, connection) = authenticated_connection(&cfg).await;
                let (mut udp_send, mut udp_recv) =
                    connection.open_bi().await.expect("UDP stream zero");
                write_udp_association_marker(&mut udp_send)
                    .await
                    .expect("association marker");
                let udp_target = target_addr_from_udp_socket(&udp);
                write_udp_envelope_stream(&mut udp_send, &udp_target, b"first UDP")
                    .await
                    .expect("first envelope");
                let mut buf = [0; 64];
                let (len, udp_peer) = udp.recv_from(&mut buf).await.expect("UDP request");
                assert_eq!(&buf[..len], b"first UDP");

                let (_slow_send, _slow_recv, slow) =
                    open_tcp_target_stream(&connection, b"slow").await;
                let (mut slow_peer, _) = slow.accept().await.expect("slow target accepted");
                slow_peer
                    .read_exact(&mut buf[..4])
                    .await
                    .expect("slow target request");
                assert_eq!(&buf[..4], b"slow");

                let failed_target = TargetAddr::Ipv4(Ipv4Addr::LOCALHOST, closed_tcp_port().await);
                let (mut failed_send, mut failed_recv) =
                    connection.open_bi().await.expect("failed stream");
                write_target_stream(&mut failed_send, &failed_target, &[])
                    .await
                    .expect("failed header");
                failed_send.finish().expect("finish failed request");
                let failed = failed_recv.read_to_end(64).await;
                assert!(failed.is_err() || failed.expect("closed stream").is_empty());

                let (mut fast_send, mut fast_recv, fast) =
                    open_tcp_target_stream(&connection, b"fast").await;
                fast_send.finish().expect("fast half-close");
                let (mut fast_peer, _) = fast.accept().await.expect("fast target accepted");
                let mut request = Vec::new();
                fast_peer
                    .read_to_end(&mut request)
                    .await
                    .expect("fast target EOF");
                assert_eq!(request, b"fast");
                fast_peer
                    .write_all(b"reverse reply")
                    .await
                    .expect("response after half-close");
                fast_peer.shutdown().await.expect("fast target EOF");
                assert_eq!(
                    fast_recv.read_to_end(64).await.expect("fast response"),
                    b"reverse reply"
                );

                // A target response interrupts a partially received second envelope.
                let mut framed = Vec::new();
                write_udp_envelope_stream(&mut framed, &udp_target, b"second UDP")
                    .await
                    .expect("encode second envelope");
                udp_send
                    .write_all(&framed[..3])
                    .await
                    .expect("fragment envelope");
                udp.send_to(b"first reply", udp_peer)
                    .await
                    .expect("competing target reply");
                let first_reply = umbra_transport::quic::read_udp_envelope_stream(&mut udp_recv)
                    .await
                    .expect("first association reply");
                assert_eq!(first_reply.payload, b"first reply");
                udp_send
                    .write_all(&framed[3..])
                    .await
                    .expect("finish envelope");
                let (len, _) = udp.recv_from(&mut buf).await.expect("resumed envelope");
                assert_eq!(&buf[..len], b"second UDP");

                stop.send(()).expect("shutdown with live streams");
                task.await.expect("supervisor joined");
                assert_eq!(
                    slow_peer.read(&mut buf).await.expect("slow target closed"),
                    0
                );
                assert_released(&runtime);
                endpoint.close(0_u32.into(), b"");
            })
            .await
            .expect("bounded authenticated multi-stream test");
        }

        #[tokio::test]
        async fn one_outcome_api_cleans_up_other_pending_flows() {
            timeout(TEST_TIMEOUT, async {
                let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("destination");
                let (runtime, _) = server(upstream.local_addr().expect("address")).await;
                let listener = Arc::clone(&runtime);
                let task = tokio::spawn(async move {
                    listener
                        .accept_one_quic_with_idle_timeout(Duration::from_millis(100))
                        .await
                        .expect("one outcome")
                });
                let first = client(&runtime).await;
                first.send(b"fallback").await.expect("fallback request");
                let mut buf = [0; 32];
                let (len, peer) = upstream.recv_from(&mut buf).await.expect("forwarded");
                assert_eq!(&buf[..len], b"fallback");
                upstream.send_to(b"reply", peer).await.expect("reply");
                let read = first.recv(&mut buf).await.expect("fallback response");
                assert_eq!(&buf[..read], b"reply");
                let slow = client(&runtime).await;
                slow.send(&initial(0, b"\x01\x00\x00\x05he", [5; 8]))
                    .await
                    .expect("pending prefetch");
                let accepted = task.await.expect("listener joins");
                assert_eq!(accepted.peer, first.local_addr().expect("first peer"));
                assert!(matches!(
                    accepted.outcome,
                    QuicRuntimeOutcome::Forwarded {
                        client_to_dest: 8,
                        dest_to_client: 5,
                        ..
                    }
                ));
                assert_released(&runtime);
            })
            .await
            .expect("bounded convenience test");
        }

        #[tokio::test]
        async fn prefetch_retains_conflicts_deadlines_and_datagram_budget() {
            let first = initial(0, b"\x01\x00\x00\x05he", [1; 8]);
            let conflict = initial(4, b"Xello", [1; 8]);
            let (sender, mut receiver) = mpsc::channel(QUIC_FLOW_QUEUE_CAPACITY);
            sender
                .send(conflict.clone())
                .await
                .expect("conflicting overlap");
            let outcome =
                prefetch_quic_client_hello(first.clone(), &mut receiver, TEST_TIMEOUT).await;
            let QuicPrefetchOutcome::Fallback { datagrams, .. } = outcome else {
                panic!("fallback")
            };
            assert_eq!(datagrams, vec![first.clone(), conflict]);
            let outcome =
                prefetch_quic_client_hello(first.clone(), &mut receiver, Duration::ZERO).await;
            let QuicPrefetchOutcome::Fallback { datagrams, .. } = outcome else {
                panic!("deadline fallback")
            };
            assert_eq!(datagrams, vec![first.clone()]);
            for _ in 1..QUIC_PREFETCH_MAX_DATAGRAMS {
                sender.send(first.clone()).await.expect("bounded duplicate");
            }
            let outcome =
                prefetch_quic_client_hello(first.clone(), &mut receiver, TEST_TIMEOUT).await;
            let QuicPrefetchOutcome::Fallback { datagrams, .. } = outcome else {
                panic!("budget fallback")
            };
            assert_eq!(datagrams, vec![first; QUIC_PREFETCH_MAX_DATAGRAMS]);
        }

        #[tokio::test]
        async fn routing_is_peer_and_cid_scoped_and_bounded() {
            let peer: SocketAddr = "127.0.0.1:10001".parse().expect("peer");
            let other: SocketAddr = "127.0.0.1:10002".parse().expect("other peer");
            let mut tasks = JoinSet::new();
            let one = tasks.spawn(std::future::pending::<()>()).id();
            let two = tasks.spawn(std::future::pending::<()>()).id();
            let three = tasks.spawn(std::future::pending::<()>()).id();
            let packet = initial(0, b"\x01\x00\x00\x05he", [1; 8]);
            let packet_two = initial(0, b"\x01\x00\x00\x05he", [2; 8]);
            let (route_one, mut inbox_one) = QuicFlowRoute::new(peer, &packet);
            let (route_two, mut inbox_two) = QuicFlowRoute::new(peer, &packet_two);
            let (route_three, mut inbox_three) = QuicFlowRoute::new(other, &packet);
            let mut routes =
                HashMap::from([(one, route_one), (two, route_two), (three, route_three)]);
            for (address, datagram) in [(peer, &packet), (peer, &packet_two), (other, &packet)] {
                let QuicRouteMatch::Existing(sender) =
                    route_quic_datagram(&routes, address, datagram)
                else {
                    panic!("known route")
                };
                sender.try_send(datagram.clone()).expect("route");
            }
            assert_eq!(inbox_one.receiver.recv().await.expect("one"), packet);
            assert_eq!(inbox_two.receiver.recv().await.expect("two"), packet_two);
            assert_eq!(inbox_three.receiver.recv().await.expect("three"), packet);
            let mut generator = RoutedCidGenerator {
                inner: quinn_proto::RandomConnectionIdGenerator::new(8),
                cids: Arc::clone(&inbox_one.cids),
            };
            let issued = generator.generate_cid();
            let mut short = vec![0x40];
            short.extend_from_slice(&issued);
            short.extend_from_slice(b"payload");
            let QuicRouteMatch::Existing(sender) = route_quic_datagram(&routes, peer, &short)
            else {
                panic!("issued CID route")
            };
            for _ in 0..QUIC_FLOW_QUEUE_CAPACITY {
                sender.try_send(short.clone()).expect("queue capacity");
            }
            assert!(matches!(
                sender.try_send(short.clone()),
                Err(mpsc::error::TrySendError::Full(_))
            ));
            assert!(matches!(
                route_quic_datagram(&routes, other, &short),
                QuicRouteMatch::Ambiguous
            ));
            inbox_three
                .cids
                .fallback
                .store(true, std::sync::atomic::Ordering::Relaxed);
            assert!(matches!(
                route_quic_datagram(&routes, other, &short),
                QuicRouteMatch::Existing(_)
            ));
            inbox_two.cids.register(&issued);
            assert!(matches!(
                route_quic_datagram(&routes, peer, &short),
                QuicRouteMatch::Ambiguous
            ));
            for _ in 0..QUIC_FLOW_MAX_CIDS {
                generator.generate_cid();
            }
            assert_eq!(
                inbox_one.cids.values.lock().expect("CID list").len(),
                QUIC_FLOW_MAX_CIDS
            );
            timeout(TEST_TIMEOUT, inbox_one.cids.exhausted.notified())
                .await
                .expect("bounded CID exhaustion");
            routes.clear();
            assert!(
                inbox_two.receiver.recv().await.is_none(),
                "route cleanup closes queue"
            );
            abort_all(&mut tasks).await;
            assert!(tasks.is_empty());
        }

        #[derive(Debug)]
        struct NeverReceiveSocket;

        impl AsyncUdpSocket for NeverReceiveSocket {
            fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
                panic!("receive test does not send")
            }
            fn try_send(&self, _: &quinn::udp::Transmit<'_>) -> io::Result<()> {
                Ok(())
            }
            fn poll_recv(
                &self,
                _: &mut Context<'_>,
                _: &mut [IoSliceMut<'_>],
                _: &mut [quinn::udp::RecvMeta],
            ) -> Poll<io::Result<usize>> {
                panic!("flow must never receive from physical socket")
            }
            fn local_addr(&self) -> io::Result<SocketAddr> {
                Ok("127.0.0.1:10000".parse().expect("address"))
            }
        }

        #[tokio::test]
        async fn queue_socket_never_competes_for_physical_receives() {
            let (sender, receiver) = mpsc::channel(1);
            let socket = PrefetchedUdpSocket {
                inner: Arc::new(NeverReceiveSocket),
                peer: "127.0.0.1:10001".parse().expect("peer"),
                pending: Mutex::new(QuicSocketQueue {
                    prefetched: VecDeque::from([b"first".to_vec()]),
                    receiver,
                }),
            };
            let mut buf = [0; 32];
            let mut meta = [quinn::udp::RecvMeta::default()];
            let read = std::future::poll_fn(|cx| {
                socket.poll_recv(cx, &mut [IoSliceMut::new(&mut buf)], &mut meta)
            })
            .await
            .expect("prefetched packet");
            assert_eq!(read, 1);
            assert_eq!(&buf[..meta[0].len], b"first");
            assert_eq!(meta[0].addr, socket.peer);
            std::future::poll_fn(|cx| {
                assert!(socket
                    .poll_recv(cx, &mut [IoSliceMut::new(&mut buf)], &mut meta)
                    .is_pending());
                Poll::Ready(())
            })
            .await;
            sender
                .send(b"second".to_vec())
                .await
                .expect("route datagram");
            std::future::poll_fn(|cx| {
                socket.poll_recv(cx, &mut [IoSliceMut::new(&mut buf)], &mut meta)
            })
            .await
            .expect("queued packet");
            assert_eq!(&buf[..meta[0].len], b"second");
            drop(sender);
            let error = std::future::poll_fn(|cx| {
                socket.poll_recv(cx, &mut [IoSliceMut::new(&mut buf)], &mut meta)
            })
            .await
            .expect_err("closed queue");
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        }
    }

    fn target_addr_from_udp_socket(socket: &UdpSocket) -> TargetAddr {
        let std::net::SocketAddr::V4(addr) = socket.local_addr().expect("local address") else {
            panic!("test binds IPv4 UDP sockets");
        };
        TargetAddr::Ipv4(*addr.ip(), addr.port())
    }
}
