//! One real SOCKS listener keeps TCP Vision and QUIC UDP sessions independent.

use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{client::TlsStream, TlsAcceptor, TlsConnector};
use umbra_core::{
    config::{ClientCfg, ServerCfg, TransportKind},
    probe::ProbeResistancePolicy,
    runtime::{ClientInnerMode, ClientRuntime, ClientSessionOutcome, ServerRuntime},
    socks::{decode_udp_packet, encode_udp_packet, SocksUdpPacket},
    CoreError,
};
use umbra_crypto::{mldsa::mldsa_keygen_from_seed, secret::Secret, x25519};
use umbra_inner::padding::PadScheme;
use umbra_proto::addr::TargetAddr;
use umbra_reality::prebuild::{CertTemplate, DestProfile};
use umbra_transport::evasion::TcpEvasionPolicy;

const TEST_TIMEOUT: Duration = Duration::from_secs(25);
const PAYLOAD_LEN: usize = 64 * 1024;

/// A failed assertion or timeout must not leave a detached fixture task running.
struct RunningTask<T> {
    task: Option<JoinHandle<T>>,
}

impl<T: Send + 'static> RunningTask<T> {
    fn spawn(future: impl Future<Output = T> + Send + 'static) -> Self {
        Self {
            task: Some(tokio::spawn(future)),
        }
    }

    async fn finish(mut self) -> T {
        let output = self
            .task
            .as_mut()
            .expect("fixture task exists")
            .await
            .expect("fixture task joins");
        self.task.take();
        output
    }
}

impl<T> Drop for RunningTask<T> {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

struct RunningServer {
    stop: oneshot::Sender<()>,
    task: RunningTask<Result<(), CoreError>>,
}

impl RunningServer {
    async fn shutdown(self) {
        self.stop.send(()).expect("server is running");
        self.task.finish().await.expect("server stops cleanly");
    }
}

async fn server_fixture() -> (ClientCfg, RunningServer) {
    let key = x25519::generate_keypair();
    let seed = [0x68; 32];
    let signing = mldsa_keygen_from_seed(&seed);
    let reservation = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve an ephemeral server port");
    let address = reservation.local_addr().expect("reserved server address");
    let mut cfg = ClientCfg {
        performance: umbra_core::resources::PerformanceCfg::default(),
        server: address.to_string(),
        transport: TransportKind::Tcp,
        udp_transport: Some(TransportKind::Quic),
        public_key: key.public,
        short_id: vec![1],
        server_name: "mixed.example".to_owned(),
        fingerprint: "chrome-latest".to_owned(),
        mldsa_verify: signing.verifying_key,
        spider_path: "/".to_owned(),
        socks_listen: "127.0.0.1:0".parse().expect("loopback SOCKS address"),
        mux: false,
        padding_scheme: PadScheme::default(),
        tcp_evasion: TcpEvasionPolicy::Off,
    };
    let server_cfg = ServerCfg {
        performance: umbra_core::resources::PerformanceCfg::default(),
        listen: address,
        udp_listen: Some(address),
        private_key: key.private,
        short_ids: vec![cfg.short_id.clone()],
        dest: "mixed.example:443".to_owned(),
        server_names: vec![cfg.server_name.clone()],
        max_time_diff: Duration::from_mins(2),
        mldsa_seed: Secret::new(seed),
        prebuild: false,
        padding_scheme: PadScheme::default(),
        tcp_evasion: TcpEvasionPolicy::Off,
    };
    drop(reservation);
    let server = ServerRuntime::bind_with_profile(
        server_cfg,
        destination_profile(),
        ProbeResistancePolicy::default(),
    )
    .await
    .expect("server binds TCP and UDP on the same port");
    let tcp_address = server.local_addr().expect("server TCP address");
    assert_eq!(
        server.udp_local_addr().expect("server UDP address"),
        Some(tcp_address)
    );
    cfg.server = tcp_address.to_string();
    let (stop, stopped) = oneshot::channel();
    let task = RunningTask::spawn(async move {
        server
            .run_until_shutdown(async {
                let _ = stopped.await;
            })
            .await
    });
    (cfg, RunningServer { stop, task })
}

fn destination_profile() -> DestProfile {
    DestProfile {
        dest: "mixed.example:443".to_owned(),
        tls_ver: 0x0304,
        cipher: 0x1301,
        group: 0x001d,
        alpn: vec![b"h2".to_vec()],
        ee_exts: vec![0x0010],
        leaf_template: CertTemplate {
            subject: "CN=mixed.example".to_owned(),
            issuer: "CN=Synthetic Mixed Transport CA".to_owned(),
            not_before_unix: 1_700_000_000,
            not_after_unix: 1_900_000_000,
            san_dns: vec!["mixed.example".to_owned()],
            sct: Vec::new(),
            signature_algorithm: "ecdsa-with-SHA256".to_owned(),
            leaf_der: Vec::new(),
        },
        ocsp: None,
        rtt: Duration::ZERO,
    }
}

fn independent_tls() -> (TlsConnector, TlsAcceptor) {
    let cert = rcgen::generate_simple_self_signed(vec!["inner.example".to_owned()])
        .expect("independent TLS certificate");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).expect("trust target");
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
    let provider = Arc::new(provider);
    let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 client")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.resumption = rustls::client::Resumption::disabled();
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 server")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .expect("independent TLS server");
    server.send_tls13_tickets = 0;
    (
        TlsConnector::from(Arc::new(client)),
        TlsAcceptor::from(Arc::new(server)),
    )
}

async fn tls_target(acceptor: TlsAcceptor) -> (SocketAddr, RunningTask<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("TLS target");
    let address = listener.local_addr().expect("TLS target address");
    let task = RunningTask::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("TLS target accepts TCP");
        let mut tls = acceptor.accept(tcp).await.expect("inner TLS handshake");
        for phase in [0x35, 0x36] {
            let mut request = vec![0; PAYLOAD_LEN];
            tls.read_exact(&mut request)
                .await
                .expect("TLS target receives request");
            assert_eq!(request, vec![phase; PAYLOAD_LEN]);
            tls.write_all(&vec![phase + 1; PAYLOAD_LEN])
                .await
                .expect("TLS target responds");
            tls.flush().await.expect("TLS target flushes response");
        }
        let mut trailing = Vec::new();
        tls.read_to_end(&mut trailing)
            .await
            .expect("TLS request half-close");
        assert!(trailing.is_empty());
        tls.shutdown().await.expect("TLS target half-close");
    });
    (address, task)
}

async fn udp_target() -> (SocketAddr, RunningTask<()>) {
    let target = UdpSocket::bind("127.0.0.1:0").await.expect("UDP target");
    let address = target.local_addr().expect("UDP target address");
    let task = RunningTask::spawn(async move {
        let mut request = [0; 512];
        let (read, peer) = target
            .recv_from(&mut request)
            .await
            .expect("UDP target receives");
        assert_eq!(&request[..read], &[0x57; 512]);
        target
            .send_to(&[0x79; 512], peer)
            .await
            .expect("UDP target responds");
    });
    (address, task)
}

fn target_addr(address: SocketAddr) -> TargetAddr {
    match address {
        SocketAddr::V4(address) => TargetAddr::Ipv4(*address.ip(), address.port()),
        SocketAddr::V6(address) => TargetAddr::Ipv6(*address.ip(), address.port()),
    }
}

async fn socks_request(
    socks: SocketAddr,
    command: u8,
    target: SocketAddr,
) -> (TcpStream, SocketAddr) {
    let mut stream = TcpStream::connect(socks)
        .await
        .expect("connect the shared SOCKS listener");
    let mut request = vec![5, 1, 0, 5, command, 0];
    request.extend(target_addr(target).encode().expect("SOCKS target encodes"));
    stream
        .write_all(&request)
        .await
        .expect("SOCKS greeting and request");
    let mut response = [0; 12];
    stream.read_exact(&mut response).await.expect("SOCKS reply");
    assert_eq!(&response[..6], &[5, 0, 5, 0, 0, 1]);
    let bound = SocketAddr::from((
        [response[6], response[7], response[8], response[9]],
        u16::from_be_bytes([response[10], response[11]]),
    ));
    (stream, bound)
}

fn accept_session(
    runtime: &Arc<ClientRuntime>,
) -> RunningTask<Result<ClientSessionOutcome, CoreError>> {
    let runtime = Arc::clone(runtime);
    RunningTask::spawn(async move { runtime.accept_one_from_config().await })
}

async fn exchange_tls(tls: &mut TlsStream<TcpStream>, phase: u8) {
    tls.write_all(&vec![phase; PAYLOAD_LEN])
        .await
        .expect("TLS application request");
    tls.flush().await.expect("flush TLS request");
    let mut response = vec![0; PAYLOAD_LEN];
    tls.read_exact(&mut response)
        .await
        .expect("TLS application response");
    assert_eq!(response, vec![phase + 1; PAYLOAD_LEN]);
}

async fn exchange_udp(bound: SocketAddr, target: SocketAddr) {
    let app = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("UDP application socket");
    let request = encode_udp_packet(&SocksUdpPacket {
        frag: 0,
        target: target_addr(target),
        payload: vec![0x57; 512],
    })
    .expect("SOCKS UDP request encodes");
    app.send_to(&request, bound)
        .await
        .expect("send to negotiated UDP relay");
    let mut response = [0; 1024];
    let (read, source) = app
        .recv_from(&mut response)
        .await
        .expect("SOCKS UDP response");
    assert_eq!(source, bound);
    let response = decode_udp_packet(&response[..read]).expect("SOCKS UDP response decodes");
    assert_eq!(response.frag, 0);
    assert_eq!(response.target, target_addr(target));
    assert_eq!(response.payload, vec![0x79; 512]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scenario_one_socks_listener_runs_tcp_vision_and_quic_udp_with_independent_cleanup() {
    timeout(TEST_TIMEOUT, async {
        let (cfg, server) = server_fixture().await;
        let runtime = Arc::new(ClientRuntime::bind(cfg).await.expect("mixed client binds"));
        let socks = runtime.local_addr().expect("shared SOCKS listener address");
        // Occupy this UDP port to prove the relay uses its own negotiated address.
        let control_port_udp = UdpSocket::bind(socks)
            .await
            .expect("reserve SOCKS control's UDP port");
        let (connector, acceptor) = independent_tls();
        let (tcp_target, tcp_target_task) = tls_target(acceptor).await;
        let (udp_target, udp_target_task) = udp_target().await;

        let tcp_session = accept_session(&runtime);
        let (app, _) = socks_request(socks, 1, tcp_target).await;
        let name =
            rustls::pki_types::ServerName::try_from("inner.example").expect("inner server name");
        let mut tls = connector
            .connect(name, app)
            .await
            .expect("real inner TLS handshake");

        let udp_session = accept_session(&runtime);
        let (udp_control, bound) =
            socks_request(socks, 3, "0.0.0.0:0".parse().expect("UDP associate")).await;
        assert!(bound.ip().is_loopback());
        assert_ne!(bound.port(), 0);
        assert_ne!(bound.port(), socks.port());
        tokio::join!(
            exchange_tls(&mut tls, 0x35),
            exchange_udp(bound, udp_target)
        );

        drop(udp_control);
        let udp_outcome = udp_session
            .finish()
            .await
            .expect("UDP association closes cleanly");
        assert_eq!(udp_outcome.transport, TransportKind::Quic);
        assert_eq!(udp_outcome.mode, ClientInnerMode::QuicStream);
        assert!(udp_outcome.vision.is_none());
        let released_relay = UdpSocket::bind(bound)
            .await
            .expect("closed UDP association releases its relay socket");
        udp_target_task.finish().await;

        // The existing TCP stream must still work after the UDP association is gone.
        exchange_tls(&mut tls, 0x36).await;
        tls.shutdown().await.expect("TLS application half-close");
        let mut trailing = Vec::new();
        tls.read_to_end(&mut trailing)
            .await
            .expect("TLS response half-close");
        assert!(trailing.is_empty());
        drop(tls);
        let tcp_outcome = tcp_session
            .finish()
            .await
            .expect("TCP Vision session completes");
        assert_eq!(tcp_outcome.transport, TransportKind::Tcp);
        assert_eq!(tcp_outcome.mode, ClientInnerMode::VisionSolo);
        assert_eq!(tcp_outcome.target, target_addr(tcp_target));
        let vision = tcp_outcome
            .vision
            .expect("TCP Vision reports its handoff evidence");
        assert!(vision.spliced);
        assert!(vision.raw_sent > 0 && vision.raw_received > 0);
        assert_eq!(vision.at_handoff, Some(vision.final_tls));
        tcp_target_task.finish().await;
        runtime
            .run_until_shutdown(async {})
            .await
            .expect("client runtime shuts down");
        drop((runtime, released_relay, control_port_udp));
        server.shutdown().await;
    })
    .await
    .expect("shared SOCKS mixed transports complete and clean up before the deadline");
}
