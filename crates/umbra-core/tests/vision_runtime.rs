//! Production-runtime proof that negotiated solo mode stops outer encryption.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use umbra_core::{
    config::{ClientCfg, ServerCfg, TransportKind},
    probe::ProbeResistancePolicy,
    runtime::{client_session_from_config, ClientSessionOutcome, ServerRuntime},
    vision_io::VisionOutcome,
    CoreError,
};
use umbra_crypto::{mldsa::mldsa_keygen_from_seed, secret::Secret, x25519};
use umbra_inner::padding::PadScheme;
use umbra_proto::addr::TargetAddr;
use umbra_reality::prebuild::{CertTemplate, DestProfile};
use umbra_transport::evasion::TcpEvasionPolicy;

const TEST_TIMEOUT: Duration = Duration::from_secs(25);
const PAYLOAD_LEN: usize = 256 * 1024;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<CapturedBytes>>);

#[derive(Default)]
struct CapturedBytes {
    received: Vec<u8>,
    sent: Vec<u8>,
}

/// Records only bytes actually accepted/read; short writes deliberately split records.
struct Tap<IO> {
    io: IO,
    captured: Captured,
}

impl<IO> Tap<IO> {
    fn new(io: IO, captured: Captured) -> Self {
        Self { io, captured }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Tap<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = output.filled().len();
        let result = Pin::new(&mut self.io).poll_read(cx, output);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.captured
                .0
                .lock()
                .expect("capture lock")
                .received
                .extend_from_slice(&output.filled()[before..]);
        }
        result
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Tap<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let bytes = &bytes[..bytes.len().min(1373)];
        match Pin::new(&mut self.io).poll_write(cx, bytes) {
            Poll::Ready(Ok(written)) => {
                self.captured
                    .0
                    .lock()
                    .expect("capture lock")
                    .sent
                    .extend_from_slice(&bytes[..written]);
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

struct RunningServer {
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), CoreError>>>,
}

impl RunningServer {
    async fn shutdown(mut self) {
        self.stop
            .take()
            .expect("stop sender")
            .send(())
            .expect("server running");
        self.task
            .take()
            .expect("server task")
            .await
            .expect("server task joins")
            .expect("server shuts down cleanly");
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn server_fixture() -> (ClientCfg, RunningServer) {
    let key = x25519::generate_keypair();
    let seed = [0x63; 32];
    let signing = mldsa_keygen_from_seed(&seed);
    let mut cfg = ClientCfg {
        server: String::new(),
        transport: TransportKind::Tcp,
        udp_transport: None,
        public_key: key.public,
        short_id: vec![1],
        server_name: "vision.example".to_owned(),
        fingerprint: "chrome-latest".to_owned(),
        mldsa_verify: signing.verifying_key,
        spider_path: "/".to_owned(),
        socks_listen: "127.0.0.1:0".parse().expect("loopback"),
        mux: false,
        padding_scheme: PadScheme::default(),
        tcp_evasion: TcpEvasionPolicy::Off,
    };
    let server_cfg = ServerCfg {
        listen: cfg.socks_listen,
        udp_listen: None,
        private_key: key.private,
        short_ids: vec![cfg.short_id.clone()],
        dest: "vision.example:443".to_owned(),
        server_names: vec![cfg.server_name.clone()],
        max_time_diff: Duration::from_mins(2),
        mldsa_seed: Secret::new(seed),
        prebuild: false,
        padding_scheme: PadScheme::default(),
        tcp_evasion: TcpEvasionPolicy::Off,
    };
    let profile = DestProfile {
        dest: server_cfg.dest.clone(),
        tls_ver: 0x0304,
        cipher: 0x1301,
        group: 0x001d,
        alpn: vec![b"h2".to_vec()],
        ee_exts: vec![0x0010],
        leaf_template: CertTemplate {
            subject: "CN=vision.example".to_owned(),
            issuer: "CN=Synthetic Vision CA".to_owned(),
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
            .expect("real Umbra server binds");
    cfg.server = server.local_addr().expect("server address").to_string();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        server
            .run_until_shutdown(async {
                let _ = stopped.await;
            })
            .await
    });
    (
        cfg,
        RunningServer {
            stop: Some(stop),
            task: Some(task),
        },
    )
}

type ClientTask = JoinHandle<Result<ClientSessionOutcome, CoreError>>;
type OuterTapTask = JoinHandle<io::Result<(u64, u64)>>;

async fn client_fixture(mut cfg: ClientCfg) -> (DuplexStream, ClientTask, Captured, OuterTapTask) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("outer tap listener");
    let actual_server = cfg.server.clone();
    cfg.server = listener.local_addr().expect("tap address").to_string();
    let captured = Captured::default();
    let outer_capture = captured.clone();
    let outer_tap = tokio::spawn(async move {
        let (downstream, _) = listener.accept().await?;
        let mut tapped = Tap::new(downstream, outer_capture);
        let mut upstream = TcpStream::connect(actual_server).await?;
        tokio::io::copy_bidirectional(&mut tapped, &mut upstream).await
    });
    let (app, mut socks) = tokio::io::duplex(32768);
    let session = tokio::spawn(async move { client_session_from_config(&cfg, &mut socks).await });
    (app, session, captured, outer_tap)
}

async fn socks_connect(app: &mut DuplexStream, target: SocketAddr) -> u8 {
    app.write_all(&[5, 1, 0]).await.expect("SOCKS greeting");
    let mut method = [0; 2];
    app.read_exact(&mut method).await.expect("SOCKS method");
    assert_eq!(method, [5, 0]);
    let target = match target {
        SocketAddr::V4(addr) => TargetAddr::Ipv4(*addr.ip(), addr.port()),
        SocketAddr::V6(addr) => TargetAddr::Ipv6(*addr.ip(), addr.port()),
    };
    let mut request = vec![5, 1, 0];
    request.extend(target.encode().expect("target address"));
    app.write_all(&request).await.expect("SOCKS CONNECT");
    let mut response = [0; 10];
    app.read_exact(&mut response)
        .await
        .expect("SOCKS CONNECT result");
    assert_eq!(response[0], 5);
    response[1]
}

fn independent_tls(
    version: &'static rustls::SupportedProtocolVersion,
) -> (TlsConnector, TlsAcceptor) {
    let cert = rcgen::generate_simple_self_signed(vec!["inner.example".to_owned()])
        .expect("independent target certificate");
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(cert.cert.der().clone())
        .expect("trust target fixture");
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
    let provider = Arc::new(provider);
    let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[version])
        .expect("client TLS version")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.resumption = rustls::client::Resumption::disabled();
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .expect("server TLS version")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .expect("independent TLS server configuration");
    server.send_tls13_tickets = 0;
    (
        TlsConnector::from(Arc::new(client)),
        TlsAcceptor::from(Arc::new(server)),
    )
}

async fn exchange_tls(
    version: &'static rustls::SupportedProtocolVersion,
) -> (VisionOutcome, Captured, Captured) {
    let (cfg, server) = server_fixture().await;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("inner listener");
    let target = listener.local_addr().expect("inner address");
    let (connector, acceptor) = independent_tls(version);
    let target_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("inner TCP accepts");
        let mut tls = acceptor.accept(tcp).await.expect("independent TLS accepts");
        let mut request = Vec::new();
        tls.read_to_end(&mut request)
            .await
            .expect("request and TLS half-close");
        assert_eq!(request, vec![0x35; PAYLOAD_LEN]);
        tls.write_all(&vec![0xa7; PAYLOAD_LEN])
            .await
            .expect("response after request half-close");
        tls.shutdown().await.expect("response TLS half-close");
    });
    let (mut app, client_task, outer_capture, tap_task) = client_fixture(cfg).await;
    assert_eq!(socks_connect(&mut app, target).await, 0);
    let inner_capture = Captured::default();
    let inner = Tap::new(app, inner_capture.clone());
    let name = rustls::pki_types::ServerName::try_from("inner.example").expect("server name");
    let mut tls = connector
        .connect(name, inner)
        .await
        .expect("inner TLS authenticates target");
    tls.write_all(&vec![0x35; PAYLOAD_LEN])
        .await
        .expect("256 KiB application request");
    tls.shutdown().await.expect("client TLS half-close");
    let mut response = Vec::new();
    tls.read_to_end(&mut response)
        .await
        .expect("read response after half-close");
    assert_eq!(response, vec![0xa7; PAYLOAD_LEN]);
    drop(tls);
    target_task.await.expect("independent target finishes");
    let result = client_task
        .await
        .expect("client task joins")
        .expect("production client completes");
    tap_task
        .await
        .expect("outer tap joins")
        .expect("outer tap preserves half-close");
    server.shutdown().await;
    (
        result.vision.expect("TCP solo produces Vision evidence"),
        inner_capture,
        outer_capture,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scenario_tls13_runtime_handoff_matches_inner_wire_and_stops_outer_crypto() {
    timeout(TEST_TIMEOUT, async {
        let (outcome, inner, outer) = exchange_tls(&rustls::version::TLS13).await;
        assert!(outcome.spliced, "real runtime must execute raw handoff");
        assert!(outcome.raw_sent > 0 && outcome.raw_received > 0);
        assert_eq!(outcome.at_handoff, Some(outcome.final_tls));
        let inner = inner.0.lock().expect("inner capture");
        let outer = outer.0.lock().expect("outer capture");
        // The outer tap faces the Umbra client, hence its receive direction is c2s.
        assert_suffix(&outer.received, &inner.sent, outcome.raw_sent);
        assert_suffix(&outer.sent, &inner.received, outcome.raw_received);
    })
    .await
    .expect("real TLS 1.3 handoff finishes without a stuck owner");
}

fn assert_suffix(outer: &[u8], inner: &[u8], raw_count: u64) {
    let count = usize::try_from(raw_count).expect("raw count fits");
    assert!(outer.len() >= count && inner.len() >= count);
    assert_eq!(&outer[outer.len() - count..], &inner[inner.len() - count..]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scenario_independent_tls12_stays_wrapped_and_preserves_half_close() {
    timeout(TEST_TIMEOUT, async {
        let (outcome, _, _) = exchange_tls(&rustls::version::TLS12).await;
        assert!(!outcome.spliced);
        assert_eq!((outcome.raw_sent, outcome.raw_received), (0, 0));
        assert!(outcome.at_handoff.is_none());
        assert!(
            outcome.final_tls.sealed_plaintext_bytes > u64::try_from(PAYLOAD_LEN).expect("size")
        );
    })
    .await
    .expect("TLS 1.2 wrapped stream finishes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scenario_non_tls_runtime_stays_wrapped_without_changing_application_bytes() {
    timeout(TEST_TIMEOUT, async {
        let (cfg, server) = server_fixture().await;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("plain target");
        let target = listener.local_addr().expect("target address");
        let target_task = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.expect("plain accept");
            let mut request = Vec::new();
            tcp.read_to_end(&mut request)
                .await
                .expect("plain request EOF");
            assert_eq!(request, vec![b'x'; 32768]);
            tcp.write_all(b"response after EOF")
                .await
                .expect("reverse response");
            tcp.shutdown().await.expect("plain response EOF");
        });
        let (mut app, client, _, tapped) = client_fixture(cfg).await;
        assert_eq!(socks_connect(&mut app, target).await, 0);
        app.write_all(&vec![b'x'; 32768])
            .await
            .expect("plain request");
        app.shutdown().await.expect("plain half-close");
        let mut response = Vec::new();
        app.read_to_end(&mut response)
            .await
            .expect("plain response");
        assert_eq!(response, b"response after EOF");
        let outcome = client
            .await
            .expect("client joins")
            .expect("plain runtime succeeds")
            .vision
            .expect("solo evidence");
        assert!(!outcome.spliced);
        assert_eq!((outcome.raw_sent, outcome.raw_received), (0, 0));
        target_task.await.expect("plain target joins");
        tapped.await.expect("tap joins").expect("tap completes");
        server.shutdown().await;
    })
    .await
    .expect("non-TLS wrapped stream finishes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scenario_failed_vision_target_returns_socks_failure_before_success() {
    timeout(TEST_TIMEOUT, async {
        let (cfg, server) = server_fixture().await;
        let unavailable = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve test address");
        let target = unavailable.local_addr().expect("closed target address");
        drop(unavailable);
        let (mut app, client, _, tapped) = client_fixture(cfg).await;
        assert_ne!(socks_connect(&mut app, target).await, 0);
        assert!(client.await.expect("client joins").is_err());
        drop(app);
        let _ = tapped.await.expect("tap joins after failed target");
        server.shutdown().await;
    })
    .await
    .expect("failed target cannot hang SOCKS setup");
}
