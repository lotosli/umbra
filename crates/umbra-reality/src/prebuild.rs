//! Destination prebuild profiles and refresh state.

use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::{Arc, LazyLock, Mutex, RwLock},
    time::{Duration, Instant},
};

use crate::RealityError;
use rustls::{
    pki_types::ServerName, ClientConfig, ClientConnection, KeyLog, ProtocolVersion, RootCertStore,
    StreamOwned,
};
use tokio::sync::Semaphore;
use umbra_crypto::secret::SecretBytes;
use umbra_tls::{
    keyschedule::derive_traffic_keys,
    records::{RecordLayer, CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_HANDSHAKE},
};
use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    prelude::*,
};

const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 0x08;
const HANDSHAKE_CERTIFICATE: u8 = 0x0b;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PROBE_WORKERS: usize = 4;
const SERVER_HANDSHAKE_SECRET: &str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
static PROBE_SLOTS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_PROBE_WORKERS)));

/// Visible certificate fields collected from the real destination.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CertTemplate {
    /// Leaf subject summary.
    pub subject: String,
    /// Leaf issuer summary.
    pub issuer: String,
    /// Not-before timestamp in Unix seconds.
    pub not_before_unix: u64,
    /// Not-after timestamp in Unix seconds.
    pub not_after_unix: u64,
    /// DNS subject alternative names.
    pub san_dns: Vec<String>,
    /// Signed certificate timestamp bytes, when observed.
    pub sct: Vec<Vec<u8>>,
    /// Leaf signature algorithm label.
    pub signature_algorithm: String,
    /// Source leaf certificate DER used as template input.
    pub leaf_der: Vec<u8>,
}

/// Destination profile consumed by the forged TLS server path.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DestProfile {
    /// Destination `host:port`.
    pub dest: String,
    /// Negotiated TLS version, normally `0x0304`.
    pub tls_ver: u16,
    /// Negotiated cipher suite.
    pub cipher: u16,
    /// Negotiated key-share group.
    pub group: u16,
    /// ALPN protocol list in destination order.
    pub alpn: Vec<Vec<u8>>,
    /// EncryptedExtensions extension identifiers.
    pub ee_exts: Vec<u16>,
    /// Leaf certificate template.
    pub leaf_template: CertTemplate,
    /// OCSP staple bytes, when observed.
    pub ocsp: Option<Vec<u8>>,
    /// Destination connection attempt (including DNS) to first TLS response.
    pub rtt: Duration,
}

impl DestProfile {
    /// Validate and construct a destination profile from a probe sample.
    pub fn from_sample(dest: &str, sample: ProbeSample) -> Result<Self, RealityError> {
        validate_dest(dest)?;
        if sample.tls_ver != 0x0304 {
            return Err(RealityError::InvalidDestProfile(
                "destination is not TLS 1.3",
            ));
        }
        if sample.cipher == 0 {
            return Err(RealityError::InvalidDestProfile("cipher suite is empty"));
        }
        if sample.group == 0 {
            return Err(RealityError::InvalidDestProfile("key share group is empty"));
        }
        if sample.leaf_template.not_after_unix <= sample.leaf_template.not_before_unix {
            return Err(RealityError::InvalidDestProfile(
                "certificate validity range is invalid",
            ));
        }
        Ok(Self {
            dest: dest.to_owned(),
            tls_ver: sample.tls_ver,
            cipher: sample.cipher,
            group: sample.group,
            alpn: sample.alpn,
            ee_exts: sample.ee_exts,
            leaf_template: sample.leaf_template,
            ocsp: sample.ocsp,
            rtt: sample.rtt,
        })
    }

    /// Convert to the minimal TLS server profile used by component A.
    #[must_use]
    pub fn to_tls_server_profile(&self) -> umbra_tls::server::DestProfile {
        umbra_tls::server::DestProfile {
            server_name: self
                .dest
                .split_once(':')
                .map_or_else(|| self.dest.clone(), |(host, _)| host.to_owned()),
            cipher_suite: self.cipher,
            key_share_group: self.group,
            alpn: self
                .alpn
                .first()
                .and_then(|value| String::from_utf8(value.clone()).ok()),
            encrypted_extensions: self.ee_exts.clone(),
            rtt_millis: u64::try_from(self.rtt.as_millis()).unwrap_or(u64::MAX),
        }
    }
}

/// Network probe settings for the default standard TLS probe.
///
/// The overall deadline is `connect_timeout + io_timeout`, including worker
/// queueing, DNS, connection establishment, TLS, and metadata extraction.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProbeSettings {
    /// Shared DNS/TCP connection budget across all resolved addresses.
    pub connect_timeout: Duration,
    /// Maximum duration of each TLS read/write, capped by the overall deadline.
    pub io_timeout: Duration,
    /// ALPN protocols offered during probing. No application request is sent.
    pub alpn: Vec<Vec<u8>>,
}

impl ProbeSettings {
    fn deadline(&self) -> Result<Instant, RealityError> {
        if self.connect_timeout.is_zero() || self.io_timeout.is_zero() {
            return Err(RealityError::InvalidDestProfile(
                "probe timeouts must be nonzero",
            ));
        }
        self.connect_timeout
            .checked_add(self.io_timeout)
            .and_then(|budget| Instant::now().checked_add(budget))
            .ok_or(RealityError::InvalidDestProfile(
                "probe timeout is too large",
            ))
    }
}

impl Default for ProbeSettings {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            io_timeout: DEFAULT_IO_TIMEOUT,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }
    }
}

/// Standard TLS probing backend used by [`probe_dest`].
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct StandardTlsProbe {
    settings: ProbeSettings,
}

impl StandardTlsProbe {
    /// Construct a probe with explicit settings.
    #[must_use]
    pub const fn new(settings: ProbeSettings) -> Self {
        Self { settings }
    }

    /// Probe without blocking the Tokio executor, using the shared worker limit.
    ///
    /// The deadline includes waiting for a worker. A timed-out or cancelled
    /// caller does not release its worker slot until the worker actually exits.
    /// OS DNS calls cannot be interrupted, but remain inside that bound. This
    /// method requires a Tokio runtime with its time driver enabled.
    pub async fn probe_async(&self, dest: &str) -> Result<DestProfile, RealityError> {
        self.probe_async_with_extra_roots(dest, Vec::new()).await
    }

    async fn probe_async_with_extra_roots(
        &self,
        dest: &str,
        extra_root_der: Vec<Vec<u8>>,
    ) -> Result<DestProfile, RealityError> {
        let deadline = self.settings.deadline()?;
        validate_dest(dest)?;
        let probe = self.clone();
        let dest = dest.to_owned();
        run_bounded_probe(PROBE_SLOTS.clone(), deadline, move || {
            probe.probe_with_extra_roots(&dest, &extra_root_der, deadline)
        })
        .await
    }

    fn probe(&self, dest: &str) -> Result<DestProfile, RealityError> {
        self.probe_with_extra_roots(dest, &[], self.settings.deadline()?)
    }

    fn probe_with_extra_roots(
        &self,
        dest: &str,
        extra_root_der: &[Vec<u8>],
        deadline: Instant,
    ) -> Result<DestProfile, RealityError> {
        remaining(deadline)?;
        let parsed = parse_dest(dest)?;
        let key_log = Arc::new(MemoryKeyLog::default());
        let mut config = tls_client_config(&self.settings, key_log.clone(), extra_root_der)?;
        config.enable_sni = true;

        let server_name = ServerName::try_from(parsed.host.clone())
            .map_err(|_| RealityError::InvalidDestProfile("destination host is not a valid SNI"))?;
        let connection = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|_| RealityError::ProbeFailed("TLS client initialization failed"))?;
        let connect_started = Instant::now();
        let stream = connect_tcp(&parsed, self.settings.connect_timeout, deadline)?;
        let mut tls = StreamOwned::new(
            connection,
            RecordingStream::new(stream, deadline, self.settings.io_timeout),
        );

        while tls.conn.is_handshaking() {
            remaining(deadline)?;
            tls.conn
                .complete_io(&mut tls.sock)
                .map_err(|_| RealityError::ProbeFailed("TLS handshake failed"))?;
        }
        // TLS already supplies every profile field. Sending HTTP here would
        // distort timing and, after negotiating h2, require an HTTP/2 client.
        let rtt = tls
            .sock
            .first_response_at
            .ok_or(RealityError::ProbeFailed("first TLS response missing"))?
            .duration_since(connect_started);

        let tls_ver = protocol_version_code(
            tls.conn
                .protocol_version()
                .ok_or(RealityError::ProbeFailed("TLS version was not negotiated"))?,
        )?;
        let cipher = tls
            .conn
            .negotiated_cipher_suite()
            .map(|suite| u16::from(suite.suite()))
            .ok_or(RealityError::ProbeFailed("cipher suite was not negotiated"))?;
        let group = tls
            .conn
            .negotiated_key_exchange_group()
            .map(|group| u16::from(group.name()))
            .ok_or(RealityError::ProbeFailed(
                "key exchange group was not negotiated",
            ))?;
        let alpn = tls
            .conn
            .alpn_protocol()
            .map_or_else(Vec::new, |protocol| vec![protocol.to_vec()]);
        let leaf_der = tls
            .conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or(RealityError::ProbeFailed("peer leaf certificate missing"))?
            .as_ref()
            .to_vec();
        let mut leaf_template = cert_template_from_der(&leaf_der)?;

        let handshake_secret = key_log.take_secret().ok_or(RealityError::ProbeFailed(
            "server handshake traffic secret missing",
        ))?;
        remaining(deadline)?;
        let metadata = collect_handshake_metadata(
            &tls.sock.inbound,
            cipher,
            handshake_secret.expose_secret(),
        )?;
        leaf_template.sct.extend(metadata.sct);
        remaining(deadline)?;

        DestProfile::from_sample(
            dest,
            ProbeSample {
                tls_ver,
                cipher,
                group,
                alpn,
                ee_exts: metadata.ee_exts,
                leaf_template,
                ocsp: metadata.ocsp,
                rtt,
            },
        )
    }
}

/// Raw probe output before destination validation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProbeSample {
    /// Negotiated TLS version.
    pub tls_ver: u16,
    /// Negotiated cipher suite.
    pub cipher: u16,
    /// Negotiated key-share group.
    pub group: u16,
    /// ALPN protocol list.
    pub alpn: Vec<Vec<u8>>,
    /// EncryptedExtensions extension identifiers.
    pub ee_exts: Vec<u16>,
    /// Leaf certificate template.
    pub leaf_template: CertTemplate,
    /// OCSP staple bytes, when present.
    pub ocsp: Option<Vec<u8>>,
    /// Destination connection attempt (including DNS) to first TLS response.
    pub rtt: Duration,
}

/// Synchronous probing backend.
///
/// Network backends may block in the OS resolver. Do not invoke these methods
/// on async executor threads; use [`probe_dest`] or [`StandardTlsProbe::probe_async`].
pub trait ProbeBackend {
    /// Probe `dest` and return a validated profile.
    fn probe_dest(&self, dest: &str) -> Result<DestProfile, RealityError>;
}

impl ProbeBackend for StandardTlsProbe {
    fn probe_dest(&self, dest: &str) -> Result<DestProfile, RealityError> {
        self.probe(dest)
    }
}

/// Probe with an injected backend.
pub fn probe_dest_with(
    dest: &str,
    backend: &dyn ProbeBackend,
) -> Result<DestProfile, RealityError> {
    validate_dest(dest)?;
    backend.probe_dest(dest)
}

/// Default network probe entry point, requiring a Tokio runtime with time enabled.
///
/// At most four default/configured async probe workers run concurrently. The
/// 20-second default deadline includes queueing and all probe stages.
pub async fn probe_dest(dest: &str) -> Result<DestProfile, RealityError> {
    StandardTlsProbe::default().probe_async(dest).await
}

async fn run_bounded_probe(
    slots: Arc<Semaphore>,
    deadline: Instant,
    probe: impl FnOnce() -> Result<DestProfile, RealityError> + Send + 'static,
) -> Result<DestProfile, RealityError> {
    tokio::time::timeout_at(deadline.into(), async move {
        let permit = slots
            .acquire_owned()
            .await
            .map_err(|_| RealityError::ProbeFailed("probe worker pool closed"))?;
        remaining(deadline)?;
        tokio::task::spawn_blocking(move || {
            // Dropping the JoinHandle on timeout/cancellation cannot stop a
            // running OS resolver. Keep the permit in the worker, never in the
            // caller, so retries cannot create unbounded replacement workers.
            let _permit = permit;
            remaining(deadline)?;
            let result = probe();
            remaining(deadline)?;
            result
        })
        .await
        .map_err(|_| RealityError::ProbeFailed("probe worker failed"))?
    })
    .await
    .map_err(|_| RealityError::ProbeFailed("probe deadline exceeded"))?
}

fn remaining(deadline: Instant) -> Result<Duration, RealityError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(RealityError::ProbeFailed("probe deadline exceeded"))
}

/// Last-known-good destination profile store.
#[derive(Debug)]
pub struct ProfileStore {
    active: RwLock<Option<DestProfile>>,
}

impl ProfileStore {
    /// Create an empty profile store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active: RwLock::new(None),
        }
    }

    /// Probe at startup and require success.
    pub fn startup_refresh(
        &self,
        dest: &str,
        backend: &dyn ProbeBackend,
    ) -> Result<DestProfile, RealityError> {
        let profile = probe_dest_with(dest, backend)?;
        self.replace(profile.clone())?;
        Ok(profile)
    }

    /// Refresh active profile, keeping the prior profile on probe failure.
    pub fn refresh(
        &self,
        dest: &str,
        backend: &dyn ProbeBackend,
    ) -> Result<DestProfile, RealityError> {
        match probe_dest_with(dest, backend) {
            Ok(profile) => {
                self.replace(profile.clone())?;
                Ok(profile)
            }
            Err(err) => self.active().or(Err(err)),
        }
    }

    /// Return the current active profile.
    pub fn active(&self) -> Result<DestProfile, RealityError> {
        self.active
            .read()
            .map_err(|_| RealityError::ProbeFailed("profile store read lock poisoned"))?
            .clone()
            .ok_or(RealityError::NoActiveProfile)
    }

    fn replace(&self, profile: DestProfile) -> Result<(), RealityError> {
        *self
            .active
            .write()
            .map_err(|_| RealityError::ProbeFailed("profile store write lock poisoned"))? =
            Some(profile);
        Ok(())
    }
}

impl Default for ProfileStore {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_dest(dest: &str) -> Result<(), RealityError> {
    parse_dest(dest).map(|_| ())
}

fn parse_dest(dest: &str) -> Result<ParsedDest, RealityError> {
    if dest.is_empty() {
        return Err(RealityError::InvalidDestProfile("destination is empty"));
    }
    let Some((host, port)) = dest.rsplit_once(':') else {
        return Err(RealityError::InvalidDestProfile(
            "destination must be host:port",
        ));
    };
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    let port = port
        .parse::<u16>()
        .map_err(|_| RealityError::InvalidDestProfile("destination must be host:port"))?;
    if host.is_empty() || port == 0 {
        return Err(RealityError::InvalidDestProfile(
            "destination must be host:port",
        ));
    }
    Ok(ParsedDest {
        host: host.to_owned(),
        port,
    })
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ParsedDest {
    host: String,
    port: u16,
}

impl ParsedDest {
    fn socket_target(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn connect_tcp(
    parsed: &ParsedDest,
    timeout: Duration,
    deadline: Instant,
) -> Result<TcpStream, RealityError> {
    let connect_deadline = Instant::now()
        .checked_add(timeout)
        .map_or(deadline, |end| end.min(deadline));
    remaining(connect_deadline)?;
    // The OS resolver is blocking and not cancellable. The async entry point
    // runs this inside the same bounded worker as TCP/TLS, under caller timeout.
    let addresses = parsed
        .socket_target()
        .to_socket_addrs()
        .map_err(|_| RealityError::ProbeFailed("DNS resolution failed"))?;
    remaining(connect_deadline)?;
    let mut last_error = false;
    for addr in addresses {
        match TcpStream::connect_timeout(&addr, remaining(connect_deadline)?) {
            Ok(stream) => return Ok(stream),
            Err(_) => last_error = true,
        }
    }
    if last_error {
        Err(RealityError::ProbeFailed("TCP connect failed"))
    } else {
        Err(RealityError::ProbeFailed(
            "DNS resolution returned no addresses",
        ))
    }
}

fn tls_client_config(
    settings: &ProbeSettings,
    key_log: Arc<dyn KeyLog>,
    extra_root_der: &[Vec<u8>],
) -> Result<ClientConfig, RealityError> {
    let mut root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for cert in extra_root_der {
        root_store
            .add(rustls::pki_types::CertificateDer::from(cert.clone()))
            .map_err(|_| RealityError::InvalidDestProfile("custom root certificate is invalid"))?;
    }
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites.retain(|suite| {
        let code = u16::from(suite.suite());
        code == 0x1301 || code == 0x1303
    });
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| RealityError::ProbeFailed("TLS 1.3 provider unavailable"))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols.clone_from(&settings.alpn);
    config.key_log = key_log;
    Ok(config)
}

fn protocol_version_code(version: ProtocolVersion) -> Result<u16, RealityError> {
    let code = u16::from(version);
    if code == 0x0304 {
        Ok(code)
    } else {
        Err(RealityError::InvalidDestProfile(
            "destination is not TLS 1.3",
        ))
    }
}

fn cert_template_from_der(leaf_der: &[u8]) -> Result<CertTemplate, RealityError> {
    let (_, cert) = X509Certificate::from_der(leaf_der)
        .map_err(|_| RealityError::InvalidDestProfile("leaf certificate DER is invalid"))?;
    let validity = cert.validity();
    let not_before_unix = u64::try_from(validity.not_before.timestamp()).map_err(|_| {
        RealityError::InvalidDestProfile("certificate not_before is before Unix epoch")
    })?;
    let not_after_unix = u64::try_from(validity.not_after.timestamp()).map_err(|_| {
        RealityError::InvalidDestProfile("certificate not_after is before Unix epoch")
    })?;

    let mut san_dns = Vec::new();
    let mut sct = Vec::new();
    for extension in cert.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(names) => {
                san_dns.extend(names.general_names.iter().filter_map(|name| {
                    if let GeneralName::DNSName(dns) = name {
                        Some((*dns).to_owned())
                    } else {
                        None
                    }
                }));
            }
            ParsedExtension::SCT(_) => sct.push(extension.value.to_vec()),
            _ => {}
        }
    }

    Ok(CertTemplate {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before_unix,
        not_after_unix,
        san_dns,
        sct,
        signature_algorithm: cert.signature_algorithm.algorithm.to_string(),
        leaf_der: leaf_der.to_vec(),
    })
}

fn collect_handshake_metadata(
    records: &[u8],
    cipher: u16,
    server_handshake_secret: &[u8],
) -> Result<HandshakeMetadata, RealityError> {
    let traffic_keys = derive_traffic_keys(cipher, server_handshake_secret)
        .map_err(|_| RealityError::ProbeFailed("server handshake keys could not be derived"))?;
    // Both TrafficKeys and RecordLayer zeroize on drop; transfer ownership
    // without creating an unprotected temporary traffic-key copy.
    let mut layer = RecordLayer::from_traffic_keys(cipher, traffic_keys);
    let mut plaintext = Vec::new();
    let mut offset = 0;

    while offset < records.len() {
        let record = next_record(records, &mut offset)?;
        if record.first() != Some(&CONTENT_TYPE_APPLICATION_DATA) {
            continue;
        }
        match layer.open(record) {
            Ok(open) if open.content_type == CONTENT_TYPE_HANDSHAKE => {
                plaintext.extend_from_slice(&open.plaintext);
            }
            Ok(_) => {
                if !plaintext.is_empty() {
                    break;
                }
            }
            Err(_) => {
                if plaintext.is_empty() {
                    return Err(RealityError::ProbeFailed(
                        "server encrypted handshake could not be opened",
                    ));
                }
                break;
            }
        }
    }

    if plaintext.is_empty() {
        return Err(RealityError::ProbeFailed(
            "server encrypted handshake records missing",
        ));
    }
    parse_decrypted_handshakes(&plaintext)
}

fn next_record<'a>(input: &'a [u8], offset: &mut usize) -> Result<&'a [u8], RealityError> {
    if input.len().saturating_sub(*offset) < 5 {
        return Err(RealityError::ProbeFailed("truncated TLS record header"));
    }
    let start = *offset;
    let len = usize::from(u16::from_be_bytes([input[start + 3], input[start + 4]]));
    let end = start
        .checked_add(5)
        .and_then(|value| value.checked_add(len))
        .ok_or(RealityError::ProbeFailed("TLS record length overflow"))?;
    if end > input.len() {
        return Err(RealityError::ProbeFailed("truncated TLS record payload"));
    }
    *offset = end;
    Ok(&input[start..end])
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
struct HandshakeMetadata {
    ee_exts: Vec<u16>,
    ocsp: Option<Vec<u8>>,
    sct: Vec<Vec<u8>>,
}

fn parse_decrypted_handshakes(input: &[u8]) -> Result<HandshakeMetadata, RealityError> {
    let mut offset = 0;
    let mut metadata = HandshakeMetadata::default();
    let mut saw_encrypted_extensions = false;
    while offset < input.len() {
        if input.len().saturating_sub(offset) < 4 {
            return Err(RealityError::ProbeFailed("truncated handshake header"));
        }
        let msg_type = input[offset];
        let len = read_u24(&input[offset + 1..offset + 4]);
        offset += 4;
        let end = offset
            .checked_add(len)
            .ok_or(RealityError::ProbeFailed("handshake length overflow"))?;
        if end > input.len() {
            return Err(RealityError::ProbeFailed("truncated handshake payload"));
        }
        let body = &input[offset..end];
        match msg_type {
            HANDSHAKE_ENCRYPTED_EXTENSIONS => {
                metadata.ee_exts = parse_extension_ids(body)?;
                saw_encrypted_extensions = true;
            }
            HANDSHAKE_CERTIFICATE => parse_certificate_message(body, &mut metadata)?,
            _ => {}
        }
        offset = end;
    }
    if saw_encrypted_extensions {
        Ok(metadata)
    } else {
        Err(RealityError::ProbeFailed("EncryptedExtensions missing"))
    }
}

fn parse_extension_ids(input: &[u8]) -> Result<Vec<u16>, RealityError> {
    let mut offset = 0;
    let ext_len = usize::from(read_u16_at(input, &mut offset)?);
    let end = checked_end(offset, ext_len)?;
    if end != input.len() {
        return Err(RealityError::ProbeFailed(
            "EncryptedExtensions length mismatch",
        ));
    }
    let mut ids = Vec::new();
    while offset < end {
        let id = read_u16_at(input, &mut offset)?;
        let len = usize::from(read_u16_at(input, &mut offset)?);
        skip(input, &mut offset, len)?;
        ids.push(id);
    }
    Ok(ids)
}

fn parse_certificate_message(
    input: &[u8],
    metadata: &mut HandshakeMetadata,
) -> Result<(), RealityError> {
    let mut offset = 0;
    let context_len = usize::from(read_u8_at(input, &mut offset)?);
    skip(input, &mut offset, context_len)?;
    let list_len = read_u24_at(input, &mut offset)?;
    let list_end = checked_end(offset, list_len)?;
    if list_end > input.len() {
        return Err(RealityError::ProbeFailed(
            "certificate list exceeds handshake",
        ));
    }
    if offset >= list_end {
        return Ok(());
    }

    let cert_len = read_u24_at(input, &mut offset)?;
    skip(input, &mut offset, cert_len)?;
    let ext_len = usize::from(read_u16_at(input, &mut offset)?);
    let ext_end = checked_end(offset, ext_len)?;
    if ext_end > list_end {
        return Err(RealityError::ProbeFailed(
            "certificate extensions exceed entry",
        ));
    }
    while offset < ext_end {
        let ext_id = read_u16_at(input, &mut offset)?;
        let len = usize::from(read_u16_at(input, &mut offset)?);
        let value = take(input, &mut offset, len)?;
        match ext_id {
            EXT_STATUS_REQUEST => metadata.ocsp = parse_ocsp_staple(value)?,
            EXT_SIGNED_CERTIFICATE_TIMESTAMP => metadata.sct.push(value.to_vec()),
            _ => {}
        }
    }
    Ok(())
}

fn parse_ocsp_staple(input: &[u8]) -> Result<Option<Vec<u8>>, RealityError> {
    let mut offset = 0;
    let status_type = read_u8_at(input, &mut offset)?;
    if status_type != 1 {
        return Ok(None);
    }
    let len = read_u24_at(input, &mut offset)?;
    Ok(Some(take(input, &mut offset, len)?.to_vec()))
}

fn read_u8_at(input: &[u8], offset: &mut usize) -> Result<u8, RealityError> {
    let byte = *input
        .get(*offset)
        .ok_or(RealityError::ProbeFailed("unexpected end of probe bytes"))?;
    *offset += 1;
    Ok(byte)
}

fn read_u16_at(input: &[u8], offset: &mut usize) -> Result<u16, RealityError> {
    let bytes = take(input, offset, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u24_at(input: &[u8], offset: &mut usize) -> Result<usize, RealityError> {
    let bytes = take(input, offset, 3)?;
    Ok(read_u24(bytes))
}

fn read_u24(input: &[u8]) -> usize {
    (usize::from(input[0]) << 16) | (usize::from(input[1]) << 8) | usize::from(input[2])
}

fn take<'a>(input: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], RealityError> {
    let end = checked_end(*offset, len)?;
    if end > input.len() {
        return Err(RealityError::ProbeFailed("unexpected end of probe bytes"));
    }
    let out = &input[*offset..end];
    *offset = end;
    Ok(out)
}

fn skip(input: &[u8], offset: &mut usize, len: usize) -> Result<(), RealityError> {
    take(input, offset, len).map(|_| ())
}

fn checked_end(offset: usize, len: usize) -> Result<usize, RealityError> {
    offset
        .checked_add(len)
        .ok_or(RealityError::ProbeFailed("probe length overflow"))
}

#[derive(Debug)]
struct RecordingStream {
    inner: TcpStream,
    inbound: Vec<u8>,
    first_response_at: Option<Instant>,
    deadline: Instant,
    io_timeout: Duration,
}

impl RecordingStream {
    const fn new(inner: TcpStream, deadline: Instant, io_timeout: Duration) -> Self {
        Self {
            inner,
            inbound: Vec::new(),
            first_response_at: None,
            deadline,
            io_timeout,
        }
    }

    fn remaining_io(&self) -> std::io::Result<Duration> {
        remaining(self.deadline)
            .map(|budget| budget.min(self.io_timeout))
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "probe deadline exceeded")
            })
    }
}

impl Read for RecordingStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.set_read_timeout(Some(self.remaining_io()?))?;
        let read = self.inner.read(buf)?;
        if read > 0 {
            self.first_response_at.get_or_insert_with(Instant::now);
            self.inbound.extend_from_slice(&buf[..read]);
        }
        Ok(read)
    }
}

impl Write for RecordingStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.set_write_timeout(Some(self.remaining_io()?))?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.set_write_timeout(Some(self.remaining_io()?))?;
        self.inner.flush()
    }
}

#[derive(Default)]
struct MemoryKeyLog {
    // Retain only the handshake secret needed for metadata decryption. Every
    // ownership path, including poison/error/timeout, drops zeroizing storage.
    secret: Mutex<Option<SecretBytes>>,
}

impl std::fmt::Debug for MemoryKeyLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryKeyLog(<redacted>)")
    }
}

impl MemoryKeyLog {
    fn take_secret(&self) -> Option<SecretBytes> {
        self.secret.lock().ok()?.take()
    }
}

impl KeyLog for MemoryKeyLog {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        if self.will_log(label) {
            if let Ok(mut stored) = self.secret.lock() {
                *stored = Some(SecretBytes::new(secret.to_vec()));
            }
        }
    }

    fn will_log(&self, label: &str) -> bool {
        label == SERVER_HANDSHAKE_SECRET
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread};

    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig, ServerConnection,
    };

    #[tokio::test(flavor = "current_thread")]
    async fn standard_probe_collects_tls_profile_without_waiting_for_http() {
        for alpn in [b"h2".to_vec(), b"http/1.1".to_vec()] {
            let rcgen::CertifiedKey { cert, key_pair } =
                rcgen::generate_simple_self_signed(["localhost".to_owned()])
                    .expect("certificate generation");
            let cert_der = cert.der().as_ref().to_vec();
            let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
            let addr = listener.local_addr().expect("local addr");
            let selected_alpn = alpn.clone();
            let (release_http, wait_for_probe) = std::sync::mpsc::channel();
            let server = thread::spawn(move || {
                let mut config = ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3 server provider")
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(cert_der)],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
                )
                .expect("server certificate");
                config.alpn_protocols = vec![selected_alpn];
                // No post-handshake tickets remain unread when the probe closes.
                config.send_tls13_tickets = 0;

                let (tcp, _) = listener.accept().expect("accept");
                tcp.set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("read timeout");
                tcp.set_write_timeout(Some(Duration::from_secs(2)))
                    .expect("write timeout");
                let connection =
                    ServerConnection::new(Arc::new(config)).expect("server connection");
                let mut tls = StreamOwned::new(connection, tcp);
                while tls.conn.is_handshaking() {
                    tls.conn
                        .complete_io(&mut tls.sock)
                        .expect("server handshake");
                }
                // Deliberately gate all application work until the probe has
                // returned. A probe waiting for HTTP will time out instead.
                wait_for_probe
                    .recv_timeout(Duration::from_secs(3))
                    .expect("probe completed before HTTP");
                let mut request = [0_u8; 1024];
                match tls.read(&mut request) {
                    Ok(read) => assert_eq!(read, 0, "probe must not send application data"),
                    Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof),
                }
            });

            let probe = StandardTlsProbe::new(ProbeSettings {
                connect_timeout: Duration::from_secs(1),
                io_timeout: Duration::from_secs(1),
                ..ProbeSettings::default()
            });
            let started = Instant::now();
            let result = probe
                .probe_async_with_extra_roots(
                    &format!("localhost:{}", addr.port()),
                    vec![cert.der().as_ref().to_vec()],
                )
                .await;
            let completed = started.elapsed();
            release_http.send(()).expect("release application gate");
            tokio::task::spawn_blocking(move || server.join().expect("server thread"))
                .await
                .expect("join task");
            let profile = result.expect("loopback TLS probe must not await HTTP");
            assert_eq!(profile.tls_ver, 0x0304);
            assert!([0x1301, 0x1303].contains(&profile.cipher));
            assert_ne!(profile.group, 0);
            assert_eq!(profile.alpn, vec![alpn]);
            assert!(profile.ee_exts.contains(&0x0010));
            assert!(profile
                .leaf_template
                .san_dns
                .contains(&"localhost".to_owned()));
            assert!(profile.rtt > Duration::ZERO);
            assert!(profile.rtt <= completed);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stalled_tls_probe_times_out_while_unrelated_work_progresses() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let dest = listener.local_addr().expect("address").to_string();
        let (accepted, ready) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.expect("accept");
            let mut hello = [0_u8; 1024];
            assert!(peer.read(&mut hello).await.expect("ClientHello") > 0);
            accepted.send(()).expect("signal handshake stall");
            let mut rest = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), peer.read_to_end(&mut rest))
                .await
                .expect("worker must close stalled connection")
                .expect("read EOF");
        });
        let probe = tokio::spawn(async move {
            StandardTlsProbe::new(ProbeSettings {
                connect_timeout: Duration::from_millis(150),
                io_timeout: Duration::from_millis(150),
                ..ProbeSettings::default()
            })
            .probe_async(&dest)
            .await
        });
        tokio::time::timeout(Duration::from_secs(1), ready)
            .await
            .expect("executor progressed")
            .expect("server ready");
        // A current-thread runtime cannot service this timer if the probe uses
        // blocking I/O directly. Keep the peer alive through the probe timeout.
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            !probe.is_finished(),
            "unrelated work runs during stalled TLS"
        );
        assert!(tokio::time::timeout(Duration::from_secs(1), probe)
            .await
            .expect("finite caller deadline")
            .expect("probe task")
            .is_err());
        server.await.expect("server task");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn trickling_tls_bytes_cannot_reset_the_overall_deadline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let dest = listener.local_addr().expect("address").to_string();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.expect("accept");
            let mut hello = [0_u8; 1024];
            assert!(peer.read(&mut hello).await.expect("ClientHello") > 0);
            // A long incomplete TLS record keeps the handshake waiting even
            // though each individual read makes progress before its I/O cap.
            peer.write_all(&[0x16, 0x03, 0x03, 0x01, 0x00])
                .await
                .expect("record header");
            tokio::pin!(stopped);
            let mut tick = tokio::time::interval(Duration::from_millis(10));
            let mut sent = 0;
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    _ = tick.tick() => {
                        if peer.write_all(&[0]).await.is_err() {
                            break;
                        }
                        sent += 1;
                    }
                }
            }
            sent
        });
        let probe = StandardTlsProbe::new(ProbeSettings {
            connect_timeout: Duration::from_millis(100),
            io_timeout: Duration::from_millis(100),
            ..ProbeSettings::default()
        });
        let started = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(1), probe.probe_async(&dest))
            .await
            .expect("overall deadline ends trickling handshake");
        let elapsed = started.elapsed();
        let _ = stop.send(());
        assert!(result.is_err());
        assert!(
            elapsed >= Duration::from_millis(150),
            "reads kept making progress"
        );
        assert!(server.await.expect("server task") > 1);
    }

    #[test]
    fn expired_work_queued_in_blocking_pool_never_starts_network_io() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .max_blocking_threads(1)
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let (release, wait) = std::sync::mpsc::channel();
            let (started, ready) = tokio::sync::oneshot::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started.send(()).expect("blocker started");
                wait.recv_timeout(Duration::from_secs(2))
                    .expect("release blocker");
            });
            ready.await.expect("blocking pool occupied");
            let slots = Arc::new(Semaphore::new(1));
            let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let worker_invoked = invoked.clone();
            assert_eq!(
                run_bounded_probe(
                    slots.clone(),
                    Instant::now() + Duration::from_millis(20),
                    move || {
                        worker_invoked.store(true, std::sync::atomic::Ordering::SeqCst);
                        Err(RealityError::ProbeFailed("expired queued work ran"))
                    }
                )
                .await,
                Err(RealityError::ProbeFailed("probe deadline exceeded"))
            );
            assert_eq!(
                slots.available_permits(),
                0,
                "queued worker still owns permit"
            );
            release.send(()).expect("release pool");
            blocker.await.expect("blocker exit");
            let permit = tokio::time::timeout(Duration::from_secs(1), slots.acquire())
                .await
                .expect("expired worker exits")
                .expect("pool open");
            drop(permit);
            assert_eq!(slots.available_permits(), 1);
            assert!(!invoked.load(std::sync::atomic::Ordering::SeqCst));
        });
    }

    #[tokio::test(flavor = "current_thread")]
    async fn default_entry_point_does_not_block_the_executor() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let dest = listener.local_addr().expect("address").to_string();
        let probe = tokio::spawn(async move { probe_dest(&dest).await });
        let (peer, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("accept must run alongside default probe")
            .expect("accept");
        tokio::task::yield_now().await;
        assert!(!probe.is_finished());
        drop(peer);
        assert!(tokio::time::timeout(Duration::from_secs(2), probe)
            .await
            .expect("closed peer terminates probe")
            .expect("probe task")
            .is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timed_out_and_cancelled_workers_keep_slots_until_they_exit() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let slots = Arc::new(Semaphore::new(2));
        let mut callers = Vec::new();
        let mut releases = Vec::new();
        for _ in 0..2 {
            let (started, ready) = tokio::sync::oneshot::channel();
            let (release, stalled) = std::sync::mpsc::channel();
            releases.push(release);
            callers.push(tokio::spawn(run_bounded_probe(
                slots.clone(),
                Instant::now() + Duration::from_millis(200),
                move || {
                    started.send(()).expect("started");
                    // Model a noninterruptible OS DNS call with a controlled
                    // gate. It outlives the caller, but never escapes its slot.
                    stalled
                        .recv_timeout(Duration::from_secs(5))
                        .expect("release worker");
                    Err(RealityError::ProbeFailed("controlled resolver finished"))
                },
            )));
            tokio::time::timeout(Duration::from_secs(1), ready)
                .await
                .expect("worker started")
                .expect("start signal");
        }
        let cancelled = callers.remove(0);
        cancelled.abort();
        assert!(cancelled
            .await
            .expect_err("caller cancelled")
            .is_cancelled());
        assert_eq!(
            callers.remove(0).await.expect("caller task"),
            Err(RealityError::ProbeFailed("probe deadline exceeded"))
        );
        assert_eq!(slots.available_permits(), 0);

        let replacements = Arc::new(AtomicUsize::new(0));
        for _ in 0..8 {
            let replacements = replacements.clone();
            assert_eq!(
                run_bounded_probe(
                    slots.clone(),
                    Instant::now() + Duration::from_millis(5),
                    move || {
                        replacements.fetch_add(1, Ordering::SeqCst);
                        Err(RealityError::ProbeFailed("replacement must not start"))
                    },
                )
                .await,
                Err(RealityError::ProbeFailed("probe deadline exceeded"))
            );
        }
        assert_eq!(replacements.load(Ordering::SeqCst), 0);
        assert_eq!(slots.available_permits(), 0);
        for release in releases {
            release.send(()).expect("release blocked worker");
        }
        let all_slots = tokio::time::timeout(Duration::from_secs(1), slots.acquire_many(2))
            .await
            .expect("workers actually exit")
            .expect("pool open");
        drop(all_slots);
        assert_eq!(slots.available_permits(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expired_and_closed_queues_never_run_the_probe() {
        let slots = Arc::new(Semaphore::new(1));
        assert_eq!(
            run_bounded_probe(slots.clone(), Instant::now(), || {
                panic!("expired work must not start");
            })
            .await,
            Err(RealityError::ProbeFailed("probe deadline exceeded"))
        );
        slots.close();
        assert_eq!(
            run_bounded_probe(slots, Instant::now() + Duration::from_secs(1), || {
                panic!("closed pool must not start work");
            })
            .await,
            Err(RealityError::ProbeFailed("probe worker pool closed"))
        );
    }

    #[test]
    fn recording_stream_preserves_first_response_timestamp_and_remaining_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let connect_started = Instant::now();
        let client = TcpStream::connect(listener.local_addr().expect("address")).expect("connect");
        let (mut peer, _) = listener.accept().expect("accept");
        let mut stream = RecordingStream::new(
            client,
            Instant::now() + Duration::from_secs(2),
            Duration::from_secs(1),
        );
        assert!(stream.first_response_at.is_none());
        peer.write_all(&[0x16]).expect("first TLS byte");
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).expect("first read");
        assert_eq!(byte, [0x16]);
        let first_response = stream.first_response_at.expect("response timestamp");
        assert!(first_response > connect_started);
        peer.write_all(&[0x03, 0x03]).expect("later TLS bytes");
        stream.read_exact(&mut byte).expect("second read");
        assert_eq!(stream.first_response_at, Some(first_response));
        assert_eq!(stream.inbound, [0x16, 0x03]);
        assert!(stream.remaining_io().expect("I/O budget") <= Duration::from_secs(1));
        stream.deadline = Instant::now() + Duration::from_millis(20);
        assert!(stream.remaining_io().expect("shortened budget") <= Duration::from_millis(20));
        stream.deadline = Instant::now();
        // Even buffered peer bytes cannot restart a spent deadline.
        assert_eq!(
            stream.read(&mut byte).expect_err("expired read").kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            stream.write(&byte).expect_err("expired write").kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            stream.flush().expect_err("expired flush").kind(),
            std::io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn recording_stream_eof_is_not_a_tls_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let client = TcpStream::connect(listener.local_addr().expect("address")).expect("connect");
        let (peer, _) = listener.accept().expect("accept");
        drop(peer);
        let mut stream = RecordingStream::new(
            client,
            Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
        );
        assert_eq!(stream.read(&mut [0_u8; 1]).expect("EOF"), 0);
        assert!(stream.first_response_at.is_none());
        assert!(stream.inbound.is_empty());
    }

    #[test]
    fn probe_settings_reject_zero_and_overflowing_deadlines() {
        for (connect_timeout, io_timeout) in [
            (Duration::ZERO, Duration::from_secs(1)),
            (Duration::from_secs(1), Duration::ZERO),
            (Duration::MAX, Duration::MAX),
        ] {
            assert!(ProbeSettings {
                connect_timeout,
                io_timeout,
                ..ProbeSettings::default()
            }
            .deadline()
            .is_err());
        }
        let before = Instant::now();
        let deadline = ProbeSettings::default().deadline().expect("default budget");
        assert!(deadline >= before + Duration::from_secs(20));
        assert!(deadline <= Instant::now() + Duration::from_secs(20));
        assert!(StandardTlsProbe::default().probe_dest("").is_err());
    }

    #[test]
    fn parse_dest_accepts_dns_and_bracketed_ipv6() {
        assert_eq!(
            parse_dest("example.com:443").expect("valid DNS destination"),
            ParsedDest {
                host: "example.com".to_owned(),
                port: 443,
            }
        );
        assert_eq!(
            parse_dest("[2001:db8::1]:8443").expect("valid IPv6 destination"),
            ParsedDest {
                host: "2001:db8::1".to_owned(),
                port: 8443,
            }
        );
        assert_eq!(
            parse_dest("example.com:0").expect_err("zero port must fail"),
            RealityError::InvalidDestProfile("destination must be host:port")
        );
    }

    #[test]
    fn certificate_template_extracts_visible_leaf_fields() {
        let rcgen::CertifiedKey { cert, .. } =
            rcgen::generate_simple_self_signed(["example.com".to_owned()])
                .expect("certificate generation");
        let template = cert_template_from_der(cert.der().as_ref()).expect("template parse");

        assert!(template.subject.contains("CN=rcgen self signed cert"));
        assert!(template.issuer.contains("CN=rcgen self signed cert"));
        assert!(template.not_after_unix > template.not_before_unix);
        assert_eq!(template.san_dns, vec!["example.com".to_owned()]);
        assert!(!template.signature_algorithm.is_empty());
        assert_eq!(template.leaf_der, cert.der().as_ref());
    }

    #[test]
    fn decrypted_handshake_parser_extracts_ee_ocsp_and_sct() {
        let mut encrypted_extensions_body = Vec::new();
        let mut ee_exts = Vec::new();
        push_extension(0x0010, b"h2", &mut ee_exts);
        push_extension(0x002b, &[0x03, 0x04], &mut ee_exts);
        push_u16(ee_exts.len(), &mut encrypted_extensions_body);
        encrypted_extensions_body.extend_from_slice(&ee_exts);

        let ocsp = b"ocsp-staple";
        let mut status_request = Vec::new();
        status_request.push(1);
        push_u24(ocsp.len(), &mut status_request);
        status_request.extend_from_slice(ocsp);

        let mut cert_exts = Vec::new();
        push_extension(EXT_STATUS_REQUEST, &status_request, &mut cert_exts);
        push_extension(
            EXT_SIGNED_CERTIFICATE_TIMESTAMP,
            b"sct-list",
            &mut cert_exts,
        );

        let mut cert_entry = Vec::new();
        push_u24(4, &mut cert_entry);
        cert_entry.extend_from_slice(b"cert");
        push_u16(cert_exts.len(), &mut cert_entry);
        cert_entry.extend_from_slice(&cert_exts);

        let mut cert_body = Vec::new();
        cert_body.push(0);
        push_u24(cert_entry.len(), &mut cert_body);
        cert_body.extend_from_slice(&cert_entry);

        let mut handshake = Vec::new();
        push_handshake(
            HANDSHAKE_ENCRYPTED_EXTENSIONS,
            &encrypted_extensions_body,
            &mut handshake,
        );
        push_handshake(HANDSHAKE_CERTIFICATE, &cert_body, &mut handshake);

        let metadata = parse_decrypted_handshakes(&handshake).expect("metadata");
        assert_eq!(metadata.ee_exts, vec![0x0010, 0x002b]);
        assert_eq!(metadata.ocsp.as_deref(), Some(ocsp.as_slice()));
        assert_eq!(metadata.sct, vec![b"sct-list".to_vec()]);
    }

    #[test]
    fn decrypted_handshake_parser_fails_on_missing_ee() {
        let mut handshake = Vec::new();
        push_handshake(HANDSHAKE_CERTIFICATE, &[0, 0, 0, 0], &mut handshake);

        assert_eq!(
            parse_decrypted_handshakes(&handshake).expect_err("EE must be present"),
            RealityError::ProbeFailed("EncryptedExtensions missing")
        );
    }

    #[test]
    fn extension_parser_rejects_length_mismatch() {
        let malformed = [0, 5, 0, 16, 0, 0];

        assert_eq!(
            parse_extension_ids(&malformed).expect_err("length mismatch"),
            RealityError::ProbeFailed("EncryptedExtensions length mismatch")
        );
    }

    #[test]
    fn memory_keylog_moves_zeroizing_secret_and_redacts_debug() {
        let log = MemoryKeyLog::default();
        assert!(log.will_log(SERVER_HANDSHAKE_SECRET));
        assert!(!log.will_log("CLIENT_TRAFFIC_SECRET_0"));
        log.log("CLIENT_TRAFFIC_SECRET_0", b"random", b"unused secret");
        assert!(log.take_secret().is_none());
        log.log(SERVER_HANDSHAKE_SECRET, b"random", b"old secret");
        log.log(SERVER_HANDSHAKE_SECRET, b"random", b"replacement secret");
        assert_eq!(format!("{log:?}"), "MemoryKeyLog(<redacted>)");
        let secret: SecretBytes = log.take_secret().expect("recorded secret");
        assert_eq!(secret.expose_secret(), b"replacement secret");
        assert_eq!(format!("{secret:?}"), "SecretBytes(<redacted>)");
        assert!(
            log.take_secret().is_none(),
            "secret must be moved, not copied"
        );
    }

    fn push_handshake(msg_type: u8, body: &[u8], out: &mut Vec<u8>) {
        out.push(msg_type);
        push_u24(body.len(), out);
        out.extend_from_slice(body);
    }

    fn push_extension(ext: u16, body: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(&ext.to_be_bytes());
        push_u16(body.len(), out);
        out.extend_from_slice(body);
    }

    fn push_u16(value: usize, out: &mut Vec<u8>) {
        let len = u16::try_from(value).expect("test length fits u16");
        out.extend_from_slice(&len.to_be_bytes());
    }

    fn push_u24(value: usize, out: &mut Vec<u8>) {
        let len = u32::try_from(value).expect("test length fits u24");
        assert!(len <= 0x00ff_ffff);
        out.push(((len >> 16) & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    }
}
