//! Destination prebuild profiles and refresh state.

use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use crate::RealityError;
use rustls::{
    pki_types::ServerName, ClientConfig, ClientConnection, KeyLog, ProtocolVersion, RootCertStore,
    StreamOwned,
};
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
    /// Measured time to first byte.
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
            alpn: self
                .alpn
                .first()
                .and_then(|value| String::from_utf8(value.clone()).ok()),
            rtt_millis: u64::try_from(self.rtt.as_millis()).unwrap_or(u64::MAX),
        }
    }
}

/// Network probe settings for the default standard TLS probe.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProbeSettings {
    /// TCP connection timeout.
    pub connect_timeout: Duration,
    /// Read/write timeout for TLS and first-byte sampling.
    pub io_timeout: Duration,
    /// HTTP request path used to elicit a first application byte.
    pub request_path: String,
    /// ALPN protocols offered during probing.
    pub alpn: Vec<Vec<u8>>,
}

impl Default for ProbeSettings {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            io_timeout: DEFAULT_IO_TIMEOUT,
            request_path: "/".to_owned(),
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

    fn probe(&self, dest: &str) -> Result<DestProfile, RealityError> {
        self.probe_with_extra_roots(dest, &[])
    }

    fn probe_with_extra_roots(
        &self,
        dest: &str,
        extra_root_der: &[Vec<u8>],
    ) -> Result<DestProfile, RealityError> {
        let parsed = parse_dest(dest)?;
        let stream = connect_tcp(&parsed, self.settings.connect_timeout)?;
        stream
            .set_read_timeout(Some(self.settings.io_timeout))
            .map_err(|_| RealityError::ProbeFailed("failed to set TCP read timeout"))?;
        stream
            .set_write_timeout(Some(self.settings.io_timeout))
            .map_err(|_| RealityError::ProbeFailed("failed to set TCP write timeout"))?;

        let key_log = Arc::new(MemoryKeyLog::default());
        let mut config = tls_client_config(&self.settings, key_log.clone(), extra_root_der)?;
        config.enable_sni = true;

        let server_name = ServerName::try_from(parsed.host.clone())
            .map_err(|_| RealityError::InvalidDestProfile("destination host is not a valid SNI"))?;
        let connection = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|_| RealityError::ProbeFailed("TLS client initialization failed"))?;
        let mut tls = StreamOwned::new(connection, RecordingStream::new(stream));

        let start = Instant::now();
        while tls.conn.is_handshaking() {
            tls.conn
                .complete_io(&mut tls.sock)
                .map_err(|_| RealityError::ProbeFailed("TLS handshake failed"))?;
        }

        let request = format!(
            "HEAD {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: UmbraProbe/0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            self.settings.request_path, parsed.host
        );
        tls.write_all(request.as_bytes())
            .map_err(|_| RealityError::ProbeFailed("probe request write failed"))?;
        tls.flush()
            .map_err(|_| RealityError::ProbeFailed("probe request flush failed"))?;

        let mut first_byte = [0_u8; 1];
        let read = tls
            .read(&mut first_byte)
            .map_err(|_| RealityError::ProbeFailed("first byte read failed"))?;
        if read == 0 {
            return Err(RealityError::ProbeFailed(
                "destination closed before first byte",
            ));
        }
        let rtt = start.elapsed();

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

        let handshake_secret =
            key_log
                .secret("SERVER_HANDSHAKE_TRAFFIC_SECRET")
                .ok_or(RealityError::ProbeFailed(
                    "server handshake traffic secret missing",
                ))?;
        let metadata = collect_handshake_metadata(&tls.sock.inbound, cipher, &handshake_secret)?;
        leaf_template.sct.extend(metadata.sct);

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
    /// Measured first-byte RTT.
    pub rtt: Duration,
}

/// Synchronous probing backend.
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

/// Default network probe entry point.
pub async fn probe_dest(dest: &str) -> Result<DestProfile, RealityError> {
    std::future::ready(()).await;
    StandardTlsProbe::default().probe_dest(dest)
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

fn connect_tcp(parsed: &ParsedDest, timeout: Duration) -> Result<TcpStream, RealityError> {
    let mut last_error = false;
    for addr in parsed
        .socket_target()
        .to_socket_addrs()
        .map_err(|_| RealityError::ProbeFailed("DNS resolution failed"))?
    {
        match TcpStream::connect_timeout(&addr, timeout) {
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
    let mut layer = RecordLayer::new(cipher, traffic_keys.key, traffic_keys.iv);
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
}

impl RecordingStream {
    const fn new(inner: TcpStream) -> Self {
        Self {
            inner,
            inbound: Vec::new(),
        }
    }
}

impl Read for RecordingStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.inbound.extend_from_slice(&buf[..read]);
        Ok(read)
    }
}

impl Write for RecordingStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Debug, Default)]
struct MemoryKeyLog {
    secrets: Mutex<Vec<KeyLogEntry>>,
}

impl MemoryKeyLog {
    fn secret(&self, label: &str) -> Option<Vec<u8>> {
        self.secrets.lock().ok().and_then(|secrets| {
            secrets
                .iter()
                .find(|entry| entry.label == label)
                .map(|entry| entry.secret.clone())
        })
    }
}

impl KeyLog for MemoryKeyLog {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        if let Ok(mut secrets) = self.secrets.lock() {
            secrets.push(KeyLogEntry {
                label: label.to_owned(),
                secret: secret.to_vec(),
            });
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct KeyLogEntry {
    label: String,
    secret: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread};

    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig, ServerConnection,
    };

    #[test]
    fn standard_probe_collects_loopback_tls13_profile() {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(["localhost".to_owned()])
                .expect("certificate generation");
        let cert_der = cert.der().as_ref().to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let addr = listener.local_addr().expect("local addr");
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
            config.alpn_protocols = vec![b"h2".to_vec()];

            let (tcp, _) = listener.accept().expect("accept");
            let connection = ServerConnection::new(Arc::new(config)).expect("server connection");
            let mut tls = StreamOwned::new(connection, tcp);
            let mut request = [0_u8; 1024];
            let read = tls.read(&mut request).expect("read request");
            assert!(read > 0);
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .expect("write response");
            tls.flush().expect("flush response");
        });

        let settings = ProbeSettings {
            connect_timeout: Duration::from_secs(2),
            io_timeout: Duration::from_secs(2),
            request_path: "/".to_owned(),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        };
        let probe = StandardTlsProbe::new(settings);
        let profile = probe
            .probe_with_extra_roots(
                &format!("localhost:{}", addr.port()),
                &[cert.der().as_ref().to_vec()],
            )
            .expect("loopback probe");

        server.join().expect("server thread");
        assert_eq!(profile.tls_ver, 0x0304);
        assert!([0x1301, 0x1303].contains(&profile.cipher));
        assert_ne!(profile.group, 0);
        assert_eq!(profile.alpn, vec![b"h2".to_vec()]);
        assert!(profile.ee_exts.contains(&0x0010));
        assert!(profile
            .leaf_template
            .san_dns
            .contains(&"localhost".to_owned()));
        assert!(profile.rtt > Duration::ZERO);
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
    fn memory_keylog_returns_recorded_secret() {
        let log = MemoryKeyLog::default();
        log.log("SERVER_HANDSHAKE_TRAFFIC_SECRET", b"random", b"secret");

        assert_eq!(
            log.secret("SERVER_HANDSHAKE_TRAFFIC_SECRET"),
            Some(b"secret".to_vec())
        );
        assert_eq!(log.secret("CLIENT_TRAFFIC_SECRET_0"), None);
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
