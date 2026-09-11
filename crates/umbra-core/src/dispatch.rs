//! Server dispatch and probe-forwarding helpers.

use std::{
    future::Future,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::Instant,
};
use umbra_crypto::{secret::Secret, x25519};
use umbra_fingerprint::grease::is_grease;
use umbra_reality::{
    auth::{open_session_id, validate_server_name},
    cert::forge_leaf_certificate,
    prebuild::DestProfile,
    replay::ReplayCache,
};
use umbra_tls::{
    clienthello::{hello0, quic_hello0},
    parse::{parse_client_hello, ParsedClientHello, QuicTransportParameter},
    server::Tls13Server,
};
use umbra_transport::quic::{decrypt_quic_initial_crypto, parse_quic_initial_header};

use crate::{probe::TimingAlignment, CoreError};

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const DEFAULT_MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_CLIENT_HELLO_RECORDS: usize = 16;
const DEFAULT_MAX_USELESS_RECORDS: usize = 0;
const CLIENT_HELLO_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Limits used while reading a complete initial ClientHello.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct HelloReadLimits {
    /// Maximum total TLS record bytes buffered before classification.
    pub max_bytes: usize,
    /// Maximum TLS records consumed while waiting for a complete ClientHello.
    pub max_records: usize,
    /// Maximum non-handshake records tolerated before the ClientHello completes.
    pub max_useless_records: usize,
}

impl Default for HelloReadLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_CLIENT_HELLO_BYTES,
            max_records: DEFAULT_MAX_CLIENT_HELLO_RECORDS,
            max_useless_records: DEFAULT_MAX_USELESS_RECORDS,
        }
    }
}

/// Server dispatch runtime configuration.
pub struct ServerCfg {
    /// Server X25519 private key used to derive REALITY authentication keys.
    pub private_key: x25519::PrivateKey,
    /// Accepted REALITY short identifiers.
    pub short_ids: Vec<Vec<u8>>,
    /// SNI names accepted for the local Umbra path.
    pub server_names: Vec<String>,
    /// Destination `host:port` used for unauthenticated fallback forwarding.
    pub dest: String,
    /// Maximum token timestamp skew in seconds.
    pub max_time_diff: u64,
    /// ML-DSA seed used by forged certificate binding.
    pub mldsa_seed: Secret<32>,
    /// Initial ClientHello read limits.
    pub hello_limits: HelloReadLimits,
}

/// Inputs required to classify a prefetched ClientHello.
#[derive(Clone, Copy)]
pub struct DispatchContext<'a> {
    /// Runtime server configuration.
    pub cfg: &'a ServerCfg,
    /// Destination profile used to forge the local TLS server flight.
    pub profile: &'a DestProfile,
    /// Bounded replay cache for accepted REALITY tokens.
    pub replay: &'a ReplayCache,
    /// Current Unix timestamp used for token freshness checks.
    pub now_unix: u64,
}

/// Reason a connection must be forwarded to the configured destination.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FallbackReason {
    /// ClientHello bytes could not be parsed.
    MalformedClientHello,
    /// The ClientHello did not carry an accepted SNI.
    ServerNameRejected,
    /// The ClientHello omitted a usable X25519 key share.
    MissingKeyShare,
    /// The compatibility session id was not the required 32-byte token.
    InvalidSessionId,
    /// REALITY authentication failed, expired, or replayed.
    AuthenticationRejected,
}

/// Result of classifying a prefetched ClientHello.
pub enum DispatchDecision {
    /// The connection authenticated and should continue on the local Umbra path.
    Authenticated(Box<AuthenticatedDispatch>),
    /// The connection must be forwarded to the real destination without throttling.
    Fallback {
        /// Why the local path was rejected.
        reason: FallbackReason,
        /// Exact ClientHello bytes read from the client and forwarded first.
        chello_raw: Vec<u8>,
    },
}

/// Result of classifying one QUIC Initial datagram.
pub enum QuicDispatchDecision {
    /// The Initial authenticated and should continue on the local QUIC path.
    Authenticated(Box<AuthenticatedQuicDispatch>),
    /// The datagram must be forwarded to the real destination QUIC service.
    Fallback {
        /// Why the local path was rejected.
        reason: FallbackReason,
        /// Exact datagram received from the client.
        datagram: Vec<u8>,
    },
}

/// Authenticated QUIC dispatch state before the local QUIC-TLS server flight.
pub struct AuthenticatedQuicDispatch {
    /// Accepted SNI.
    pub sni: String,
    /// REALITY auth token carried by QUIC transport parameters.
    pub session_id: [u8; 32],
    /// Derived REALITY shared secret.
    pub shared_secret: Secret<32>,
    /// Raw ClientHello handshake bytes recovered from QUIC CRYPTO.
    pub client_hello: Vec<u8>,
}

/// Authenticated dispatch state for the local TLS server path.
pub struct AuthenticatedDispatch {
    /// Accepted SNI.
    pub sni: String,
    /// Client compatibility session id used for certificate binding.
    pub session_id: [u8; 32],
    /// Derived REALITY shared secret.
    pub shared_secret: Secret<32>,
    /// TLS server state after producing the initial server flight.
    pub tls_server: Tls13Server,
    /// Initial TLS server response bytes.
    pub server_flight: Vec<u8>,
}

/// Observable result of async dispatch.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DispatchOutcome {
    /// The local Umbra TLS path accepted the connection.
    Authenticated {
        /// Accepted SNI.
        sni: String,
        /// Bytes written as the initial local server flight.
        server_flight_len: usize,
    },
    /// The connection was relayed to the configured destination.
    Forwarded {
        /// Why the local path was rejected.
        reason: FallbackReason,
        /// Bytes copied from client to destination after the forwarded ClientHello.
        client_to_dest: u64,
        /// Bytes copied from destination to client.
        dest_to_client: u64,
    },
}

/// Read original TLS records through a complete, possibly fragmented ClientHello.
///
/// EOF, read limits, or a five-second overall deadline return the exact consumed
/// prefix for fallback. Invalid limits and terminal I/O failures remain errors.
pub async fn read_client_hello_raw<R>(
    reader: &mut R,
    limits: HelloReadLimits,
) -> Result<Vec<u8>, CoreError>
where
    R: AsyncRead + Unpin,
{
    read_client_hello_raw_with_timeout(reader, limits, CLIENT_HELLO_READ_TIMEOUT).await
}

async fn read_client_hello_raw_with_timeout<R>(
    reader: &mut R,
    limits: HelloReadLimits,
    timeout: Duration,
) -> Result<Vec<u8>, CoreError>
where
    R: AsyncRead + Unpin,
{
    validate_limits(limits)?;
    // The timeout owns only a borrow: cancellation must not discard consumed bytes.
    let mut raw = Vec::new();
    let deadline = Instant::now() + timeout;
    if let Ok(result) = tokio::time::timeout_at(
        deadline,
        read_client_hello_prefix(reader, limits, &mut raw, deadline),
    )
    .await
    {
        result?;
    }
    Ok(raw)
}

async fn read_client_hello_prefix<R>(
    reader: &mut R,
    limits: HelloReadLimits,
    raw: &mut Vec<u8>,
    deadline: Instant,
) -> Result<(), CoreError>
where
    R: AsyncRead + Unpin,
{
    let mut handshake = Vec::new();
    let mut useless_records = 0_usize;

    for _ in 0..limits.max_records {
        let header_start = raw.len();
        let header_end = header_start
            .saturating_add(TLS_RECORD_HEADER_LEN)
            .min(limits.max_bytes);
        if !read_prefix_until(reader, raw, header_end, deadline).await?
            || header_end - header_start < TLS_RECORD_HEADER_LEN
        {
            return Ok(());
        }
        let record_type = raw[header_start];
        let record_len = usize::from(u16::from_be_bytes([
            raw[header_end - 2],
            raw[header_end - 1],
        ]));
        let Some(record_end) = header_end
            .checked_add(record_len)
            .filter(|end| *end <= limits.max_bytes)
        else {
            return Ok(());
        };
        if !read_prefix_until(reader, raw, record_end, deadline).await? {
            return Ok(());
        }

        if record_type != TLS_RECORD_HANDSHAKE {
            useless_records += 1;
            if useless_records > limits.max_useless_records {
                return Ok(());
            }
            continue;
        }

        handshake.extend_from_slice(&raw[header_end..record_end]);
        match complete_client_hello_len(&handshake) {
            Ok(Some(needed)) if needed > limits.max_bytes || handshake.len() >= needed => {
                return Ok(());
            }
            Err(_) => return Ok(()),
            _ => {}
        }
    }
    Ok(())
}

async fn read_prefix_until<R>(
    reader: &mut R,
    raw: &mut Vec<u8>,
    end: usize,
    deadline: Instant,
) -> Result<bool, CoreError>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0_u8; 4096];
    while raw.len() < end {
        // Also bound readers that keep returning immediately without yielding.
        if Instant::now() >= deadline {
            return Ok(false);
        }
        let capacity = (end - raw.len()).min(chunk.len());
        let read = reader.read(&mut chunk[..capacity]).await?;
        if read == 0 {
            return Ok(false);
        }
        // No await between a successful, cancellation-safe read and retention.
        raw.extend_from_slice(&chunk[..read]);
    }
    Ok(true)
}

/// Classify a prefetched ClientHello or incomplete prefix for fallback.
pub fn classify_client_hello(
    chello_raw: Vec<u8>,
    ctx: DispatchContext<'_>,
) -> Result<DispatchDecision, CoreError> {
    validate_cfg(ctx.cfg)?;
    let Ok(handshake) = assemble_client_hello_handshake(&chello_raw) else {
        return Ok(fallback(FallbackReason::MalformedClientHello, chello_raw));
    };
    let Ok(parsed) = parse_client_hello(&handshake) else {
        return Ok(fallback(FallbackReason::MalformedClientHello, chello_raw));
    };

    let Some(sni) = parsed.sni.clone() else {
        return Ok(fallback(FallbackReason::ServerNameRejected, chello_raw));
    };
    if validate_server_name(&sni, &ctx.cfg.server_names).is_err() {
        return Ok(fallback(FallbackReason::ServerNameRejected, chello_raw));
    }

    let Some(client_public) = parsed.x25519_key_share else {
        return Ok(fallback(FallbackReason::MissingKeyShare, chello_raw));
    };
    let Some(session_id) = session_id_array(&parsed) else {
        return Ok(fallback(FallbackReason::InvalidSessionId, chello_raw));
    };

    let Ok(shared) = x25519::agree(&ctx.cfg.private_key, &client_public) else {
        return Ok(fallback(FallbackReason::MissingKeyShare, chello_raw));
    };
    let aad = hello0(&handshake)?;
    if open_session_id(
        shared.expose_secret(),
        &session_id,
        &aad,
        &ctx.cfg.short_ids,
        ctx.now_unix,
        ctx.cfg.max_time_diff,
        ctx.replay,
    )
    .is_err()
    {
        return Ok(fallback(FallbackReason::AuthenticationRejected, chello_raw));
    }

    let forged = forge_leaf_certificate(
        ctx.profile,
        &sni,
        shared.expose_secret(),
        &session_id,
        &ctx.cfg.mldsa_seed,
    )?;
    let accept_input = accept_input(&chello_raw, &handshake)?;
    let tls_profile = ctx.profile.to_tls_server_profile();
    let (tls_server, server_flight) =
        Tls13Server::accept(&accept_input, forged.tls_cert, &tls_profile)?;

    Ok(DispatchDecision::Authenticated(Box::new(
        AuthenticatedDispatch {
            sni,
            session_id,
            shared_secret: shared,
            tls_server,
            server_flight,
        },
    )))
}

/// Classify a protected QUIC Initial into local-authenticated or fallback path.
pub fn classify_quic_initial(
    datagram: Vec<u8>,
    ctx: DispatchContext<'_>,
) -> Result<QuicDispatchDecision, CoreError> {
    validate_cfg(ctx.cfg)?;
    let Ok(header) = parse_quic_initial_header(&datagram) else {
        return Ok(fallback_quic(
            FallbackReason::MalformedClientHello,
            datagram,
        ));
    };
    let Ok(client_hello) = decrypt_quic_initial_crypto(&datagram) else {
        return Ok(fallback_quic(
            FallbackReason::MalformedClientHello,
            datagram,
        ));
    };
    classify_quic_client_hello(datagram, client_hello, &header.scid, ctx)
}

/// Classify a complete QUIC ClientHello recovered from Initial CRYPTO data.
pub fn classify_quic_client_hello(
    datagram: Vec<u8>,
    client_hello: Vec<u8>,
    scid: &[u8],
    ctx: DispatchContext<'_>,
) -> Result<QuicDispatchDecision, CoreError> {
    validate_cfg(ctx.cfg)?;
    let Ok(parsed) = parse_client_hello(&client_hello) else {
        return Ok(fallback_quic(
            FallbackReason::MalformedClientHello,
            datagram,
        ));
    };

    let Some(sni) = parsed.sni.clone() else {
        return Ok(fallback_quic(FallbackReason::ServerNameRejected, datagram));
    };
    if validate_server_name(&sni, &ctx.cfg.server_names).is_err() {
        return Ok(fallback_quic(FallbackReason::ServerNameRejected, datagram));
    }
    if !parsed.session_id.is_empty() {
        return Ok(fallback_quic(FallbackReason::InvalidSessionId, datagram));
    }

    let Some(client_public) = parsed.x25519_key_share else {
        return Ok(fallback_quic(FallbackReason::MissingKeyShare, datagram));
    };
    let Some((grease_parameter, session_id)) =
        quic_session_id_array(&parsed.quic_transport_parameters, scid)
    else {
        return Ok(fallback_quic(FallbackReason::InvalidSessionId, datagram));
    };
    let Ok(shared) = x25519::agree(&ctx.cfg.private_key, &client_public) else {
        return Ok(fallback_quic(FallbackReason::MissingKeyShare, datagram));
    };
    let aad = quic_hello0(&client_hello, grease_parameter)?;
    if open_session_id(
        shared.expose_secret(),
        &session_id,
        &aad,
        &ctx.cfg.short_ids,
        ctx.now_unix,
        ctx.cfg.max_time_diff,
        ctx.replay,
    )
    .is_err()
    {
        return Ok(fallback_quic(
            FallbackReason::AuthenticationRejected,
            datagram,
        ));
    }

    Ok(QuicDispatchDecision::Authenticated(Box::new(
        AuthenticatedQuicDispatch {
            sni,
            session_id,
            shared_secret: shared,
            client_hello,
        },
    )))
}

/// Dispatch a connection using the configured destination over TCP.
pub async fn dispatch<C>(
    conn: C,
    cfg: &ServerCfg,
    profile: &DestProfile,
    replay: &ReplayCache,
) -> Result<DispatchOutcome, CoreError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    dispatch_with_connector(conn, cfg, profile, replay, current_unix_time()?, |dest| {
        tokio::net::TcpStream::connect(dest)
    })
    .await
}

/// Dispatch with an injected destination connector, primarily for tests.
pub async fn dispatch_with_connector<C, D, Connect, ConnectFuture>(
    conn: C,
    cfg: &ServerCfg,
    profile: &DestProfile,
    replay: &ReplayCache,
    now_unix: u64,
    connect_dest: Connect,
) -> Result<DispatchOutcome, CoreError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    D: AsyncRead + AsyncWrite + Unpin,
    Connect: FnOnce(String) -> ConnectFuture,
    ConnectFuture: Future<Output = Result<D, std::io::Error>>,
{
    dispatch_with_connector_and_timing(
        conn,
        cfg,
        profile,
        replay,
        now_unix,
        connect_dest,
        TimingAlignment::disabled(),
    )
    .await
}

/// Dispatch with an injected destination connector and first-byte timing policy.
pub async fn dispatch_with_connector_and_timing<C, D, Connect, ConnectFuture>(
    mut conn: C,
    cfg: &ServerCfg,
    profile: &DestProfile,
    replay: &ReplayCache,
    now_unix: u64,
    connect_dest: Connect,
    timing: TimingAlignment,
) -> Result<DispatchOutcome, CoreError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    D: AsyncRead + AsyncWrite + Unpin,
    Connect: FnOnce(String) -> ConnectFuture,
    ConnectFuture: Future<Output = Result<D, std::io::Error>>,
{
    let started_at = Instant::now();
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
        DispatchDecision::Authenticated(authenticated) => {
            timing.wait_started_at(started_at, profile).await;
            conn.write_all(&authenticated.server_flight).await?;
            conn.flush().await?;
            Ok(DispatchOutcome::Authenticated {
                sni: authenticated.sni,
                server_flight_len: authenticated.server_flight.len(),
            })
        }
        DispatchDecision::Fallback { reason, chello_raw } => {
            let mut dest = connect_dest(cfg.dest.clone()).await?;
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

/// Write the prefetched ClientHello bytes to the destination and flush.
pub async fn write_fallback_prefix<W>(dest: &mut W, chello_raw: &[u8]) -> Result<(), CoreError>
where
    W: AsyncWrite + Unpin,
{
    dest.write_all(chello_raw).await?;
    dest.flush().await?;
    Ok(())
}

/// Relay a client stream to a destination after replaying a prefix first.
pub async fn relay_prefixed<C, D>(
    client: C,
    mut dest: D,
    prefix: Vec<u8>,
) -> Result<(u64, u64), CoreError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    D: AsyncRead + AsyncWrite + Unpin,
{
    let mut client = crate::prefixed::PrefixedStream::new(prefix, client);
    tokio::io::copy_bidirectional(&mut client, &mut dest)
        .await
        .map_err(CoreError::from)
}

fn validate_limits(limits: HelloReadLimits) -> Result<(), CoreError> {
    if limits.max_records == 0 {
        return Err(CoreError::InvalidConfig("max_records must be positive"));
    }
    if limits.max_bytes < TLS_RECORD_HEADER_LEN {
        return Err(CoreError::InvalidConfig(
            "max_bytes must hold a TLS record header",
        ));
    }
    Ok(())
}

fn validate_cfg(cfg: &ServerCfg) -> Result<(), CoreError> {
    if cfg.short_ids.is_empty() {
        return Err(CoreError::InvalidConfig(
            "at least one short id is required",
        ));
    }
    if cfg.server_names.is_empty() {
        return Err(CoreError::InvalidConfig(
            "at least one server name is required",
        ));
    }
    if cfg.dest.is_empty() {
        return Err(CoreError::InvalidConfig("fallback destination is empty"));
    }
    if cfg.max_time_diff == 0 {
        return Err(CoreError::InvalidConfig("max_time_diff must be positive"));
    }
    validate_limits(cfg.hello_limits)
}

fn fallback(reason: FallbackReason, chello_raw: Vec<u8>) -> DispatchDecision {
    DispatchDecision::Fallback { reason, chello_raw }
}

fn fallback_quic(reason: FallbackReason, datagram: Vec<u8>) -> QuicDispatchDecision {
    QuicDispatchDecision::Fallback { reason, datagram }
}

fn session_id_array(parsed: &ParsedClientHello) -> Option<[u8; 32]> {
    parsed.session_id.as_slice().try_into().ok()
}

fn quic_session_id_array(
    parameters: &[QuicTransportParameter],
    scid: &[u8],
) -> Option<(u64, [u8; 32])> {
    for parameter in parameters {
        if !is_grease_u64(parameter.id) {
            continue;
        }
        if let Ok(session_id) = parameter.value.as_slice().try_into() {
            return Some((parameter.id, session_id));
        }
        if parameter.value.len() == 24 && scid.len() >= 8 {
            let mut session_id = [0_u8; 32];
            session_id[..8].copy_from_slice(&scid[..8]);
            session_id[8..].copy_from_slice(&parameter.value);
            return Some((parameter.id, session_id));
        }
    }
    None
}

fn is_grease_u64(value: u64) -> bool {
    u16::try_from(value).is_ok_and(is_grease)
}

fn accept_input(chello_raw: &[u8], handshake: &[u8]) -> Result<Vec<u8>, CoreError> {
    if single_complete_record(chello_raw) {
        Ok(chello_raw.to_vec())
    } else {
        tls_record(handshake)
    }
}

fn assemble_client_hello_handshake(raw: &[u8]) -> Result<Vec<u8>, CoreError> {
    if raw.first() != Some(&TLS_RECORD_HANDSHAKE) {
        return Ok(raw.to_vec());
    }
    let mut offset = 0_usize;
    let mut handshake = Vec::new();
    while offset < raw.len() {
        let header_end = offset
            .checked_add(TLS_RECORD_HEADER_LEN)
            .ok_or(CoreError::ClientHelloTooLarge)?;
        if header_end > raw.len() {
            return Err(CoreError::InvalidClientHello("short TLS record"));
        }
        let record_type = raw[offset];
        let len = usize::from(u16::from_be_bytes([raw[offset + 3], raw[offset + 4]]));
        let payload_start = header_end;
        let payload_end = payload_start
            .checked_add(len)
            .ok_or(CoreError::ClientHelloTooLarge)?;
        if payload_end > raw.len() {
            return Err(CoreError::InvalidClientHello("truncated TLS record"));
        }
        if record_type == TLS_RECORD_HANDSHAKE {
            handshake.extend_from_slice(&raw[payload_start..payload_end]);
            if complete_client_hello_len(&handshake)?
                .is_some_and(|needed| handshake.len() >= needed)
            {
                let needed = complete_client_hello_len(&handshake)?
                    .ok_or(CoreError::InvalidClientHello("missing ClientHello length"))?;
                handshake.truncate(needed);
                return Ok(handshake);
            }
        }
        offset = payload_end;
    }
    Err(CoreError::InvalidClientHello("truncated ClientHello"))
}

fn single_complete_record(raw: &[u8]) -> bool {
    if raw.len() < TLS_RECORD_HEADER_LEN || raw[0] != TLS_RECORD_HANDSHAKE {
        return false;
    }
    let len = usize::from(u16::from_be_bytes([raw[3], raw[4]]));
    TLS_RECORD_HEADER_LEN + len == raw.len()
}

fn complete_client_hello_len(handshake: &[u8]) -> Result<Option<usize>, CoreError> {
    if handshake.len() < 4 {
        return Ok(None);
    }
    if handshake[0] != TLS_HANDSHAKE_CLIENT_HELLO {
        return Err(CoreError::InvalidClientHello("not a ClientHello"));
    }
    let len = read_u24(&handshake[1..4])?;
    Ok(Some(
        4_usize
            .checked_add(len)
            .ok_or(CoreError::ClientHelloTooLarge)?,
    ))
}

fn tls_record(handshake: &[u8]) -> Result<Vec<u8>, CoreError> {
    let len = u16::try_from(handshake.len())
        .map_err(|_| CoreError::InvalidClientHello("ClientHello record too large"))?;
    let mut out = Vec::with_capacity(TLS_RECORD_HEADER_LEN + handshake.len());
    out.push(TLS_RECORD_HANDSHAKE);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(handshake);
    Ok(out)
}

fn read_u24(input: &[u8]) -> Result<usize, CoreError> {
    if input.len() != 3 {
        return Err(CoreError::InvalidClientHello("bad uint24"));
    }
    Ok((usize::from(input[0]) << 16) | (usize::from(input[1]) << 8) | usize::from(input[2]))
}

fn current_unix_time() -> Result<u64, CoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoreError::InvalidConfig("system clock is before Unix epoch"))
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::{self, ReadBuf};

    use super::*;

    #[tokio::test]
    async fn deadline_preserves_each_partial_header_and_body_then_relays() {
        // Two fragments, including a split handshake header, never complete the hello.
        let input = [
            0x16, 3, 3, 0, 2, 1, 0, 0x16, 3, 3, 0, 6, 0, 32, 0xaa, 0xbb, 0xcc, 0xdd,
        ];
        for end in 0..input.len() {
            let (mut client, mut server) = io::duplex(64);
            client
                .write_all(&input[..end])
                .await
                .expect("write partial hello");
            let raw = tokio::time::timeout(
                Duration::from_secs(1),
                read_client_hello_raw_with_timeout(
                    &mut server,
                    HelloReadLimits::default(),
                    Duration::from_millis(10),
                ),
            )
            .await
            .expect("classification deadline fires")
            .expect("timeout returns prefix");
            assert_eq!(raw, input[..end]);

            client
                .write_all(&input[end..])
                .await
                .expect("write after deadline");
            client.shutdown().await.expect("half-close request");
            let (dest, mut dest_peer) = io::duplex(64);
            let destination = async {
                let mut received = Vec::new();
                dest_peer
                    .read_to_end(&mut received)
                    .await
                    .expect("receive request EOF");
                assert_eq!(received, input);
                dest_peer
                    .write_all(b"response")
                    .await
                    .expect("reply after EOF");
                dest_peer.shutdown().await.expect("half-close destination");
            };
            let (copied, ()) = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(relay_prefixed(server, dest, raw), destination)
            })
            .await
            .expect("relay completes");
            assert_eq!(copied.expect("relay succeeds"), (18, 8));
            let mut response = Vec::new();
            client
                .read_to_end(&mut response)
                .await
                .expect("read reverse response");
            assert_eq!(response, b"response");
        }
    }

    #[tokio::test]
    async fn slow_progress_does_not_reset_overall_deadline() {
        let (mut client, mut server) = io::duplex(512);
        let mut sent = vec![0x16, 3, 3, 0x10, 0];
        client.write_all(&sent).await.expect("write record header");
        let raw = tokio::time::timeout(Duration::from_millis(500), async {
            tokio::select! {
                result = read_client_hello_raw_with_timeout(
                    &mut server,
                    HelloReadLimits::default(),
                    Duration::from_millis(60),
                ) => result.expect("deadline returns prefix"),
                () = async {
                    for byte in 0..200_u8 {
                        client.write_all(&[byte]).await.expect("drip one byte");
                        sent.push(byte);
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                } => panic!("classification waited for the slow sender"),
            }
        })
        .await
        .expect("overall deadline must not restart after progress");
        assert!(raw.len() > TLS_RECORD_HEADER_LEN);
        assert_eq!(raw, sent[..raw.len()]);
        client.shutdown().await.expect("half-close sender");
        let mut remaining = Vec::new();
        server
            .read_to_end(&mut remaining)
            .await
            .expect("read remaining bytes");
        assert_eq!([raw, remaining].concat(), sent);
    }

    #[tokio::test]
    async fn expired_deadline_consumes_nothing() {
        let mut reader = &b"untouched"[..];
        let raw = read_client_hello_raw_with_timeout(
            &mut reader,
            HelloReadLimits::default(),
            Duration::ZERO,
        )
        .await
        .expect("expired deadline returns prefix");
        assert!(raw.is_empty());
        assert_eq!(reader, b"untouched");
    }

    struct ResetAtEof(io::DuplexStream);

    impl AsyncRead for ResetAtEof {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let before = buf.filled().len();
            match Pin::new(&mut self.0).poll_read(cx, buf) {
                Poll::Ready(Ok(())) if buf.filled().len() == before => {
                    Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
                }
                result => result,
            }
        }
    }

    #[tokio::test]
    async fn terminal_read_error_remains_an_error() {
        let (mut client, server) = io::duplex(64);
        client
            .write_all(&[0x16, 3])
            .await
            .expect("write partial header");
        client.shutdown().await.expect("finish test input");
        let err = read_client_hello_raw(&mut ResetAtEof(server), HelloReadLimits::default())
            .await
            .expect_err("terminal reset must remain an error");
        assert!(
            matches!(err, CoreError::Io(error) if error.kind() == std::io::ErrorKind::ConnectionReset)
        );
    }
}
