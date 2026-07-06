//! TCP outer connection helpers.

use std::{future::Future, net::SocketAddr};

use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use umbra_fingerprint::FingerprintProfile;
use umbra_tls::clienthello::{build_client_hello, ClientHelloParams, MlkemShare};

use crate::{
    evasion::{plan_client_hello_writes, TcpEvasionPolicy},
    TransportError,
};

/// Inputs used to build a TCP outer ClientHello.
#[derive(Debug, Clone)]
pub struct TcpClientHelloConfig {
    /// Configured SNI.
    pub sni: String,
    /// REALITY session id token.
    pub session_id: [u8; 32],
    /// Client X25519 private key bytes.
    pub x25519_priv: [u8; 32],
    /// Client X25519 public key bytes.
    pub x25519_pub: [u8; 32],
    /// Hybrid key-share bytes.
    pub mlkem_key_exchange: Vec<u8>,
    /// Fingerprint profile.
    pub profile: FingerprintProfile,
    /// ClientHello random.
    pub random: [u8; 32],
}

/// Result of a TCP ClientHello send.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TcpSendReport {
    /// Number of ordered writes issued.
    pub writes: usize,
    /// Total bytes written.
    pub bytes: usize,
}

/// Build a profile-shaped TCP ClientHello containing the configured SNI.
pub fn build_tcp_client_hello(cfg: TcpClientHelloConfig) -> Result<Vec<u8>, TransportError> {
    build_client_hello(&ClientHelloParams {
        sni: cfg.sni,
        session_id: cfg.session_id.to_vec(),
        x25519_priv: cfg.x25519_priv,
        x25519_pub: cfg.x25519_pub,
        mlkem: MlkemShare::x25519_mlkem768(cfg.mlkem_key_exchange),
        profile: cfg.profile,
        random: cfg.random,
        quic_transport_parameters: Vec::new(),
    })
    .map_err(TransportError::from)
}

/// Send ClientHello bytes with the configured TCP evasion policy.
pub async fn send_client_hello<W>(
    writer: &mut W,
    client_hello: &[u8],
    policy: &TcpEvasionPolicy,
) -> Result<TcpSendReport, TransportError>
where
    W: AsyncWrite + Unpin,
{
    let chunks = plan_client_hello_writes(client_hello, policy)?;
    for chunk in &chunks {
        writer.write_all(chunk).await?;
    }
    writer.flush().await?;
    Ok(TcpSendReport {
        writes: chunks.len(),
        bytes: client_hello.len(),
    })
}

/// Establish a TCP connection and send the ClientHello.
pub async fn tcp_connect_and_send(
    server: &str,
    client_hello: &[u8],
    policy: &TcpEvasionPolicy,
) -> Result<(TcpStream, TcpSendReport), TransportError> {
    let mut stream = TcpStream::connect(server).await?;
    let report = send_client_hello(&mut stream, client_hello, policy).await?;
    Ok((stream, report))
}

/// Bind a TCP listener.
pub async fn bind_listener(addr: SocketAddr) -> Result<TcpListener, TransportError> {
    TcpListener::bind(addr).await.map_err(TransportError::from)
}

/// Accept one TCP stream and pass it to a dispatch callback.
pub async fn accept_once_with_dispatch<D, Fut>(
    listener: &TcpListener,
    dispatch: D,
) -> Result<(), TransportError>
where
    D: FnOnce(TcpStream, SocketAddr) -> Fut,
    Fut: Future<Output = Result<(), TransportError>>,
{
    let (stream, peer) = listener.accept().await?;
    dispatch(stream, peer).await
}
