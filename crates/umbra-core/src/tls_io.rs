//! Async I/O bridge for Umbra's minimal TLS 1.3 application-data records.

use std::{
    io,
    sync::{Arc, Mutex},
};

use tokio::{
    io::{
        split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf,
        WriteHalf,
    },
    task::JoinHandle,
};
use umbra_tls::{handshake::Tls13Client, server::Tls13Server, TlsError};

const TLS_RECORD_HEADER_LEN: usize = 5;
const APP_IO_BUFFER_LEN: usize = 16 * 1024;
const DUPLEX_BUFFER_LEN: usize = 256 * 1024;

/// TLS endpoint capable of sealing and opening application-data records.
pub enum TlsAppEndpoint {
    /// Client-side TLS endpoint after the handshake completed.
    Client(Box<Tls13Client>),
    /// Server-side TLS endpoint after the handshake completed.
    Server(Box<Tls13Server>),
}

impl TlsAppEndpoint {
    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        match self {
            Self::Client(client) => client.app_seal(plaintext),
            Self::Server(server) => server.app_seal(plaintext),
        }
    }

    pub(crate) fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, TlsError> {
        match self {
            Self::Client(client) => client.app_open(record),
            Self::Server(server) => server.app_open(record),
        }
    }
}

/// Plaintext TLS bridge whose lifetime owns both record workers.
pub struct TlsAppIo {
    io: DuplexStream,
    workers: [JoinHandle<()>; 2],
    pub(crate) lease: Option<umbra_inner::budget::BudgetLease>,
}

impl Drop for TlsAppIo {
    fn drop(&mut self) {
        for worker in &self.workers {
            worker.abort();
        }
    }
}

impl AsyncRead for TlsAppIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for TlsAppIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Start background record translation and return the plaintext side.
///
/// The returned stream is what inner mux/Vision code reads and writes. Two
/// background tasks translate between TLS application-data records on `io` and
/// plaintext bytes on the returned duplex stream.
pub fn spawn_tls_app_io<IO>(io: IO, endpoint: TlsAppEndpoint) -> TlsAppIo
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let endpoint = Arc::new(Mutex::new(endpoint));
    let (plain_local, plain_remote) = tokio::io::duplex(DUPLEX_BUFFER_LEN);
    let (raw_read, raw_write) = split(io);
    let (plain_read, plain_write) = split(plain_remote);

    let opening = spawn_open_task(raw_read, plain_write, Arc::clone(&endpoint));
    let sealing = spawn_seal_task(plain_read, raw_write, endpoint);
    TlsAppIo {
        io: plain_local,
        workers: [opening, sealing],
        lease: None,
    }
}

fn spawn_open_task<R>(
    mut raw_read: ReadHalf<R>,
    mut plain_write: WriteHalf<DuplexStream>,
    endpoint: Arc<Mutex<TlsAppEndpoint>>,
) -> JoinHandle<()>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut record = Vec::new();
        loop {
            match read_tls_record_into(&mut raw_read, &mut record).await {
                Ok(true) => {}
                Ok(false) => {
                    let _ = plain_write.shutdown().await;
                    return;
                }
                Err(error) => {
                    report_bridge_error("TCP record read", &error);
                    let _ = plain_write.shutdown().await;
                    return;
                }
            }
            let plaintext = match endpoint.lock() {
                Ok(mut endpoint) => endpoint.open(&record).map_err(tls_to_io),
                Err(_) => Err(io::Error::other("TLS endpoint mutex poisoned")),
            };
            let plaintext = match plaintext {
                Ok(plaintext) => plaintext,
                Err(error) => {
                    report_bridge_error("record decrypt", &error);
                    let _ = plain_write.shutdown().await;
                    return;
                }
            };
            if plain_write.write_all(&plaintext).await.is_err() {
                return;
            }
            if plain_write.flush().await.is_err() {
                return;
            }
        }
    })
}

fn spawn_seal_task<W>(
    mut plain_read: ReadHalf<DuplexStream>,
    mut raw_write: WriteHalf<W>,
    endpoint: Arc<Mutex<TlsAppEndpoint>>,
) -> JoinHandle<()>
where
    W: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = [0_u8; APP_IO_BUFFER_LEN];
        loop {
            let read = match plain_read.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = raw_write.shutdown().await;
                    return;
                }
                Ok(read) => read,
            };
            let record = match endpoint.lock() {
                Ok(mut endpoint) => endpoint.seal(&buf[..read]).map_err(tls_to_io),
                Err(_) => Err(io::Error::other("TLS endpoint mutex poisoned")),
            };
            let record = match record {
                Ok(record) => record,
                Err(error) => {
                    report_bridge_error("record encrypt", &error);
                    let _ = raw_write.shutdown().await;
                    return;
                }
            };
            if let Err(error) = raw_write.write_all(&record).await {
                report_bridge_error("TCP record write", &error);
                return;
            }
            if let Err(error) = raw_write.flush().await {
                report_bridge_error("TCP flush", &error);
                return;
            }
        }
    })
}

fn report_bridge_error(phase: &'static str, error: &io::Error) {
    // Only the stage and OS error class are emitted, never peer or payload data.
    eprintln!(
        "umbra TLS bridge error: phase={phase}, kind={:?}",
        error.kind()
    );
}

/// Read one complete TLS record from an async reader.
pub async fn read_tls_record<R>(reader: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut record = Vec::new();
    if read_tls_record_into(reader, &mut record).await? {
        Ok(Some(record))
    } else {
        Ok(None)
    }
}

async fn read_tls_record_into<R: AsyncRead + Unpin>(
    reader: &mut R,
    record: &mut Vec<u8>,
) -> io::Result<bool> {
    record.resize(TLS_RECORD_HEADER_LEN, 0);
    if reader.read(&mut record[..1]).await? == 0 {
        return Ok(false);
    }
    reader
        .read_exact(&mut record[1..TLS_RECORD_HEADER_LEN])
        .await?;
    let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    record.resize(TLS_RECORD_HEADER_LEN + len, 0);
    reader
        .read_exact(&mut record[TLS_RECORD_HEADER_LEN..])
        .await?;
    Ok(true)
}

fn tls_to_io(err: TlsError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use umbra_crypto::{mlkem::mlkem_keygen, x25519};
    use umbra_fingerprint::load_profile;
    use umbra_tls::{
        clienthello::{ClientHelloParams, MlkemShare},
        handshake::{CertVerify, PeerKind, Tls13Client},
        server::{DestProfile, ForgedCert, Tls13Server},
    };

    use super::*;

    #[tokio::test]
    async fn scenario_tls_app_bridge_relays_plaintext_both_directions() {
        let params = client_hello_params();
        let profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
        let (mut client, chello) = Tls13Client::start(params).expect("client starts");
        let (mut server, server_flight) =
            Tls13Server::accept(&chello, forged_cert(), &profile).expect("server accepts");
        let client_out = client
            .drive(&server_flight, &AcceptAll)
            .expect("client completes");
        server
            .drive(&client_out.outbound)
            .expect("server completes");

        let (client_raw, server_raw) = tokio::io::duplex(16 * 1024);
        let mut client_plain =
            spawn_tls_app_io(client_raw, TlsAppEndpoint::Client(Box::new(client)));
        let mut server_plain =
            spawn_tls_app_io(server_raw, TlsAppEndpoint::Server(Box::new(server)));

        client_plain
            .write_all(b"client bytes")
            .await
            .expect("client writes plaintext");
        let mut server_observed = [0_u8; 12];
        server_plain
            .read_exact(&mut server_observed)
            .await
            .expect("server reads plaintext");
        assert_eq!(&server_observed, b"client bytes");

        server_plain
            .write_all(b"server bytes")
            .await
            .expect("server writes plaintext");
        let mut client_observed = [0_u8; 12];
        client_plain
            .read_exact(&mut client_observed)
            .await
            .expect("client reads plaintext");
        assert_eq!(&client_observed, b"server bytes");
    }

    #[tokio::test]
    async fn scenario_read_tls_record_handles_complete_eof_and_truncated_input() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer
            .write_all(&[0x17, 0x03, 0x03, 0x00, 0x01, 0xaa])
            .await
            .expect("write record");
        let record = read_tls_record(&mut reader)
            .await
            .expect("record read succeeds")
            .expect("record present");
        assert_eq!(record, [0x17, 0x03, 0x03, 0x00, 0x01, 0xaa]);

        let (writer, mut reader) = tokio::io::duplex(64);
        drop(writer);
        assert!(read_tls_record(&mut reader)
            .await
            .expect("eof read succeeds")
            .is_none());

        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer
            .write_all(&[0x17, 0x03, 0x03, 0x00, 0x02, 0xaa])
            .await
            .expect("write truncated record");
        writer.shutdown().await.expect("close writer");
        assert!(read_tls_record(&mut reader).await.is_err());
    }

    struct AcceptAll;

    impl CertVerify for AcceptAll {
        fn verify(&self, _leaf_der: &[u8], _chain: &[Vec<u8>]) -> PeerKind {
            PeerKind::UmbraTrusted
        }
    }

    fn client_hello_params() -> ClientHelloParams {
        let profile = load_profile("chrome-latest").expect("profile loads");
        let keypair = x25519::generate_keypair();
        let x25519_pub = *keypair.public.as_bytes();
        ClientHelloParams {
            sni: "server.example".to_owned(),
            session_id: vec![0x44; 32],
            x25519_priv: *keypair.private.expose_secret(),
            x25519_pub,
            mlkem: hybrid_mlkem_share(&x25519_pub),
            profile,
            random: [0x22; 32],
            quic_transport_parameters: Vec::new(),
        }
    }

    fn hybrid_mlkem_share(x25519_public: &[u8; 32]) -> MlkemShare {
        let mlkem = mlkem_keygen();
        let mut key_exchange =
            Vec::with_capacity(x25519_public.len() + mlkem.encapsulation_key.len());
        key_exchange.extend_from_slice(&mlkem.encapsulation_key);
        key_exchange.extend_from_slice(x25519_public);
        MlkemShare::x25519_mlkem768_with_decapsulation_key(key_exchange, mlkem.decapsulation_key)
    }

    fn forged_cert() -> ForgedCert {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(["server.example".to_owned()])
                .expect("test cert generates");
        ForgedCert {
            leaf_der: cert.der().as_ref().to_vec(),
            chain_der: Vec::new(),
            certificate_verify_key_der: key_pair.serialize_der(),
        }
    }
}
