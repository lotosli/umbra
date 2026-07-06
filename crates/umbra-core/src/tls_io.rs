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
    Client(Tls13Client),
    /// Server-side TLS endpoint after the handshake completed.
    Server(Tls13Server),
}

impl TlsAppEndpoint {
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        match self {
            Self::Client(client) => client.app_seal(plaintext),
            Self::Server(server) => server.app_seal(plaintext),
        }
    }

    fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, TlsError> {
        match self {
            Self::Client(client) => client.app_open(record),
            Self::Server(server) => server.app_open(record),
        }
    }
}

/// Start background record translation and return the plaintext side.
///
/// The returned stream is what inner mux/Vision code reads and writes. Two
/// background tasks translate between TLS application-data records on `io` and
/// plaintext bytes on the returned duplex stream.
pub fn spawn_tls_app_io<IO>(io: IO, endpoint: TlsAppEndpoint) -> DuplexStream
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let endpoint = Arc::new(Mutex::new(endpoint));
    let (plain_local, plain_remote) = tokio::io::duplex(DUPLEX_BUFFER_LEN);
    let (raw_read, raw_write) = split(io);
    let (plain_read, plain_write) = split(plain_remote);

    spawn_open_task(raw_read, plain_write, Arc::clone(&endpoint));
    spawn_seal_task(plain_read, raw_write, endpoint);

    plain_local
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
        loop {
            let Ok(Some(record)) = read_tls_record(&mut raw_read).await else {
                let _ = plain_write.shutdown().await;
                return;
            };
            let plaintext = match endpoint.lock() {
                Ok(mut endpoint) => endpoint.open(&record).map_err(tls_to_io),
                Err(_) => Err(io::Error::other("TLS endpoint mutex poisoned")),
            };
            let Ok(plaintext) = plaintext else {
                let _ = plain_write.shutdown().await;
                return;
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
            let Ok(record) = record else {
                let _ = raw_write.shutdown().await;
                return;
            };
            if raw_write.write_all(&record).await.is_err() {
                return;
            }
            if raw_write.flush().await.is_err() {
                return;
            }
        }
    })
}

/// Read one complete TLS record from an async reader.
pub async fn read_tls_record<R>(reader: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; TLS_RECORD_HEADER_LEN];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut record = header.to_vec();
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload).await?;
    record.extend_from_slice(&payload);
    Ok(Some(record))
}

fn tls_to_io(err: TlsError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}
