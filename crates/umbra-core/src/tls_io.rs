//! Async I/O bridge for Umbra's minimal TLS 1.3 application-data records.

use std::io;

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
    pub(crate) fn into_records(self) -> Result<umbra_tls::records::ApplicationRecords, TlsError> {
        match self {
            Self::Client(client) => (*client).into_application_records(),
            Self::Server(server) => (*server).into_application_records(),
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
    spawn_tls_app_io_scheduled(io, endpoint, None)
}

pub(crate) fn spawn_tls_app_io_scheduled<IO>(
    io: IO,
    endpoint: TlsAppEndpoint,
    group: Option<&crate::work::WorkGroup>,
) -> TlsAppIo
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reading, writing) = match endpoint.into_records() {
        Ok(records) => (Ok(records.read), Ok(records.write)),
        Err(error) => (Err(error.clone()), Err(error)),
    };
    let (plain_local, plain_remote) = tokio::io::duplex(DUPLEX_BUFFER_LEN);
    let (raw_read, raw_write) = split(io);
    let (plain_read, plain_write) = split(plain_remote);

    let opening = spawn_open_task(raw_read, plain_write, reading, group);
    let sealing = spawn_seal_task(plain_read, raw_write, writing, group);
    TlsAppIo {
        io: plain_local,
        workers: [opening, sealing],
        lease: None,
    }
}

fn spawn_open_task<R>(
    mut raw_read: ReadHalf<R>,
    mut plain_write: WriteHalf<DuplexStream>,
    records: Result<umbra_tls::records::RecordLayer, TlsError>,
    group: Option<&crate::work::WorkGroup>,
) -> JoinHandle<()>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    crate::work::spawn(group, async move {
        let mut records = match records {
            Ok(records) => records,
            Err(error) => {
                report_bridge_error("record keys", &tls_to_io(error));
                let _ = plain_write.shutdown().await;
                return;
            }
        };
        let mut record = Vec::with_capacity(16_645);
        loop {
            match read_tls_record_into(&mut raw_read, &mut record, true).await {
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
            if let Err(error) = records.open_application_in_place(&mut record) {
                report_bridge_error("record decrypt", &tls_to_io(error));
                let _ = plain_write.shutdown().await;
                return;
            }
            if plain_write
                .write_all(&record[TLS_RECORD_HEADER_LEN..])
                .await
                .is_err()
            {
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
    records: Result<umbra_tls::records::RecordLayer, TlsError>,
    group: Option<&crate::work::WorkGroup>,
) -> JoinHandle<()>
where
    W: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    crate::work::spawn(group, async move {
        let mut records = match records {
            Ok(records) => records,
            Err(error) => {
                report_bridge_error("record keys", &tls_to_io(error));
                let _ = raw_write.shutdown().await;
                return;
            }
        };
        let mut buf = [0; APP_IO_BUFFER_LEN];
        let mut record = Vec::with_capacity(16_645);
        loop {
            let read = match plain_read.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = raw_write.shutdown().await;
                    return;
                }
                Ok(read) => read,
            };
            if let Err(error) = records.seal_into(
                umbra_tls::records::CONTENT_TYPE_APPLICATION_DATA,
                &buf[..read],
                &mut record,
            ) {
                report_bridge_error("record encrypt", &tls_to_io(error));
                let _ = raw_write.shutdown().await;
                return;
            }
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
    if read_tls_record_into(reader, &mut record, false).await? {
        Ok(Some(record))
    } else {
        Ok(None)
    }
}

async fn read_tls_record_into<R: AsyncRead + Unpin>(
    reader: &mut R,
    record: &mut Vec<u8>,
    application: bool,
) -> io::Result<bool> {
    record.resize(TLS_RECORD_HEADER_LEN, 0);
    let first = reader.read(&mut record[..TLS_RECORD_HEADER_LEN]).await?;
    if first == 0 {
        return Ok(false);
    }
    reader
        .read_exact(&mut record[first..TLS_RECORD_HEADER_LEN])
        .await?;
    let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    if len > 16_640 {
        return Err(tls_to_io(TlsError::LengthOutOfRange));
    }
    if application {
        umbra_tls::records::protected_record_length(record).map_err(tls_to_io)?;
        if len < 17 {
            return Err(tls_to_io(TlsError::AuthenticationFailed));
        }
    }
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
    async fn oversized_and_invalid_application_headers_fail_before_body_read() {
        for header in [
            [0x17, 3, 3, 0xff, 0xff],
            [0x16, 3, 3, 0, 17],
            [0x17, 3, 1, 0, 17],
            [0x17, 3, 3, 0, 1],
        ] {
            let mut reader = std::io::Cursor::new(header);
            let mut record = Vec::new();
            assert_eq!(
                read_tls_record_into(&mut reader, &mut record, true)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(record.len(), 5);
            assert_eq!(reader.position(), 5);
        }
    }

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
