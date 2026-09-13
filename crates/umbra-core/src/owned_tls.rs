//! Owned, cancellation-safe TLS record I/O with an explicit raw handoff.
//!
//! Unlike the legacy byte-stream bridge, these owners never spawn tasks, merge
//! plaintext records, read beyond the requested record, or retain the TLS
//! endpoint after both halves have been consumed. The caller owns protocol
//! framing and reserves the writer's second queue slot for control records.

use std::{
    collections::VecDeque,
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    time::Instant,
};

use crate::{prefixed::PrefixedStream, tls_io::TlsAppEndpoint};

const HEADER_LEN: usize = 5;
const MAX_PLAINTEXT: usize = 16_384;
const MAX_PAYLOAD: usize = 16_640;
const MAX_RECORD: usize = HEADER_LEN + MAX_PAYLOAD;
const MAX_PENDING_INPUT: usize = 32_768;
const MAX_QUEUED_RECORDS: usize = 2;
const MAX_QUEUED_BYTES: usize = MAX_QUEUED_RECORDS * MAX_RECORD;

/// Observable outer encryption work; this value contains no keys or payloads.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TlsIoSnapshot {
    /// Successfully sealed outer application records.
    pub sealed_records: u64,
    /// Successfully opened outer application records.
    pub opened_records: u64,
    /// Application plaintext bytes passed to outer encryption.
    pub sealed_plaintext_bytes: u64,
    /// Application plaintext bytes returned by outer decryption.
    pub opened_plaintext_bytes: u64,
    /// Complete outer ciphertext bytes produced, including record headers.
    pub sealed_wire_bytes: u64,
    /// Complete authenticated outer ciphertext bytes, including record headers.
    pub opened_wire_bytes: u64,
}

struct Counters {
    sealed_records: AtomicU64,
    opened_records: AtomicU64,
    sealed_plaintext_bytes: AtomicU64,
    opened_plaintext_bytes: AtomicU64,
    sealed_wire_bytes: AtomicU64,
    opened_wire_bytes: AtomicU64,
    last_io_progress: Mutex<Instant>,
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            sealed_records: AtomicU64::new(0),
            opened_records: AtomicU64::new(0),
            sealed_plaintext_bytes: AtomicU64::new(0),
            opened_plaintext_bytes: AtomicU64::new(0),
            sealed_wire_bytes: AtomicU64::new(0),
            opened_wire_bytes: AtomicU64::new(0),
            last_io_progress: Mutex::new(Instant::now()),
        }
    }
}

/// A clonable observation handle that does not retain the TLS endpoint.
#[derive(Clone, Default)]
pub struct TlsIoStats(Arc<Counters>);

impl TlsIoStats {
    /// Time of the last positive socket read or write, or owner creation.
    ///
    /// Unlike record counters, this advances during partial records even when
    /// the enclosing operation is cancelled. Handshake-prefix replay, sealing,
    /// and unsuccessful polls do not represent new transport progress.
    #[must_use]
    pub fn last_io_progress(&self) -> Instant {
        *self
            .0
            .last_io_progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn note_io_progress(&self) {
        *self
            .0
            .last_io_progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
    }

    /// Read monotonic counters, normally after the owners reach a boundary.
    ///
    /// Concurrent updates may appear between individual counter loads.
    #[must_use]
    pub fn snapshot(&self) -> TlsIoSnapshot {
        TlsIoSnapshot {
            sealed_records: self.0.sealed_records.load(Ordering::Relaxed),
            opened_records: self.0.opened_records.load(Ordering::Relaxed),
            sealed_plaintext_bytes: self.0.sealed_plaintext_bytes.load(Ordering::Relaxed),
            opened_plaintext_bytes: self.0.opened_plaintext_bytes.load(Ordering::Relaxed),
            sealed_wire_bytes: self.0.sealed_wire_bytes.load(Ordering::Relaxed),
            opened_wire_bytes: self.0.opened_wire_bytes.load(Ordering::Relaxed),
        }
    }
}

/// Established transport and its TLS state, before splitting ownership.
pub struct EstablishedTcp<IO> {
    io: IO,
    endpoint: TlsAppEndpoint,
    pending_input: Vec<u8>,
}

impl<IO> EstablishedTcp<IO> {
    /// Retain any bytes coalesced with the completed TLS handshake.
    ///
    /// # Errors
    /// Rejects pending input beyond the protocol's 32,768-byte bound.
    pub fn new(io: IO, endpoint: TlsAppEndpoint, pending_input: Vec<u8>) -> io::Result<Self> {
        if pending_input.len() > MAX_PENDING_INPUT {
            return Err(invalid("TLS handshake pending input exceeds its bound"));
        }
        Ok(Self {
            io,
            endpoint,
            pending_input,
        })
    }
}

impl<IO: AsyncRead + AsyncWrite> EstablishedTcp<IO> {
    /// Split into explicitly owned record halves and a key-free counter handle.
    pub fn split(
        self,
    ) -> (
        OwnedTlsReader<ReadHalf<IO>>,
        OwnedTlsWriter<WriteHalf<IO>>,
        TlsIoStats,
    ) {
        let (read, write) = split(self.io);
        let endpoint = Arc::new(Mutex::new(self.endpoint));
        let stats = TlsIoStats::default();
        (
            OwnedTlsReader {
                io: read,
                endpoint: Arc::clone(&endpoint),
                stats: stats.clone(),
                pending_input: self.pending_input,
                pending_offset: 0,
                record: vec![0; HEADER_LEN],
                filled: 0,
                expected_len: HEADER_LEN,
                failed: false,
            },
            OwnedTlsWriter {
                io: write,
                endpoint,
                stats: stats.clone(),
                queue: VecDeque::with_capacity(MAX_QUEUED_RECORDS),
                queued_bytes: 0,
                dirty: false,
                failed: false,
            },
            stats,
        )
    }
}

/// Record reader with persistent partial-read state and retained read-ahead.
pub struct OwnedTlsReader<R> {
    io: R,
    endpoint: Arc<Mutex<TlsAppEndpoint>>,
    stats: TlsIoStats,
    pending_input: Vec<u8>,
    pending_offset: usize,
    record: Vec<u8>,
    filled: usize,
    expected_len: usize,
    failed: bool,
}

impl<R> OwnedTlsReader<R> {
    /// Whether no partial outer record has been consumed and no error occurred.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        !self.failed && self.filled == 0
    }

    /// Number of handshake-prefetched bytes that have not been interpreted.
    #[must_use]
    pub fn pending_input_len(&self) -> usize {
        self.pending_input.len() - self.pending_offset
    }

    /// Consume this owner at a verified protocol boundary, preserving read-ahead.
    ///
    /// # Errors
    /// Rejects handoff after an error or in the middle of an outer record.
    pub fn into_raw(self) -> io::Result<PrefixedStream<R>> {
        if !self.is_idle() {
            return Err(invalid("raw handoff requires an outer record boundary"));
        }
        let mut prefix = self.pending_input;
        prefix.drain(..self.pending_offset);
        Ok(PrefixedStream::new(prefix, self.io))
    }
}

impl<R: AsyncRead + Unpin> OwnedTlsReader<R> {
    /// Read and authenticate exactly one outer application record.
    ///
    /// Cancellation preserves every byte already read. A clean transport EOF
    /// is returned as `None`; the protocol owner decides whether FIN permits it.
    ///
    /// # Errors
    /// Rejects malformed, oversized, unauthenticated or truncated records and
    /// propagates transport errors. After any error this owner is terminal.
    pub async fn next_record(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.failed {
            return Err(invalid("TLS reader is terminal"));
        }
        let result = self.read_and_open().await;
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    async fn read_and_open(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            while self.filled < self.expected_len {
                let remaining = self.expected_len - self.filled;
                if self.pending_offset < self.pending_input.len() {
                    let count = remaining.min(self.pending_input_len());
                    let end = self.pending_offset + count;
                    self.record[self.filled..self.filled + count]
                        .copy_from_slice(&self.pending_input[self.pending_offset..end]);
                    self.pending_offset = end;
                    self.filled += count;
                    continue;
                }
                // Only the currently requested record is read from the socket.
                // The filled offset changes only after read returns Ready, with
                // no intervening await; cancellation never loses consumed bytes.
                let count = match self
                    .io
                    .read(&mut self.record[self.filled..self.expected_len])
                    .await
                {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                if count == 0 {
                    return if self.filled == 0 {
                        Ok(None)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated outer TLS record",
                        ))
                    };
                }
                self.filled += count;
                self.stats.note_io_progress();
            }
            if self.expected_len == HEADER_LEN {
                let payload_len = usize::from(u16::from_be_bytes([self.record[3], self.record[4]]));
                if self.record[..3] != [0x17, 0x03, 0x03]
                    || !(17..=MAX_PAYLOAD).contains(&payload_len)
                {
                    return Err(invalid("invalid outer TLS application record header"));
                }
                self.expected_len = HEADER_LEN + payload_len;
                self.record.resize(self.expected_len, 0);
                continue;
            }
            let plaintext = self
                .endpoint
                .lock()
                .map_err(|_| invalid("TLS endpoint mutex poisoned"))?
                .open(&self.record)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if plaintext.len() > MAX_PLAINTEXT {
                return Err(invalid("outer TLS plaintext exceeds its bound"));
            }
            increment(&self.stats.0.opened_records, 1);
            increment(&self.stats.0.opened_plaintext_bytes, plaintext.len());
            increment(&self.stats.0.opened_wire_bytes, self.record.len());
            self.record.truncate(HEADER_LEN);
            self.filled = 0;
            self.expected_len = HEADER_LEN;
            return Ok(Some(plaintext));
        }
    }
}

struct PendingRecord {
    ciphertext: Vec<u8>,
    written: usize,
}

/// Record writer that seals each accepted plaintext once and resumes ciphertext.
pub struct OwnedTlsWriter<W> {
    io: W,
    endpoint: Arc<Mutex<TlsAppEndpoint>>,
    stats: TlsIoStats,
    queue: VecDeque<PendingRecord>,
    queued_bytes: usize,
    dirty: bool,
    failed: bool,
}

impl<W> OwnedTlsWriter<W> {
    /// Queue exactly one TLS record, without performing socket I/O.
    ///
    /// A full queue rejects the plaintext before sealing it. The session owner
    /// reserves the second slot for control records by applying DATA backpressure.
    ///
    /// # Errors
    /// Returns `WouldBlock` at the queue bound, or rejects oversized plaintext,
    /// a terminal writer, or TLS encryption failure.
    pub fn queue_record(&mut self, plaintext: &[u8]) -> io::Result<()> {
        if self.failed {
            return Err(invalid("TLS writer is terminal"));
        }
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(invalid("outer TLS plaintext exceeds its bound"));
        }
        if self.queue.len() >= MAX_QUEUED_RECORDS
            || self.queued_bytes > MAX_QUEUED_BYTES - MAX_RECORD
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "outer TLS ciphertext queue is full",
            ));
        }
        let sealed = match self.endpoint.lock() {
            Ok(mut endpoint) => endpoint
                .seal(plaintext)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
            Err(_) => Err(invalid("TLS endpoint mutex poisoned")),
        };
        let ciphertext = match sealed {
            Ok(ciphertext) if ciphertext.len() <= MAX_RECORD => ciphertext,
            Ok(_) => {
                self.failed = true;
                return Err(invalid("sealed outer TLS record exceeds its bound"));
            }
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        increment(&self.stats.0.sealed_records, 1);
        increment(&self.stats.0.sealed_plaintext_bytes, plaintext.len());
        increment(&self.stats.0.sealed_wire_bytes, ciphertext.len());
        self.queued_bytes += ciphertext.len();
        self.queue.push_back(PendingRecord {
            ciphertext,
            written: 0,
        });
        self.dirty = true;
        Ok(())
    }

    /// Number of retained ciphertext records, including a partial front record.
    #[must_use]
    pub fn pending_records(&self) -> usize {
        self.queue.len()
    }

    /// Complete allocated ciphertext lengths retained by the queue.
    #[must_use]
    pub const fn pending_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Whether the queue and transport flush have completed without error.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        !self.failed && !self.dirty && self.queue.is_empty()
    }

    /// Consume this owner only after its final outer record has fully flushed.
    ///
    /// # Errors
    /// Rejects queued/partially written records, incomplete flush, or prior error.
    pub fn into_raw(self) -> io::Result<W> {
        if !self.is_idle() {
            return Err(invalid("raw handoff requires flushed outer ciphertext"));
        }
        Ok(self.io)
    }
}

impl<W: AsyncWrite + Unpin> OwnedTlsWriter<W> {
    /// Resume queued ciphertext from its exact byte offset and flush transport.
    ///
    /// Cancellation retains the queue, write offset and incomplete flush state.
    /// No plaintext is re-encrypted when this operation is resumed.
    ///
    /// # Errors
    /// Propagates transport failure, including zero-length writes. Any error
    /// makes this owner terminal and prevents raw handoff.
    pub async fn flush_pending(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(invalid("TLS writer is terminal"));
        }
        let result = self.write_and_flush().await;
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    async fn write_and_flush(&mut self) -> io::Result<()> {
        while let Some(record) = self.queue.front_mut() {
            while record.written < record.ciphertext.len() {
                let count = match self.io.write(&record.ciphertext[record.written..]).await {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "zero-length outer TLS ciphertext write",
                    ));
                }
                record.written += count;
                self.stats.note_io_progress();
            }
            self.queued_bytes -= record.ciphertext.len();
            self.queue.pop_front();
        }
        if self.dirty {
            loop {
                match self.io.flush().await {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                }
                break;
            }
            self.dirty = false;
        }
        Ok(())
    }
}

fn increment(counter: &AtomicU64, amount: usize) {
    let amount = u64::try_from(amount).unwrap_or(u64::MAX);
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(amount))
    });
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::{
        future::{poll_fn, Future},
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::ReadBuf;
    use umbra_crypto::{mlkem::mlkem_keygen, x25519};
    use umbra_fingerprint::load_profile;
    use umbra_tls::{
        clienthello::{ClientHelloParams, MlkemShare},
        handshake::{CertVerify, PeerKind, Tls13Client},
        server::{DestProfile, ForgedCert, Tls13Server},
    };

    use super::*;

    #[derive(Default)]
    struct GateState {
        input: VecDeque<u8>,
        output: Vec<u8>,
        write_budget: usize,
        flush_ready: bool,
        eof: bool,
        zero_write: bool,
        read_error: Option<io::ErrorKind>,
        write_error: Option<io::ErrorKind>,
        flush_error: Option<io::ErrorKind>,
    }

    #[derive(Clone, Default)]
    struct GateIo(Arc<Mutex<GateState>>);

    impl AsyncRead for GateIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut gate_state = self.0.lock().expect("gate lock");
            if let Some(kind) = gate_state.read_error.take() {
                return Poll::Ready(Err(io::Error::from(kind)));
            }
            if gate_state.input.is_empty() {
                return if gate_state.eof || buf.remaining() == 0 {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                };
            }
            let count = buf.remaining().min(gate_state.input.len());
            for byte in gate_state.input.drain(..count) {
                buf.put_slice(&[byte]);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for GateIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut gate_state = self.0.lock().expect("gate lock");
            if let Some(kind) = gate_state.write_error.take() {
                return Poll::Ready(Err(io::Error::from(kind)));
            }
            if gate_state.zero_write {
                return Poll::Ready(Ok(0));
            }
            if gate_state.write_budget == 0 {
                return Poll::Pending;
            }
            let count = gate_state.write_budget.min(buf.len());
            gate_state.output.extend_from_slice(&buf[..count]);
            gate_state.write_budget -= count;
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut gate_state = self.0.lock().expect("gate lock");
            if let Some(kind) = gate_state.flush_error.take() {
                return Poll::Ready(Err(io::Error::from(kind)));
            }
            if gate_state.flush_ready {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    async fn cancel_while_pending<F: Future>(future: F) {
        tokio::pin!(future);
        poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn scenario_owned_tls_relays_exact_records_bidirectionally() {
        let (client, server) = established_endpoints();
        let (client_io, server_io) = tokio::io::duplex(128);
        let (mut cr, mut cw, cs) = EstablishedTcp::new(
            client_io,
            TlsAppEndpoint::Client(Box::new(client)),
            Vec::new(),
        )
        .expect("client owner")
        .split();
        let (mut sr, mut sw, ss) = EstablishedTcp::new(
            server_io,
            TlsAppEndpoint::Server(Box::new(server)),
            Vec::new(),
        )
        .expect("server owner")
        .split();
        cw.queue_record(b"target").expect("target record");
        cw.queue_record(b"hello").expect("hello record");
        cw.flush_pending().await.expect("client flush");
        assert_eq!(
            sr.next_record().await.expect("open 1"),
            Some(b"target".to_vec())
        );
        assert_eq!(
            sr.next_record().await.expect("open 2"),
            Some(b"hello".to_vec())
        );
        sw.queue_record(b"ack").expect("ack record");
        sw.flush_pending().await.expect("server flush");
        assert_eq!(
            cr.next_record().await.expect("open ack"),
            Some(b"ack".to_vec())
        );
        assert_eq!(cs.snapshot().sealed_records, 2);
        assert_eq!(cs.snapshot().sealed_plaintext_bytes, 11);
        assert_eq!(ss.snapshot().opened_records, 2);
        assert_eq!(ss.snapshot().opened_plaintext_bytes, 11);
        assert_eq!(cs.snapshot().opened_records, 1);
        assert_eq!(ss.snapshot().sealed_records, 1);
        assert_eq!(
            cs.snapshot().sealed_wire_bytes,
            ss.snapshot().opened_wire_bytes
        );
        assert!(cr.is_idle() && sr.is_idle() && cw.is_idle() && sw.is_idle());
    }

    #[tokio::test]
    async fn scenario_cancel_read_at_every_record_byte_preserves_ciphertext() {
        let (mut client, server) = established_endpoints();
        let io = GateIo::default();
        let gate = Arc::clone(&io.0);
        let (mut reader, _writer, stats) =
            EstablishedTcp::new(io, TlsAppEndpoint::Server(Box::new(server)), Vec::new())
                .expect("owner")
                .split();
        let plaintext = b"independent endpoint authenticates every resumed record";
        let record_len = plaintext.len() + 22;
        for split_at in 0..record_len {
            let ciphertext = client.app_seal(plaintext).expect("seal next");
            assert_eq!(ciphertext.len(), record_len);
            gate.lock()
                .expect("gate")
                .input
                .extend(&ciphertext[..split_at]);
            cancel_while_pending(reader.next_record()).await;
            assert_eq!(reader.is_idle(), split_at == 0);
            assert_eq!(reader.filled, split_at);
            gate.lock()
                .expect("gate")
                .input
                .extend(&ciphertext[split_at..]);
            assert_eq!(
                reader.next_record().await.expect("resume"),
                Some(plaintext.to_vec())
            );
        }
        assert_eq!(stats.snapshot().opened_records, record_len as u64);
        assert!(reader.is_idle());
        gate.lock().expect("gate").eof = true;
        assert_eq!(reader.next_record().await.expect("clean eof"), None);
    }

    #[tokio::test]
    async fn scenario_cancel_write_at_every_byte_never_reseals_or_replays() {
        let (client, mut server) = established_endpoints();
        let io = GateIo::default();
        let gate = Arc::clone(&io.0);
        let (_reader, mut writer, stats) =
            EstablishedTcp::new(io, TlsAppEndpoint::Client(Box::new(client)), Vec::new())
                .expect("owner")
                .split();
        let plaintext = b"partial writes retain the same ciphertext";
        let record_len = plaintext.len() + 22;
        for split_at in 0..=record_len {
            writer.queue_record(plaintext).expect("seal once");
            let expected = writer.queue[0].ciphertext.clone();
            {
                let mut gate_state = gate.lock().expect("gate");
                gate_state.write_budget = split_at;
                gate_state.flush_ready = false;
                gate_state.output.clear();
            }
            cancel_while_pending(writer.flush_pending()).await;
            assert_eq!(gate.lock().expect("gate").output, expected[..split_at]);
            assert!(!writer.is_idle());
            let before_resume = stats.snapshot();
            {
                let mut gate_state = gate.lock().expect("gate");
                gate_state.write_budget = usize::MAX;
                gate_state.flush_ready = true;
            }
            writer.flush_pending().await.expect("resume flush");
            let observed = gate.lock().expect("gate").output.clone();
            assert_eq!(observed, expected);
            assert_eq!(
                server.app_open(&observed).expect("independent open"),
                plaintext
            );
            assert_eq!(stats.snapshot(), before_resume);
            assert!(writer.is_idle());
            assert_eq!(writer.pending_bytes(), 0);
            assert_eq!(writer.pending_records(), 0);
        }
    }

    #[tokio::test]
    async fn scenario_handoff_retains_coalesced_raw_records_and_drops_tls_state() {
        let (mut client, server) = established_endpoints();
        let final_record = client.app_seal(b"final control").expect("final seal");
        let raw = [
            [0x17, 0x03, 0x03, 0x00, 0x11].as_slice(),
            &[0x51; 17],
            &[0x17, 0x03, 0x03, 0x00, 0x12],
            &[0x52; 18],
        ]
        .concat();
        let pending = [final_record, raw.clone()].concat();
        let io = GateIo::default();
        {
            let mut gate_state = io.0.lock().expect("gate");
            gate_state.eof = true;
            gate_state.write_budget = usize::MAX;
            gate_state.flush_ready = true;
        }
        let (mut reader, writer, stats) =
            EstablishedTcp::new(io, TlsAppEndpoint::Server(Box::new(server)), pending)
                .expect("owner")
                .split();
        let endpoint = Arc::downgrade(&reader.endpoint);
        assert_eq!(
            reader.next_record().await.expect("final open"),
            Some(b"final control".to_vec())
        );
        assert_eq!(reader.pending_input_len(), raw.len());
        let before = stats.snapshot();
        let mut raw_read = reader.into_raw().expect("reader handoff");
        assert!(endpoint.upgrade().is_some());
        let mut raw_write = writer.into_raw().expect("writer handoff");
        assert!(endpoint.upgrade().is_none());
        let mut observed = Vec::new();
        raw_read
            .read_to_end(&mut observed)
            .await
            .expect("read raw prefix");
        assert_eq!(observed, raw);
        raw_write.write_all(&raw).await.expect("raw write");
        raw_write.flush().await.expect("raw flush");
        assert_eq!(stats.snapshot(), before);
    }

    #[tokio::test]
    async fn scenario_queue_bounds_apply_before_sealing() {
        let (client, mut server) = established_endpoints();
        let io = GateIo::default();
        let gate = Arc::clone(&io.0);
        let (_reader, mut writer, stats) =
            EstablishedTcp::new(io, TlsAppEndpoint::Client(Box::new(client)), Vec::new())
                .expect("owner")
                .split();
        assert_eq!(
            writer
                .queue_record(&vec![0; MAX_PLAINTEXT + 1])
                .expect_err("oversized")
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(stats.snapshot(), TlsIoSnapshot::default());
        let payload = vec![0x4a; MAX_PLAINTEXT];
        writer.queue_record(&payload).expect("first maximum record");
        writer
            .queue_record(&payload)
            .expect("second maximum record");
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.sealed_records, 2);
        assert_eq!(writer.pending_records(), 2);
        assert!(writer.pending_bytes() <= MAX_QUEUED_BYTES);
        assert_eq!(
            writer
                .queue_record(b"third")
                .expect_err("queue full")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(stats.snapshot(), snapshot);
        {
            let mut gate_state = gate.lock().expect("gate");
            gate_state.write_budget = usize::MAX;
            gate_state.flush_ready = true;
        }
        writer.flush_pending().await.expect("flush two records");
        let ciphertext = gate.lock().expect("gate").output.clone();
        let record_len = MAX_PLAINTEXT + 22;
        for record in ciphertext.chunks_exact(record_len) {
            assert_eq!(
                server.app_open(record).expect("maximum record opens"),
                payload
            );
        }
        assert_eq!(ciphertext.len(), record_len * 2);
        assert!(writer.is_idle());
    }

    #[tokio::test]
    async fn scenario_partial_eof_is_terminal_at_every_header_and_body_prefix() {
        let plaintext = b"truncation";
        for cutoff in 1..plaintext.len() + 22 {
            let (mut client, server) = established_endpoints();
            let ciphertext = client.app_seal(plaintext).expect("seal");
            let io = GateIo::default();
            io.0.lock().expect("gate").eof = true;
            let (mut reader, _writer, stats) = EstablishedTcp::new(
                io,
                TlsAppEndpoint::Server(Box::new(server)),
                ciphertext[..cutoff].to_vec(),
            )
            .expect("owner")
            .split();
            assert_eq!(
                reader.next_record().await.expect_err("truncated").kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert!(!reader.is_idle());
            assert!(reader.next_record().await.is_err());
            assert!(reader.into_raw().is_err());
            assert_eq!(stats.snapshot().opened_records, 0);
        }
    }

    #[tokio::test]
    async fn scenario_invalid_outer_headers_and_authentication_fail_closed() {
        for header in [
            [0x16, 0x03, 0x03, 0x00, 0x11],
            [0x17, 0x03, 0x01, 0x00, 0x11],
            [0x17, 0x03, 0x03, 0x00, 0x10],
            [0x17, 0x03, 0x03, 0x41, 0x01],
            [0x17, 0x03, 0x03, 0xff, 0xff],
        ] {
            let (_client, server) = established_endpoints();
            let (mut reader, _writer, stats) = EstablishedTcp::new(
                GateIo::default(),
                TlsAppEndpoint::Server(Box::new(server)),
                header.to_vec(),
            )
            .expect("owner")
            .split();
            assert_eq!(
                reader.next_record().await.expect_err("bad header").kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(reader.record.len(), HEADER_LEN);
            assert_eq!(stats.snapshot().opened_records, 0);
            assert!(reader.into_raw().is_err());
        }
        let (mut client, server) = established_endpoints();
        let mut ciphertext = client.app_seal(b"authenticated").expect("seal");
        ciphertext[8] ^= 0x80;
        let (mut reader, _writer, stats) = EstablishedTcp::new(
            GateIo::default(),
            TlsAppEndpoint::Server(Box::new(server)),
            ciphertext,
        )
        .expect("owner")
        .split();
        assert_eq!(
            reader.next_record().await.expect_err("bad tag").kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(stats.snapshot().opened_records, 0);
        assert!(reader.next_record().await.is_err());
    }

    #[tokio::test]
    async fn scenario_read_and_write_interruptions_resume_without_poisoning() {
        let (mut client, server) = established_endpoints();
        let ciphertext = client.app_seal(b"read interrupt").expect("seal");
        let io = GateIo::default();
        {
            let mut gate_state = io.0.lock().expect("gate");
            gate_state.read_error = Some(io::ErrorKind::Interrupted);
            gate_state.write_error = Some(io::ErrorKind::Interrupted);
            gate_state.flush_error = Some(io::ErrorKind::Interrupted);
            gate_state.input.extend(ciphertext);
            gate_state.write_budget = usize::MAX;
            gate_state.flush_ready = true;
        }
        let (mut reader, mut writer, stats) =
            EstablishedTcp::new(io, TlsAppEndpoint::Server(Box::new(server)), Vec::new())
                .expect("owner")
                .split();
        assert_eq!(
            reader.next_record().await.expect("retry read"),
            Some(b"read interrupt".to_vec())
        );
        writer.queue_record(b"write interrupt").expect("queue");
        writer.flush_pending().await.expect("retry write and flush");
        assert_eq!(stats.snapshot().sealed_records, 1);
        assert!(reader.is_idle() && writer.is_idle());
    }

    #[tokio::test]
    async fn scenario_transport_failures_prevent_retry_and_handoff() {
        for failure in ["read", "write", "zero", "flush"] {
            let (client, _server) = established_endpoints();
            let io = GateIo::default();
            {
                let mut gate_state = io.0.lock().expect("gate");
                gate_state.write_budget = usize::MAX;
                match failure {
                    "read" => gate_state.read_error = Some(io::ErrorKind::ConnectionReset),
                    "write" => gate_state.write_error = Some(io::ErrorKind::BrokenPipe),
                    "zero" => gate_state.zero_write = true,
                    _ => gate_state.flush_error = Some(io::ErrorKind::BrokenPipe),
                }
            }
            let (mut reader, mut writer, _stats) =
                EstablishedTcp::new(io, TlsAppEndpoint::Client(Box::new(client)), Vec::new())
                    .expect("owner")
                    .split();
            if failure == "read" {
                assert_eq!(
                    reader.next_record().await.expect_err("read failure").kind(),
                    io::ErrorKind::ConnectionReset
                );
                assert!(reader.into_raw().is_err());
            } else {
                writer.queue_record(b"write").expect("queue");
                assert!(writer.flush_pending().await.is_err());
                assert!(writer.flush_pending().await.is_err());
                assert!(writer.queue_record(b"retry").is_err());
                assert!(writer.into_raw().is_err());
            }
        }
    }

    #[tokio::test]
    async fn scenario_incomplete_record_or_flush_prevents_handoff() {
        let (client, _server) = established_endpoints();
        let (mut reader, mut writer, _) = EstablishedTcp::new(
            GateIo::default(),
            TlsAppEndpoint::Client(Box::new(client)),
            vec![0x17, 0x03],
        )
        .expect("owner")
        .split();
        cancel_while_pending(reader.next_record()).await;
        assert!(reader.into_raw().is_err());
        writer.queue_record(b"pending").expect("queue");
        assert!(writer.into_raw().is_err());

        let (client, _server) = established_endpoints();
        let io = GateIo::default();
        io.0.lock().expect("gate").write_budget = usize::MAX;
        let (_reader, mut writer, _) =
            EstablishedTcp::new(io, TlsAppEndpoint::Client(Box::new(client)), Vec::new())
                .expect("owner")
                .split();
        writer
            .queue_record(b"written but not flushed")
            .expect("queue");
        cancel_while_pending(writer.flush_pending()).await;
        assert_eq!(writer.pending_records(), 0);
        assert_eq!(writer.pending_bytes(), 0);
        assert!(!writer.is_idle());
        assert!(writer.into_raw().is_err());
    }

    #[tokio::test]
    async fn scenario_poisoned_crypto_owner_is_terminal_in_both_directions() {
        let (mut client, server) = established_endpoints();
        let ciphertext = client.app_seal(b"mutex failure").expect("seal");
        let (mut reader, mut writer, stats) = EstablishedTcp::new(
            GateIo::default(),
            TlsAppEndpoint::Server(Box::new(server)),
            ciphertext,
        )
        .expect("owner")
        .split();
        let endpoint = Arc::clone(&reader.endpoint);
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = endpoint.lock().expect("lock before poison");
            panic!("injected panic while owning crypto state");
        }));
        assert!(panic_result.is_err());
        assert!(reader.next_record().await.is_err());
        assert!(writer.queue_record(b"must not seal").is_err());
        assert!(reader.into_raw().is_err());
        assert!(writer.into_raw().is_err());
        assert_eq!(stats.snapshot(), TlsIoSnapshot::default());
    }

    #[test]
    fn scenario_pending_handshake_input_is_bounded() {
        let (client, server) = established_endpoints();
        let owner = EstablishedTcp::new(
            GateIo::default(),
            TlsAppEndpoint::Client(Box::new(client)),
            vec![0; MAX_PENDING_INPUT],
        )
        .expect("maximum pending input");
        let (reader, _writer, _) = owner.split();
        assert_eq!(reader.pending_input_len(), MAX_PENDING_INPUT);
        assert!(EstablishedTcp::new(
            GateIo::default(),
            TlsAppEndpoint::Server(Box::new(server)),
            vec![0; MAX_PENDING_INPUT + 1],
        )
        .is_err());
    }

    #[test]
    fn scenario_unestablished_endpoint_seal_failure_is_terminal() {
        let (client, _hello) = Tls13Client::start(client_hello_params()).expect("start");
        let (_reader, mut writer, stats) = EstablishedTcp::new(
            GateIo::default(),
            TlsAppEndpoint::Client(Box::new(client)),
            Vec::new(),
        )
        .expect("owner")
        .split();
        assert!(writer.queue_record(b"not established").is_err());
        assert!(writer.queue_record(b"retry").is_err());
        assert!(writer.into_raw().is_err());
        assert_eq!(stats.snapshot().sealed_records, 0);
    }

    #[test]
    fn scenario_stats_saturate_without_wrapping() {
        let counter = AtomicU64::new(u64::MAX - 1);
        increment(&counter, 2);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    #[tokio::test]
    async fn scenario_partial_socket_progress_updates_idle_clock_without_record_completion() {
        let (client, _server) = established_endpoints();
        let io = GateIo::default();
        let gate = Arc::clone(&io.0);
        let (mut reader, mut writer, stats) =
            EstablishedTcp::new(io, TlsAppEndpoint::Client(Box::new(client)), vec![0x17])
                .expect("owner")
                .split();
        let initial = stats.last_io_progress();
        cancel_while_pending(reader.next_record()).await;
        assert_eq!(reader.filled, 1);
        assert_eq!(stats.last_io_progress(), initial);
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        gate.lock().expect("gate").input.push_back(0x03);
        cancel_while_pending(reader.next_record()).await;
        let after_read = stats.last_io_progress();
        assert!(after_read > initial);
        assert_eq!(reader.filled, 2);
        assert_eq!(stats.snapshot().opened_records, 0);
        cancel_while_pending(reader.next_record()).await;
        assert_eq!(stats.last_io_progress(), after_read);

        writer.queue_record(b"partial ciphertext").expect("queue");
        assert_eq!(stats.last_io_progress(), after_read);
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        gate.lock().expect("gate").write_budget = 1;
        cancel_while_pending(writer.flush_pending()).await;
        let after_write = stats.last_io_progress();
        assert!(after_write > after_read);
        assert_eq!(writer.queue[0].written, 1);
        cancel_while_pending(writer.flush_pending()).await;
        assert_eq!(stats.last_io_progress(), after_write);
    }

    fn established_endpoints() -> (Tls13Client, Tls13Server) {
        let params = client_hello_params();
        let profile = DestProfile::from_fingerprint(params.sni.clone(), &params.profile);
        let (mut client, hello) = Tls13Client::start(params).expect("client starts");
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(["server.example".to_owned()])
                .expect("test certificate");
        let forged = ForgedCert {
            leaf_der: cert.der().as_ref().to_vec(),
            chain_der: Vec::new(),
            certificate_verify_key_der: key_pair.serialize_der(),
        };
        let (mut server, flight) =
            Tls13Server::accept(&hello, forged, &profile).expect("server accepts");
        let output = client.drive(&flight, &AcceptAll).expect("client handshake");
        server.drive(&output.outbound).expect("server handshake");
        (client, server)
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
        let public = *keypair.public.as_bytes();
        let mlkem = mlkem_keygen();
        let mut key_exchange = public.to_vec();
        key_exchange.extend_from_slice(&mlkem.encapsulation_key);
        ClientHelloParams {
            sni: "server.example".to_owned(),
            session_id: vec![0x44; 32],
            x25519_priv: *keypair.private.expose_secret(),
            x25519_pub: public,
            mlkem: MlkemShare::x25519_mlkem768_with_decapsulation_key(
                key_exchange,
                mlkem.decapsulation_key,
            ),
            profile,
            random: [0x22; 32],
            quic_transport_parameters: Vec::new(),
        }
    }
}
