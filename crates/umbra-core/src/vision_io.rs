//! Authenticated solo envelopes and the committed transition to raw inner TLS.

use std::{collections::VecDeque, future::Future, io, time::Duration};

use rand::{rngs::OsRng, RngCore};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::watch,
    time::Instant,
};
use umbra_inner::vision_observer::{protected_record_len, Tls13Observer, VisionDirection};
use umbra_proto::{
    addr::TargetAddr,
    vision::{Boundaries, Envelope, Message},
};

use crate::owned_tls::{EstablishedTcp, OwnedTlsReader, OwnedTlsWriter, TlsIoSnapshot, TlsIoStats};

const OPEN_TIMEOUT: Duration = Duration::from_secs(25);
const PREFACE_TIMEOUT: Duration = Duration::from_secs(5);
const TARGET_TIMEOUT: Duration = Duration::from_secs(14);
const SWITCH_TIMEOUT: Duration = Duration::from_secs(5);
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(5);
const DATA_CHUNK: usize = 8192;
const QUEUE_LIMIT: usize = 32768;

/// Encryption and byte evidence from a completed Vision session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisionOutcome {
    /// Whether the authenticated transition actually took place.
    pub spliced: bool,
    /// Raw inner record bytes sent by this endpoint.
    pub raw_sent: u64,
    /// Raw inner record bytes received by this endpoint.
    pub raw_received: u64,
    /// Counters immediately after final encrypted controls, if a handoff occurred.
    pub at_handoff: Option<TlsIoSnapshot>,
    /// Counters after the entire relay has completed.
    pub final_tls: TlsIoSnapshot,
}

/// A bounded, independently polled read/write session with no detached TLS tasks.
pub struct VisionSession<R, W> {
    reader: OwnedTlsReader<R>,
    writer: OwnedTlsWriter<W>,
    stats: TlsIoStats,
    role: Role,
    raw_enabled: bool,
    observer: Tls13Observer,
    stage: Stage,
    tx_offset: u64,
    rx_offset: u64,
    tx_state: SendState,
    rx_fin: bool,
    data_records: u8,
    observation_started: Option<Instant>,
    switch_started: Option<Instant>,
    switch_attempted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendState {
    Open,
    Eof,
    Fin,
}

enum Event {
    Peer(io::Result<Option<Vec<u8>>>),
    Local(io::Result<usize>),
    Flushed(io::Result<()>),
    Delivered(io::Result<bool>),
    Timer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Wrapped,
    WrappedOnly,
    ClientWaitAck { c: u64 },
    ClientPrepareCommit(Boundaries),
    ClientCommitDraining(Boundaries),
    ClientWaitFinal(Boundaries),
    ServerPrepareAck { c: u64 },
    ServerPrepareReject { c: u64, reason: u8 },
    ServerWaitCommit(Boundaries),
    ServerPrepareFinal(Boundaries),
    ServerFinalDraining,
    Raw,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn encode(message: Message, padding: Vec<u8>) -> io::Result<Vec<u8>> {
    Envelope::new(message, padding)
        .and_then(|envelope| envelope.encode())
        .map_err(|_| invalid("invalid Vision envelope"))
}

fn decode(bytes: &[u8]) -> io::Result<Message> {
    Envelope::decode(bytes)
        .map(|envelope| envelope.message)
        .map_err(|_| invalid("invalid Vision envelope"))
}

async fn receive<R: AsyncRead + Unpin>(reader: &mut OwnedTlsReader<R>) -> io::Result<Message> {
    let bytes = reader
        .next_record()
        .await?
        .ok_or_else(|| invalid("EOF before Vision control"))?;
    decode(&bytes)
}

async fn send<W: AsyncWrite + Unpin>(
    writer: &mut OwnedTlsWriter<W>,
    message: Message,
) -> io::Result<()> {
    writer.queue_record(&encode(message, Vec::new())?)?;
    writer.flush_pending().await
}

/// Negotiate a v2 target before the caller acknowledges SOCKS success.
pub async fn client_open<IO>(
    established: EstablishedTcp<IO>,
    target: &TargetAddr,
) -> io::Result<VisionSession<ReadHalf<IO>, WriteHalf<IO>>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(OPEN_TIMEOUT, async {
        let (mut reader, mut writer, stats) = established.split();
        writer.queue_record(
            &target
                .encode()
                .map_err(|_| invalid("invalid Vision target"))?,
        )?;
        writer.flush_pending().await?;
        send(
            &mut writer,
            Message::Hello {
                min_raw_ver: 1,
                max_raw_ver: 1,
                features: 1,
            },
        )
        .await?;
        let Message::HelloAck {
            selected_raw_ver,
            target_result,
            features,
        } = receive(&mut reader).await?
        else {
            return Err(invalid("expected Vision HELLO_ACK"));
        };
        if target_result != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Vision target connection failed",
            ));
        }
        let raw_enabled = match (selected_raw_ver, features) {
            (0, 0) => false,
            (1, 1) => true,
            _ => return Err(invalid("unoffered Vision capability")),
        };
        Ok(VisionSession::new(
            reader,
            writer,
            stats,
            Role::Client,
            raw_enabled,
        ))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Vision target setup timed out"))?
}

/// Accept a v2 target and capability; no control bytes are sent to the target.
pub async fn server_open<IO, D, Connect, Connecting>(
    established: EstablishedTcp<IO>,
    mut connect: Connect,
) -> io::Result<(VisionSession<ReadHalf<IO>, WriteHalf<IO>>, D)>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    Connect: FnMut(TargetAddr) -> Connecting,
    Connecting: Future<Output = io::Result<D>>,
{
    let (mut reader, mut writer, stats) = established.split();
    let (target, raw_enabled) = tokio::time::timeout(PREFACE_TIMEOUT, async {
        let bytes = reader
            .next_record()
            .await?
            .ok_or_else(|| invalid("missing Vision target"))?;
        let target =
            TargetAddr::decode(&bytes).map_err(|_| invalid("invalid Vision target record"))?;
        let Message::Hello {
            min_raw_ver,
            max_raw_ver,
            features,
        } = receive(&mut reader).await?
        else {
            return Err(invalid("expected Vision HELLO"));
        };
        if min_raw_ver == 0 || max_raw_ver < min_raw_ver || features & !1 != 0 {
            return Err(invalid("invalid Vision capability"));
        }
        Ok((target, min_raw_ver == 1 && features == 1))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Vision preface timed out"))??;
    let connected = tokio::time::timeout(TARGET_TIMEOUT, connect(target)).await;
    let success = matches!(&connected, Ok(Ok(_)));
    tokio::time::timeout(
        PREFACE_TIMEOUT,
        send(
            &mut writer,
            Message::HelloAck {
                selected_raw_ver: u8::from(raw_enabled),
                target_result: u8::from(!success),
                features: u16::from(raw_enabled),
            },
        ),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Vision response timed out"))??;
    let target = connected
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Vision target timed out"))??;
    Ok((
        VisionSession::new(reader, writer, stats, Role::Server, raw_enabled),
        target,
    ))
}

impl<R, W> VisionSession<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn new(
        reader: OwnedTlsReader<R>,
        writer: OwnedTlsWriter<W>,
        stats: TlsIoStats,
        role: Role,
        raw_enabled: bool,
    ) -> Self {
        Self {
            reader,
            writer,
            stats,
            role,
            raw_enabled,
            observer: Tls13Observer::new(),
            stage: if raw_enabled {
                Stage::Wrapped
            } else {
                Stage::WrappedOnly
            },
            tx_offset: 0,
            rx_offset: 0,
            tx_state: SendState::Open,
            rx_fin: false,
            data_records: 0,
            observation_started: None,
            switch_started: None,
            switch_attempted: false,
        }
    }

    fn tx_direction(&self) -> VisionDirection {
        match self.role {
            Role::Client => VisionDirection::ClientToTarget,
            Role::Server => VisionDirection::TargetToClient,
        }
    }

    fn rx_direction(&self) -> VisionDirection {
        match self.role {
            Role::Client => VisionDirection::TargetToClient,
            Role::Server => VisionDirection::ClientToTarget,
        }
    }

    fn queue(&mut self, message: Message) -> io::Result<()> {
        self.writer.queue_record(&encode(message, Vec::new())?)
    }

    fn observe(&mut self, direction: VisionDirection, bytes: &[u8]) -> io::Result<()> {
        self.observation_started.get_or_insert_with(Instant::now);
        self.observer
            .observe(direction, bytes)
            .map_err(|_| invalid("Vision observer counter overflow"))
    }

    fn queue_data(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.observe(self.tx_direction(), bytes)?;
        self.tx_offset = add_bytes(self.tx_offset, bytes.len())?;
        let padding = if self.data_records < 16 {
            self.data_records += 1;
            let len = 100 + (OsRng.next_u32() % 1301) as usize;
            let mut bytes = vec![0; len];
            OsRng.fill_bytes(&mut bytes);
            bytes
        } else {
            Vec::new()
        };
        self.writer
            .queue_record(&encode(Message::Data(bytes.to_vec()), padding)?)
    }

    fn can_read_local(&self) -> bool {
        if self.tx_state != SendState::Open || self.writer.pending_records() != 0 {
            return false;
        }
        match self.stage {
            Stage::Wrapped | Stage::WrappedOnly => true,
            Stage::ServerPrepareAck { .. } => !self.observer.is_boundary(self.tx_direction()),
            _ => false,
        }
    }

    fn can_read_peer(&self) -> bool {
        !matches!(
            self.stage,
            Stage::ClientPrepareCommit(_)
                | Stage::ClientCommitDraining(_)
                | Stage::ServerPrepareFinal(_)
                | Stage::ServerFinalDraining
                | Stage::Raw
        )
    }

    fn drive(&mut self, local_idle: bool) -> io::Result<()> {
        if self.switch_started.is_none()
            && self
                .observation_started
                .is_some_and(|at| at.elapsed() >= OBSERVE_TIMEOUT)
        {
            self.observer.disable();
        }
        if !self.writer.is_idle() {
            return Ok(());
        }
        match self.stage {
            Stage::Wrapped
                if self.role == Role::Client
                    && self.raw_enabled
                    && self.tx_state == SendState::Open
                    && !self.rx_fin
                    && self.observer.eligible()
                    && self.observer.is_boundary(self.tx_direction())
                    && self.observer.is_boundary(self.rx_direction()) =>
            {
                self.queue(Message::SwitchReq {
                    switch_id: 1,
                    c2s_boundary: self.tx_offset,
                })?;
                self.switch_started = Some(Instant::now());
                self.switch_attempted = true;
                self.stage = Stage::ClientWaitAck { c: self.tx_offset };
            }
            Stage::ServerPrepareAck { c } if local_idle => {
                if !self.observer.eligible() {
                    self.reject(c, 1)?;
                } else if self.observer.is_boundary(self.tx_direction()) {
                    let bounds = Boundaries {
                        switch_id: 1,
                        c2s_boundary: c,
                        s2c_boundary: self.tx_offset,
                    };
                    self.queue(Message::SwitchAck(bounds))?;
                    self.stage = Stage::ServerWaitCommit(bounds);
                }
            }
            Stage::ServerPrepareReject { c, reason } => self.reject(c, reason)?,
            Stage::ClientPrepareCommit(bounds) if local_idle => {
                self.queue(Message::Commit(bounds))?;
                self.stage = Stage::ClientCommitDraining(bounds);
            }
            Stage::ClientCommitDraining(bounds) => {
                self.stage = Stage::ClientWaitFinal(bounds);
            }
            Stage::ServerPrepareFinal(bounds) if local_idle => {
                self.queue(Message::CommitAck(bounds))?;
                self.stage = Stage::ServerFinalDraining;
            }
            Stage::ServerFinalDraining if local_idle => self.stage = Stage::Raw,
            _ => {}
        }
        if self.tx_state != SendState::Open
            && self.tx_state != SendState::Fin
            && matches!(self.stage, Stage::Wrapped | Stage::WrappedOnly)
            && self.writer.is_idle()
        {
            self.queue(Message::Fin {
                final_offset: self.tx_offset,
            })?;
            self.tx_state = SendState::Fin;
        }
        Ok(())
    }

    fn reject(&mut self, c: u64, reason: u8) -> io::Result<()> {
        self.queue(Message::SwitchReject {
            boundaries: Boundaries {
                switch_id: 1,
                c2s_boundary: c,
                s2c_boundary: self.tx_offset,
            },
            reason,
        })?;
        self.stage = Stage::WrappedOnly;
        self.switch_started = None;
        Ok(())
    }

    fn receive_switch_request(&mut self, switch_id: u32, c2s_boundary: u64) -> io::Result<()> {
        if self.role != Role::Server
            || !self.raw_enabled
            || self.switch_attempted
            || !matches!(self.stage, Stage::Wrapped | Stage::WrappedOnly)
            || switch_id != 1
            || c2s_boundary != self.rx_offset
        {
            return Err(invalid("invalid Vision switch request"));
        }
        self.switch_started = Some(Instant::now());
        self.switch_attempted = true;
        let reason = if self.tx_state == SendState::Fin {
            Some(2)
        } else if self.stage == Stage::WrappedOnly || !self.observer.eligible() {
            Some(1)
        } else {
            None
        };
        if let Some(reason) = reason {
            self.stage = Stage::ServerPrepareReject {
                c: c2s_boundary,
                reason,
            };
        } else {
            if self.rx_fin || !self.observer.is_boundary(self.rx_direction()) {
                return Err(invalid("Vision client boundary is not a complete record"));
            }
            self.stage = Stage::ServerPrepareAck { c: c2s_boundary };
        }
        Ok(())
    }

    fn accept_message(&mut self, message: Message, local: &mut PendingBytes) -> io::Result<()> {
        match message {
            Message::Data(bytes) => {
                if self.rx_fin
                    || !matches!(
                        self.stage,
                        Stage::Wrapped | Stage::WrappedOnly | Stage::ClientWaitAck { .. }
                    )
                {
                    return Err(invalid("Vision DATA after boundary or FIN"));
                }
                self.observe(self.rx_direction(), &bytes)?;
                self.rx_offset = add_bytes(self.rx_offset, bytes.len())?;
                local.push(bytes)?;
            }
            Message::Fin { final_offset } => {
                if self.rx_fin
                    || final_offset != self.rx_offset
                    || !matches!(
                        self.stage,
                        Stage::Wrapped | Stage::WrappedOnly | Stage::ClientWaitAck { .. }
                    )
                {
                    return Err(invalid("invalid Vision FIN"));
                }
                self.rx_fin = true;
                if self.stage == Stage::Wrapped {
                    self.stage = Stage::WrappedOnly;
                }
            }
            Message::Padding => {
                if !matches!(self.stage, Stage::Wrapped | Stage::WrappedOnly) {
                    return Err(invalid("Vision PADDING after boundary"));
                }
            }
            Message::SwitchReq {
                switch_id,
                c2s_boundary,
            } => self.receive_switch_request(switch_id, c2s_boundary)?,
            Message::SwitchAck(bounds) => {
                let Stage::ClientWaitAck { c } = self.stage else {
                    return Err(invalid("unexpected Vision switch acknowledgement"));
                };
                if self.rx_fin
                    || bounds.switch_id != 1
                    || bounds.c2s_boundary != c
                    || bounds.s2c_boundary != self.rx_offset
                    || !self.observer.is_boundary(self.rx_direction())
                {
                    return Err(invalid("Vision switch acknowledgement boundary mismatch"));
                }
                self.stage = Stage::ClientPrepareCommit(bounds);
            }
            Message::SwitchReject { boundaries, reason } => {
                let Stage::ClientWaitAck { c } = self.stage else {
                    return Err(invalid("unexpected Vision switch rejection"));
                };
                if boundaries.switch_id != 1
                    || boundaries.c2s_boundary != c
                    || boundaries.s2c_boundary != self.rx_offset
                    || !matches!(reason, 1 | 2)
                    || (self.rx_fin && reason != 2)
                    || (!self.rx_fin && reason == 2)
                {
                    return Err(invalid("invalid Vision switch rejection"));
                }
                self.stage = Stage::WrappedOnly;
                self.switch_started = None;
            }
            Message::Commit(bounds) => {
                if self.stage != Stage::ServerWaitCommit(bounds) {
                    return Err(invalid("unexpected Vision commit"));
                }
                self.stage = Stage::ServerPrepareFinal(bounds);
            }
            Message::CommitAck(bounds) => {
                if self.stage != Stage::ClientWaitFinal(bounds) {
                    return Err(invalid("unexpected Vision final acknowledgement"));
                }
                self.stage = Stage::Raw;
            }
            Message::Hello { .. } | Message::HelloAck { .. } => {
                return Err(invalid("duplicate Vision capability exchange"));
            }
        }
        Ok(())
    }

    async fn finish_raw<LR: AsyncRead + Unpin, LW: AsyncWrite + Unpin>(
        self,
        local_read: &mut LR,
        local_write: &mut LW,
        idle_timeout: Duration,
    ) -> io::Result<VisionOutcome> {
        let at_handoff = self.stats.snapshot();
        let peer_read = self.reader.into_raw()?;
        let peer_write = self.writer.into_raw()?;
        eprintln!("umbra vision splice active");
        let (raw_sent, raw_received) = raw_relay(
            local_read,
            local_write,
            peer_read,
            peer_write,
            self.tx_state != SendState::Open,
            idle_timeout,
        )
        .await?;
        let final_tls = self.stats.snapshot();
        if final_tls != at_handoff {
            return Err(invalid("outer TLS advanced after Vision handoff"));
        }
        eprintln!(
                    "umbra vision splice complete: raw_sent={raw_sent}, raw_received={raw_received}, outer_records_unchanged=true"
                );
        Ok(VisionOutcome {
            spliced: true,
            raw_sent,
            raw_received,
            at_handoff: Some(at_handoff),
            final_tls,
        })
    }

    /// Relay target bytes, committing only at acknowledged protected-record boundaries.
    pub async fn relay<L>(
        mut self,
        local: &mut L,
        idle_timeout: Duration,
    ) -> io::Result<VisionOutcome>
    where
        L: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut local_read, mut local_write) = tokio::io::split(local);
        let mut pending_local = PendingBytes::default();
        let mut local_shutdown = false;
        let mut peer_eof = false;
        let mut input = [0_u8; DATA_CHUNK];
        let mut last_progress = Instant::now();
        loop {
            self.drive(pending_local.is_idle())?;
            if self.stage == Stage::Raw {
                return self
                    .finish_raw(&mut local_read, &mut local_write, idle_timeout)
                    .await;
            }
            if self.tx_state == SendState::Fin
                && self.rx_fin
                && self.writer.is_idle()
                && local_shutdown
            {
                return Ok(VisionOutcome {
                    spliced: false,
                    raw_sent: 0,
                    raw_received: 0,
                    at_handoff: None,
                    final_tls: self.stats.snapshot(),
                });
            }
            let switch_deadline = self
                .switch_started
                .map_or(last_progress + idle_timeout, |at| at + SWITCH_TIMEOUT);
            let deadline = (last_progress + idle_timeout).min(switch_deadline);
            let read_limit = self.observer.read_limit(self.tx_direction(), DATA_CHUNK);
            let read_local = self.can_read_local();
            let read_peer =
                !peer_eof && self.can_read_peer() && pending_local.bytes <= QUEUE_LIMIT - 16376;
            let event = tokio::select! {
                result = self.reader.next_record(), if read_peer => Event::Peer(result),
                result = local_read.read(&mut input[..read_limit]), if read_local => Event::Local(result),
                result = self.writer.flush_pending(), if !self.writer.is_idle() => Event::Flushed(result),
                result = pending_local.flush_or_shutdown(&mut local_write, self.rx_fin && !local_shutdown), if !pending_local.is_idle() || (self.rx_fin && !local_shutdown) => Event::Delivered(result),
                () = tokio::time::sleep_until(deadline) => Event::Timer,
            };
            match event {
                Event::Timer => {
                    last_progress = last_progress.max(self.stats.last_io_progress());
                    if self
                        .switch_started
                        .is_some_and(|at| at.elapsed() >= SWITCH_TIMEOUT)
                        || last_progress.elapsed() >= idle_timeout
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Vision session or switch timed out",
                        ));
                    }
                    continue;
                }
                Event::Peer(record) => {
                    if let Some(record) = record? {
                        self.accept_message(decode(&record)?, &mut pending_local)?;
                    } else if self.rx_fin
                        && matches!(self.stage, Stage::Wrapped | Stage::WrappedOnly)
                    {
                        peer_eof = true;
                    } else {
                        return Err(invalid("truncated Vision session"));
                    }
                }
                Event::Local(read) => {
                    let read = read?;
                    if read == 0 {
                        self.tx_state = SendState::Eof;
                        if matches!(self.stage, Stage::ServerPrepareAck { .. })
                            && !self.observer.is_boundary(self.tx_direction())
                        {
                            return Err(invalid("incomplete inner record at Vision EOF"));
                        }
                    } else {
                        self.queue_data(&input[..read])?;
                    }
                }
                Event::Flushed(result) => result?,
                Event::Delivered(result) => local_shutdown |= result?,
            }
            last_progress = Instant::now();
        }
    }
}

fn add_bytes(count: u64, len: usize) -> io::Result<u64> {
    count
        .checked_add(u64::try_from(len).map_err(|_| invalid("Vision byte length overflow"))?)
        .ok_or_else(|| invalid("Vision byte counter overflow"))
}

#[derive(Default)]
struct PendingBytes {
    chunks: VecDeque<Vec<u8>>,
    offset: usize,
    bytes: usize,
    needs_flush: bool,
}

impl PendingBytes {
    fn push(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        if bytes.len() > QUEUE_LIMIT.saturating_sub(self.bytes) {
            return Err(invalid("Vision receive queue exceeds limit"));
        }
        self.bytes += bytes.len();
        self.chunks.push_back(bytes);
        self.needs_flush = true;
        Ok(())
    }

    fn is_idle(&self) -> bool {
        self.chunks.is_empty() && !self.needs_flush
    }

    async fn flush_or_shutdown<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        shutdown: bool,
    ) -> io::Result<bool> {
        if let Some(front) = self.chunks.front() {
            let written = writer.write(&front[self.offset..]).await?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "Vision target write stopped",
                ));
            }
            self.offset += written;
            self.bytes -= written;
            if self.offset == front.len() {
                self.chunks.pop_front();
                self.offset = 0;
            }
            return Ok(false);
        }
        writer.flush().await?;
        self.needs_flush = false;
        if shutdown {
            writer.shutdown().await?;
        }
        Ok(shutdown)
    }
}

async fn forward_records<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    already_eof: bool,
    progress: &watch::Sender<Instant>,
) -> io::Result<u64> {
    let mut count = 0;
    if already_eof {
        writer.shutdown().await?;
        return Ok(count);
    }
    loop {
        let mut header = [0_u8; 5];
        let first = reader.read(&mut header[..1]).await?;
        if first == 0 {
            writer.shutdown().await?;
            return Ok(count);
        }
        progress.send_replace(Instant::now());
        read_progress(reader, &mut header[1..], progress).await?;
        let len = protected_record_len(&header)
            .map_err(|_| invalid("invalid protected record after Vision handoff"))?;
        let mut record = vec![0_u8; len];
        record[..5].copy_from_slice(&header);
        read_progress(reader, &mut record[5..], progress).await?;
        progress.send_replace(Instant::now());
        let mut written = 0;
        while written < record.len() {
            let n = writer.write(&record[written..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "raw TLS write stopped",
                ));
            }
            written += n;
            progress.send_replace(Instant::now());
        }
        writer.flush().await?;
        count = add_bytes(count, len)?;
        progress.send_replace(Instant::now());
    }
}

async fn read_progress<R: AsyncRead + Unpin>(
    reader: &mut R,
    bytes: &mut [u8],
    progress: &watch::Sender<Instant>,
) -> io::Result<()> {
    let mut read = 0;
    while read < bytes.len() {
        let n = reader.read(&mut bytes[read..]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated raw TLS record",
            ));
        }
        read += n;
        progress.send_replace(Instant::now());
    }
    Ok(())
}

async fn wait_idle(mut progress: watch::Receiver<Instant>, idle: Duration) {
    loop {
        let deadline = *progress.borrow_and_update() + idle;
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => {
                if progress.borrow().elapsed() >= idle { return; }
            },
            changed = progress.changed() => if changed.is_err() { return; },
        }
    }
}

async fn raw_relay<LR, LW, R, W>(
    local_read: &mut LR,
    local_write: &mut LW,
    mut peer_read: R,
    mut peer_write: W,
    local_eof: bool,
    idle: Duration,
) -> io::Result<(u64, u64)>
where
    LR: AsyncRead + Unpin,
    LW: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (progress, changes) = watch::channel(Instant::now());
    tokio::select! {
        result = async {
            tokio::try_join!(
                forward_records(local_read, &mut peer_write, local_eof, &progress),
                forward_records(&mut peer_read, local_write, false, &progress),
            )
        } => result,
        () = wait_idle(changes, idle) => Err(io::Error::new(io::ErrorKind::TimedOut, "Vision raw relay idle timeout")),
    }
}

#[cfg(test)]
#[path = "vision_io_tests.rs"]
mod tests;
