//! Shared CONNECT-only mux I/O, driven by one task owning the outer session.
//!
//! Keep the returned [`MuxDriver`] alive for the lifetime of the connection.
//! Dropping it aborts the task and wakes every outstanding operation; clones of
//! [`ClientMux`] do not own background tasks. Failed sessions never replay data.
//! The supplied session must be fresh and have the matching role. Stream-zero
//! UDP associations must continue using a separate session.
//!
//! Each stream owns at most one unsent DATA chunk, plus session-owned serialized
//! output. Inbound storage is charged to the session's reserved receive credit;
//! only `AsyncRead` consumption returns credit. Short mutex sections implement
//! the bounded mailboxes, with one coalescing notification for the driver. No
//! mutex is held across an await or transport I/O.

use std::{
    collections::{BTreeMap, VecDeque},
    future::{pending, poll_fn, Future},
    io,
    pin::{pin, Pin},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    task::{Context, Poll, Waker},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, Notify},
    task::JoinHandle,
};
use umbra_inner::{
    mux::{
        MuxEvent, MuxRole, MuxSession, MAX_DATA_CHUNK_LEN, MAX_RECEIVE_BUFFER_BYTES, MAX_STREAMS,
    },
    InnerError,
};
use umbra_proto::addr::TargetAddr;

/// The owner of a single shared mux task. Dropping the owner cancels that task.
///
/// Retain this separately from the clonable client handle (for example in the
/// runtime's connection pool). Explicit shutdown also joins the cancelled task.
#[must_use = "dropping the owner stops the shared mux connection"]
pub(crate) struct MuxDriver {
    task: JoinHandle<()>,
    healthy: Arc<AtomicBool>,
}

impl MuxDriver {
    /// Stop the outer connection and wait until its owned task has been dropped.
    pub(crate) async fn shutdown(mut self) {
        self.healthy.store(false, Ordering::Release);
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for MuxDriver {
    fn drop(&mut self) {
        self.healthy.store(false, Ordering::Release);
        self.task.abort();
    }
}

/// Clonable opener for independent streams on one healthy outer connection.
#[derive(Clone)]
pub(crate) struct ClientMux {
    opens: mpsc::Sender<OpenRequest>,
    notify: Arc<Notify>,
    healthy: Arc<AtomicBool>,
}

impl ClientMux {
    /// Whether the existing outer is still usable. A failure is terminal; callers
    /// may establish a replacement for future opens, never replay old payloads.
    pub(crate) fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// Open a stream, returning only after the peer's SYN_ACK.
    ///
    /// Cancellation resets an already submitted open. It never repeats SYN or
    /// transfers the cancelled stream to a later caller.
    pub(crate) async fn open(&self, target: TargetAddr) -> io::Result<MuxIo> {
        if !self.is_healthy() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let stream = MuxIo::new(0, Phase::Opening, self.notify.clone());
        let request = OpenRequest {
            target,
            shared: stream.shared.clone(),
            armed: true,
        };
        self.opens
            .send(request)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        stream.ready().await?;
        Ok(stream)
    }
}

/// Receiver of server-side SYNs. Target connections should be made concurrently
/// by caller-owned tasks; this receiver never waits for a target connection.
pub(crate) struct ServerMux {
    incoming: mpsc::Receiver<PendingMux>,
    healthy: Arc<AtomicBool>,
}

impl ServerMux {
    /// Whether the server's outer connection is still usable.
    pub(crate) fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// Receive a pending CONNECT, without acknowledging it to the client.
    /// Cancellation of this wait does not consume an incoming stream.
    pub(crate) async fn accept(&mut self) -> io::Result<PendingMux> {
        if !self.is_healthy() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        loop {
            let pending = self
                .incoming
                .recv()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
            if !self.is_healthy() {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            if pending.stream.shared.lock().error.is_none() {
                return Ok(pending);
            }
            // A cancelled SYN may have been reset while still in the backlog.
            // Do not start a target connection for an already retired stream.
        }
    }
}

/// An incoming stream which has not yet received SYN_ACK.
///
/// Connect `target` first, then call [`Self::accept`]. A failed target connection
/// should call [`Self::reject`] or simply drop this value, resetting only this
/// stream. The caller owns and must supervise any spawned target-connect tasks.
pub(crate) struct PendingMux {
    /// Requested CONNECT destination. Do not include it in default logs.
    pub(crate) target: TargetAddr,
    stream: MuxIo,
}

impl PendingMux {
    /// The incoming logical stream identifier.
    #[cfg(test)]
    fn stream_id(&self) -> u32 {
        self.stream.stream_id()
    }

    /// Acknowledge a successfully connected target and return its logical I/O.
    /// Cancellation resets the stream, including a partially sent SYN_ACK.
    pub(crate) async fn accept(self) -> io::Result<MuxIo> {
        {
            let mut state = self.stream.shared.lock();
            state.phase = Phase::AcceptReady;
        }
        self.stream.shared.notify.notify_one();
        self.stream.ready().await?;
        Ok(self.stream)
    }

    /// Reject this target. RST is retained and retried by the driver if its
    /// bounded output queue is full; this method does not await transport I/O.
    pub(crate) fn reject(self) {
        drop(self);
    }
}

/// Start a client driver over a fresh authenticated CONNECT-only session.
/// The caller must be inside a Tokio runtime and retain the returned owner.
/// All outer I/O is owned by the task and therefore must be `Send + 'static`.
pub(crate) fn start_client<IO>(session: MuxSession<IO>) -> io::Result<(MuxDriver, ClientMux)>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    check_session(&session, MuxRole::Client)?;
    let (opens, receiver) = mpsc::channel(MAX_STREAMS);
    let driver = Driver::new(session, Some(receiver), None);
    let client = ClientMux {
        opens,
        notify: driver.notify.clone(),
        healthy: driver.healthy.clone(),
    };
    Ok((spawn(driver), client))
}

/// Start a server driver over a fresh authenticated CONNECT-only session.
/// No target is acknowledged until the caller invokes [`PendingMux::accept`].
#[cfg(test)]
pub(crate) fn start_server<IO>(session: MuxSession<IO>) -> io::Result<(MuxDriver, ServerMux)>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    check_session(&session, MuxRole::Server)?;
    let (incoming, receiver) = mpsc::channel(MAX_STREAMS);
    let driver = Driver::new(session, None, Some(incoming));
    let server = ServerMux {
        incoming: receiver,
        healthy: driver.healthy.clone(),
    };
    Ok((spawn(driver), server))
}

pub(crate) fn start_server_after_syn<IO>(
    session: MuxSession<IO>,
    stream_id: u32,
    target: TargetAddr,
) -> io::Result<(MuxDriver, ServerMux)>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if session.role() != MuxRole::Server || session.active_stream_count() != 1 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let (incoming, receiver) = mpsc::channel(MAX_STREAMS);
    let mut driver = Driver::new(session, None, Some(incoming));
    driver
        .dispatch(MuxEvent::Syn { stream_id, target })
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let server = ServerMux {
        incoming: receiver,
        healthy: driver.healthy.clone(),
    };
    Ok((spawn(driver), server))
}

fn check_session<IO>(session: &MuxSession<IO>, role: MuxRole) -> io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if session.role() != role || session.active_stream_count() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "shared mux requires a fresh session with the matching role",
        ));
    }
    Ok(())
}

fn spawn<IO>(mut driver: Driver<IO>) -> MuxDriver
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let healthy = driver.healthy.clone();
    // The guard exists before spawn, so aborting even before the first poll
    // drops all queues and publishes failure rather than detaching any work.
    let task = tokio::spawn(async move {
        let _ = driver.run().await;
    });
    MuxDriver { task, healthy }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Opening,
    Accepting,
    AcceptReady,
    Established,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SendPhase {
    Open,
    FinRequested,
    FinQueued,
    FinFlushed,
}

impl SendPhase {
    fn is_queued(self) -> bool {
        matches!(self, Self::FinQueued | Self::FinFlushed)
    }
}

struct WriteChunk {
    bytes: Vec<u8>,
    offset: usize,
    sequence: u64,
}

struct State {
    id: u32,
    phase: Phase,
    inbound: VecDeque<u8>,
    consumed: usize,
    outbound: Option<WriteChunk>,
    accepted: u64,
    submitted: u64,
    flushed: u64,
    send_phase: SendPhase,
    peer_finished: bool,
    reset_requested: bool,
    error: Option<io::ErrorKind>,
    reader: Option<Waker>,
    writer: Option<Waker>,
    opener: Option<Waker>,
}

impl State {
    fn new(id: u32, phase: Phase) -> Self {
        Self {
            id,
            phase,
            inbound: VecDeque::new(),
            consumed: 0,
            outbound: None,
            accepted: 0,
            submitted: 0,
            flushed: 0,
            send_phase: SendPhase::Open,
            peer_finished: false,
            reset_requested: false,
            error: None,
            reader: None,
            writer: None,
            opener: None,
        }
    }

    fn check(&self) -> io::Result<()> {
        self.error.map_or(Ok(()), |kind| Err(kind.into()))
    }

    fn wake_all(&mut self) {
        wake(&mut self.reader);
        wake(&mut self.writer);
        wake(&mut self.opener);
    }

    fn fail(&mut self, kind: io::ErrorKind) {
        self.error = Some(kind);
        self.inbound = VecDeque::new();
        self.outbound = None;
        self.consumed = 0;
        self.wake_all();
    }

    fn peer_closed(&mut self) {
        // Graceful outer end after the peer's FIN: retained inbound still drains
        // to the reader, then reads report EOF. Without that FIN the peer's data
        // may be truncated, so the stream fails like any other outer error.
        if !self.peer_finished {
            self.fail(io::ErrorKind::BrokenPipe);
            return;
        }
        // Writes can never complete on a dead outer, so they fail at once.
        if self.error.is_none() {
            self.error = Some(io::ErrorKind::BrokenPipe);
        }
        self.wake_all();
    }
}

struct Shared {
    state: Mutex<State>,
    notify: Arc<Notify>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn wake(slot: &mut Option<Waker>) {
    if let Some(waker) = slot.take() {
        waker.wake();
    }
}

fn register(slot: &mut Option<Waker>, cx: &Context<'_>) {
    if !slot
        .as_ref()
        .is_some_and(|waker| waker.will_wake(cx.waker()))
    {
        *slot = Some(cx.waker().clone());
    }
}

/// Owned logical stream implementing `AsyncRead + AsyncWrite + Unpin + Send`.
///
/// `flush` waits for all preceding accepted writes to drain through the outer
/// writer, not merely enter its queue. `shutdown` additionally drains ordered
/// FIN, leaving reads available for a delayed response. Dropping an incompletely
/// closed stream requests RST without waiting for mailbox capacity. Cancellation
/// of a pending flush/shutdown retains accepted bytes and FIN in driver state.
pub(crate) struct MuxIo {
    shared: Arc<Shared>,
}

impl MuxIo {
    fn new(id: u32, phase: Phase, notify: Arc<Notify>) -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State::new(id, phase)),
                notify,
            }),
        }
    }

    /// Identifier of this logical stream on the existing outer connection.
    #[cfg(test)]
    fn stream_id(&self) -> u32 {
        self.shared.lock().id
    }

    async fn ready(&self) -> io::Result<()> {
        poll_fn(|cx| {
            let mut state = self.shared.lock();
            state.check()?;
            if state.phase == Phase::Established {
                Poll::Ready(Ok(()))
            } else {
                register(&mut state.opener, cx);
                Poll::Pending
            }
        })
        .await
    }
}

impl AsyncRead for MuxIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.shared.lock();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let amount = state.inbound.len().min(buf.remaining());
        if amount != 0 {
            let (first, second) = state.inbound.as_slices();
            let first_len = amount.min(first.len());
            buf.put_slice(&first[..first_len]);
            buf.put_slice(&second[..amount - first_len]);
            state.inbound.drain(..amount);
            state.consumed += amount;
            // Session-reserved receive credit bounds both this count and storage.
            self.shared.notify.notify_one();
            return Poll::Ready(Ok(()));
        }
        if state.peer_finished {
            return Poll::Ready(Ok(()));
        }
        state.check()?;
        register(&mut state.reader, cx);
        Poll::Pending
    }
}

impl AsyncWrite for MuxIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.shared.lock();
        state.check()?;
        if state.send_phase != SendPhase::Open {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if state.outbound.is_some() {
            register(&mut state.writer, cx);
            return Poll::Pending;
        }
        let Some(sequence) = state.accepted.checked_add(1) else {
            return Poll::Ready(Err(io::ErrorKind::Other.into()));
        };
        let amount = bytes.len().min(MAX_DATA_CHUNK_LEN);
        state.outbound = Some(WriteChunk {
            bytes: bytes[..amount].to_vec(),
            offset: 0,
            sequence,
        });
        state.accepted = sequence;
        self.shared.notify.notify_one();
        Poll::Ready(Ok(amount))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.shared.lock();
        state.check()?;
        if state.flushed == state.accepted {
            return Poll::Ready(Ok(()));
        }
        register(&mut state.writer, cx);
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.shared.lock();
        state.check()?;
        if state.send_phase == SendPhase::FinFlushed {
            return Poll::Ready(Ok(()));
        }
        if state.send_phase == SendPhase::Open {
            state.send_phase = SendPhase::FinRequested;
            self.shared.notify.notify_one();
        }
        register(&mut state.writer, cx);
        Poll::Pending
    }
}

impl Drop for MuxIo {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        if state.error.is_none()
            && !(state.send_phase.is_queued() && state.peer_finished && state.inbound.is_empty())
        {
            state.reset_requested = true;
        }
        self.shared.notify.notify_one();
    }
}

struct OpenRequest {
    target: TargetAddr,
    shared: Arc<Shared>,
    // A request still in the admission channel must wake its opener if the
    // driver disappears. Successfully registered requests disarm this guard.
    armed: bool,
}

impl Drop for OpenRequest {
    fn drop(&mut self) {
        if self.armed {
            self.shared.lock().fail(io::ErrorKind::BrokenPipe);
        }
    }
}

struct Driver<IO> {
    session: MuxSession<IO>,
    streams: BTreeMap<u32, Arc<Shared>>,
    opens: Option<mpsc::Receiver<OpenRequest>>,
    pending_open: Option<OpenRequest>,
    incoming: Option<mpsc::Sender<PendingMux>>,
    notify: Arc<Notify>,
    healthy: Arc<AtomicBool>,
    need_flush: bool,
    first_stream: usize,
}

struct Progress {
    flushed: bool,
    event: Option<MuxEvent>,
}

impl<IO> Driver<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn new(
        session: MuxSession<IO>,
        opens: Option<mpsc::Receiver<OpenRequest>>,
        incoming: Option<mpsc::Sender<PendingMux>>,
    ) -> Self {
        Self {
            session,
            streams: BTreeMap::new(),
            opens,
            pending_open: None,
            incoming,
            notify: Arc::new(Notify::new()),
            healthy: Arc::new(AtomicBool::new(true)),
            need_flush: false,
            first_stream: 0,
        }
    }

    async fn run(&mut self) -> Result<(), InnerError> {
        let result = self.run_loop().await;
        if let Err(InnerError::Io(error)) = &result {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                for shared in self.streams.values() {
                    shared.lock().peer_closed();
                }
            }
        }
        result
    }

    async fn run_loop(&mut self) -> Result<(), InnerError> {
        loop {
            // Freeze each finite output batch until it drains. This makes flush
            // barriers independent of subsequent traffic and retains partial
            // suffixes even if another stream has zero send credit.
            if !self.need_flush {
                self.pump()?;
            }
            tokio::select! {
                () = self.notify.notified() => {}
                request = async {
                    match &mut self.opens {
                        Some(receiver) => receiver.recv().await,
                        None => pending().await,
                    }
                }, if self.pending_open.is_none() => {
                    if let Some(request) = request {
                        self.pending_open = Some(request);
                    } else {
                        self.opens = None;
                    }
                }
                progress = poll_fn(|cx| poll_session(&mut self.session, self.need_flush, cx)) => {
                    let progress = progress?;
                    if progress.flushed {
                        self.need_flush = false;
                        for shared in self.streams.values() {
                            let mut state = shared.lock();
                            state.flushed = state.submitted;
                            if state.send_phase == SendPhase::FinQueued {
                                state.send_phase = SendPhase::FinFlushed;
                            }
                            wake(&mut state.writer);
                        }
                    }
                    if let Some(event) = progress.event {
                        self.dispatch(event)?;
                    }
                }
            }
        }
    }

    fn pump(&mut self) -> Result<(), InnerError> {
        let mut retired = Vec::new();
        // Rotate the first serviced id on every batch, even when the serialized
        // writer fills before all streams have obtained their next DATA chunk.
        let mut ids: Vec<_> = self.streams.keys().copied().collect();
        if !ids.is_empty() {
            let first = self.first_stream % ids.len();
            ids.rotate_left(first);
            self.first_stream = (first + 1) % ids.len();
        }
        for id in ids {
            let Some(shared) = self.streams.get(&id) else {
                continue;
            };
            let mut state = shared.lock();
            match pump_stream(&mut self.session, &mut state, &mut self.need_flush) {
                Ok(true) => retired.push(id),
                Ok(false) => {}
                Err(error) => return Err(error),
            }
        }
        for id in retired {
            self.streams.remove(&id);
        }
        self.admit_open();
        Ok(())
    }

    fn admit_open(&mut self) {
        let Some(request) = self.pending_open.as_mut() else {
            return;
        };
        if request.shared.lock().reset_requested {
            self.pending_open = None;
            return;
        }
        if self.streams.len() >= MAX_STREAMS {
            return;
        }
        match self.session.begin_open(&request.target) {
            Ok(stream) => {
                request.shared.lock().id = stream.stream_id;
                self.streams
                    .insert(stream.stream_id, request.shared.clone());
                request.armed = false;
                self.pending_open = None;
                self.need_flush = true;
            }
            Err(error) if would_block(&error) => {}
            Err(_) => {
                request.shared.lock().fail(io::ErrorKind::InvalidInput);
                request.armed = false;
                self.pending_open = None;
            }
        }
    }

    fn dispatch(&mut self, event: MuxEvent) -> Result<(), InnerError> {
        match event {
            MuxEvent::Syn { stream_id, target } => {
                let stream = MuxIo::new(stream_id, Phase::Accepting, self.notify.clone());
                self.streams.insert(stream_id, stream.shared.clone());
                let pending = PendingMux { target, stream };
                // Backlog saturation or a dropped acceptor resets the new stream;
                // it must never suspend dispatch for established siblings.
                if let Some(incoming) = &self.incoming {
                    let _ = incoming.try_send(pending);
                }
            }
            MuxEvent::SynAck { stream_id } => {
                if let Some(shared) = self.streams.get(&stream_id) {
                    let mut state = shared.lock();
                    state.phase = Phase::Established;
                    wake(&mut state.opener);
                }
            }
            MuxEvent::Data { stream_id, payload } => {
                let buffered: usize = self.streams.values().map(|s| s.lock().inbound.len()).sum();
                if payload.len() > MAX_RECEIVE_BUFFER_BYTES.saturating_sub(buffered) {
                    return Err(io::Error::from(io::ErrorKind::InvalidData).into());
                }
                if let Some(shared) = self.streams.get(&stream_id) {
                    let mut state = shared.lock();
                    state.inbound.extend(payload);
                    wake(&mut state.reader);
                }
            }
            MuxEvent::Fin { stream_id } => {
                if let Some(shared) = self.streams.get(&stream_id) {
                    let mut state = shared.lock();
                    state.peer_finished = true;
                    wake(&mut state.reader);
                }
            }
            MuxEvent::Rst { stream_id } => {
                if let Some(shared) = self.streams.remove(&stream_id) {
                    shared.lock().fail(io::ErrorKind::ConnectionReset);
                }
            }
            MuxEvent::WindowUpdate { .. } | MuxEvent::Ping { .. } => {}
            MuxEvent::UdpDatagram { .. } => {
                return Err(io::Error::from(io::ErrorKind::InvalidData).into())
            }
        }
        Ok(())
    }
}

impl<IO> Drop for Driver<IO> {
    fn drop(&mut self) {
        self.healthy.store(false, Ordering::Release);
        for shared in self.streams.values() {
            let mut state = shared.lock();
            // Gracefully closed streams keep their retained inbound for draining.
            if state.error.is_none() {
                state.fail(io::ErrorKind::BrokenPipe);
            }
        }
        // OpenRequest::drop wakes requests in pending_open and the channel.
        // Dropping the incoming sender wakes a blocked ServerMux::accept.
    }
}

fn pump_stream<IO>(
    session: &mut MuxSession<IO>,
    state: &mut State,
    dirty: &mut bool,
) -> Result<bool, InnerError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let id = state.id;
    if state.reset_requested {
        match session.queue_reset(id) {
            Ok(()) => *dirty = true,
            Err(InnerError::StreamReset) => {}
            Err(error) if would_block(&error) => return Ok(false),
            Err(error) => return Err(error),
        }
        state.fail(io::ErrorKind::ConnectionReset);
        return Ok(true);
    }
    if state.phase == Phase::AcceptReady {
        match session.queue_accept(id) {
            Ok(_) => {
                *dirty = true;
                state.phase = Phase::Established;
                wake(&mut state.opener);
            }
            Err(error) if would_block(&error) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    if state.consumed != 0 {
        let increment = u32::try_from(state.consumed).map_err(|_| InnerError::WindowOverflow)?;
        match session.queue_window_update(id, increment) {
            Ok(()) => {
                state.consumed = 0;
                *dirty = true;
            }
            Err(InnerError::StreamReset) => state.consumed = 0,
            Err(error) if would_block(&error) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    if let Some(chunk) = &mut state.outbound {
        let accepted = session.try_send_data(id, &chunk.bytes[chunk.offset..])?;
        chunk.offset += accepted;
        *dirty |= accepted != 0;
        if chunk.offset == chunk.bytes.len() {
            state.submitted = chunk.sequence;
            state.outbound = None;
            wake(&mut state.writer);
        }
    }
    if state.send_phase == SendPhase::FinRequested && state.outbound.is_none() {
        match session.queue_finish(id) {
            Ok(()) => {
                state.send_phase = SendPhase::FinQueued;
                *dirty = true;
            }
            Err(error) if would_block(&error) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    // Inner state may live past both FINs until the final consumption updates
    // arrive. Keep dispatching those, and free the mailbox only after reclamation.
    if state.send_phase == SendPhase::FinFlushed
        && state.peer_finished
        && state.inbound.is_empty()
        && state.consumed == 0
        && matches!(session.send_credit(id), Err(InnerError::StreamReset))
    {
        state.inbound = VecDeque::new();
        return Ok(true);
    }
    Ok(false)
}

fn would_block(error: &InnerError) -> bool {
    matches!(error, InnerError::Io(error) if error.kind() == io::ErrorKind::WouldBlock)
}

fn poll_session<IO>(
    session: &mut MuxSession<IO>,
    need_flush: bool,
    cx: &mut Context<'_>,
) -> Poll<Result<Progress, InnerError>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let flushed = if need_flush {
        match pin!(session.flush_pending()).poll(cx) {
            Poll::Ready(result) => {
                result?;
                true
            }
            Poll::Pending => false,
        }
    } else {
        false
    };
    // Always poll input, even when output is blocked or a flush just completed.
    // Both futures retain partial offsets inside MuxSession when dropped here.
    match pin!(session.receive_next()).poll(cx) {
        Poll::Ready(event) => Poll::Ready(Ok(Progress {
            flushed,
            event: Some(event?),
        })),
        Poll::Pending if flushed => Poll::Ready(Ok(Progress {
            flushed,
            event: None,
        })),
        Poll::Pending => Poll::Pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::Ipv4Addr, sync::atomic::AtomicUsize, time::Duration};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::time::timeout;
    use umbra_inner::{mux::MuxSettings, padding::PadScheme};

    const DEADLINE: Duration = Duration::from_secs(5);

    fn target(port: u16) -> TargetAddr {
        TargetAddr::Ipv4(Ipv4Addr::LOCALHOST, port)
    }

    fn session<IO: AsyncRead + AsyncWrite + Unpin>(
        io: IO,
        role: MuxRole,
        window: usize,
    ) -> MuxSession<IO> {
        MuxSession::with_settings(
            io,
            role,
            &PadScheme::none(),
            MuxSettings {
                initial_window: window,
                ..MuxSettings::default()
            },
        )
        .unwrap()
    }

    fn pair(window: usize, capacity: usize) -> (MuxDriver, ClientMux, MuxDriver, ServerMux) {
        let (left, right) = duplex(capacity);
        let (client_owner, client) = start_client(session(left, MuxRole::Client, window)).unwrap();
        let (server_owner, server) = start_server(session(right, MuxRole::Server, window)).unwrap();
        (client_owner, client, server_owner, server)
    }

    async fn connect(client: &ClientMux, server: &mut ServerMux, port: u16) -> (MuxIo, MuxIo) {
        timeout(DEADLINE, async {
            let (client, server) = tokio::join!(client.open(target(port)), async {
                let pending = server.accept().await.unwrap();
                assert_eq!(pending.target, target(port));
                assert_ne!(pending.stream_id(), 0);
                pending.accept().await
            });
            let client = client.unwrap();
            let server = server.unwrap();
            assert_eq!(client.stream_id(), server.stream_id());
            (client, server)
        })
        .await
        .unwrap()
    }

    async fn until(mut condition: impl FnMut() -> bool) {
        timeout(DEADLINE, async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn assert_pending<F: Future>(mut future: Pin<&mut F>) {
        poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn two_streams_interleave_on_one_outer() {
        timeout(DEADLINE, async {
            let (_co, client, _so, mut server) = pair(16, 7);
            let (mut c1, mut s1) = connect(&client, &mut server, 1).await;
            let (mut c2, mut s2) = connect(&client.clone(), &mut server, 2).await;
            assert_ne!(c1.stream_id(), c2.stream_id());
            let send1 = async {
                for _ in 0..30 {
                    c1.write_all(b"abcdef").await.unwrap();
                }
                c1.shutdown().await.unwrap();
                let mut reply = Vec::new();
                c1.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"first");
            };
            let send2 = async {
                for _ in 0..30 {
                    c2.write_all(b"123456").await.unwrap();
                }
                c2.shutdown().await.unwrap();
                let mut reply = Vec::new();
                c2.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"second");
            };
            let recv1 = async {
                let mut bytes = Vec::new();
                s1.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"abcdef".repeat(30));
                s1.write_all(b"first").await.unwrap();
                s1.shutdown().await.unwrap();
            };
            let recv2 = async {
                let mut bytes = Vec::new();
                s2.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"123456".repeat(30));
                s2.write_all(b"second").await.unwrap();
                s2.shutdown().await.unwrap();
            };
            tokio::join!(send1, send2, recv1, recv2);
            assert!(client.is_healthy());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn consumption_credit_and_zero_window_do_not_starve_sibling() {
        timeout(DEADLINE, async {
            let (_co, client, _so, mut server) = pair(4, 64);
            let (mut slow, mut sink) = connect(&client, &mut server, 1).await;
            let (mut fast, mut peer) = connect(&client, &mut server, 2).await;
            slow.write_all(b"abcdefgh").await.unwrap();
            until(|| sink.shared.lock().inbound.len() == 4).await;
            assert_eq!(sink.shared.lock().consumed, 0);
            assert_pending(pin!(slow.flush())).await;
            assert_eq!(slow.shared.lock().outbound.as_ref().unwrap().offset, 4);
            fast.write_all(b"live").await.unwrap();
            fast.flush().await.unwrap();
            let mut bytes = [0; 4];
            peer.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"live");
            let mut first = [0; 2];
            sink.read_exact(&mut first).await.unwrap();
            assert_eq!(&first, b"ab");
            until(|| {
                slow.shared
                    .lock()
                    .outbound
                    .as_ref()
                    .is_some_and(|c| c.offset == 6)
            })
            .await;
            assert_eq!(sink.shared.lock().inbound.len(), 4);
            let mut rest = [0; 6];
            sink.read_exact(&mut rest).await.unwrap();
            slow.flush().await.unwrap();
            assert_eq!(&rest, b"cdefgh");
            assert!(client.is_healthy());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn half_close_keeps_delayed_response_and_reclaims_streams() {
        timeout(DEADLINE, async {
            let (_co, client, _so, mut server) = pair(8, 32);
            for port in 1..=140 {
                let (mut request, mut response) = connect(&client, &mut server, port).await;
                let request_weak = Arc::downgrade(&request.shared);
                let response_weak = Arc::downgrade(&response.shared);
                request.write_all(b"req").await.unwrap();
                request.shutdown().await.unwrap();
                assert!(request.write(b"after FIN").await.is_err());
                let mut received = Vec::new();
                response.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, b"req");
                tokio::task::yield_now().await;
                let ((), ()) = tokio::join!(
                    async {
                        response.write_all(b"delayed response").await.unwrap();
                        response.shutdown().await.unwrap();
                    },
                    async {
                        let mut reply = Vec::new();
                        request.read_to_end(&mut reply).await.unwrap();
                        assert_eq!(reply, b"delayed response");
                    }
                );
                drop(request);
                drop(response);
                until(|| request_weak.upgrade().is_none() && response_weak.upgrade().is_none())
                    .await;
            }
            assert!(client.is_healthy());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn target_rejection_and_slow_connect_are_isolated() {
        timeout(DEADLINE, async {
            let (_co, client, _so, mut server) = pair(8, 64);
            let mut slow_open = Box::pin(client.open(target(1)));
            assert_pending(slow_open.as_mut()).await;
            let pending = server.accept().await.unwrap();
            assert_pending(slow_open.as_mut()).await; // No premature SYN_ACK.
            let (mut fast, mut peer) = connect(&client, &mut server, 2).await;
            fast.write_all(b"ok").await.unwrap();
            let mut bytes = [0; 2];
            peer.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ok");
            pending.reject();
            assert_eq!(
                slow_open.await.err().unwrap().kind(),
                io::ErrorKind::ConnectionReset
            );
            peer.write_all(b"yes").await.unwrap();
            let mut reply = [0; 3];
            fast.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"yes");
            assert!(client.is_healthy());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelled_open_resets_without_replaying_syn() {
        timeout(DEADLINE, async {
            let (_co, client, _so, mut server) = pair(8, 3);
            let mut opening = Box::pin(client.open(target(1)));
            assert_pending(opening.as_mut()).await;
            let pending = server.accept().await.unwrap();
            let cancelled_id = pending.stream_id();
            drop(opening);
            until(|| pending.stream.shared.lock().error.is_some()).await;
            assert!(pending.accept().await.is_err());
            let (stream, peer) = connect(&client, &mut server, 2).await;
            assert!(stream.stream_id() > cancelled_id);
            assert_eq!(peer.stream_id(), stream.stream_id());
            assert!(client.is_healthy());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelled_credit_wait_and_shutdown_retain_exact_bytes_and_fin() {
        timeout(DEADLINE, async {
            let (_co, client, _so, mut server) = pair(4, 1);
            let (mut stream, mut peer) = connect(&client, &mut server, 1).await;
            stream.write_all(b"abcdefgh").await.unwrap();
            until(|| peer.shared.lock().inbound.len() == 4).await;
            assert_pending(pin!(stream.flush())).await;
            // Cancel a pending write: it must not enqueue its input at all.
            assert_pending(pin!(stream.write(b"NOT ACCEPTED"))).await;
            // Cancel shutdown while the driver still owns a partial DATA suffix.
            assert_pending(pin!(stream.shutdown())).await;
            let mut received = Vec::new();
            peer.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"abcdefgh");
            stream.shutdown().await.unwrap();
            peer.shutdown().await.unwrap();
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
            assert!(client.is_healthy());
        })
        .await
        .unwrap();
    }

    #[derive(Default)]
    struct Gate {
        allowance: AtomicUsize,
        written: AtomicUsize,
        blocked: AtomicBool,
        waker: Mutex<Option<Waker>>,
    }

    impl Gate {
        fn allow(&self, amount: usize) {
            self.allowance.store(amount, Ordering::SeqCst);
            if let Some(waker) = self.waker.lock().unwrap().take() {
                waker.wake();
            }
        }

        fn block(&self) {
            self.written.store(0, Ordering::SeqCst);
            self.blocked.store(false, Ordering::SeqCst);
            self.allow(0);
        }
    }

    struct GatedIo {
        io: DuplexStream,
        gate: Arc<Gate>,
    }

    impl AsyncRead for GatedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for GatedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let amount = self.gate.allowance.load(Ordering::SeqCst).min(bytes.len());
            if amount == 0 {
                self.gate.blocked.store(true, Ordering::SeqCst);
                *self.gate.waker.lock().unwrap() = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let result = Pin::new(&mut self.io).poll_write(cx, &bytes[..amount]);
            if let Poll::Ready(Ok(written)) = result {
                self.gate.allowance.fetch_sub(written, Ordering::SeqCst);
                self.gate.written.fetch_add(written, Ordering::SeqCst);
            }
            result
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn cancellation_during_partial_outer_data_and_fin_is_exact_once() {
        timeout(DEADLINE, async {
            let (left, right) = duplex(64);
            let gate = Arc::new(Gate::default());
            gate.allow(usize::MAX);
            let (_co, client) = start_client(session(
                GatedIo {
                    io: left,
                    gate: gate.clone(),
                },
                MuxRole::Client,
                64,
            ))
            .unwrap();
            let (_so, mut server) = start_server(session(right, MuxRole::Server, 64)).unwrap();
            let (mut stream, mut peer) = connect(&client, &mut server, 1).await;
            let (mut sibling, mut sibling_peer) = connect(&client, &mut server, 2).await;
            gate.block();
            stream.write_all(b"exactly once").await.unwrap();
            until(|| gate.blocked.load(Ordering::SeqCst)).await;
            gate.allow(5);
            until(|| gate.written.load(Ordering::SeqCst) == 5).await;
            assert_pending(pin!(stream.flush())).await;
            // Even when outer writing is blocked, incoming sibling DATA is read.
            sibling_peer.write_all(b"inbound").await.unwrap();
            let mut incoming = [0; 7];
            sibling.read_exact(&mut incoming).await.unwrap();
            assert_eq!(&incoming, b"inbound");
            gate.allow(usize::MAX);
            stream.flush().await.unwrap();
            let mut received = [0; 12];
            peer.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"exactly once");
            // Settle read acknowledgements before gating exactly the FIN header.
            until(|| peer.shared.lock().consumed == 0).await;
            gate.block();
            assert_pending(pin!(stream.shutdown())).await;
            until(|| gate.blocked.load(Ordering::SeqCst)).await;
            gate.allow(3);
            until(|| gate.written.load(Ordering::SeqCst) == 3).await;
            assert_pending(pin!(stream.shutdown())).await;
            gate.allow(usize::MAX);
            stream.shutdown().await.unwrap();
            assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
            assert!(client.is_healthy());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn outer_error_wakes_open_read_write_flush_and_shutdown() {
        timeout(DEADLINE, async {
            let (_co, client, so, mut server) = pair(0, 64);
            let (stream, _peer) = connect(&client, &mut server, 1).await;
            let (mut reader, mut writer) = tokio::io::split(stream);
            writer.write_all(b"queued with zero credit").await.unwrap();
            assert_pending(pin!(writer.write(b"blocked"))).await;
            assert_pending(pin!(writer.flush())).await;
            assert_pending(pin!(writer.shutdown())).await;
            assert_pending(pin!(reader.read(&mut [0; 1]))).await;
            let mut opening = Box::pin(client.open(target(2)));
            assert_pending(opening.as_mut()).await;
            let _pending = server.accept().await.unwrap();
            so.shutdown().await;
            assert!(opening.await.is_err());
            assert!(reader.read(&mut [0; 1]).await.is_err());
            assert!(writer.write(b"never replay").await.is_err());
            assert!(writer.flush().await.is_err());
            assert!(writer.shutdown().await.is_err());
            assert!(!client.is_healthy());
            assert!(client.open(target(3)).await.is_err());
            assert!(!server.is_healthy());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn owner_drop_before_first_poll_closes_queued_opens() {
        let (co, client, so, mut server) = pair(8, 64);
        let mut opening = Box::pin(client.open(target(1)));
        assert_pending(opening.as_mut()).await;
        drop(co);
        assert!(!client.is_healthy());
        assert!(timeout(DEADLINE, opening).await.unwrap().is_err());
        assert!(timeout(DEADLINE, server.accept()).await.unwrap().is_err());
        so.shutdown().await;
    }

    #[tokio::test]
    async fn open_mailbox_is_bounded_and_owner_drop_wakes_capacity_waiters() {
        let (co, client, so, _server) = pair(8, 64);
        let mut opens = Vec::new();
        for _ in 0..MAX_STREAMS + 2 {
            let mut open = Box::pin(client.open(target(1)));
            assert_pending(open.as_mut()).await;
            opens.push(open);
        }
        // No runtime yield above: two requests are waiting for channel capacity.
        assert_eq!(client.opens.capacity(), 0);
        drop(co);
        for open in opens {
            assert!(timeout(DEADLINE, open).await.unwrap().is_err());
        }
        assert!(!client.is_healthy());
        so.shutdown().await;
    }

    #[tokio::test]
    async fn invalid_target_and_cancelled_backlog_do_not_block_future_opens() {
        timeout(DEADLINE, async {
            let (_co, client, _so, mut server) = pair(8, 64);
            let invalid = TargetAddr::Domain(String::new(), 1);
            assert_eq!(
                client.open(invalid).await.err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
            let mut opening = Box::pin(client.open(target(1)));
            assert_pending(opening.as_mut()).await;
            until(|| server.incoming.len() == 1).await;
            drop(opening);
            // Wait until the RST has reached the server-side backlog entry.
            let pending = server.incoming.recv().await.unwrap();
            until(|| pending.stream.shared.lock().error.is_some()).await;
            // Put a reset entry ahead of a live entry to exercise accept's filter.
            let (sender, receiver) = mpsc::channel(2);
            sender.send(pending).await.ok().unwrap();
            let mut filtered = ServerMux {
                incoming: receiver,
                healthy: server.healthy.clone(),
            };
            let mut next = Box::pin(client.open(target(2)));
            assert_pending(next.as_mut()).await;
            sender
                .send(server.accept().await.unwrap())
                .await
                .ok()
                .unwrap();
            let accepted = filtered.accept().await.unwrap();
            assert_eq!(accepted.target, target(2));
            let (local, remote) = tokio::join!(next, accepted.accept());
            assert!(local.is_ok());
            assert!(remote.is_ok());
            assert!(client.is_healthy());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn dropped_acceptor_rejects_new_targets_without_killing_outer() {
        let (_co, client, so, server) = pair(8, 64);
        drop(server);
        let result = timeout(DEADLINE, client.open(target(1))).await.unwrap();
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::ConnectionReset);
        assert!(client.is_healthy());
        so.shutdown().await;
    }

    #[tokio::test]
    async fn stream_zero_udp_is_rejected_on_shared_connect_outer() {
        let (left, right) = duplex(64);
        let mut raw = session(left, MuxRole::Client, 8);
        let (_so, mut server) = start_server(session(right, MuxRole::Server, 8)).unwrap();
        raw.send_udp_datagram(&target(1), b"dedicated session only")
            .await
            .unwrap();
        assert!(timeout(DEADLINE, server.accept()).await.unwrap().is_err());
        assert!(!server.is_healthy());
    }

    #[tokio::test]
    async fn reset_wakes_zero_credit_writer_without_harming_sibling() {
        timeout(DEADLINE, async {
            let (_co, client, _so, mut server) = pair(0, 64);
            let (mut stream, peer) = connect(&client, &mut server, 1).await;
            stream.write_all(b"unsent").await.unwrap();
            assert_pending(pin!(stream.flush())).await;
            drop(peer);
            assert_eq!(
                stream.flush().await.unwrap_err().kind(),
                io::ErrorKind::ConnectionReset
            );
            let (sibling, _) = connect(&client, &mut server, 2).await;
            assert_ne!(stream.stream_id(), sibling.stream_id());
            assert!(client.is_healthy());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn simultaneous_stream_drops_do_not_kill_the_outer() {
        timeout(DEADLINE, async {
            let (left, right) = duplex(64);
            let client_gate = Arc::new(Gate::default());
            let server_gate = Arc::new(Gate::default());
            client_gate.allow(usize::MAX);
            server_gate.allow(usize::MAX);
            let (_co, client) = start_client(session(
                GatedIo {
                    io: left,
                    gate: client_gate.clone(),
                },
                MuxRole::Client,
                8,
            ))
            .unwrap();
            let (_so, mut server) = start_server(session(
                GatedIo {
                    io: right,
                    gate: server_gate.clone(),
                },
                MuxRole::Server,
                8,
            ))
            .unwrap();
            let (stream, peer) = connect(&client, &mut server, 1).await;
            client_gate.block();
            server_gate.block();
            drop(stream);
            drop(peer);
            until(|| {
                client_gate.blocked.load(Ordering::SeqCst)
                    && server_gate.blocked.load(Ordering::SeqCst)
            })
            .await;
            // Both RSTs are now session-owned, with their frames still in flight.
            client_gate.allow(usize::MAX);
            server_gate.allow(usize::MAX);
            let (mut sibling, mut receiver) = connect(&client, &mut server, 2).await;
            sibling.write_all(b"alive").await.unwrap();
            let mut bytes = [0; 5];
            receiver.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"alive");
            assert!(client.is_healthy());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rejects_wrong_roles_and_nonfresh_sessions() {
        let (left, _right) = duplex(64);
        assert!(start_server(session(left, MuxRole::Client, 8)).is_err());
        let (left, _right) = duplex(64);
        assert!(start_client(session(left, MuxRole::Server, 8)).is_err());
        let (left, _right) = duplex(64);
        let mut used = session(left, MuxRole::Client, 8);
        used.begin_open(&target(1)).unwrap();
        assert!(start_client(used).is_err());
    }

    #[test]
    fn io_traits_and_bounded_write_mailbox() {
        fn assert_traits<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>() {}
        assert_traits::<MuxIo>();
        let mut stream = MuxIo::new(1, Phase::Established, Arc::new(Notify::new()));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, &[]),
            Poll::Ready(Ok(0))
        ));
        let bytes = vec![1; MAX_DATA_CHUNK_LEN * 2];
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, &bytes),
            Poll::Ready(Ok(MAX_DATA_CHUNK_LEN))
        ));
        assert!(Pin::new(&mut stream)
            .poll_write(&mut cx, b"full")
            .is_pending());
        assert_eq!(
            stream.shared.lock().outbound.as_ref().unwrap().bytes.len(),
            MAX_DATA_CHUNK_LEN
        );
        let mut empty = [];
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut ReadBuf::new(&mut empty)),
            Poll::Ready(Ok(()))
        ));
        let shared = stream.shared.clone();
        drop(stream);
        assert!(shared.lock().reset_requested);
    }
}
