//! Authenticated inner mux sessions with bounded, cancellation-safe framing.
//!
//! A multi-stream driver should use [`MuxSession::begin_open`],
//! [`MuxSession::try_send_data`] and the `queue_*` methods, and keep polling
//! [`MuxSession::receive_next`]. Receiving also advances the serialized writer;
//! [`MuxSession::flush_pending`] is useful when no event is expected. Both I/O
//! operations may be cancelled and resumed. Queue operations never perform I/O:
//! success transfers ownership to the session, and must not be replayed.
//!
//! DATA credit is returned only by acknowledging application consumption, not by
//! decoding or dequeuing an event. Drivers must bound their own event queues and
//! must continue receiving control frames after a peer FIN. FIN closes only the
//! peer's sending direction; the local direction can still send a delayed reply.

use std::{
    collections::{HashMap, VecDeque},
    future::poll_fn,
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use umbra_proto::{
    addr::TargetAddr,
    consts::MUX_VERSION,
    frame::{MuxCommand, MuxFrame, MAX_FRAME_PAYLOAD_LEN},
    udp::UdpEnvelope,
    ProtocolError,
};

use crate::{
    padding::{is_padding, PadScheme, PaddingPlanner},
    InnerError,
};

/// Maximum DATA payload emitted or accepted in one mux frame.
pub const MAX_DATA_CHUNK_LEN: usize = 16_384;
/// Default per-stream flow-control window.
pub const DEFAULT_INITIAL_WINDOW: usize = 256 * 1024;
/// Maximum live streams, including streams awaiting acceptance or consumption.
pub const MAX_STREAMS: usize = 128;
/// Aggregate reserved receive credit across live streams (eight MiB).
pub const MAX_RECEIVE_BUFFER_BYTES: usize = 8 * 1024 * 1024;
/// Maximum events retained by the convenience open/accept/credit wait methods.
pub const MAX_PENDING_EVENTS: usize = 1024;
/// Maximum payload bytes retained by the convenience wait methods.
pub const MAX_PENDING_EVENT_BYTES: usize = MAX_RECEIVE_BUFFER_BYTES;
/// Maximum encoded bytes owned by the serialized writer.
pub const MAX_PENDING_WRITE_BYTES: usize = 1024 * 1024;
/// Maximum encoded frames owned by the serialized writer, including padding.
pub const MAX_PENDING_WRITE_FRAMES: usize = 256;

/// Mux role.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MuxRole {
    /// Client-side mux role opens streams with SYN.
    Client,
    /// Server-side mux role accepts SYN and replies with SYN_ACK.
    Server,
}

/// Mux session settings. Both peers must use the same initial window.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MuxSettings {
    /// Initial credit in each direction, reserved before admitting a stream.
    /// Must not exceed [`MAX_RECEIVE_BUFFER_BYTES`]. Zero disables DATA; it
    /// cannot be bootstrapped by an unsolicited consumption acknowledgement.
    pub initial_window: usize,
    /// Maximum frame payload accepted from the peer (at most the wire limit).
    pub max_payload_len: usize,
}

impl Default for MuxSettings {
    fn default() -> Self {
        Self {
            initial_window: DEFAULT_INITIAL_WINDOW,
            max_payload_len: MAX_FRAME_PAYLOAD_LEN,
        }
    }
}

/// Logical stream snapshot. The session, not a cloned handle, owns the credit.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MuxStream {
    /// Logical stream identifier.
    pub stream_id: u32,
    send_window: usize,
    reset: bool,
    send_closed: bool,
    receive_closed: bool,
}

impl MuxStream {
    /// Return the send window at the time this snapshot was refreshed.
    /// Use [`MuxSession::send_credit`] for authoritative, current credit.
    #[must_use]
    pub const fn send_window(&self) -> usize {
        self.send_window
    }

    /// Return true when this handle has observed a reset.
    #[must_use]
    pub const fn is_reset(&self) -> bool {
        self.reset
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StreamPhase {
    Opening,
    Accepting,
    Established,
}

struct StreamState {
    stream: MuxStream,
    phase: StreamPhase,
    receive_window: usize,
    delivered_unacked: usize,
}

impl StreamState {
    fn new(stream_id: u32, window: usize, phase: StreamPhase) -> Self {
        Self {
            stream: MuxStream {
                stream_id,
                send_window: window,
                reset: false,
                send_closed: false,
                receive_closed: false,
            },
            phase,
            receive_window: window,
            delivered_unacked: 0,
        }
    }
}

/// Event returned by [`MuxSession::receive_next`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MuxEvent {
    /// Peer opened a stream. Connect the target before acknowledging this event.
    Syn {
        /// Stream id.
        stream_id: u32,
        /// Target address.
        target: TargetAddr,
    },
    /// Peer acknowledged stream creation.
    SynAck {
        /// Stream id.
        stream_id: u32,
    },
    /// Peer sent data. Acknowledge only bytes actually consumed by the application.
    Data {
        /// Stream id.
        stream_id: u32,
        /// Data bytes.
        payload: Vec<u8>,
    },
    /// Peer increased a stream window. Credit has already been applied exactly once.
    WindowUpdate {
        /// Stream id.
        stream_id: u32,
        /// Window increment.
        increment: u32,
    },
    /// Peer finished its sending direction, not the entire stream or session.
    Fin {
        /// Stream id.
        stream_id: u32,
    },
    /// Peer reset a stream. Its state has been reclaimed; queued events stay ordered.
    Rst {
        /// Stream id.
        stream_id: u32,
    },
    /// Peer sent a ping.
    Ping {
        /// Stream id.
        stream_id: u32,
        /// Ping payload.
        payload: Vec<u8>,
    },
    /// Peer sent a UDP datagram envelope.
    UdpDatagram {
        /// UDP target or reply source address.
        target: TargetAddr,
        /// UDP payload bytes.
        payload: Vec<u8>,
    },
}

impl MuxEvent {
    fn buffered_len(&self) -> usize {
        match self {
            Self::Data { payload, .. } | Self::Ping { payload, .. } => payload.len(),
            // A target address occupies at most 259 wire bytes.
            Self::UdpDatagram { payload, .. } => payload.len() + 259,
            Self::Syn { .. } => 259,
            _ => 0,
        }
    }
}

/// Mux session over an authenticated TLS I/O object.
///
/// Malformed frames, unissued/invalid stream controls and over-credit live frames
/// are terminal protocol errors; they never allocate stream entries. Valid trailing
/// stream-local frames for retired IDs are ignored, but SYN can never reuse an ID.
/// Exhausting a convenience wait's event buffer also closes the session rather than
/// silently dropping events. Use the nonblocking APIs to dispatch continuously.
/// Local queue/stream-capacity exhaustion is `Io(WouldBlock)` and
/// leaves the requested operation unaccepted. Terminal I/O errors drop the outer
/// transport; business data must not be automatically replayed on a new session.
pub struct MuxSession<IO> {
    io: Option<IO>,
    role: MuxRole,
    settings: MuxSettings,
    adaptive: Option<crate::flow::AdaptiveFlow>,
    adaptive_control: Option<MuxFrame>,
    memory_leases: Vec<crate::budget::BudgetLease>,
    next_stream_id: u32,
    last_peer_stream_id: u32,
    streams: HashMap<u32, StreamState>,
    padding: PaddingPlanner,
    reader: FrameReader,
    writer: FrameWriter,
    events: VecDeque<MuxEvent>,
    event_bytes: usize,
}

impl<IO> MuxSession<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Construct a client mux session with default settings.
    pub fn client(io: IO, pad: &PadScheme) -> Result<Self, InnerError> {
        Self::with_settings(io, MuxRole::Client, pad, MuxSettings::default())
    }

    /// Construct a server mux session with default settings.
    pub fn server(io: IO, pad: &PadScheme) -> Result<Self, InnerError> {
        Self::with_settings(io, MuxRole::Server, pad, MuxSettings::default())
    }

    /// Construct a mux session with explicit, bounded settings.
    pub fn with_settings(
        io: IO,
        role: MuxRole,
        pad: &PadScheme,
        settings: MuxSettings,
    ) -> Result<Self, InnerError> {
        if settings.initial_window > MAX_RECEIVE_BUFFER_BYTES
            || settings.max_payload_len > MAX_FRAME_PAYLOAD_LEN
        {
            return Err(InnerError::WindowOverflow);
        }
        Ok(Self {
            io: Some(io),
            role,
            settings,
            adaptive: None,
            adaptive_control: None,
            memory_leases: Vec::new(),
            next_stream_id: 1,
            last_peer_stream_id: 0,
            streams: HashMap::new(),
            padding: PaddingPlanner::new(pad.clone())?,
            reader: FrameReader::new(),
            writer: FrameWriter::default(),
            events: VecDeque::new(),
            event_bytes: 0,
        })
    }

    /// Construct an adaptive session using receiver-owned shared commitments.
    /// Both endpoints must support adaptive settings; legacy constructors stay fixed.
    pub fn adaptive(
        io: IO,
        role: MuxRole,
        pad: &PadScheme,
        limits: umbra_proto::flow::FlowSettings,
        lease: crate::budget::BudgetLease,
    ) -> Result<Self, InnerError> {
        let mut session = Self::with_settings(io, role, pad, MuxSettings::default())?;
        let mut flow = crate::flow::AdaptiveFlow::new(limits, lease)?;
        let settings = flow
            .next_control()?
            .ok_or_else(|| invalid("adaptive settings missing"))?;
        let covers = session.padding.clone().schedule(settings.clone())?;
        let mut batch = settings.encode()?;
        let mut extra = 0;
        for frame in covers
            .iter()
            .filter(|frame| frame.command == MuxCommand::Padding)
        {
            batch.extend_from_slice(&frame.encode()?);
            extra += 1;
        }
        session.writer.bytes = batch.len();
        session.writer.setup_extra_frames = extra;
        session.writer.frames.push_back(batch);
        session.adaptive = Some(flow);
        Ok(session)
    }

    /// Adaptive window and transfer counters, absent for a legacy connection.
    #[must_use]
    pub fn flow_snapshot(&self) -> Option<crate::flow::FlowSnapshot> {
        self.adaptive
            .as_ref()
            .map(crate::flow::AdaptiveFlow::snapshot)
    }

    /// Bytes held by serialized output, including the current partially written frame.
    pub fn pending_output_bytes(&self) -> usize {
        self.writer.bytes
    }

    /// Funded aggregate receive capacity for the connection's event driver.
    #[must_use]
    pub fn receive_capacity(&self) -> usize {
        self.flow_snapshot()
            .map_or(MAX_RECEIVE_BUFFER_BYTES, |flow| {
                flow.receive_window as usize
            })
    }

    /// Keep separate transport storage alive with retained logical-stream data.
    pub fn retain_lease(&mut self, lease: crate::budget::BudgetLease) {
        self.memory_leases.push(lease);
    }

    /// Clone reservation ownership without duplicating its accounted commitment.
    #[must_use]
    pub fn memory_leases(&self) -> Vec<crate::budget::BudgetLease> {
        let mut leases = self.memory_leases.clone();
        if let Some(flow) = &self.adaptive {
            leases.push(flow.lease());
        }
        leases
    }

    /// Return this session role.
    #[must_use]
    pub const fn role(&self) -> MuxRole {
        self.role
    }

    /// Return the number of streams still reserving receive capacity.
    #[must_use]
    pub fn active_stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Maximum streams allowed by both the stream count and reserved receive budget.
    #[must_use]
    pub fn stream_capacity(&self) -> usize {
        if self.adaptive.is_some() {
            return MAX_STREAMS;
        }
        MAX_RECEIVE_BUFFER_BYTES
            .checked_div(self.settings.initial_window)
            .map_or(MAX_STREAMS, |limit| MAX_STREAMS.min(limit))
    }

    /// Queue SYN without waiting for I/O or SYN_ACK (client only).
    ///
    /// The returned id belongs to the session immediately. Wait for its SynAck
    /// event before considering the connection successful. On cancellation of
    /// subsequent I/O, keep this id; do not repeat this operation.
    pub fn begin_open(&mut self, dst: &TargetAddr) -> Result<MuxStream, InnerError> {
        self.ensure_alive()?;
        if self.role != MuxRole::Client {
            return Err(invalid("only clients can open mux streams"));
        }
        self.check_stream_capacity()?;
        let stream_id = self.next_stream_id;
        let next_id = stream_id.checked_add(2).ok_or(InnerError::WindowOverflow)?;
        let state = StreamState::new(
            stream_id,
            self.settings.initial_window,
            StreamPhase::Opening,
        );
        self.queue_frame(
            MuxFrame::new(MuxCommand::Syn, stream_id, dst.encode()?)?,
            true,
        )?;
        let stream = state.stream.clone();
        self.streams.insert(stream_id, state);
        if let Some(flow) = &mut self.adaptive {
            flow.register(stream_id);
        }
        self.next_stream_id = next_id;
        Ok(stream)
    }

    /// Open a logical stream and wait for SYN_ACK, retaining unrelated events.
    ///
    /// This convenience wait cannot dispatch other streams. Shared drivers should
    /// use [`Self::begin_open`] and [`Self::receive_next`]. Cancelling this method
    /// does not undo a queued SYN; do not retry it as the same logical request.
    pub async fn open(&mut self, dst: &TargetAddr) -> Result<MuxStream, InnerError> {
        let stream = self.begin_open(dst)?;
        loop {
            let event = self.receive_wire_event().await?;
            if event
                == (MuxEvent::SynAck {
                    stream_id: stream.stream_id,
                })
            {
                return self.snapshot(stream.stream_id);
            }
            self.queue_event(event)?;
            if !self.streams.contains_key(&stream.stream_id) {
                return Err(InnerError::StreamReset);
            }
        }
    }

    /// Accept the next SYN, retaining any unrelated queued or newly read events.
    pub async fn accept(&mut self) -> Result<(MuxStream, TargetAddr), InnerError> {
        loop {
            let queued_syn = self
                .events
                .iter()
                .position(|event| matches!(event, MuxEvent::Syn { .. }));
            let event = if let Some(index) = queued_syn {
                let event = self.events.remove(index).ok_or(InnerError::StreamClosed)?;
                self.event_bytes -= event.buffered_len();
                event
            } else {
                self.receive_wire_event().await?
            };
            if let MuxEvent::Syn { stream_id, target } = event {
                return self.accept_syn(stream_id, target).await;
            }
            self.queue_event(event)?;
        }
    }

    /// Queue SYN_ACK for a previously delivered SYN after the target connects.
    /// Returns the accepted stream without performing I/O; a SYN cannot be
    /// acknowledged twice. A refused target should instead use [`Self::queue_reset`].
    pub fn queue_accept(&mut self, stream_id: u32) -> Result<MuxStream, InnerError> {
        let state = self.state(stream_id)?;
        if state.phase != StreamPhase::Accepting {
            return Err(invalid("stream is not awaiting acceptance"));
        }
        self.queue_control(MuxCommand::SynAck, stream_id, Vec::new())?;
        let state = self.state_mut(stream_id)?;
        state.phase = StreamPhase::Established;
        Ok(state.stream.clone())
    }

    /// Accept an already delivered SYN and flush its acknowledgement.
    /// Cancelling the flush does not undo acceptance; resume with `flush_pending`.
    pub async fn accept_syn(
        &mut self,
        stream_id: u32,
        target: TargetAddr,
    ) -> Result<(MuxStream, TargetAddr), InnerError> {
        let stream = self.queue_accept(stream_id)?;
        self.flush_pending().await?;
        Ok((stream, target))
    }

    /// Return current send credit, or zero while SYN_ACK is pending.
    /// Local FIN returns `StreamClosed`; a reset/reclaimed id returns `StreamReset`.
    /// Peer FIN does not prevent sending. This method never performs I/O.
    pub fn send_credit(&self, stream_id: u32) -> Result<usize, InnerError> {
        let state = self.state(stream_id)?;
        if state.stream.send_closed {
            return Err(InnerError::StreamClosed);
        }
        Ok(if state.phase == StreamPhase::Established {
            self.adaptive
                .as_ref()
                .map_or(state.stream.send_window, |flow| flow.send_credit(stream_id))
        } else {
            0
        })
    }

    /// Queue at most one DATA chunk and return the number of accepted bytes.
    ///
    /// Zero means empty input, pending SYN_ACK, exhausted stream credit, or a full
    /// writer queue. Retain the unsent suffix and keep driving `receive_next` or
    /// `flush_pending`. Accepted bytes debit session credit immediately and must
    /// never be retried, even if a later I/O future is cancelled.
    pub fn try_send_data(&mut self, stream_id: u32, data: &[u8]) -> Result<usize, InnerError> {
        let allowed = self
            .send_credit(stream_id)?
            .min(MAX_DATA_CHUNK_LEN)
            .min(data.len());
        if allowed == 0 {
            return Ok(0);
        }
        let frame = MuxFrame::new(MuxCommand::Data, stream_id, Vec::new())?;
        match self.queue_frame_payload(frame, true, Some(&data[..allowed])) {
            Err(InnerError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(0)
            }
            result => result?,
        }
        if let Some(flow) = &mut self.adaptive {
            flow.sent(stream_id, allowed)?;
        } else {
            self.state_mut(stream_id)?.stream.send_window -= allowed;
        }
        Ok(allowed)
    }

    /// Send DATA, retaining unrelated events while waiting for stream credit.
    ///
    /// Handles are refreshed before every chunk, including after an external
    /// `receive_next`. This convenience method is not a replay-safe transaction:
    /// cancellation may leave an accepted prefix queued. Multi-stream drivers
    /// should track accepted bytes using [`Self::try_send_data`] instead.
    pub async fn send_data_wait_window(
        &mut self,
        stream: &mut MuxStream,
        data: &[u8],
    ) -> Result<(), InnerError> {
        let mut offset = 0;
        self.refresh_handle(stream)?;
        while offset < data.len() {
            let accepted = self.try_send_data(stream.stream_id, &data[offset..])?;
            self.refresh_handle(stream)?;
            offset += accepted;
            if accepted == 0 {
                self.flush_pending().await?;
                // A full writer queue may have been the only obstruction.
                if self.send_credit(stream.stream_id)? == 0 {
                    let event = self.receive_wire_event().await?;
                    self.queue_event(event)?;
                    self.refresh_handle(stream)?;
                }
            }
        }
        self.flush_pending().await
    }

    /// Queue acknowledgement of DATA actually consumed by the application.
    ///
    /// `increment` must be positive and no larger than bytes returned in DATA
    /// events but not previously acknowledged. Buffered events do not qualify.
    /// On `WouldBlock`, no credit is returned: flush and retry the acknowledgement.
    /// Success restores bounded receive credit immediately and owns the update.
    /// Acknowledge consumption even after FIN, so the peer can settle its credit
    /// and reclaim the stream. Both FINs and all DATA acknowledged in both
    /// directions reclaim state; an in-flight final update must not become an
    /// unknown-stream error. A reset/reclaimed id returns `StreamReset` (discard
    /// that stream's pending acknowledgements).
    pub fn queue_window_update(
        &mut self,
        stream_id: u32,
        increment: u32,
    ) -> Result<(), InnerError> {
        let amount = usize::try_from(increment).map_err(|_| InnerError::WindowOverflow)?;
        if self.adaptive.is_some() {
            if amount == 0 || amount > self.state(stream_id)?.delivered_unacked {
                return Err(InnerError::WindowOverflow);
            }
            if let Some(flow) = &mut self.adaptive {
                flow.consume(stream_id, amount)?;
            }
            self.state_mut(stream_id)?.delivered_unacked -= amount;
            self.reclaim_closed(stream_id);
            return Ok(());
        }
        let state = self.state(stream_id)?;
        let window = state
            .receive_window
            .checked_add(amount)
            .ok_or(InnerError::WindowOverflow)?;
        if amount == 0 || amount > state.delivered_unacked || window > self.settings.initial_window
        {
            return Err(InnerError::WindowOverflow);
        }
        self.queue_control(
            MuxCommand::WindowUpdate,
            stream_id,
            increment.to_be_bytes().to_vec(),
        )?;
        let state = self.state_mut(stream_id)?;
        state.delivered_unacked -= amount;
        state.receive_window = window;
        self.reclaim_closed(stream_id);
        Ok(())
    }

    /// Acknowledge application consumption and flush the owned WINDOW_UPDATE.
    /// Cancellation does not roll back acknowledgement; resume `flush_pending`,
    /// not this operation with the same byte count.
    pub async fn send_window_update(
        &mut self,
        stream_id: u32,
        increment: u32,
    ) -> Result<(), InnerError> {
        self.queue_window_update(stream_id, increment)?;
        self.flush_pending().await
    }

    /// Queue local FIN after all previously accepted DATA. Only the local sending
    /// direction closes; keep delivering peer DATA and receiving control frames.
    /// Repeated FIN is a no-op while the stream remains live.
    pub fn queue_finish(&mut self, stream_id: u32) -> Result<(), InnerError> {
        if self.state(stream_id)?.stream.send_closed {
            return Ok(());
        }
        if self.state(stream_id)?.phase != StreamPhase::Established {
            return Err(invalid("cannot finish an unestablished stream"));
        }
        self.queue_control(MuxCommand::Fin, stream_id, Vec::new())?;
        self.state_mut(stream_id)?.stream.send_closed = true;
        self.reclaim_closed(stream_id);
        Ok(())
    }

    /// Send local FIN without closing the peer's data direction.
    pub async fn finish_stream(&mut self, stream_id: u32) -> Result<(), InnerError> {
        self.queue_finish(stream_id)?;
        self.flush_pending().await
    }

    /// Queue RST and immediately reclaim stream state, without affecting others.
    /// Already accepted output stays serialized before RST. Pending input events
    /// remain ordered; no credit acknowledgement is needed after reset.
    pub fn queue_reset(&mut self, stream_id: u32) -> Result<(), InnerError> {
        self.state(stream_id)?;
        self.queue_control(MuxCommand::Rst, stream_id, Vec::new())?;
        self.streams.remove(&stream_id);
        if let Some(flow) = &mut self.adaptive {
            flow.retire(stream_id)?;
        }
        Ok(())
    }

    /// Send RST for a stream without closing unrelated streams.
    pub async fn reset_stream(&mut self, stream_id: u32) -> Result<(), InnerError> {
        self.queue_reset(stream_id)?;
        self.flush_pending().await
    }

    /// Send one UDP envelope on reserved stream zero. Stream-zero UDP associations
    /// should use a dedicated outer connection, not the shared CONNECT pool.
    pub async fn send_udp_datagram(
        &mut self,
        target: &TargetAddr,
        payload: &[u8],
    ) -> Result<(), InnerError> {
        let envelope = UdpEnvelope::new(target.clone(), payload.to_vec())?;
        self.queue_frame(
            MuxFrame::new(MuxCommand::UdpDatagram, 0, envelope.encode()?)?,
            true,
        )?;
        self.flush_pending().await
    }

    /// Receive the next event exactly once, draining retained events first.
    ///
    /// Cancellation retains every partial header/body and every partial write.
    /// This also advances queued writes even when no input is ready, and still
    /// reads when writing is blocked. Call again after peer FIN to service credit
    /// for the still-open local direction. A returned DATA event is eligible for
    /// consumption acknowledgement, but dequeueing it does not itself grant credit.
    pub async fn receive_next(&mut self) -> Result<MuxEvent, InnerError> {
        poll_fn(|cx| {
            if let Poll::Ready(Err(error)) = self.poll_flush(cx) {
                return Poll::Ready(Err(error));
            }
            let event = if let Some(event) = self.events.pop_front() {
                self.event_bytes -= event.buffered_len();
                event
            } else {
                ready!(self.poll_wire_event(cx))?
            };
            if let MuxEvent::Data { stream_id, payload } = &event {
                // A prior wait may have decoded RST after queuing this DATA.
                if let Some(state) = self.streams.get_mut(stream_id) {
                    state.delivered_unacked += payload.len();
                }
            }
            Poll::Ready(Ok(event))
        })
        .await
    }

    /// Flush all session-owned frames without reading events. Cancellation is safe:
    /// offsets and trailing padding remain owned by the session. Use `receive_next`
    /// instead when simultaneous incoming control traffic must remain serviceable.
    pub async fn flush_pending(&mut self) -> Result<(), InnerError> {
        poll_fn(|cx| self.poll_flush(cx)).await
    }

    fn queue_frame(&mut self, frame: MuxFrame, business: bool) -> Result<(), InnerError> {
        self.queue_frame_payload(frame, business, None)
    }

    fn queue_frame_payload(
        &mut self,
        frame: MuxFrame,
        business: bool,
        data: Option<&[u8]>,
    ) -> Result<(), InnerError> {
        self.ensure_alive()?;
        // Roll back the padding schedule too when queue admission fails.
        let mut padding = self.padding.clone();
        let frames = if business {
            padding.schedule(frame)?
        } else {
            vec![frame]
        };
        let encoded: Vec<Vec<u8>> = frames
            .iter()
            .map(|frame| match data {
                Some(data) if frame.command == MuxCommand::Data => {
                    MuxFrame::encode_payload(frame.command, frame.stream_id, data)
                }
                _ => frame.encode(),
            })
            .collect::<Result<_, _>>()?;
        let bytes: usize = encoded.iter().map(Vec::len).sum();
        let reserve = usize::from(business && self.adaptive.is_some());
        if self.writer.frames.len() + self.writer.setup_extra_frames + encoded.len()
            > MAX_PENDING_WRITE_FRAMES - 8 * reserve
            || self.writer.bytes + bytes > MAX_PENDING_WRITE_BYTES - 1024 * reserve
        {
            return Err(would_block());
        }
        self.writer.frames.extend(encoded);
        self.writer.bytes += bytes;
        self.padding = padding;
        Ok(())
    }

    fn queue_control(
        &mut self,
        command: MuxCommand,
        stream_id: u32,
        payload: Vec<u8>,
    ) -> Result<(), InnerError> {
        self.queue_frame(MuxFrame::new(command, stream_id, payload)?, false)
    }

    fn queue_adaptive_controls(&mut self) -> Result<(), InnerError> {
        loop {
            if self.adaptive_control.is_none() {
                self.adaptive_control = match self.adaptive.as_mut() {
                    Some(flow) => flow.next_control()?,
                    None => None,
                };
            }
            let Some(frame) = &self.adaptive_control else {
                return Ok(());
            };
            let bytes = frame.payload.len() + 8;
            if self.writer.frames.len() + self.writer.setup_extra_frames == MAX_PENDING_WRITE_FRAMES
                || self.writer.bytes + bytes > MAX_PENDING_WRITE_BYTES
            {
                return Ok(());
            }
            self.writer.frames.push_back(frame.encode()?);
            self.writer.bytes += bytes;
            self.adaptive_control = None;
        }
    }

    async fn receive_wire_event(&mut self) -> Result<MuxEvent, InnerError> {
        poll_fn(|cx| self.poll_wire_event(cx)).await
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), InnerError>> {
        if let Err(error) = self.queue_adaptive_controls() {
            return Poll::Ready(Err(self.terminate(error)));
        }
        let Some(io) = self.io.as_mut() else {
            return Poll::Ready(Err(InnerError::StreamClosed));
        };
        match self.writer.poll_flush(io, cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.terminate(error.into()))),
            result => result.map_err(InnerError::from),
        }
    }

    fn poll_wire_event(&mut self, cx: &mut Context<'_>) -> Poll<Result<MuxEvent, InnerError>> {
        if let Poll::Ready(Err(error)) = self.poll_flush(cx) {
            return Poll::Ready(Err(error));
        }
        loop {
            if let Poll::Ready(Err(error)) = self.poll_flush(cx) {
                return Poll::Ready(Err(error));
            }
            let Some(io) = self.io.as_mut() else {
                return Poll::Ready(Err(InnerError::StreamClosed));
            };
            let frame = match ready!(self
                .reader
                .poll_frame(io, cx, self.settings.max_payload_len))
            {
                Ok(frame) => frame,
                Err(error) => return Poll::Ready(Err(self.terminate(error))),
            };
            if is_padding(&frame) {
                continue;
            }
            match self.apply_frame(frame) {
                Ok(Some(event)) => return Poll::Ready(Ok(event)),
                Ok(None) => {}
                Err(error) => return Poll::Ready(Err(self.terminate(error))),
            }
        }
    }

    fn queue_event(&mut self, event: MuxEvent) -> Result<(), InnerError> {
        let bytes = event.buffered_len();
        if self.events.len() == MAX_PENDING_EVENTS
            || self.event_bytes + bytes > MAX_PENDING_EVENT_BYTES
        {
            return Err(self.terminate(invalid("mux pending event capacity exceeded")));
        }
        self.event_bytes += bytes;
        self.events.push_back(event);
        Ok(())
    }

    fn apply_frame(&mut self, frame: MuxFrame) -> Result<Option<MuxEvent>, InnerError> {
        if self.adaptive.as_ref().is_some_and(|flow| !flow.is_ready())
            && frame.command != MuxCommand::Settings
        {
            return Err(invalid(
                "adaptive peer settings must precede stream traffic",
            ));
        }
        let stream_id = frame.stream_id;
        let event = match frame.command {
            MuxCommand::Syn => self.apply_syn(stream_id, &frame.payload)?,
            MuxCommand::SynAck => {
                require_empty(&frame.payload)?;
                let Some(state) = self.peer_state(stream_id)? else {
                    return Ok(None);
                };
                if state.phase != StreamPhase::Opening {
                    return Err(invalid("unexpected SYN_ACK"));
                }
                state.phase = StreamPhase::Established;
                MuxEvent::SynAck { stream_id }
            }
            MuxCommand::Data => {
                if frame.payload.len() > MAX_DATA_CHUNK_LEN {
                    return Err(ProtocolError::LengthViolation.into());
                }
                let _ = self.peer_state(stream_id)?;
                if let Some(flow) = &mut self.adaptive {
                    flow.received(stream_id, frame.payload.len())?;
                }
                let adaptive = self.adaptive.is_some();
                let Some(state) = self.peer_state(stream_id)? else {
                    return Ok(None);
                };
                if state.phase != StreamPhase::Established || state.stream.receive_closed {
                    return Err(invalid("DATA on unopened or finished direction"));
                }
                if !adaptive {
                    state.receive_window = state
                        .receive_window
                        .checked_sub(frame.payload.len())
                        .ok_or(InnerError::WindowOverflow)?;
                }
                MuxEvent::Data {
                    stream_id,
                    payload: frame.payload,
                }
            }
            MuxCommand::WindowUpdate => return self.apply_window_update(stream_id, &frame.payload),
            MuxCommand::Fin => {
                require_empty(&frame.payload)?;
                let Some(state) = self.peer_state(stream_id)? else {
                    return Ok(None);
                };
                if state.phase != StreamPhase::Established || state.stream.receive_closed {
                    return Err(invalid("unexpected FIN"));
                }
                state.stream.receive_closed = true;
                self.reclaim_closed(stream_id);
                MuxEvent::Fin { stream_id }
            }
            MuxCommand::Rst => {
                require_empty(&frame.payload)?;
                if self.peer_state(stream_id)?.is_none() {
                    return Ok(None);
                }
                self.streams.remove(&stream_id);
                if let Some(flow) = &mut self.adaptive {
                    flow.retire(stream_id)?;
                }
                MuxEvent::Rst { stream_id }
            }
            MuxCommand::Ping => MuxEvent::Ping {
                stream_id,
                payload: frame.payload,
            },
            MuxCommand::UdpDatagram => {
                if stream_id != 0 {
                    return Err(invalid("UDP requires stream zero"));
                }
                let envelope = UdpEnvelope::decode(&frame.payload)?;
                MuxEvent::UdpDatagram {
                    target: envelope.target,
                    payload: envelope.payload,
                }
            }
            MuxCommand::Settings
            | MuxCommand::Credit
            | MuxCommand::Probe
            | MuxCommand::ProbeAck => {
                return self.apply_adaptive(&frame);
            }
            MuxCommand::Padding => return Err(invalid("padding is not an event")),
        };
        Ok(Some(event))
    }

    fn apply_window_update(
        &mut self,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<Option<MuxEvent>, InnerError> {
        if self.adaptive.is_some() {
            return Err(invalid("legacy update in adaptive mux"));
        }
        let increment = parse_window_update(payload)?;
        let maximum = self.settings.initial_window;
        let Some(state) = self.peer_state(stream_id)? else {
            return Ok(None);
        };
        if state.phase != StreamPhase::Established {
            return Err(invalid("WINDOW_UPDATE before establishment"));
        }
        let amount = usize::try_from(increment).map_err(|_| InnerError::WindowOverflow)?;
        let window = state
            .stream
            .send_window
            .checked_add(amount)
            .ok_or(InnerError::WindowOverflow)?;
        if window > maximum {
            return Err(InnerError::WindowOverflow);
        }
        state.stream.send_window = window;
        self.reclaim_closed(stream_id);
        Ok(Some(MuxEvent::WindowUpdate {
            stream_id,
            increment,
        }))
    }

    fn apply_adaptive(&mut self, frame: &MuxFrame) -> Result<Option<MuxEvent>, InnerError> {
        let stream_id = frame.stream_id;

        if frame.command == MuxCommand::Credit && stream_id != 0 {
            let _ = self.peer_state(stream_id)?;
        }
        let flow = self
            .adaptive
            .as_mut()
            .ok_or_else(|| invalid("adaptive command on legacy mux"))?;
        let before = if stream_id == 0 {
            flow.connection_credit()
        } else {
            flow.send_credit(stream_id)
        };
        flow.handle(frame)?;
        let after = if stream_id == 0 {
            flow.connection_credit()
        } else {
            flow.send_credit(stream_id)
        };
        if stream_id != 0 {
            self.reclaim_closed(stream_id);
        }
        if frame.command == MuxCommand::Credit && before == 0 && after > 0 {
            return Ok(Some(MuxEvent::WindowUpdate {
                stream_id,
                increment: 0,
            }));
        }
        Ok(None)
    }

    fn apply_syn(&mut self, stream_id: u32, payload: &[u8]) -> Result<MuxEvent, InnerError> {
        if self.role != MuxRole::Server
            || stream_id % 2 != 1
            || stream_id <= self.last_peer_stream_id
        {
            return Err(invalid("invalid or reused peer stream id"));
        }
        let target = TargetAddr::decode(payload)?;
        self.check_stream_capacity()
            .map_err(|_| invalid("mux stream capacity exceeded"))?;
        self.streams.insert(
            stream_id,
            StreamState::new(
                stream_id,
                self.settings.initial_window,
                StreamPhase::Accepting,
            ),
        );
        if let Some(flow) = &mut self.adaptive {
            flow.register(stream_id);
        }
        self.last_peer_stream_id = stream_id;
        Ok(MuxEvent::Syn { stream_id, target })
    }

    fn check_stream_capacity(&self) -> Result<(), InnerError> {
        if self.streams.len() >= self.stream_capacity() {
            return Err(would_block());
        }
        Ok(())
    }

    fn state(&self, stream_id: u32) -> Result<&StreamState, InnerError> {
        self.ensure_alive()?;
        self.streams.get(&stream_id).ok_or(InnerError::StreamReset)
    }

    fn state_mut(&mut self, stream_id: u32) -> Result<&mut StreamState, InnerError> {
        self.streams
            .get_mut(&stream_id)
            .ok_or(InnerError::StreamReset)
    }

    fn peer_state(&mut self, stream_id: u32) -> Result<Option<&mut StreamState>, InnerError> {
        let admitted = match self.role {
            MuxRole::Client => stream_id < self.next_stream_id,
            MuxRole::Server => stream_id <= self.last_peer_stream_id,
        };
        if stream_id % 2 != 1 || !admitted {
            return Err(invalid("unknown mux stream"));
        }
        // Monotonic admission makes absent IDs below the high-water mark retired,
        // including skipped peer IDs: none can ever be opened again. No tombstone
        // storage is needed. Valid in-flight frames may cross local reclamation.
        Ok(self.streams.get_mut(&stream_id))
    }

    fn snapshot(&self, stream_id: u32) -> Result<MuxStream, InnerError> {
        let mut stream = self.state(stream_id)?.stream.clone();
        if let Some(flow) = &self.adaptive {
            stream.send_window = flow.send_credit(stream_id);
        }
        Ok(stream)
    }

    fn refresh_handle(&self, stream: &mut MuxStream) -> Result<(), InnerError> {
        match self.snapshot(stream.stream_id) {
            Ok(current) => *stream = current,
            Err(error) => {
                stream.reset = true;
                return Err(error);
            }
        }
        if stream.send_closed {
            return Err(InnerError::StreamClosed);
        }
        Ok(())
    }

    fn reclaim_closed(&mut self, stream_id: u32) {
        if self.streams.get(&stream_id).is_some_and(|state| {
            state.stream.send_closed
                && state.stream.receive_closed
                && self.adaptive.as_ref().map_or(
                    state.receive_window == self.settings.initial_window
                        && state.stream.send_window == self.settings.initial_window,
                    |flow| flow.settled(stream_id),
                )
        }) {
            self.streams.remove(&stream_id);
            if let Some(flow) = &mut self.adaptive {
                // A settled stream has no unconsumed receive bytes to return.
                let _ = flow.retire(stream_id);
            }
        }
    }

    fn ensure_alive(&self) -> Result<(), InnerError> {
        if self.io.is_none() {
            Err(InnerError::StreamClosed)
        } else {
            Ok(())
        }
    }

    fn terminate(&mut self, error: InnerError) -> InnerError {
        self.io.take();
        self.adaptive.take();
        self.adaptive_control.take();
        self.streams.clear();
        self.events.clear();
        self.event_bytes = 0;
        self.writer = FrameWriter::default();
        self.reader = FrameReader::new();
        error
    }
}

struct FrameReader {
    bytes: Vec<u8>,
    offset: usize,
}

impl FrameReader {
    fn new() -> Self {
        Self {
            bytes: vec![0; 8],
            offset: 0,
        }
    }

    fn poll_frame<IO: AsyncRead + Unpin>(
        &mut self,
        io: &mut IO,
        cx: &mut Context<'_>,
        max_payload_len: usize,
    ) -> Poll<Result<MuxFrame, InnerError>> {
        loop {
            if self.offset == 8 {
                if self.bytes[0] != MUX_VERSION {
                    return Poll::Ready(Err(
                        ProtocolError::UnsupportedVersion(self.bytes[0]).into()
                    ));
                }
                MuxCommand::try_from(self.bytes[1])?;
                let len = usize::from(u16::from_be_bytes([self.bytes[6], self.bytes[7]]));
                if len > max_payload_len {
                    return Poll::Ready(Err(ProtocolError::LengthViolation.into()));
                }
                self.bytes.resize(8 + len, 0);
            }
            if self.offset == self.bytes.len() {
                let frame =
                    MuxFrame::decode(&self.bytes, max_payload_len).map_err(InnerError::from);
                self.bytes.truncate(8);
                self.offset = 0;
                return Poll::Ready(frame);
            }
            let mut buf = ReadBuf::new(&mut self.bytes[self.offset..]);
            ready!(Pin::new(&mut *io).poll_read(cx, &mut buf))?;
            let read = buf.filled().len();
            if read == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()));
            }
            self.offset += read;
        }
    }
}

#[derive(Default)]
struct FrameWriter {
    frames: VecDeque<Vec<u8>>,
    setup_extra_frames: usize,
    offset: usize,
    bytes: usize,
    needs_flush: bool,
}

impl FrameWriter {
    fn poll_flush<IO: AsyncWrite + Unpin>(
        &mut self,
        io: &mut IO,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while let Some(frame) = self.frames.front() {
            let written = ready!(Pin::new(&mut *io).poll_write(cx, &frame[self.offset..]))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.offset += written;
            self.needs_flush = true;
            if self.offset == frame.len() {
                self.bytes -= frame.len();
                self.frames.pop_front();
                self.setup_extra_frames = 0;
                self.offset = 0;
            }
        }
        if self.needs_flush {
            ready!(Pin::new(io).poll_flush(cx))?;
            self.needs_flush = false;
        }
        Poll::Ready(Ok(()))
    }
}

fn require_empty(payload: &[u8]) -> Result<(), InnerError> {
    if payload.is_empty() {
        Ok(())
    } else {
        Err(ProtocolError::LengthViolation.into())
    }
}

fn parse_window_update(payload: &[u8]) -> Result<u32, InnerError> {
    let bytes: [u8; 4] = payload
        .try_into()
        .map_err(|_| ProtocolError::LengthViolation)?;
    let increment = u32::from_be_bytes(bytes);
    if increment == 0 {
        Err(InnerError::WindowOverflow)
    } else {
        Ok(increment)
    }
}

fn invalid(message: &'static str) -> InnerError {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}

fn would_block() -> InnerError {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "mux queue or stream capacity exhausted",
    )
    .into()
}
