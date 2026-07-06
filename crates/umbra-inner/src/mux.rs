//! Authenticated inner mux session roles and stream flow control.

use std::collections::HashMap;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use umbra_proto::{
    addr::TargetAddr,
    frame::{MuxCommand, MuxFrame, MAX_FRAME_PAYLOAD_LEN},
};

use crate::{
    padding::{is_padding, PadScheme, PaddingPlanner},
    InnerError,
};

/// Maximum DATA payload emitted in one mux frame.
pub const MAX_DATA_CHUNK_LEN: usize = 16_384;
/// Default per-stream flow-control window.
pub const DEFAULT_INITIAL_WINDOW: usize = 256 * 1024;

/// Mux role.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MuxRole {
    /// Client-side mux role opens streams with SYN.
    Client,
    /// Server-side mux role accepts SYN and replies with SYN_ACK.
    Server,
}

/// Mux session settings.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MuxSettings {
    /// Initial send window for each logical stream.
    pub initial_window: usize,
    /// Maximum frame payload accepted from the peer.
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

/// Logical stream handle.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MuxStream {
    /// Logical stream identifier.
    pub stream_id: u32,
    send_window: usize,
    reset: bool,
    finished: bool,
}

impl MuxStream {
    /// Return the current send window.
    #[must_use]
    pub const fn send_window(&self) -> usize {
        self.send_window
    }

    /// Return true when this stream has been reset.
    #[must_use]
    pub const fn is_reset(&self) -> bool {
        self.reset
    }
}

/// Event returned by [`MuxSession::receive_next`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MuxEvent {
    /// Peer opened a stream.
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
    /// Peer sent data.
    Data {
        /// Stream id.
        stream_id: u32,
        /// Data bytes.
        payload: Vec<u8>,
    },
    /// Peer increased a stream window.
    WindowUpdate {
        /// Stream id.
        stream_id: u32,
        /// Window increment.
        increment: u32,
    },
    /// Peer gracefully finished a stream direction.
    Fin {
        /// Stream id.
        stream_id: u32,
    },
    /// Peer reset a stream.
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
}

/// Mux session over an authenticated TLS I/O object.
pub struct MuxSession<IO> {
    io: IO,
    role: MuxRole,
    settings: MuxSettings,
    next_stream_id: u32,
    streams: HashMap<u32, MuxStream>,
    padding: PaddingPlanner,
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

    /// Construct a mux session with explicit settings.
    pub fn with_settings(
        io: IO,
        role: MuxRole,
        pad: &PadScheme,
        settings: MuxSettings,
    ) -> Result<Self, InnerError> {
        let next_stream_id = match role {
            MuxRole::Client => 1,
            MuxRole::Server => 2,
        };
        Ok(Self {
            io,
            role,
            settings,
            next_stream_id,
            streams: HashMap::new(),
            padding: PaddingPlanner::new(pad.clone())?,
        })
    }

    /// Return this session role.
    #[must_use]
    pub const fn role(&self) -> MuxRole {
        self.role
    }

    /// Open a logical stream and wait for SYN_ACK.
    pub async fn open(&mut self, dst: &TargetAddr) -> Result<MuxStream, InnerError> {
        let stream_id = self.allocate_stream_id()?;
        let stream = MuxStream {
            stream_id,
            send_window: self.settings.initial_window,
            reset: false,
            finished: false,
        };
        self.streams.insert(stream_id, stream.clone());
        let payload = dst.encode()?;
        self.send_business_frame(MuxFrame::new(MuxCommand::Syn, stream_id, payload)?)
            .await?;
        loop {
            if let MuxEvent::SynAck { stream_id: acked } = self.receive_next().await? {
                if acked == stream_id {
                    return Ok(self.streams.get(&stream_id).cloned().unwrap_or(stream));
                }
            }
        }
    }

    /// Accept the next SYN and return a stream plus target address.
    pub async fn accept(&mut self) -> Result<(MuxStream, TargetAddr), InnerError> {
        loop {
            if let MuxEvent::Syn { stream_id, target } = self.receive_next().await? {
                let stream = MuxStream {
                    stream_id,
                    send_window: self.settings.initial_window,
                    reset: false,
                    finished: false,
                };
                self.streams.insert(stream_id, stream.clone());
                self.send_control_frame(MuxFrame::new(MuxCommand::SynAck, stream_id, Vec::new())?)
                    .await?;
                return Ok((stream, target));
            }
        }
    }

    /// Send DATA, waiting for WINDOW_UPDATE when the stream window is exhausted.
    pub async fn send_data_wait_window(
        &mut self,
        stream: &mut MuxStream,
        data: &[u8],
    ) -> Result<(), InnerError> {
        let mut offset = 0_usize;
        while offset < data.len() {
            while stream.send_window == 0 {
                self.receive_next().await?;
                refresh_stream(stream, &self.streams)?;
            }
            let allowed = stream
                .send_window
                .min(MAX_DATA_CHUNK_LEN)
                .min(MAX_FRAME_PAYLOAD_LEN)
                .min(data.len() - offset);
            let end = offset + allowed;
            self.send_business_frame(MuxFrame::new(
                MuxCommand::Data,
                stream.stream_id,
                data[offset..end].to_vec(),
            )?)
            .await?;
            consume_window(stream, allowed)?;
            if let Some(stored) = self.streams.get_mut(&stream.stream_id) {
                consume_window(stored, allowed)?;
            }
            offset = end;
        }
        Ok(())
    }

    /// Send a WINDOW_UPDATE increment for a stream.
    pub async fn send_window_update(
        &mut self,
        stream_id: u32,
        increment: u32,
    ) -> Result<(), InnerError> {
        self.send_control_frame(MuxFrame::new(
            MuxCommand::WindowUpdate,
            stream_id,
            increment.to_be_bytes().to_vec(),
        )?)
        .await
    }

    /// Send FIN for a stream.
    pub async fn finish_stream(&mut self, stream_id: u32) -> Result<(), InnerError> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.finished = true;
        }
        self.send_control_frame(MuxFrame::new(MuxCommand::Fin, stream_id, Vec::new())?)
            .await
    }

    /// Send RST for a stream without closing unrelated streams.
    pub async fn reset_stream(&mut self, stream_id: u32) -> Result<(), InnerError> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.reset = true;
        }
        self.send_control_frame(MuxFrame::new(MuxCommand::Rst, stream_id, Vec::new())?)
            .await
    }

    /// Receive the next non-padding mux event.
    pub async fn receive_next(&mut self) -> Result<MuxEvent, InnerError> {
        loop {
            let frame = self.read_frame().await?;
            if is_padding(&frame) {
                continue;
            }
            if let Some(event) = self.apply_frame(frame)? {
                return Ok(event);
            }
        }
    }

    async fn send_business_frame(&mut self, frame: MuxFrame) -> Result<(), InnerError> {
        let frames = self.padding.schedule(frame)?;
        for frame in frames {
            self.write_frame(&frame).await?;
        }
        Ok(())
    }

    async fn send_control_frame(&mut self, frame: MuxFrame) -> Result<(), InnerError> {
        self.write_frame(&frame).await
    }

    async fn read_frame(&mut self) -> Result<MuxFrame, InnerError> {
        let mut header = [0_u8; 8];
        self.io.read_exact(&mut header).await?;
        let len = usize::from(u16::from_be_bytes([header[6], header[7]]));
        if len > self.settings.max_payload_len {
            return Err(InnerError::from(
                umbra_proto::ProtocolError::LengthViolation,
            ));
        }
        let mut raw = header.to_vec();
        let mut payload = vec![0_u8; len];
        self.io.read_exact(&mut payload).await?;
        raw.extend_from_slice(&payload);
        MuxFrame::decode(&raw, self.settings.max_payload_len).map_err(InnerError::from)
    }

    async fn write_frame(&mut self, frame: &MuxFrame) -> Result<(), InnerError> {
        let bytes = frame.encode()?;
        self.io.write_all(&bytes).await?;
        self.io.flush().await?;
        Ok(())
    }

    fn apply_frame(&mut self, frame: MuxFrame) -> Result<Option<MuxEvent>, InnerError> {
        match frame.command {
            MuxCommand::Syn => {
                let target = TargetAddr::decode(&frame.payload)?;
                Ok(Some(MuxEvent::Syn {
                    stream_id: frame.stream_id,
                    target,
                }))
            }
            MuxCommand::SynAck => Ok(Some(MuxEvent::SynAck {
                stream_id: frame.stream_id,
            })),
            MuxCommand::Data => Ok(Some(MuxEvent::Data {
                stream_id: frame.stream_id,
                payload: frame.payload,
            })),
            MuxCommand::WindowUpdate => {
                let increment = parse_window_update(&frame.payload)?;
                let stream = self
                    .streams
                    .entry(frame.stream_id)
                    .or_insert_with(|| new_stream(frame.stream_id, self.settings.initial_window));
                stream.send_window = stream
                    .send_window
                    .checked_add(
                        usize::try_from(increment).map_err(|_| InnerError::WindowOverflow)?,
                    )
                    .ok_or(InnerError::WindowOverflow)?;
                Ok(Some(MuxEvent::WindowUpdate {
                    stream_id: frame.stream_id,
                    increment,
                }))
            }
            MuxCommand::Fin => {
                if let Some(stream) = self.streams.get_mut(&frame.stream_id) {
                    stream.finished = true;
                }
                Ok(Some(MuxEvent::Fin {
                    stream_id: frame.stream_id,
                }))
            }
            MuxCommand::Rst => {
                if let Some(stream) = self.streams.get_mut(&frame.stream_id) {
                    stream.reset = true;
                }
                Ok(Some(MuxEvent::Rst {
                    stream_id: frame.stream_id,
                }))
            }
            MuxCommand::Padding => Ok(None),
            MuxCommand::Ping => Ok(Some(MuxEvent::Ping {
                stream_id: frame.stream_id,
                payload: frame.payload,
            })),
        }
    }

    fn allocate_stream_id(&mut self) -> Result<u32, InnerError> {
        let stream_id = self.next_stream_id;
        self.next_stream_id = self
            .next_stream_id
            .checked_add(2)
            .ok_or(InnerError::WindowOverflow)?;
        Ok(stream_id)
    }
}

fn new_stream(stream_id: u32, initial_window: usize) -> MuxStream {
    MuxStream {
        stream_id,
        send_window: initial_window,
        reset: false,
        finished: false,
    }
}

fn consume_window(stream: &mut MuxStream, amount: usize) -> Result<(), InnerError> {
    if stream.reset {
        return Err(InnerError::StreamReset);
    }
    if stream.finished {
        return Err(InnerError::StreamClosed);
    }
    stream.send_window = stream
        .send_window
        .checked_sub(amount)
        .ok_or(InnerError::WindowOverflow)?;
    Ok(())
}

fn refresh_stream(
    stream: &mut MuxStream,
    streams: &HashMap<u32, MuxStream>,
) -> Result<(), InnerError> {
    let Some(stored) = streams.get(&stream.stream_id) else {
        return Err(InnerError::StreamReset);
    };
    stream.send_window = stored.send_window;
    stream.reset = stored.reset;
    stream.finished = stored.finished;
    Ok(())
}

fn parse_window_update(payload: &[u8]) -> Result<u32, InnerError> {
    let bytes: [u8; 4] = payload
        .try_into()
        .map_err(|_| umbra_proto::ProtocolError::LengthViolation)?;
    Ok(u32::from_be_bytes(bytes))
}
