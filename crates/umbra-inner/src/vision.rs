//! Vision solo-mode preface, TLS sniffing, and splice-state helpers.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use umbra_proto::addr::TargetAddr;

use crate::InnerError;

const TLS_HANDSHAKE: u8 = 0x16;
const TLS_APPLICATION_DATA: u8 = 0x17;
const TLS_MAJOR_VERSION: u8 = 0x03;
const TLS_RECORD_HEADER_LEN: usize = 5;

/// Direction for observed inner TLS bytes.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VisionDirection {
    /// Client-to-target direction.
    ClientToTarget,
    /// Target-to-client direction.
    TargetToClient,
}

/// Vision relay phase.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VisionPhase {
    /// The stream does not look like TLS and should relay without TLS state.
    NonTls,
    /// TLS handshake records are being shaped before splice.
    Shaping,
    /// Both directions reached application data; raw splice is active.
    Splice,
}

/// Outcome returned by [`vision_relay`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct VisionRelayOutcome {
    /// Final observed phase.
    pub phase: VisionPhase,
    /// Bytes copied from client to target after sniffing.
    pub client_to_target: u64,
    /// Bytes copied from target to client.
    pub target_to_client: u64,
}

/// Tracks Vision TLS detection and splice readiness.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VisionTracker {
    phase: VisionPhase,
    client_app_data: bool,
    target_app_data: bool,
}

impl VisionTracker {
    /// Create a tracker before any bytes have been observed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: VisionPhase::NonTls,
            client_app_data: false,
            target_app_data: false,
        }
    }

    /// Return the current Vision phase.
    #[must_use]
    pub const fn phase(&self) -> VisionPhase {
        self.phase
    }

    /// Observe bytes in one direction and update phase.
    pub fn observe(&mut self, direction: VisionDirection, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.phase == VisionPhase::NonTls && is_tls_handshake_start(bytes) {
            self.phase = VisionPhase::Shaping;
        }
        if self.phase == VisionPhase::Shaping && contains_tls_application_data(bytes) {
            match direction {
                VisionDirection::ClientToTarget => self.client_app_data = true,
                VisionDirection::TargetToClient => self.target_app_data = true,
            }
            if self.client_app_data && self.target_app_data {
                self.phase = VisionPhase::Splice;
            }
        }
    }
}

impl Default for VisionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Return true when bytes begin like a TLS handshake record.
#[must_use]
pub fn is_tls_handshake_start(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == TLS_HANDSHAKE && bytes[1] == TLS_MAJOR_VERSION
}

/// Split handshake bytes into shaping chunks no larger than `max_chunk`.
pub fn shape_handshake_bytes(bytes: &[u8], max_chunk: usize) -> Result<Vec<Vec<u8>>, InnerError> {
    if max_chunk == 0 {
        return Err(InnerError::InvalidPaddingScheme(
            "Vision shaping chunk must be positive",
        ));
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    Ok(bytes.chunks(max_chunk).map(<[u8]>::to_vec).collect())
}

/// Encode the solo-mode target preface.
pub fn encode_solo_preface(target: &TargetAddr) -> Result<Vec<u8>, InnerError> {
    target.encode().map_err(InnerError::from)
}

/// Decode the solo-mode target preface from a buffered payload.
pub fn decode_solo_preface(input: &[u8]) -> Result<(TargetAddr, usize), InnerError> {
    TargetAddr::decode_from(input).map_err(InnerError::from)
}

/// Send the solo-mode target preface before relaying target bytes.
pub async fn send_solo_preface<W>(writer: &mut W, target: &TargetAddr) -> Result<(), InnerError>
where
    W: AsyncWrite + Unpin,
{
    let preface = encode_solo_preface(target)?;
    writer.write_all(&preface).await?;
    writer.flush().await?;
    Ok(())
}

/// Read and decode a solo-mode target preface.
pub async fn read_solo_preface<R>(reader: &mut R) -> Result<TargetAddr, InnerError>
where
    R: AsyncRead + Unpin,
{
    let mut first = [0_u8; 1];
    reader.read_exact(&mut first).await?;
    let mut raw = vec![first[0]];
    match first[0] {
        0x01 => {
            let mut rest = vec![0_u8; 6];
            reader.read_exact(&mut rest).await?;
            raw.extend_from_slice(&rest);
        }
        0x03 => {
            let mut len = [0_u8; 1];
            reader.read_exact(&mut len).await?;
            raw.push(len[0]);
            let needed = usize::from(len[0])
                .checked_add(2)
                .ok_or(InnerError::WindowOverflow)?;
            let mut rest = vec![0_u8; needed];
            reader.read_exact(&mut rest).await?;
            raw.extend_from_slice(&rest);
        }
        0x04 => {
            let mut rest = vec![0_u8; 18];
            reader.read_exact(&mut rest).await?;
            raw.extend_from_slice(&rest);
        }
        _ => return Err(InnerError::from(umbra_proto::ProtocolError::InvalidAddress)),
    }
    TargetAddr::decode(&raw).map_err(InnerError::from)
}

/// Relay a solo stream after sniffing the first bytes.
pub async fn vision_relay<C, T>(
    mut client: C,
    mut target: T,
) -> Result<VisionRelayOutcome, InnerError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut tracker = VisionTracker::new();
    let mut first = [0_u8; 4096];
    let read = client.read(&mut first).await?;
    let mut client_to_target = u64::try_from(read).map_err(|_| InnerError::WindowOverflow)?;
    let mut target_to_client = 0_u64;
    if read > 0 {
        tracker.observe(VisionDirection::ClientToTarget, &first[..read]);
        write_shaped(&mut target, &first[..read]).await?;
        target.flush().await?;
    }

    if tracker.phase() == VisionPhase::Shaping {
        let mut client_open = read > 0;
        let mut target_open = true;
        let mut client_buf = [0_u8; 4096];
        let mut target_buf = [0_u8; 4096];
        while tracker.phase() == VisionPhase::Shaping && (client_open || target_open) {
            tokio::select! {
                read = client.read(&mut client_buf), if client_open => {
                    let read = read?;
                    if read == 0 {
                        client_open = false;
                        target.shutdown().await?;
                    } else {
                        tracker.observe(VisionDirection::ClientToTarget, &client_buf[..read]);
                        write_shaped(&mut target, &client_buf[..read]).await?;
                        target.flush().await?;
                        client_to_target = client_to_target
                            .checked_add(u64::try_from(read).map_err(|_| InnerError::WindowOverflow)?)
                            .ok_or(InnerError::WindowOverflow)?;
                    }
                }
                read = target.read(&mut target_buf), if target_open => {
                    let read = read?;
                    if read == 0 {
                        target_open = false;
                        client.shutdown().await?;
                    } else {
                        tracker.observe(VisionDirection::TargetToClient, &target_buf[..read]);
                        write_shaped(&mut client, &target_buf[..read]).await?;
                        client.flush().await?;
                        target_to_client = target_to_client
                            .checked_add(u64::try_from(read).map_err(|_| InnerError::WindowOverflow)?)
                            .ok_or(InnerError::WindowOverflow)?;
                    }
                }
            }
        }
    }

    if matches!(tracker.phase(), VisionPhase::Splice | VisionPhase::NonTls) {
        let (more_client_to_target, more_target_to_client) =
            tokio::io::copy_bidirectional(&mut client, &mut target).await?;
        client_to_target = client_to_target
            .checked_add(more_client_to_target)
            .ok_or(InnerError::WindowOverflow)?;
        target_to_client = target_to_client
            .checked_add(more_target_to_client)
            .ok_or(InnerError::WindowOverflow)?;
    }

    Ok(VisionRelayOutcome {
        phase: tracker.phase(),
        client_to_target,
        target_to_client,
    })
}

async fn write_shaped<W>(writer: &mut W, bytes: &[u8]) -> Result<(), InnerError>
where
    W: AsyncWrite + Unpin,
{
    if is_tls_handshake_start(bytes) {
        for chunk in shape_handshake_bytes(bytes, 1024)? {
            writer.write_all(&chunk).await?;
        }
    } else {
        writer.write_all(bytes).await?;
    }
    Ok(())
}

fn contains_tls_application_data(bytes: &[u8]) -> bool {
    let mut offset = 0_usize;
    while offset + TLS_RECORD_HEADER_LEN <= bytes.len() {
        let content_type = bytes[offset];
        let major = bytes[offset + 1];
        let len = usize::from(u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]));
        if content_type == TLS_APPLICATION_DATA && major == TLS_MAJOR_VERSION {
            return true;
        }
        let Some(next) = offset
            .checked_add(TLS_RECORD_HEADER_LEN)
            .and_then(|value| value.checked_add(len))
        else {
            return false;
        };
        if next <= offset {
            return false;
        }
        offset = next;
    }
    false
}
