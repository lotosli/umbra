//! SOCKS5 no-auth negotiation, CONNECT parsing, and UDP ASSOCIATE helpers.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use umbra_proto::addr::TargetAddr;

use crate::CoreError;

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const SOCKS_UDP_HEADER_PREFIX_LEN: usize = 3;
const FRAG_END: u8 = 0x80;
const FRAG_POSITION_MASK: u8 = 0x7f;

/// Reassembly timer required by RFC 1928.
pub const SOCKS_FRAGMENT_REASSEMBLY_TIMER: Duration = Duration::from_secs(5);
/// Default number of in-flight fragment queues per association.
pub const DEFAULT_MAX_FRAGMENT_QUEUES: usize = 64;
/// Default queued fragment bytes per association.
pub const DEFAULT_MAX_FRAGMENT_BYTES: usize = 1024 * 1024;
/// Default SOCKS UDP response payload bytes per emitted fragment.
pub const DEFAULT_RESPONSE_FRAGMENT_PAYLOAD: usize = 1200;

/// Parsed SOCKS5 CONNECT request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SocksConnect {
    /// Requested destination.
    pub target: TargetAddr,
}

/// Parsed SOCKS5 UDP ASSOCIATE request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SocksUdpAssociate {
    /// Client-advertised UDP endpoint from the request body.
    pub client_addr: TargetAddr,
}

/// Parsed SOCKS5 request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SocksRequest {
    /// TCP CONNECT request.
    Connect(SocksConnect),
    /// UDP ASSOCIATE request.
    UdpAssociate(SocksUdpAssociate),
}

/// SOCKS UDP request or response packet.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SocksUdpPacket {
    /// Fragment field from the SOCKS UDP header.
    pub frag: u8,
    /// UDP target or response source address.
    pub target: TargetAddr,
    /// UDP payload bytes.
    pub payload: Vec<u8>,
}

/// Completed SOCKS UDP payload after any local reassembly.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SocksUdpPayload {
    /// UDP target address.
    pub target: TargetAddr,
    /// Reassembled payload bytes.
    pub payload: Vec<u8>,
}

/// Bounded SOCKS UDP fragment reassembler for one association.
pub struct SocksUdpReassembler {
    queues: HashMap<TargetAddr, FragmentQueue>,
    max_queues: usize,
    max_bytes: usize,
    queued_bytes: usize,
    timer: Duration,
}

#[derive(Debug)]
struct FragmentQueue {
    fragments: Vec<Vec<u8>>,
    highest_position: u8,
    expires_at: Instant,
}

/// Complete SOCKS5 no-auth negotiation and CONNECT parsing.
pub async fn accept_connect<IO>(io: &mut IO) -> Result<SocksConnect, CoreError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_no_auth(io).await?;
    let request = read_connect_request(io).await;
    match request {
        Ok(connect) => {
            write_success_reply(io).await?;
            Ok(connect)
        }
        Err(CoreError::Socks("unsupported SOCKS command")) => {
            write_unsupported_command_reply(io).await?;
            Err(CoreError::Socks("unsupported SOCKS command"))
        }
        Err(err) => Err(err),
    }
}

/// Select the SOCKS5 no-auth method when the client offers it.
pub async fn negotiate_no_auth<IO>(io: &mut IO) -> Result<(), CoreError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0_u8; 2];
    io.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION {
        return Err(CoreError::Socks("unsupported SOCKS version"));
    }
    let method_count = usize::from(header[1]);
    if method_count == 0 {
        io.write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE]).await?;
        io.flush().await?;
        return Err(CoreError::Socks("no SOCKS auth methods offered"));
    }
    let mut methods = vec![0_u8; method_count];
    io.read_exact(&mut methods).await?;
    if methods.contains(&METHOD_NO_AUTH) {
        io.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
        io.flush().await?;
        Ok(())
    } else {
        io.write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE]).await?;
        io.flush().await?;
        Err(CoreError::Socks("SOCKS no-auth method missing"))
    }
}

/// Read a SOCKS5 CONNECT request and convert it to a target address.
pub async fn read_connect_request<R>(reader: &mut R) -> Result<SocksConnect, CoreError>
where
    R: AsyncRead + Unpin,
{
    match read_request(reader).await? {
        SocksRequest::Connect(connect) => Ok(connect),
        SocksRequest::UdpAssociate(_) => Err(CoreError::Socks("unsupported SOCKS command")),
    }
}

/// Read a SOCKS5 request and convert supported commands to structured values.
pub async fn read_request<R>(reader: &mut R) -> Result<SocksRequest, CoreError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION {
        return Err(CoreError::Socks("unsupported SOCKS version"));
    }
    if header[2] != 0 {
        return Err(CoreError::Socks("SOCKS reserved byte is invalid"));
    }
    let target = read_target(reader, header[3]).await?;
    match header[1] {
        CMD_CONNECT => Ok(SocksRequest::Connect(SocksConnect { target })),
        CMD_UDP_ASSOCIATE => Ok(SocksRequest::UdpAssociate(SocksUdpAssociate {
            client_addr: target,
        })),
        _ => Err(CoreError::Socks("unsupported SOCKS command")),
    }
}

/// Write a SOCKS5 success reply with an unspecified bound address.
pub async fn write_success_reply<W>(writer: &mut W) -> Result<(), CoreError>
where
    W: AsyncWrite + Unpin,
{
    write_bound_reply(writer, REP_SUCCEEDED, SocketAddr::from(([0, 0, 0, 0], 0))).await
}

/// Report a failed CONNECT setup without falsely acknowledging a target connection.
pub async fn write_failure_reply<W>(writer: &mut W) -> Result<(), CoreError>
where
    W: AsyncWrite + Unpin,
{
    write_bound_reply(
        writer,
        REP_GENERAL_FAILURE,
        SocketAddr::from(([0, 0, 0, 0], 0)),
    )
    .await
}

/// Write a SOCKS5 success reply with the supplied bound UDP endpoint.
pub async fn write_bound_success_reply<W>(
    writer: &mut W,
    bound: SocketAddr,
) -> Result<(), CoreError>
where
    W: AsyncWrite + Unpin,
{
    write_bound_reply(writer, REP_SUCCEEDED, bound).await
}

/// Write a SOCKS5 unsupported-command reply.
pub async fn write_unsupported_command_reply<W>(writer: &mut W) -> Result<(), CoreError>
where
    W: AsyncWrite + Unpin,
{
    write_bound_reply(
        writer,
        REP_COMMAND_NOT_SUPPORTED,
        SocketAddr::from(([0, 0, 0, 0], 0)),
    )
    .await
}

/// Decode one SOCKS UDP request or response packet.
pub fn decode_udp_packet(input: &[u8]) -> Result<SocksUdpPacket, CoreError> {
    if input.len() < SOCKS_UDP_HEADER_PREFIX_LEN + 1 {
        return Err(CoreError::Socks("SOCKS UDP packet is truncated"));
    }
    if input[0] != 0 || input[1] != 0 {
        return Err(CoreError::Socks("SOCKS UDP reserved field is invalid"));
    }
    let frag = input[2];
    let (target, consumed) = TargetAddr::decode_from(&input[SOCKS_UDP_HEADER_PREFIX_LEN..])?;
    let payload_offset =
        SOCKS_UDP_HEADER_PREFIX_LEN
            .checked_add(consumed)
            .ok_or(CoreError::InvalidConfig(
                "SOCKS UDP packet length overflows",
            ))?;
    let payload = input
        .get(payload_offset..)
        .ok_or(CoreError::Socks("SOCKS UDP packet is truncated"))?
        .to_vec();
    Ok(SocksUdpPacket {
        frag,
        target,
        payload,
    })
}

/// Encode one SOCKS UDP request or response packet.
pub fn encode_udp_packet(packet: &SocksUdpPacket) -> Result<Vec<u8>, CoreError> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0, 0, packet.frag]);
    out.extend_from_slice(&packet.target.encode()?);
    out.extend_from_slice(&packet.payload);
    Ok(out)
}

/// Encode a UDP payload as one or more SOCKS UDP packets.
pub fn encode_udp_response_packets(
    target: &TargetAddr,
    payload: &[u8],
    max_fragment_payload: usize,
) -> Result<Vec<Vec<u8>>, CoreError> {
    if max_fragment_payload == 0 {
        return Err(CoreError::InvalidConfig(
            "SOCKS UDP fragment payload limit is zero",
        ));
    }
    if payload.len() <= max_fragment_payload {
        return Ok(vec![encode_udp_packet(&SocksUdpPacket {
            frag: 0,
            target: target.clone(),
            payload: payload.to_vec(),
        })?]);
    }

    let fragment_count = payload.len().div_ceil(max_fragment_payload);
    if fragment_count > usize::from(FRAG_POSITION_MASK) {
        return Err(CoreError::InvalidConfig(
            "SOCKS UDP payload requires too many fragments",
        ));
    }

    let mut packets = Vec::with_capacity(fragment_count);
    for (index, chunk) in payload.chunks(max_fragment_payload).enumerate() {
        let position = u8::try_from(index + 1)
            .map_err(|_| CoreError::InvalidConfig("SOCKS UDP fragment index overflows"))?;
        let frag = if index + 1 == fragment_count {
            FRAG_END | position
        } else {
            position
        };
        packets.push(encode_udp_packet(&SocksUdpPacket {
            frag,
            target: target.clone(),
            payload: chunk.to_vec(),
        })?);
    }
    Ok(packets)
}

impl Default for SocksUdpReassembler {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_FRAGMENT_QUEUES,
            DEFAULT_MAX_FRAGMENT_BYTES,
            SOCKS_FRAGMENT_REASSEMBLY_TIMER,
        )
    }
}

impl SocksUdpReassembler {
    /// Create a bounded reassembler.
    #[must_use]
    pub fn new(max_queues: usize, max_bytes: usize, timer: Duration) -> Self {
        Self {
            queues: HashMap::new(),
            max_queues,
            max_bytes,
            queued_bytes: 0,
            timer: timer.max(SOCKS_FRAGMENT_REASSEMBLY_TIMER),
        }
    }

    /// Process one decoded SOCKS UDP packet.
    pub fn process(
        &mut self,
        packet: SocksUdpPacket,
        now: Instant,
    ) -> Result<Option<SocksUdpPayload>, CoreError> {
        self.expire(now);
        if packet.frag == 0 {
            return Ok(Some(SocksUdpPayload {
                target: packet.target,
                payload: packet.payload,
            }));
        }

        let position = packet.frag & FRAG_POSITION_MASK;
        if position == 0 {
            return Err(CoreError::Socks("SOCKS UDP fragment position is invalid"));
        }
        let is_end = packet.frag & FRAG_END != 0;
        self.insert_fragment(packet.target, position, is_end, packet.payload, now)
    }

    fn insert_fragment(
        &mut self,
        target: TargetAddr,
        position: u8,
        is_end: bool,
        payload: Vec<u8>,
        now: Instant,
    ) -> Result<Option<SocksUdpPayload>, CoreError> {
        if !self.queues.contains_key(&target) && self.queues.len() >= self.max_queues {
            return Ok(None);
        }

        let reset = self
            .queues
            .get(&target)
            .is_some_and(|queue| position < queue.highest_position);
        if reset {
            self.remove_queue(&target);
        }

        let payload_len = payload.len();
        if self
            .queued_bytes
            .checked_add(payload_len)
            .is_none_or(|len| len > self.max_bytes)
        {
            self.remove_queue(&target);
            return Ok(None);
        }

        let queue = self
            .queues
            .entry(target.clone())
            .or_insert_with(|| FragmentQueue {
                fragments: Vec::new(),
                highest_position: 0,
                expires_at: now + self.timer,
            });
        if position <= queue.highest_position && position != queue.highest_position + 1 {
            self.remove_queue(&target);
            return Ok(None);
        }
        if position != queue.highest_position + 1 {
            self.remove_queue(&target);
            return Ok(None);
        }
        queue.highest_position = position;
        queue.expires_at = now + self.timer;
        queue.fragments.push(payload);
        self.queued_bytes =
            self.queued_bytes
                .checked_add(payload_len)
                .ok_or(CoreError::InvalidConfig(
                    "SOCKS UDP fragment bytes overflow",
                ))?;

        if !is_end {
            return Ok(None);
        }

        let queue = self
            .queues
            .remove(&target)
            .ok_or(CoreError::InvalidConfig("SOCKS UDP fragment queue missing"))?;
        self.queued_bytes = self
            .queued_bytes
            .saturating_sub(queue.fragments.iter().map(Vec::len).sum());
        let total_len = queue
            .fragments
            .iter()
            .map(Vec::len)
            .try_fold(0_usize, |total, len| {
                total.checked_add(len).ok_or(CoreError::InvalidConfig(
                    "SOCKS UDP fragment length overflows",
                ))
            })?;
        let mut reassembled = Vec::with_capacity(total_len);
        for fragment in queue.fragments {
            reassembled.extend_from_slice(&fragment);
        }
        Ok(Some(SocksUdpPayload {
            target,
            payload: reassembled,
        }))
    }

    fn expire(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .queues
            .iter()
            .filter(|(_, queue)| queue.expires_at <= now)
            .map(|(target, _)| target.clone())
            .collect();
        for target in expired {
            self.remove_queue(&target);
        }
    }

    fn remove_queue(&mut self, target: &TargetAddr) {
        if let Some(queue) = self.queues.remove(target) {
            let removed = queue.fragments.iter().map(Vec::len).sum();
            self.queued_bytes = self.queued_bytes.saturating_sub(removed);
        }
    }
}

async fn read_target<R>(reader: &mut R, atyp: u8) -> Result<TargetAddr, CoreError>
where
    R: AsyncRead + Unpin,
{
    match atyp {
        ATYP_IPV4 => {
            let mut bytes = [0_u8; 6];
            reader.read_exact(&mut bytes).await?;
            let addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            let port = u16::from_be_bytes([bytes[4], bytes[5]]);
            Ok(TargetAddr::Ipv4(addr, port))
        }
        ATYP_DOMAIN => {
            let mut len = [0_u8; 1];
            reader.read_exact(&mut len).await?;
            let len = usize::from(len[0]);
            if len == 0 {
                return Err(CoreError::Socks("SOCKS domain is empty"));
            }
            let mut domain = vec![0_u8; len];
            reader.read_exact(&mut domain).await?;
            let mut port = [0_u8; 2];
            reader.read_exact(&mut port).await?;
            let domain = String::from_utf8(domain)
                .map_err(|_| CoreError::Socks("SOCKS domain is not UTF-8"))?;
            TargetAddr::domain(domain, u16::from_be_bytes(port)).map_err(CoreError::from)
        }
        ATYP_IPV6 => {
            let mut bytes = [0_u8; 18];
            reader.read_exact(&mut bytes).await?;
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[..16]);
            let port = u16::from_be_bytes([bytes[16], bytes[17]]);
            Ok(TargetAddr::Ipv6(Ipv6Addr::from(octets), port))
        }
        _ => Err(CoreError::Socks("unsupported SOCKS address type")),
    }
}

async fn write_bound_reply<W>(writer: &mut W, reply: u8, bound: SocketAddr) -> Result<(), CoreError>
where
    W: AsyncWrite + Unpin,
{
    let mut response = vec![SOCKS_VERSION, reply, 0x00];
    match bound {
        SocketAddr::V4(addr) => {
            response.push(ATYP_IPV4);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            response.push(ATYP_IPV6);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    writer.write_all(&response).await?;
    writer.flush().await?;
    Ok(())
}
