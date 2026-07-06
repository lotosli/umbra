//! QUIC fingerprint, REALITY carrier, fallback, and target stream helpers.

use umbra_fingerprint::FingerprintProfile;
use umbra_proto::addr::TargetAddr;

use crate::TransportError;

const QUIC_LONG_HEADER_BIT: u8 = 0x80;
const QUIC_FIXED_BIT: u8 = 0x40;
const QUIC_LONG_TYPE_MASK: u8 = 0x30;
const QUIC_LONG_TYPE_INITIAL: u8 = 0x00;
const MAX_QUIC_CID_LEN: usize = 20;

/// QUIC transport parameter.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QuicTransportParameter {
    /// Parameter identifier.
    pub id: u64,
    /// Parameter value.
    pub value: Vec<u8>,
}

/// Chrome-shaped QUIC fingerprint surface.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QuicFingerprint {
    /// Offered QUIC versions.
    pub versions: Vec<u32>,
    /// Transport parameter identifiers in wire order.
    pub transport_parameters: Vec<u64>,
    /// GREASE transport parameter used for auth carrier.
    pub grease_parameter: u64,
    /// QUIC ALPN.
    pub alpn: String,
    /// Source connection id length.
    pub scid_len: usize,
    /// Maximum auth bytes carried in the GREASE parameter before SCID split.
    pub grease_value_capacity: usize,
}

/// Built QUIC ClientHello carrier surface.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QuicClientHelloSurface {
    /// ALPN advertised in TLS.
    pub alpn: String,
    /// Source connection id.
    pub scid: Vec<u8>,
    /// QUIC transport parameters.
    pub transport_parameters: Vec<QuicTransportParameter>,
}

/// Parsed QUIC Initial invariant header fields.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QuicInitialHeader {
    /// QUIC version from the long header.
    pub version: u32,
    /// Destination connection id.
    pub dcid: Vec<u8>,
    /// Source connection id.
    pub scid: Vec<u8>,
    /// Retry/initial token bytes.
    pub token: Vec<u8>,
    /// Protected payload length, including packet number bytes.
    pub payload_len: usize,
    /// Offset where the protected packet number starts.
    pub packet_number_offset: usize,
    /// Total length of the first QUIC packet in this datagram.
    pub packet_len: usize,
}

/// QUIC dispatch decision for unauthenticated Initial datagrams.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum QuicDispatchDecision {
    /// Authenticated QUIC connection may be handled locally.
    Authenticated,
    /// Datagram must be forwarded to the real destination.
    ForwardToDest {
        /// Original datagram bytes.
        datagram: Vec<u8>,
    },
}

/// Authenticated QUIC stream payload for one target.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QuicTargetStream {
    /// Stream bytes, beginning with encoded target address.
    pub bytes: Vec<u8>,
}

/// Build QUIC fingerprint data from the selected Chrome profile.
#[must_use]
pub fn quic_fingerprint_from_profile(profile: &FingerprintProfile) -> QuicFingerprint {
    QuicFingerprint {
        versions: profile.quic.versions.clone(),
        transport_parameters: profile.quic.transport_parameters.clone(),
        grease_parameter: profile.quic.grease_parameter,
        alpn: profile.quic.alpn.clone(),
        scid_len: profile.quic.scid_len,
        grease_value_capacity: 32,
    }
}

/// Build a QUIC ClientHello auth carrier surface.
pub fn build_quic_client_hello_surface(
    auth_token: &[u8; 32],
    fp: &QuicFingerprint,
) -> Result<QuicClientHelloSurface, TransportError> {
    if fp.alpn != "h3" {
        return Err(TransportError::InvalidQuicSurface("QUIC ALPN must be h3"));
    }
    let (scid, carrier_value) = split_auth_token(auth_token, fp)?;
    let mut params = Vec::new();
    for id in &fp.transport_parameters {
        let value = if *id == fp.grease_parameter {
            carrier_value.clone()
        } else {
            Vec::new()
        };
        params.push(QuicTransportParameter { id: *id, value });
    }
    if !params.iter().any(|param| param.id == fp.grease_parameter) {
        params.push(QuicTransportParameter {
            id: fp.grease_parameter,
            value: carrier_value,
        });
    }
    Ok(QuicClientHelloSurface {
        alpn: fp.alpn.clone(),
        scid,
        transport_parameters: params,
    })
}

/// Recover the 32-byte REALITY token from QUIC carrier fields.
pub fn recover_quic_auth_token(
    surface: &QuicClientHelloSurface,
    fp: &QuicFingerprint,
) -> Result<[u8; 32], TransportError> {
    let grease_value = surface
        .transport_parameters
        .iter()
        .find(|param| param.id == fp.grease_parameter)
        .ok_or(TransportError::InvalidQuicSurface(
            "GREASE auth carrier missing",
        ))?
        .value
        .as_slice();
    let mut out = [0_u8; 32];
    if grease_value.len() == 32 {
        out.copy_from_slice(grease_value);
        return Ok(out);
    }
    if surface.scid.len() < 8 || grease_value.len() != 24 {
        return Err(TransportError::InvalidQuicSurface(
            "split auth carrier has wrong length",
        ));
    }
    out[..8].copy_from_slice(&surface.scid[..8]);
    out[8..].copy_from_slice(grease_value);
    Ok(out)
}

/// Parse the invariant header of a QUIC Initial packet.
///
/// This intentionally stops before header protection and packet protection.
/// REALITY-over-QUIC dispatch uses it to obtain the client SCID and to decide
/// whether malformed datagrams must be forwarded instead of answered locally.
pub fn parse_quic_initial_header(datagram: &[u8]) -> Result<QuicInitialHeader, TransportError> {
    if datagram.len() < 7 {
        return Err(TransportError::InvalidQuicSurface("short QUIC datagram"));
    }
    let first = datagram[0];
    if first & QUIC_LONG_HEADER_BIT == 0 {
        return Err(TransportError::InvalidQuicSurface(
            "QUIC packet is not long header",
        ));
    }
    if first & QUIC_FIXED_BIT == 0 {
        return Err(TransportError::InvalidQuicSurface(
            "QUIC fixed bit is not set",
        ));
    }
    if first & QUIC_LONG_TYPE_MASK != QUIC_LONG_TYPE_INITIAL {
        return Err(TransportError::InvalidQuicSurface(
            "QUIC packet is not Initial",
        ));
    }

    let mut offset = 1_usize;
    let version = read_u32(datagram, &mut offset)?;
    let dcid = read_cid(datagram, &mut offset)?;
    let scid = read_cid(datagram, &mut offset)?;
    let token_len = read_varint_usize(datagram, &mut offset)?;
    let token = take(datagram, &mut offset, token_len)?.to_vec();
    let payload_len = read_varint_usize(datagram, &mut offset)?;
    let packet_number_offset = offset;
    let packet_len =
        packet_number_offset
            .checked_add(payload_len)
            .ok_or(TransportError::InvalidQuicSurface(
                "QUIC packet length overflows",
            ))?;
    if datagram.len() < packet_len {
        return Err(TransportError::InvalidQuicSurface(
            "truncated QUIC Initial payload",
        ));
    }

    Ok(QuicInitialHeader {
        version,
        dcid,
        scid,
        token,
        payload_len,
        packet_number_offset,
        packet_len,
    })
}

/// Decide whether a bad QUIC auth result must be forwarded.
#[must_use]
pub fn quic_dispatch_bad_auth(datagram: &[u8]) -> QuicDispatchDecision {
    QuicDispatchDecision::ForwardToDest {
        datagram: datagram.to_vec(),
    }
}

/// Build an authenticated QUIC stream payload carrying target address and data.
pub fn open_target_stream(
    target: &TargetAddr,
    initial_bytes: &[u8],
) -> Result<QuicTargetStream, TransportError> {
    let mut bytes = target.encode()?;
    bytes.extend_from_slice(initial_bytes);
    Ok(QuicTargetStream { bytes })
}

fn split_auth_token(
    auth_token: &[u8; 32],
    fp: &QuicFingerprint,
) -> Result<(Vec<u8>, Vec<u8>), TransportError> {
    if fp.scid_len < 8 {
        return Err(TransportError::InvalidQuicSurface(
            "SCID length must allow split carrier",
        ));
    }
    if fp.grease_value_capacity >= 32 {
        Ok((vec![0_u8; fp.scid_len], auth_token.to_vec()))
    } else {
        let mut scid = vec![0_u8; fp.scid_len];
        scid[..8].copy_from_slice(&auth_token[..8]);
        Ok((scid, auth_token[8..].to_vec()))
    }
}

fn read_u32(input: &[u8], offset: &mut usize) -> Result<u32, TransportError> {
    let bytes = take(input, offset, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_cid(input: &[u8], offset: &mut usize) -> Result<Vec<u8>, TransportError> {
    let len = usize::from(
        *input
            .get(*offset)
            .ok_or(TransportError::InvalidQuicSurface(
                "missing QUIC CID length",
            ))?,
    );
    *offset += 1;
    if len > MAX_QUIC_CID_LEN {
        return Err(TransportError::InvalidQuicSurface(
            "QUIC CID length is too large",
        ));
    }
    Ok(take(input, offset, len)?.to_vec())
}

fn read_varint_usize(input: &[u8], offset: &mut usize) -> Result<usize, TransportError> {
    let first = *input
        .get(*offset)
        .ok_or(TransportError::InvalidQuicSurface("missing QUIC varint"))?;
    let len = 1_usize << usize::from(first >> 6);
    let bytes = take(input, offset, len)?;
    let mut value = u64::from(bytes[0] & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    usize::try_from(value).map_err(|_| TransportError::InvalidQuicSurface("QUIC varint too large"))
}

fn take<'a>(input: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], TransportError> {
    let end = offset
        .checked_add(len)
        .ok_or(TransportError::InvalidQuicSurface("QUIC offset overflows"))?;
    let bytes = input
        .get(*offset..end)
        .ok_or(TransportError::InvalidQuicSurface("truncated QUIC field"))?;
    *offset = end;
    Ok(bytes)
}
