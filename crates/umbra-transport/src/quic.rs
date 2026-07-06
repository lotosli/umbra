//! QUIC fingerprint, REALITY carrier, fallback, and target stream helpers.

use rustls::{
    quic::{HeaderProtectionKey, Version},
    CipherSuite, Side,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use umbra_fingerprint::FingerprintProfile;
use umbra_proto::{
    addr::TargetAddr,
    consts::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6},
};
use umbra_tls::parse::parse_client_hello;

use crate::TransportError;

const QUIC_LONG_HEADER_BIT: u8 = 0x80;
const QUIC_FIXED_BIT: u8 = 0x40;
const QUIC_LONG_TYPE_MASK: u8 = 0x30;
const QUIC_LONG_TYPE_INITIAL: u8 = 0x00;
const MAX_QUIC_CID_LEN: usize = 20;
const QUIC_FRAME_PADDING: u8 = 0x00;
const QUIC_FRAME_PING: u8 = 0x01;
const QUIC_FRAME_ACK: u8 = 0x02;
const QUIC_FRAME_ACK_ECN: u8 = 0x03;
const QUIC_FRAME_CRYPTO: u8 = 0x06;
const QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT: u8 = 0x1c;
const QUIC_FRAME_CONNECTION_CLOSE_APPLICATION: u8 = 0x1d;
const QUIC_MIN_INITIAL_DATAGRAM_LEN: usize = 1200;
const QUIC_INITIAL_PACKET_NUMBER: u64 = 1;
const QUIC_INITIAL_PACKET_NUMBER_LEN: usize = 4;

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

/// Recover a REALITY-over-QUIC auth token from a protected QUIC Initial packet.
pub fn recover_quic_auth_token_from_initial(
    datagram: &[u8],
    fp: &QuicFingerprint,
) -> Result<[u8; 32], TransportError> {
    let header = parse_quic_initial_header(datagram)?;
    let crypto = decrypt_quic_initial_crypto(datagram)?;
    let parsed = parse_client_hello(&crypto)?;
    if !parsed.session_id.is_empty() {
        return Err(TransportError::InvalidQuicSurface(
            "QUIC ClientHello legacy_session_id must be empty",
        ));
    }
    let surface = QuicClientHelloSurface {
        alpn: fp.alpn.clone(),
        scid: header.scid,
        transport_parameters: parsed
            .quic_transport_parameters
            .into_iter()
            .map(|param| QuicTransportParameter {
                id: param.id,
                value: param.value,
            })
            .collect(),
    };
    recover_quic_auth_token(&surface, fp)
}

/// Build a protected client QUIC Initial packet carrying raw ClientHello CRYPTO bytes.
pub fn build_quic_initial_crypto_packet(
    crypto: &[u8],
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
) -> Result<Vec<u8>, TransportError> {
    validate_cid(dcid)?;
    validate_cid(scid)?;
    let mut padding_len = 0_usize;
    loop {
        let plaintext = crypto_plaintext(crypto, padding_len)?;
        let packet = seal_client_initial_plaintext(
            &plaintext,
            dcid,
            scid,
            token,
            QUIC_INITIAL_PACKET_NUMBER,
            QUIC_INITIAL_PACKET_NUMBER_LEN,
        )?;
        if packet.len() >= QUIC_MIN_INITIAL_DATAGRAM_LEN {
            return Ok(packet);
        }
        padding_len = padding_len
            .checked_add(QUIC_MIN_INITIAL_DATAGRAM_LEN - packet.len())
            .ok_or(TransportError::InvalidQuicSurface(
                "QUIC Initial padding length overflows",
            ))?;
    }
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

/// Decrypt a client QUIC Initial packet and concatenate contiguous CRYPTO frame bytes.
///
/// The returned bytes are TLS handshake bytes, not TLS records. A caller can
/// pass them to `umbra_tls::parse::parse_client_hello` to inspect SNI,
/// key_share, empty QUIC `legacy_session_id`, and QUIC transport parameters.
pub fn decrypt_quic_initial_crypto(datagram: &[u8]) -> Result<Vec<u8>, TransportError> {
    let header = parse_quic_initial_header(datagram)?;
    if header.version != 1 {
        return Err(TransportError::InvalidQuicSurface(
            "unsupported QUIC Initial version",
        ));
    }
    let suite = initial_quic_suite()?;
    let keys = suite.keys(&header.dcid, Side::Server, Version::V1);
    let mut packet = datagram[..header.packet_len].to_vec();
    remove_header_protection(
        &mut packet,
        header.packet_number_offset,
        keys.remote.header.as_ref(),
    )?;
    let packet_number_len = usize::from(packet[0] & 0x03) + 1;
    if packet_number_len > 4 {
        return Err(TransportError::InvalidQuicSurface(
            "invalid QUIC packet number length",
        ));
    }
    let packet_number_end = header
        .packet_number_offset
        .checked_add(packet_number_len)
        .ok_or(TransportError::InvalidQuicSurface(
            "QUIC packet number offset overflows",
        ))?;
    if packet_number_end > packet.len() {
        return Err(TransportError::InvalidQuicSurface(
            "truncated QUIC packet number",
        ));
    }
    let packet_number =
        decode_packet_number(&packet[header.packet_number_offset..packet_number_end]);
    let (aad, payload) = packet.split_at_mut(packet_number_end);
    let plaintext = keys
        .remote
        .packet
        .decrypt_in_place(packet_number, aad, payload)
        .map_err(|_| TransportError::InvalidQuicSurface("QUIC Initial authentication failed"))?;
    extract_crypto_frames(plaintext)
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

/// Parse a QUIC target stream payload into its target prefix and remaining bytes.
pub fn parse_target_stream_payload(bytes: &[u8]) -> Result<(TargetAddr, &[u8]), TransportError> {
    let (target, consumed) = TargetAddr::decode_from(bytes)?;
    Ok((target, &bytes[consumed..]))
}

/// Write one authenticated QUIC target stream preface and optional first bytes.
pub async fn write_target_stream<W>(
    writer: &mut W,
    target: &TargetAddr,
    initial_bytes: &[u8],
) -> Result<(), TransportError>
where
    W: AsyncWrite + Unpin,
{
    let stream = open_target_stream(target, initial_bytes)?;
    writer.write_all(&stream.bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Read the target address prefix from an authenticated QUIC stream.
pub async fn read_target_stream<R>(reader: &mut R) -> Result<TargetAddr, TransportError>
where
    R: AsyncRead + Unpin,
{
    let mut atyp = [0_u8; 1];
    reader.read_exact(&mut atyp).await?;
    let mut encoded = vec![atyp[0]];
    match atyp[0] {
        ATYP_IPV4 => read_exact_to(reader, 6, &mut encoded).await?,
        ATYP_DOMAIN => {
            let mut len = [0_u8; 1];
            reader.read_exact(&mut len).await?;
            encoded.push(len[0]);
            read_exact_to(reader, usize::from(len[0]) + 2, &mut encoded).await?;
        }
        ATYP_IPV6 => read_exact_to(reader, 18, &mut encoded).await?,
        _ => {
            return Err(TransportError::Protocol(
                umbra_proto::ProtocolError::InvalidAddress,
            ))
        }
    }
    TargetAddr::decode(&encoded).map_err(TransportError::from)
}

async fn read_exact_to<R>(
    reader: &mut R,
    len: usize,
    out: &mut Vec<u8>,
) -> Result<(), TransportError>
where
    R: AsyncRead + Unpin,
{
    let start = out.len();
    let end = start
        .checked_add(len)
        .ok_or(TransportError::InvalidQuicSurface(
            "target prefix length overflows",
        ))?;
    out.resize(end, 0);
    reader.read_exact(&mut out[start..end]).await?;
    Ok(())
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

fn validate_cid(cid: &[u8]) -> Result<(), TransportError> {
    if cid.len() > MAX_QUIC_CID_LEN {
        return Err(TransportError::InvalidQuicSurface(
            "QUIC CID length is too large",
        ));
    }
    Ok(())
}

fn append_packet_number(
    packet_number: u64,
    packet_number_len: usize,
    out: &mut Vec<u8>,
) -> Result<(), TransportError> {
    if !(1..=4).contains(&packet_number_len) {
        return Err(TransportError::InvalidQuicSurface(
            "invalid QUIC packet number length",
        ));
    }
    let bytes = packet_number.to_be_bytes();
    out.extend_from_slice(&bytes[bytes.len() - packet_number_len..]);
    Ok(())
}

fn crypto_plaintext(crypto: &[u8], padding_len: usize) -> Result<Vec<u8>, TransportError> {
    let mut plaintext = Vec::new();
    plaintext.push(QUIC_FRAME_CRYPTO);
    write_varint(0, &mut plaintext)?;
    write_varint(
        u64::try_from(crypto.len())
            .map_err(|_| TransportError::InvalidQuicSurface("CRYPTO length is too large"))?,
        &mut plaintext,
    )?;
    plaintext.extend_from_slice(crypto);
    let new_len =
        plaintext
            .len()
            .checked_add(padding_len)
            .ok_or(TransportError::InvalidQuicSurface(
                "QUIC padding length overflows",
            ))?;
    plaintext.resize(new_len, QUIC_FRAME_PADDING);
    Ok(plaintext)
}

fn seal_client_initial_plaintext(
    plaintext: &[u8],
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
    packet_number: u64,
    packet_number_len: usize,
) -> Result<Vec<u8>, TransportError> {
    if !(1..=4).contains(&packet_number_len) {
        return Err(TransportError::InvalidQuicSurface(
            "invalid QUIC packet number length",
        ));
    }
    validate_cid(dcid)?;
    validate_cid(scid)?;
    let suite = initial_quic_suite()?;
    let keys = suite.keys(dcid, Side::Client, Version::V1);

    let mut header = Vec::new();
    header.push(
        0xc0 | u8::try_from(packet_number_len - 1)
            .map_err(|_| TransportError::InvalidQuicSurface("invalid QUIC packet number length"))?,
    );
    header.extend_from_slice(&1_u32.to_be_bytes());
    header.push(
        u8::try_from(dcid.len())
            .map_err(|_| TransportError::InvalidQuicSurface("QUIC DCID length is too large"))?,
    );
    header.extend_from_slice(dcid);
    header.push(
        u8::try_from(scid.len())
            .map_err(|_| TransportError::InvalidQuicSurface("QUIC SCID length is too large"))?,
    );
    header.extend_from_slice(scid);
    write_varint(
        u64::try_from(token.len())
            .map_err(|_| TransportError::InvalidQuicSurface("QUIC token length is too large"))?,
        &mut header,
    )?;
    header.extend_from_slice(token);
    let payload_len = packet_number_len
        .checked_add(plaintext.len())
        .and_then(|len| len.checked_add(keys.local.packet.tag_len()))
        .ok_or(TransportError::InvalidQuicSurface(
            "QUIC Initial payload length overflows",
        ))?;
    write_varint(
        u64::try_from(payload_len).map_err(|_| {
            TransportError::InvalidQuicSurface("QUIC Initial payload length is too large")
        })?,
        &mut header,
    )?;
    let packet_number_offset = header.len();
    append_packet_number(packet_number, packet_number_len, &mut header)?;

    let mut payload = plaintext.to_vec();
    let tag = keys
        .local
        .packet
        .encrypt_in_place(packet_number, &header, &mut payload)
        .map_err(|_| TransportError::InvalidQuicSurface("QUIC Initial encryption failed"))?;
    let mut packet = header;
    packet.extend_from_slice(&payload);
    packet.extend_from_slice(tag.as_ref());
    add_header_protection(
        &mut packet,
        packet_number_offset,
        keys.local.header.as_ref(),
    )?;
    Ok(packet)
}

fn add_header_protection(
    packet: &mut [u8],
    packet_number_offset: usize,
    key: &dyn HeaderProtectionKey,
) -> Result<(), TransportError> {
    let sample_start =
        packet_number_offset
            .checked_add(4)
            .ok_or(TransportError::InvalidQuicSurface(
                "QUIC sample offset overflows",
            ))?;
    let sample_end =
        sample_start
            .checked_add(key.sample_len())
            .ok_or(TransportError::InvalidQuicSurface(
                "QUIC sample length overflows",
            ))?;
    let sample = packet
        .get(sample_start..sample_end)
        .ok_or(TransportError::InvalidQuicSurface(
            "QUIC header protection sample is truncated",
        ))?
        .to_vec();
    let packet_number_end =
        packet_number_offset
            .checked_add(4)
            .ok_or(TransportError::InvalidQuicSurface(
                "QUIC packet number offset overflows",
            ))?;
    if packet_number_end > packet.len() {
        return Err(TransportError::InvalidQuicSurface(
            "truncated QUIC protected packet number",
        ));
    }
    let (first, rest) = packet.split_at_mut(1);
    let pn_start =
        packet_number_offset
            .checked_sub(1)
            .ok_or(TransportError::InvalidQuicSurface(
                "invalid QUIC packet number offset",
            ))?;
    key.encrypt_in_place(&sample, &mut first[0], &mut rest[pn_start..pn_start + 4])
        .map_err(|_| TransportError::InvalidQuicSurface("QUIC header protection failed"))
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

fn write_varint(value: u64, out: &mut Vec<u8>) -> Result<(), TransportError> {
    if value < 64 {
        out.push(
            u8::try_from(value)
                .map_err(|_| TransportError::InvalidQuicSurface("QUIC varint is too large"))?,
        );
    } else if value < 16_384 {
        let encoded = u16::try_from(value | 0x4000)
            .map_err(|_| TransportError::InvalidQuicSurface("QUIC varint is too large"))?;
        out.extend_from_slice(&encoded.to_be_bytes());
    } else if value < 1_073_741_824 {
        let encoded = u32::try_from(value | 0x8000_0000)
            .map_err(|_| TransportError::InvalidQuicSurface("QUIC varint is too large"))?;
        out.extend_from_slice(&encoded.to_be_bytes());
    } else if value < 4_611_686_018_427_387_904 {
        let encoded = value | 0xc000_0000_0000_0000;
        out.extend_from_slice(&encoded.to_be_bytes());
    } else {
        return Err(TransportError::InvalidQuicSurface(
            "QUIC varint is too large",
        ));
    }
    Ok(())
}

fn initial_quic_suite() -> Result<rustls::quic::Suite, TransportError> {
    let provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .iter()
        .find_map(|suite| match (suite.suite(), suite.tls13()) {
            (CipherSuite::TLS13_AES_128_GCM_SHA256, Some(tls13)) => tls13.quic_suite(),
            _ => None,
        })
        .ok_or(TransportError::InvalidQuicSurface(
            "rustls provider has no QUIC AES-128-GCM suite",
        ))
}

fn remove_header_protection(
    packet: &mut [u8],
    packet_number_offset: usize,
    key: &dyn HeaderProtectionKey,
) -> Result<(), TransportError> {
    let sample_start =
        packet_number_offset
            .checked_add(4)
            .ok_or(TransportError::InvalidQuicSurface(
                "QUIC sample offset overflows",
            ))?;
    let sample_end =
        sample_start
            .checked_add(key.sample_len())
            .ok_or(TransportError::InvalidQuicSurface(
                "QUIC sample length overflows",
            ))?;
    let sample = packet
        .get(sample_start..sample_end)
        .ok_or(TransportError::InvalidQuicSurface(
            "QUIC header protection sample is truncated",
        ))?
        .to_vec();
    let packet_number_end =
        packet_number_offset
            .checked_add(4)
            .ok_or(TransportError::InvalidQuicSurface(
                "QUIC packet number offset overflows",
            ))?;
    if packet_number_end > packet.len() {
        return Err(TransportError::InvalidQuicSurface(
            "truncated QUIC protected packet number",
        ));
    }
    let (first, rest) = packet.split_at_mut(1);
    let pn_start =
        packet_number_offset
            .checked_sub(1)
            .ok_or(TransportError::InvalidQuicSurface(
                "invalid QUIC packet number offset",
            ))?;
    key.decrypt_in_place(&sample, &mut first[0], &mut rest[pn_start..pn_start + 4])
        .map_err(|_| TransportError::InvalidQuicSurface("QUIC header protection failed"))
}

fn decode_packet_number(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0_u64, |packet_number, byte| {
        (packet_number << 8) | u64::from(*byte)
    })
}

fn extract_crypto_frames(plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
    let mut offset = 0_usize;
    let mut crypto = Vec::new();
    while offset < plaintext.len() {
        let frame_type = read_u8(plaintext, &mut offset)?;
        match frame_type {
            QUIC_FRAME_PADDING | QUIC_FRAME_PING => {}
            QUIC_FRAME_ACK | QUIC_FRAME_ACK_ECN => skip_ack_frame(plaintext, &mut offset)?,
            QUIC_FRAME_CRYPTO => {
                let crypto_offset = read_varint_usize(plaintext, &mut offset)?;
                let len = read_varint_usize(plaintext, &mut offset)?;
                if crypto_offset != crypto.len() {
                    return Err(TransportError::InvalidQuicSurface(
                        "non-contiguous QUIC CRYPTO data",
                    ));
                }
                crypto.extend_from_slice(take(plaintext, &mut offset, len)?);
            }
            QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT => {
                skip_varint(plaintext, &mut offset)?;
                skip_varint(plaintext, &mut offset)?;
                skip_length_prefixed(plaintext, &mut offset)?;
            }
            QUIC_FRAME_CONNECTION_CLOSE_APPLICATION => {
                skip_varint(plaintext, &mut offset)?;
                skip_length_prefixed(plaintext, &mut offset)?;
            }
            _ => {
                return Err(TransportError::InvalidQuicSurface(
                    "unsupported QUIC Initial frame",
                ));
            }
        }
    }
    if crypto.is_empty() {
        return Err(TransportError::InvalidQuicSurface(
            "QUIC Initial has no CRYPTO frame",
        ));
    }
    Ok(crypto)
}

fn skip_ack_frame(input: &[u8], offset: &mut usize) -> Result<(), TransportError> {
    skip_varint(input, offset)?;
    skip_varint(input, offset)?;
    let range_count = read_varint_usize(input, offset)?;
    skip_varint(input, offset)?;
    for _ in 0..range_count {
        skip_varint(input, offset)?;
        skip_varint(input, offset)?;
    }
    Ok(())
}

fn skip_length_prefixed(input: &[u8], offset: &mut usize) -> Result<(), TransportError> {
    let len = read_varint_usize(input, offset)?;
    take(input, offset, len).map(|_| ())
}

fn skip_varint(input: &[u8], offset: &mut usize) -> Result<(), TransportError> {
    read_varint_usize(input, offset).map(|_| ())
}

fn read_u8(input: &[u8], offset: &mut usize) -> Result<u8, TransportError> {
    let value = *input
        .get(*offset)
        .ok_or(TransportError::InvalidQuicSurface(
            "missing QUIC frame byte",
        ))?;
    *offset += 1;
    Ok(value)
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

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_crypto::x25519;
    use umbra_fingerprint::load_profile;
    use umbra_tls::clienthello::{
        build_client_hello, ClientHelloParams, ClientQuicTransportParameter, MlkemShare,
        EXT_QUIC_TRANSPORT_PARAMETERS,
    };

    #[test]
    fn scenario_quic_initial_crypto_decrypts_contiguous_crypto_frame() {
        let crypto = b"\x01\x00\x00\x00test-client-hello";
        let datagram = seal_client_initial_crypto_for_test(crypto, &[]);

        assert_eq!(
            decrypt_quic_initial_crypto(&datagram).expect("Initial decrypts"),
            crypto
        );
    }

    #[test]
    fn scenario_quic_initial_builder_encrypts_clienthello_crypto() {
        let crypto = b"\x01\x00\x00\x04test";
        let dcid = [9_u8, 8, 7, 6, 5, 4, 3, 2];
        let scid = [0x11_u8, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
        let datagram =
            build_quic_initial_crypto_packet(crypto, &dcid, &scid, &[]).expect("Initial builds");

        assert!(datagram.len() >= QUIC_MIN_INITIAL_DATAGRAM_LEN);
        let header = parse_quic_initial_header(&datagram).expect("header parses");
        assert_eq!(header.dcid, dcid);
        assert_eq!(header.scid, scid);
        assert_eq!(
            decrypt_quic_initial_crypto(&datagram).expect("Initial decrypts"),
            crypto
        );
    }

    #[test]
    fn scenario_quic_initial_crypto_rejects_noncontiguous_crypto_frame() {
        let crypto = [QUIC_FRAME_CRYPTO, 1, 1, 0xaa];
        let datagram = seal_client_initial_plaintext_for_test(&crypto, &[]);

        assert!(decrypt_quic_initial_crypto(&datagram).is_err());
    }

    #[test]
    fn scenario_quic_initial_crypto_rejects_unsupported_version() {
        let crypto = b"\x01\x00\x00\x00test-client-hello";
        let mut datagram = seal_client_initial_crypto_for_test(crypto, &[]);
        datagram[1..5].copy_from_slice(&2_u32.to_be_bytes());

        assert!(decrypt_quic_initial_crypto(&datagram).is_err());
    }

    #[test]
    fn scenario_quic_initial_crypto_skips_ack_padding_and_ping() {
        let plaintext = [
            QUIC_FRAME_PADDING,
            QUIC_FRAME_PING,
            QUIC_FRAME_ACK,
            0,
            0,
            0,
            0,
            QUIC_FRAME_CRYPTO,
            0,
            1,
            0xab,
        ];
        let datagram = seal_client_initial_plaintext_for_test(&plaintext, &[]);

        assert_eq!(
            decrypt_quic_initial_crypto(&datagram).expect("Initial decrypts"),
            [0xab]
        );
    }

    #[test]
    fn scenario_quic_initial_crypto_skips_connection_close_frames() {
        let plaintext = [
            QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT,
            0,
            0,
            0,
            QUIC_FRAME_CONNECTION_CLOSE_APPLICATION,
            0,
            0,
            QUIC_FRAME_CRYPTO,
            0,
            1,
            0xcd,
        ];
        let datagram = seal_client_initial_plaintext_for_test(&plaintext, &[]);

        assert_eq!(
            decrypt_quic_initial_crypto(&datagram).expect("Initial decrypts"),
            [0xcd]
        );
    }

    #[test]
    fn scenario_quic_initial_crypto_rejects_missing_and_unknown_crypto_frames() {
        let no_crypto =
            seal_client_initial_plaintext_for_test(&[QUIC_FRAME_PADDING, QUIC_FRAME_PADDING], &[]);
        assert!(decrypt_quic_initial_crypto(&no_crypto).is_err());

        let unknown = seal_client_initial_plaintext_for_test(&[0xff, QUIC_FRAME_PADDING], &[]);
        assert!(decrypt_quic_initial_crypto(&unknown).is_err());
    }

    #[test]
    fn scenario_quic_initial_recovers_auth_token_from_clienthello_carrier() {
        let token = [0x7b_u8; 32];
        let (crypto, fp) = quic_client_hello_crypto_for_test(Vec::new(), token);
        let datagram = seal_client_initial_crypto_for_test(&crypto, &[]);

        assert_eq!(
            recover_quic_auth_token_from_initial(&datagram, &fp).expect("QUIC auth token recovers"),
            token
        );
    }

    #[test]
    fn scenario_quic_initial_rejects_non_empty_legacy_session_id() {
        let token = [0x7b_u8; 32];
        let (crypto, fp) = quic_client_hello_crypto_for_test(vec![0xaa; 32], token);
        let datagram = seal_client_initial_crypto_for_test(&crypto, &[]);

        assert!(recover_quic_auth_token_from_initial(&datagram, &fp).is_err());
    }

    fn quic_client_hello_crypto_for_test(
        session_id: Vec<u8>,
        token: [u8; 32],
    ) -> (Vec<u8>, QuicFingerprint) {
        let mut profile = load_profile("chrome-latest").expect("profile loads");
        profile.alpn = vec!["h3".to_owned()];
        if !profile
            .extension_order
            .contains(&EXT_QUIC_TRANSPORT_PARAMETERS)
        {
            let insert_at = profile
                .extension_order
                .iter()
                .position(|ext| *ext == 0x0015)
                .unwrap_or(profile.extension_order.len());
            profile
                .extension_order
                .insert(insert_at, EXT_QUIC_TRANSPORT_PARAMETERS);
        }
        let fp = quic_fingerprint_from_profile(&profile);
        let keypair = x25519::generate_keypair();
        let record = build_client_hello(&ClientHelloParams {
            sni: "server.example".to_owned(),
            session_id,
            x25519_priv: *keypair.private.expose_secret(),
            x25519_pub: *keypair.public.as_bytes(),
            mlkem: MlkemShare::x25519_mlkem768(vec![0x42; 32]),
            profile,
            random: [0x33; 32],
            quic_transport_parameters: vec![ClientQuicTransportParameter {
                id: fp.grease_parameter,
                value: token.to_vec(),
            }],
        })
        .expect("ClientHello builds");
        (record[5..].to_vec(), fp)
    }

    fn seal_client_initial_crypto_for_test(crypto: &[u8], token: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.push(QUIC_FRAME_CRYPTO);
        write_varint_for_test(0, &mut frame);
        write_varint_for_test(crypto.len(), &mut frame);
        frame.extend_from_slice(crypto);
        seal_client_initial_plaintext_for_test(&frame, token)
    }

    fn seal_client_initial_plaintext_for_test(plaintext: &[u8], token: &[u8]) -> Vec<u8> {
        let dcid = [1_u8, 2, 3, 4, 5, 6, 7, 8];
        let scid = [0xa0_u8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7];
        let packet_number = 1_u64;
        let packet_number_len = 2_usize;
        let suite = initial_quic_suite().expect("suite exists");
        let keys = suite.keys(&dcid, Side::Client, Version::V1);

        let mut header = Vec::new();
        header.push(0xc0 | u8::try_from(packet_number_len - 1).expect("pn len"));
        header.extend_from_slice(&1_u32.to_be_bytes());
        header.push(u8::try_from(dcid.len()).expect("dcid len"));
        header.extend_from_slice(&dcid);
        header.push(u8::try_from(scid.len()).expect("scid len"));
        header.extend_from_slice(&scid);
        write_varint_for_test(token.len(), &mut header);
        header.extend_from_slice(token);
        let payload_len = packet_number_len + plaintext.len() + keys.local.packet.tag_len();
        write_varint_for_test(payload_len, &mut header);
        let packet_number_offset = header.len();
        header.extend_from_slice(&[0, u8::try_from(packet_number).expect("packet number")]);

        let mut payload = plaintext.to_vec();
        let tag = keys
            .local
            .packet
            .encrypt_in_place(packet_number, &header, &mut payload)
            .expect("encrypt Initial");
        let mut packet = header;
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(tag.as_ref());
        add_header_protection_for_test(
            &mut packet,
            packet_number_offset,
            keys.local.header.as_ref(),
        );
        packet
    }

    fn add_header_protection_for_test(
        packet: &mut [u8],
        packet_number_offset: usize,
        key: &dyn HeaderProtectionKey,
    ) {
        let sample_start = packet_number_offset + 4;
        let sample = packet[sample_start..sample_start + key.sample_len()].to_vec();
        let (first, rest) = packet.split_at_mut(1);
        let pn_start = packet_number_offset - 1;
        key.encrypt_in_place(&sample, &mut first[0], &mut rest[pn_start..pn_start + 4])
            .expect("header protection applies");
    }

    fn write_varint_for_test(value: usize, out: &mut Vec<u8>) {
        if value < 64 {
            out.push(u8::try_from(value).expect("varint 1"));
        } else if value < 16_384 {
            let encoded = u16::try_from(value | 0x4000).expect("varint 2");
            out.extend_from_slice(&encoded.to_be_bytes());
        } else {
            panic!("test varint too large");
        }
    }

    #[test]
    #[should_panic(expected = "test varint too large")]
    fn scenario_test_varint_rejects_too_large_values() {
        let mut out = Vec::new();
        write_varint_for_test(16_384, &mut out);
    }
}
