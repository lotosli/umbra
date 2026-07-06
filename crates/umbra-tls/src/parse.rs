//! Safe parsers for ClientHello-visible fields.

use umbra_fingerprint::grease::is_grease;

use crate::{
    clienthello::{EXT_QUIC_TRANSPORT_PARAMETERS, GROUP_X25519},
    TlsError,
};

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const RECORD_HANDSHAKE: u8 = 0x16;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_KEY_SHARE: u16 = 0x0033;

/// Parsed key share entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedKeyShare {
    /// Named group identifier.
    pub group: u16,
    /// Key exchange bytes.
    pub key_exchange: Vec<u8>,
}

/// Parsed QUIC transport parameter.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QuicTransportParameter {
    /// Parameter identifier.
    pub id: u64,
    /// Raw parameter value bytes.
    pub value: Vec<u8>,
}

/// Parsed ClientHello fields needed by REALITY and dispatch.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedClientHello {
    /// SNI host name, when present.
    pub sni: Option<String>,
    /// Compatibility session id bytes.
    pub session_id: Vec<u8>,
    /// Classic X25519 key share, when present.
    pub x25519_key_share: Option<[u8; 32]>,
    /// Extension identifiers in wire order.
    pub extensions: Vec<u16>,
    /// Parsed key-share entries in wire order.
    pub key_shares: Vec<ParsedKeyShare>,
    /// QUIC transport parameters, when carried in ClientHello.
    pub quic_transport_parameters: Vec<QuicTransportParameter>,
    /// Values from GREASE-looking QUIC transport parameters.
    pub quic_auth_carriers: Vec<Vec<u8>>,
}

/// Parse a ClientHello from a TLS record or raw handshake bytes.
pub fn parse_client_hello(input: &[u8]) -> Result<ParsedClientHello, TlsError> {
    let handshake = handshake_bytes(input)?;
    if handshake.len() < 4 || handshake[0] != HANDSHAKE_CLIENT_HELLO {
        return Err(TlsError::InvalidInput("not a ClientHello"));
    }
    let declared = read_u24(&handshake[1..4])?;
    if handshake.len() < 4 + declared {
        return Err(TlsError::InvalidInput("truncated ClientHello"));
    }
    parse_body(&handshake[4..4 + declared])
}

fn parse_body(body: &[u8]) -> Result<ParsedClientHello, TlsError> {
    let mut offset = 0;
    let _legacy_version = read_u16_at(body, &mut offset)?;
    skip(body, &mut offset, 32)?;

    let session_len = usize::from(read_u8_at(body, &mut offset)?);
    let session_id = take(body, &mut offset, session_len)?.to_vec();

    let cipher_len = usize::from(read_u16_at(body, &mut offset)?);
    if !cipher_len.is_multiple_of(2) {
        return Err(TlsError::InvalidInput("odd cipher suite vector"));
    }
    skip(body, &mut offset, cipher_len)?;

    let compression_len = usize::from(read_u8_at(body, &mut offset)?);
    skip(body, &mut offset, compression_len)?;

    let mut sni = None;
    let mut extensions = Vec::new();
    let mut key_shares = Vec::new();
    let mut quic_transport_parameters = Vec::new();
    let mut quic_auth_carriers = Vec::new();

    if offset < body.len() {
        let ext_len = usize::from(read_u16_at(body, &mut offset)?);
        let ext_end = checked_end(offset, ext_len)?;
        if ext_end > body.len() {
            return Err(TlsError::InvalidInput("extensions exceed ClientHello"));
        }
        while offset < ext_end {
            let ext_type = read_u16_at(body, &mut offset)?;
            let data_len = usize::from(read_u16_at(body, &mut offset)?);
            let data = take(body, &mut offset, data_len)?;
            extensions.push(ext_type);
            match ext_type {
                EXT_SERVER_NAME => sni = parse_sni(data)?,
                EXT_KEY_SHARE => key_shares = parse_key_shares(data)?,
                EXT_QUIC_TRANSPORT_PARAMETERS => {
                    quic_transport_parameters = parse_quic_transport_parameters(data)?;
                    quic_auth_carriers = quic_transport_parameters
                        .iter()
                        .filter(|param| is_grease_u64(param.id))
                        .map(|param| param.value.clone())
                        .collect();
                }
                _ => {}
            }
        }
        if offset != ext_end {
            return Err(TlsError::InvalidInput("extension parser lost sync"));
        }
    }

    let x25519_key_share = key_shares.iter().find_map(|share| {
        if share.group == GROUP_X25519 && share.key_exchange.len() == 32 {
            share.key_exchange.as_slice().try_into().ok()
        } else {
            None
        }
    });

    Ok(ParsedClientHello {
        sni,
        session_id,
        x25519_key_share,
        extensions,
        key_shares,
        quic_transport_parameters,
        quic_auth_carriers,
    })
}

fn parse_sni(data: &[u8]) -> Result<Option<String>, TlsError> {
    let mut offset = 0;
    let list_len = usize::from(read_u16_at(data, &mut offset)?);
    let list_end = checked_end(offset, list_len)?;
    if list_end != data.len() {
        return Err(TlsError::InvalidInput("bad SNI list length"));
    }
    while offset < list_end {
        let name_type = read_u8_at(data, &mut offset)?;
        let name_len = usize::from(read_u16_at(data, &mut offset)?);
        let name = take(data, &mut offset, name_len)?;
        if name_type == 0 {
            let host = core::str::from_utf8(name)
                .map_err(|_| TlsError::InvalidInput("SNI is not UTF-8"))?;
            return Ok(Some(host.to_owned()));
        }
    }
    Ok(None)
}

fn parse_key_shares(data: &[u8]) -> Result<Vec<ParsedKeyShare>, TlsError> {
    let mut offset = 0;
    let total = usize::from(read_u16_at(data, &mut offset)?);
    let end = checked_end(offset, total)?;
    if end != data.len() {
        return Err(TlsError::InvalidInput("bad key_share length"));
    }
    let mut out = Vec::new();
    while offset < end {
        let group = read_u16_at(data, &mut offset)?;
        let len = usize::from(read_u16_at(data, &mut offset)?);
        let key_exchange = take(data, &mut offset, len)?.to_vec();
        out.push(ParsedKeyShare {
            group,
            key_exchange,
        });
    }
    Ok(out)
}

fn parse_quic_transport_parameters(data: &[u8]) -> Result<Vec<QuicTransportParameter>, TlsError> {
    let mut offset = 0;
    let mut out = Vec::new();
    while offset < data.len() {
        let id = read_quic_varint(data, &mut offset)?;
        let len = usize::try_from(read_quic_varint(data, &mut offset)?)
            .map_err(|_| TlsError::LengthOutOfRange)?;
        let value = take(data, &mut offset, len)?.to_vec();
        out.push(QuicTransportParameter { id, value });
    }
    Ok(out)
}

fn handshake_bytes(input: &[u8]) -> Result<&[u8], TlsError> {
    if input.first() == Some(&RECORD_HANDSHAKE) {
        if input.len() < 5 {
            return Err(TlsError::InvalidInput("short TLS record"));
        }
        let len = usize::from(u16::from_be_bytes([input[3], input[4]]));
        if input.len() < 5 + len {
            return Err(TlsError::InvalidInput("truncated TLS record"));
        }
        Ok(&input[5..5 + len])
    } else {
        Ok(input)
    }
}

fn read_u8_at(input: &[u8], offset: &mut usize) -> Result<u8, TlsError> {
    let byte = *input
        .get(*offset)
        .ok_or(TlsError::InvalidInput("unexpected end of input"))?;
    *offset += 1;
    Ok(byte)
}

fn read_u16_at(input: &[u8], offset: &mut usize) -> Result<u16, TlsError> {
    let bytes = take(input, offset, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take<'a>(input: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], TlsError> {
    let end = checked_end(*offset, len)?;
    if end > input.len() {
        return Err(TlsError::InvalidInput("unexpected end of input"));
    }
    let out = &input[*offset..end];
    *offset = end;
    Ok(out)
}

fn skip(input: &[u8], offset: &mut usize, len: usize) -> Result<(), TlsError> {
    take(input, offset, len).map(|_| ())
}

fn read_u24(input: &[u8]) -> Result<usize, TlsError> {
    if input.len() != 3 {
        return Err(TlsError::InvalidInput("bad uint24"));
    }
    Ok((usize::from(input[0]) << 16) | (usize::from(input[1]) << 8) | usize::from(input[2]))
}

fn read_quic_varint(input: &[u8], offset: &mut usize) -> Result<u64, TlsError> {
    let first = read_u8_at(input, offset)?;
    let prefix = first >> 6;
    let len = 1_usize << usize::from(prefix);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..len {
        value = (value << 8) | u64::from(read_u8_at(input, offset)?);
    }
    Ok(value)
}

fn checked_end(offset: usize, len: usize) -> Result<usize, TlsError> {
    offset
        .checked_add(len)
        .ok_or(TlsError::InvalidInput("offset overflow"))
}

fn is_grease_u64(value: u64) -> bool {
    u16::try_from(value).is_ok_and(is_grease)
}
