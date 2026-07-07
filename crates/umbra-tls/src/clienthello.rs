//! Chrome-shaped ClientHello construction.

use umbra_crypto::secret::SecretBytes;
use umbra_fingerprint::{
    grease::is_grease,
    profile::{FingerprintError, FingerprintProfile},
};

use crate::TlsError;

/// TLS 1.3 AES-128-GCM-SHA256 cipher suite.
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
/// TLS 1.3 AES-256-GCM-SHA384 cipher suite.
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
/// TLS 1.3 ChaCha20-Poly1305-SHA256 cipher suite.
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
/// X25519 named group.
pub const GROUP_X25519: u16 = 0x001d;
/// Chrome hybrid X25519MLKEM768 group codepoint used by the profile.
pub const GROUP_X25519_MLKEM768: u16 = 0x11ec;
/// TLS extension carrying QUIC transport parameters.
pub const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const RECORD_HANDSHAKE: u8 = 0x16;
const LEGACY_VERSION: u16 = 0x0303;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_ALPN: u16 = 0x0010;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_APPLICATION_SETTINGS: u16 = 0x4469;
const EXT_APPLICATION_SETTINGS_CHROME_150: u16 = 0x44cd;
const EXT_PADDING: u16 = 0x0015;

/// Hybrid key-share bytes offered alongside the classic X25519 share.
pub struct MlkemShare {
    /// Named group for the hybrid share, normally X25519MLKEM768.
    pub group: u16,
    /// Encoded hybrid key exchange bytes.
    pub key_exchange: Vec<u8>,
    /// Client ML-KEM decapsulation key, retained only by live handshake state.
    pub decapsulation_key: Option<SecretBytes>,
}

impl MlkemShare {
    /// Construct a hybrid share with the Chrome X25519MLKEM768 group.
    #[must_use]
    pub fn x25519_mlkem768(key_exchange: Vec<u8>) -> Self {
        Self {
            group: GROUP_X25519_MLKEM768,
            key_exchange,
            decapsulation_key: None,
        }
    }

    /// Construct a hybrid share with the matching client decapsulation key.
    #[must_use]
    pub fn x25519_mlkem768_with_decapsulation_key(
        key_exchange: Vec<u8>,
        decapsulation_key: SecretBytes,
    ) -> Self {
        Self {
            group: GROUP_X25519_MLKEM768,
            key_exchange,
            decapsulation_key: Some(decapsulation_key),
        }
    }
}

impl core::fmt::Debug for MlkemShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlkemShare")
            .field("group", &self.group)
            .field("key_exchange_len", &self.key_exchange.len())
            .field(
                "decapsulation_key",
                &self.decapsulation_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// QUIC transport parameter value inserted into a ClientHello.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientQuicTransportParameter {
    /// Transport parameter identifier.
    pub id: u64,
    /// Raw transport parameter value.
    pub value: Vec<u8>,
}

/// Parameters for deterministic ClientHello construction.
pub struct ClientHelloParams {
    /// Server name indication.
    pub sni: String,
    /// Caller-controlled legacy session id. TCP REALITY uses 32 bytes; QUIC uses empty.
    pub session_id: Vec<u8>,
    /// Caller-owned X25519 private key retained by REALITY.
    pub x25519_priv: [u8; 32],
    /// Classic X25519 public key placed in the key_share extension.
    pub x25519_pub: [u8; 32],
    /// Hybrid key-share bytes for the profile's PQ entry.
    pub mlkem: MlkemShare,
    /// Visible Chrome fingerprint profile.
    pub profile: FingerprintProfile,
    /// Caller-provided ClientHello random.
    pub random: [u8; 32],
    /// QUIC transport parameters with explicit values, keyed by identifier.
    pub quic_transport_parameters: Vec<ClientQuicTransportParameter>,
}

impl core::fmt::Debug for ClientHelloParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientHelloParams")
            .field("sni", &self.sni)
            .field("session_id", &"<redacted>")
            .field("x25519_priv", &"<redacted>")
            .field("x25519_pub", &self.x25519_pub)
            .field("mlkem", &self.mlkem)
            .field("profile", &self.profile.name)
            .field("random", &self.random)
            .field("quic_transport_parameters", &"<redacted>")
            .finish()
    }
}

/// Build one raw ClientHello handshake message.
pub fn build_client_hello_handshake(params: &ClientHelloParams) -> Result<Vec<u8>, TlsError> {
    let mut body_prefix = Vec::new();
    body_prefix.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
    body_prefix.extend_from_slice(&params.random);
    let session_id_len =
        u8::try_from(params.session_id.len()).map_err(|_| TlsError::LengthOutOfRange)?;
    body_prefix.push(session_id_len);
    body_prefix.extend_from_slice(&params.session_id);

    let mut ciphers = Vec::new();
    for cipher in &params.profile.ciphers {
        ciphers.extend_from_slice(&cipher.to_be_bytes());
    }
    push_u16_len(ciphers.len(), &mut body_prefix)?;
    body_prefix.extend_from_slice(&ciphers);
    body_prefix.push(1);
    body_prefix.push(0);

    let extensions = build_extensions(params, body_prefix.len())?;
    let mut body = body_prefix;
    push_u16_len(extensions.len(), &mut body)?;
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(HANDSHAKE_CLIENT_HELLO);
    push_u24_len(body.len(), &mut handshake)?;
    handshake.extend_from_slice(&body);

    Ok(handshake)
}

/// Build a TLS record containing one ClientHello handshake message.
pub fn build_client_hello(params: &ClientHelloParams) -> Result<Vec<u8>, TlsError> {
    let handshake = build_client_hello_handshake(params)?;
    record(RECORD_HANDSHAKE, &handshake)
}

/// Build the HELLO0 associated-data value used by REALITY.
///
/// The returned bytes have the same shape as `client_hello`, with the 32-byte
/// legacy session id zeroed in place.
pub fn hello0(client_hello: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut out = client_hello.to_vec();
    let (handshake_offset, body_offset) = handshake_body_offsets(&out)?;
    let session_len_offset = body_offset
        .checked_add(34)
        .ok_or(TlsError::InvalidInput("ClientHello offset overflow"))?;
    let session_len = usize::from(
        *out.get(session_len_offset)
            .ok_or(TlsError::InvalidInput("missing session id length"))?,
    );
    if session_len != 32 {
        return Err(TlsError::InvalidInput("session id is not 32 bytes"));
    }
    let session_start = session_len_offset + 1;
    let session_end = session_start
        .checked_add(session_len)
        .ok_or(TlsError::InvalidInput("session id offset overflow"))?;
    if session_end > handshake_offset + 4 + declared_handshake_len(&out[handshake_offset..])? {
        return Err(TlsError::InvalidInput("session id exceeds ClientHello"));
    }
    out[session_start..session_end].fill(0);
    Ok(out)
}

/// Build QUIC REALITY associated data by zeroing the GREASE carrier value.
///
/// The input may be a raw ClientHello handshake or a TLS record containing one
/// ClientHello. QUIC requires an empty `legacy_session_id`, so the only bytes
/// cleared are the selected GREASE QUIC transport parameter value.
pub fn quic_hello0(client_hello: &[u8], grease_parameter: u64) -> Result<Vec<u8>, TlsError> {
    let mut out = client_hello.to_vec();
    let (handshake_offset, body_offset) = handshake_body_offsets(&out)?;
    let declared = declared_handshake_len(&out[handshake_offset..])?;
    let handshake_end = handshake_offset
        .checked_add(4)
        .and_then(|offset| offset.checked_add(declared))
        .ok_or(TlsError::InvalidInput("ClientHello offset overflow"))?;
    if handshake_end > out.len() {
        return Err(TlsError::InvalidInput("truncated ClientHello"));
    }

    let mut offset = body_offset;
    skip_bytes(&out, &mut offset, 2)?;
    skip_bytes(&out, &mut offset, 32)?;
    let session_len = usize::from(read_u8(&out, &mut offset)?);
    if session_len != 0 {
        return Err(TlsError::InvalidInput(
            "QUIC ClientHello session id is not empty",
        ));
    }
    skip_bytes(&out, &mut offset, session_len)?;

    let cipher_len = usize::from(read_u16(&out, &mut offset)?);
    skip_bytes(&out, &mut offset, cipher_len)?;
    let compression_len = usize::from(read_u8(&out, &mut offset)?);
    skip_bytes(&out, &mut offset, compression_len)?;
    let all_extensions_len = usize::from(read_u16(&out, &mut offset)?);
    let all_extensions_end = offset
        .checked_add(all_extensions_len)
        .ok_or(TlsError::InvalidInput("ClientHello offset overflow"))?;
    if all_extensions_end > handshake_end {
        return Err(TlsError::InvalidInput("extensions exceed ClientHello"));
    }

    let mut cleared = false;
    while offset < all_extensions_end {
        let extension_type = read_u16(&out, &mut offset)?;
        let this_extension_len = usize::from(read_u16(&out, &mut offset)?);
        let this_extension_end = offset
            .checked_add(this_extension_len)
            .ok_or(TlsError::InvalidInput("extension offset overflow"))?;
        if this_extension_end > all_extensions_end {
            return Err(TlsError::InvalidInput("extension exceeds ClientHello"));
        }
        if extension_type == EXT_QUIC_TRANSPORT_PARAMETERS {
            cleared |= clear_quic_transport_parameter(
                &mut out,
                offset,
                this_extension_end,
                grease_parameter,
            )?;
        }
        offset = this_extension_end;
    }
    if !cleared {
        return Err(TlsError::InvalidInput("QUIC GREASE auth carrier missing"));
    }
    Ok(out)
}

fn build_extensions(
    params: &ClientHelloParams,
    body_prefix_len: usize,
) -> Result<Vec<u8>, TlsError> {
    let mut extensions = Vec::new();
    for ext in &params.profile.extension_order {
        if *ext == EXT_PADDING {
            let record_len_with_empty_padding = 5 + 4 + body_prefix_len + 2 + extensions.len() + 4;
            let padding_len = params
                .profile
                .padding_target
                .saturating_sub(record_len_with_empty_padding);
            push_extension(*ext, &vec![0_u8; padding_len], &mut extensions)?;
        } else {
            let data = extension_data(*ext, params)?;
            push_extension(*ext, &data, &mut extensions)?;
        }
    }
    Ok(extensions)
}

fn extension_data(ext: u16, params: &ClientHelloParams) -> Result<Vec<u8>, TlsError> {
    match ext {
        value if is_grease(value) => Ok(Vec::new()),
        EXT_SERVER_NAME => server_name(&params.sni),
        EXT_EXTENDED_MASTER_SECRET | EXT_SESSION_TICKET | EXT_SIGNED_CERTIFICATE_TIMESTAMP => {
            Ok(Vec::new())
        }
        EXT_RENEGOTIATION_INFO => Ok(vec![0]),
        EXT_SUPPORTED_GROUPS => vector_u16(&params.profile.supported_groups),
        EXT_EC_POINT_FORMATS => Ok(vec![1, 0]),
        EXT_ALPN => alpn_wire(&params.profile.alpn),
        EXT_STATUS_REQUEST => Ok(vec![1, 0, 0, 0, 0]),
        EXT_SIGNATURE_ALGORITHMS => vector_u16(&params.profile.signature_algorithms),
        EXT_KEY_SHARE => key_share(params),
        EXT_PSK_KEY_EXCHANGE_MODES => Ok(vec![1, 1]),
        EXT_SUPPORTED_VERSIONS => supported_versions(&params.profile),
        EXT_COMPRESS_CERTIFICATE => vector_u16(&[2]),
        EXT_APPLICATION_SETTINGS | EXT_APPLICATION_SETTINGS_CHROME_150 => {
            alpn_wire(&params.profile.alps)
        }
        EXT_QUIC_TRANSPORT_PARAMETERS => quic_transport_parameters(params),
        _ => Ok(Vec::new()),
    }
}

fn server_name(sni: &str) -> Result<Vec<u8>, TlsError> {
    let host = sni.as_bytes();
    if host.is_empty() {
        return Err(TlsError::InvalidInput("SNI is empty"));
    }
    let mut list = Vec::new();
    list.push(0);
    push_u16_len(host.len(), &mut list)?;
    list.extend_from_slice(host);
    let mut out = Vec::new();
    push_u16_len(list.len(), &mut out)?;
    out.extend_from_slice(&list);
    Ok(out)
}

fn vector_u16(values: &[u16]) -> Result<Vec<u8>, TlsError> {
    let mut items = Vec::new();
    for value in values {
        items.extend_from_slice(&value.to_be_bytes());
    }
    let mut out = Vec::new();
    push_u16_len(items.len(), &mut out)?;
    out.extend_from_slice(&items);
    Ok(out)
}

fn alpn_wire(protocols: &[String]) -> Result<Vec<u8>, TlsError> {
    let mut list = Vec::new();
    for protocol in protocols {
        let bytes = protocol.as_bytes();
        let len = u8::try_from(bytes.len()).map_err(|_| TlsError::LengthOutOfRange)?;
        list.push(len);
        list.extend_from_slice(bytes);
    }
    let mut out = Vec::new();
    push_u16_len(list.len(), &mut out)?;
    out.extend_from_slice(&list);
    Ok(out)
}

fn key_share(params: &ClientHelloParams) -> Result<Vec<u8>, TlsError> {
    let mut entries = Vec::new();
    for group in &params.profile.supported_groups {
        if is_grease(*group) {
            push_key_share_entry(*group, &[0], &mut entries)?;
        } else if *group == params.mlkem.group {
            push_key_share_entry(*group, &params.mlkem.key_exchange, &mut entries)?;
        } else if *group == GROUP_X25519 {
            push_key_share_entry(*group, &params.x25519_pub, &mut entries)?;
        }
    }

    let mut out = Vec::new();
    push_u16_len(entries.len(), &mut out)?;
    out.extend_from_slice(&entries);
    Ok(out)
}

fn supported_versions(profile: &FingerprintProfile) -> Result<Vec<u8>, TlsError> {
    let mut versions = Vec::new();
    for version in &profile.supported_versions {
        versions.extend_from_slice(&version.to_be_bytes());
    }
    let mut out = Vec::new();
    let len = u8::try_from(versions.len()).map_err(|_| TlsError::LengthOutOfRange)?;
    out.push(len);
    out.extend_from_slice(&versions);
    Ok(out)
}

fn quic_transport_parameters(params: &ClientHelloParams) -> Result<Vec<u8>, TlsError> {
    let mut out = Vec::new();
    for parameter in &params.profile.quic.transport_parameters {
        let Some(configured) = params
            .quic_transport_parameters
            .iter()
            .find(|configured| configured.id == *parameter)
        else {
            continue;
        };
        write_quic_varint(*parameter, &mut out)?;
        let value = configured.value.as_slice();
        write_quic_varint(
            u64::try_from(value.len()).map_err(|_| TlsError::LengthOutOfRange)?,
            &mut out,
        )?;
        out.extend_from_slice(value);
    }
    for configured in &params.quic_transport_parameters {
        if params
            .profile
            .quic
            .transport_parameters
            .contains(&configured.id)
        {
            continue;
        }
        write_quic_varint(configured.id, &mut out)?;
        write_quic_varint(
            u64::try_from(configured.value.len()).map_err(|_| TlsError::LengthOutOfRange)?,
            &mut out,
        )?;
        out.extend_from_slice(&configured.value);
    }
    Ok(out)
}

fn push_key_share_entry(
    group: u16,
    key_exchange: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), TlsError> {
    out.extend_from_slice(&group.to_be_bytes());
    push_u16_len(key_exchange.len(), out)?;
    out.extend_from_slice(key_exchange);
    Ok(())
}

fn push_extension(ext: u16, data: &[u8], out: &mut Vec<u8>) -> Result<(), TlsError> {
    out.extend_from_slice(&ext.to_be_bytes());
    push_u16_len(data.len(), out)?;
    out.extend_from_slice(data);
    Ok(())
}

fn record(content_type: u8, payload: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut out = Vec::new();
    out.push(content_type);
    out.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
    push_u16_len(payload.len(), &mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

fn handshake_body_offsets(input: &[u8]) -> Result<(usize, usize), TlsError> {
    let handshake_offset = if input.first() == Some(&RECORD_HANDSHAKE) {
        if input.len() < 5 {
            return Err(TlsError::InvalidInput("short TLS record"));
        }
        5
    } else {
        0
    };
    if input.get(handshake_offset) != Some(&HANDSHAKE_CLIENT_HELLO) {
        return Err(TlsError::InvalidInput("not a ClientHello"));
    }
    Ok((handshake_offset, handshake_offset + 4))
}

fn declared_handshake_len(handshake: &[u8]) -> Result<usize, TlsError> {
    if handshake.len() < 4 {
        return Err(TlsError::InvalidInput("short handshake"));
    }
    Ok((usize::from(handshake[1]) << 16)
        | (usize::from(handshake[2]) << 8)
        | usize::from(handshake[3]))
}

fn push_u16_len(value: usize, out: &mut Vec<u8>) -> Result<(), TlsError> {
    let value = u16::try_from(value).map_err(|_| TlsError::LengthOutOfRange)?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn push_u24_len(value: usize, out: &mut Vec<u8>) -> Result<(), TlsError> {
    if value > 0x00ff_ffff {
        return Err(TlsError::LengthOutOfRange);
    }
    out.push(u8::try_from((value >> 16) & 0xff).map_err(|_| TlsError::LengthOutOfRange)?);
    out.push(u8::try_from((value >> 8) & 0xff).map_err(|_| TlsError::LengthOutOfRange)?);
    out.push(u8::try_from(value & 0xff).map_err(|_| TlsError::LengthOutOfRange)?);
    Ok(())
}

fn clear_quic_transport_parameter(
    out: &mut [u8],
    mut offset: usize,
    end: usize,
    grease_parameter: u64,
) -> Result<bool, TlsError> {
    let mut cleared = false;
    while offset < end {
        let id = read_quic_varint_at(out, end, &mut offset)?;
        let len = usize::try_from(read_quic_varint_at(out, end, &mut offset)?)
            .map_err(|_| TlsError::LengthOutOfRange)?;
        let value_end = offset
            .checked_add(len)
            .ok_or(TlsError::InvalidInput("QUIC transport parameter overflow"))?;
        if value_end > end {
            return Err(TlsError::InvalidInput(
                "QUIC transport parameter exceeds extension",
            ));
        }
        if id == grease_parameter {
            out[offset..value_end].fill(0);
            cleared = true;
        }
        offset = value_end;
    }
    Ok(cleared)
}

fn read_quic_varint_at(input: &[u8], limit: usize, offset: &mut usize) -> Result<u64, TlsError> {
    let first = *input
        .get(*offset)
        .ok_or(TlsError::InvalidInput("missing QUIC varint"))?;
    let len = 1_usize << usize::from(first >> 6);
    let end = (*offset)
        .checked_add(len)
        .ok_or(TlsError::InvalidInput("QUIC varint offset overflow"))?;
    if end > limit {
        return Err(TlsError::InvalidInput("truncated QUIC varint"));
    }
    let bytes = input
        .get(*offset..end)
        .ok_or(TlsError::InvalidInput("truncated QUIC varint"))?;
    let mut value = u64::from(bytes[0] & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    *offset = end;
    Ok(value)
}

fn read_u16(input: &[u8], offset: &mut usize) -> Result<u16, TlsError> {
    let end = (*offset)
        .checked_add(2)
        .ok_or(TlsError::InvalidInput("ClientHello offset overflow"))?;
    let bytes = input
        .get(*offset..end)
        .ok_or(TlsError::InvalidInput("truncated ClientHello field"))?;
    *offset = end;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u8(input: &[u8], offset: &mut usize) -> Result<u8, TlsError> {
    let value = *input
        .get(*offset)
        .ok_or(TlsError::InvalidInput("truncated ClientHello field"))?;
    *offset += 1;
    Ok(value)
}

fn skip_bytes(input: &[u8], offset: &mut usize, len: usize) -> Result<(), TlsError> {
    let end = (*offset)
        .checked_add(len)
        .ok_or(TlsError::InvalidInput("ClientHello offset overflow"))?;
    if end > input.len() {
        return Err(TlsError::InvalidInput("truncated ClientHello field"));
    }
    *offset = end;
    Ok(())
}

fn write_quic_varint(value: u64, out: &mut Vec<u8>) -> Result<(), TlsError> {
    if value < 64 {
        out.push(u8::try_from(value).map_err(|_| TlsError::LengthOutOfRange)?);
    } else if value < 16_384 {
        let encoded = u16::try_from(value | 0x4000).map_err(|_| TlsError::LengthOutOfRange)?;
        out.extend_from_slice(&encoded.to_be_bytes());
    } else if value < 1_073_741_824 {
        let encoded = u32::try_from(value | 0x8000_0000).map_err(|_| TlsError::LengthOutOfRange)?;
        out.extend_from_slice(&encoded.to_be_bytes());
    } else if value < 4_611_686_018_427_387_904 {
        let encoded = value | 0xc000_0000_0000_0000;
        out.extend_from_slice(&encoded.to_be_bytes());
    } else {
        return Err(TlsError::LengthOutOfRange);
    }
    Ok(())
}

impl From<FingerprintError> for TlsError {
    fn from(_: FingerprintError) -> Self {
        Self::InvalidInput("fingerprint profile error")
    }
}
