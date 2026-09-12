//! JA3 and JA4 self-check helpers for ClientHello bytes.

use md5::{Digest as Md5Digest, Md5};
use sha2::Sha256;

use crate::{
    grease::without_grease,
    profile::{FingerprintError, FingerprintProfile},
};

/// Parsed visible ClientHello fields used for fingerprinting.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientHelloFingerprint {
    /// ClientHello legacy version.
    pub legacy_version: u16,
    /// Cipher suites in wire order.
    pub ciphers: Vec<u16>,
    /// Extension identifiers in wire order.
    pub extensions: Vec<u16>,
    /// Supported groups from extension 10.
    pub supported_groups: Vec<u16>,
    /// EC point formats from extension 11.
    pub ec_point_formats: Vec<u8>,
    /// Offered TLS versions from extension 43, in wire order (including GREASE).
    pub supported_versions: Vec<u16>,
    /// Whether a structurally valid SNI extension is present; no hostname is retained.
    pub has_sni: bool,
    /// ALPN protocol identifiers as opaque bytes, in wire order.
    pub alpn: Vec<Vec<u8>>,
    /// Signature algorithms from extension 13, in wire order (including GREASE).
    pub signature_algorithms: Vec<u16>,
}

/// Transport carrying a ClientHello, independent of its record framing.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Ja4Transport {
    /// TLS over TCP.
    Tcp,
    /// TLS carried in QUIC CRYPTO frames.
    Quic,
}

impl ClientHelloFingerprint {
    /// Build the canonical JA3 string with GREASE values removed.
    #[must_use]
    pub fn ja3_string(&self) -> String {
        format!(
            "{},{},{},{},{}",
            self.legacy_version,
            join_u16(&without_grease(&self.ciphers)),
            join_u16(&without_grease(&self.extensions)),
            join_u16(&without_grease(&self.supported_groups)),
            join_u8(&self.ec_point_formats)
        )
    }

    /// Build the JA3 MD5 hash.
    #[must_use]
    pub fn ja3_hash(&self) -> String {
        let digest = Md5::digest(self.ja3_string().as_bytes());
        hex_lower(&digest)
    }

    /// Build standard JA4 for TLS over TCP.
    ///
    /// For a QUIC ClientHello use [`Self::ja4_with_transport`] explicitly.
    #[must_use]
    pub fn ja4(&self) -> String {
        self.ja4_with_transport(Ja4Transport::Tcp)
    }

    /// Build standard JA4 with explicit transport context.
    ///
    /// Independently implemented from FoxIO's BSD-3-Clause JA4 definition at
    /// `d3dedafd6d3ac27a37107183533fc7274c5f4ea9/technical_details/JA4.md`.
    /// Record framing never determines transport. GREASE is ignored; ciphers
    /// and extensions are sorted, but signature algorithms retain wire order.
    #[must_use]
    pub fn ja4_with_transport(&self, transport: Ja4Transport) -> String {
        let mut ciphers = without_grease(&self.ciphers);
        let mut extensions = without_grease(&self.extensions);
        let cipher_count = ciphers.len().min(99);
        let extension_count = extensions.len().min(99);
        ciphers.sort_unstable();
        extensions.retain(|extension| !matches!(extension, 0x0000 | 0x0010));
        extensions.sort_unstable();
        let cipher_hash = ja4_hash(&join_hex(&ciphers));
        let mut extension_input = join_hex(&extensions);
        let signatures = without_grease(&self.signature_algorithms);
        // An empty sorted extension list is always represented by twelve zeros.
        if !extensions.is_empty() && !signatures.is_empty() {
            extension_input.push('_');
            extension_input.push_str(&join_hex(&signatures));
        }
        let extension_hash = ja4_hash(&extension_input);
        let version = if self.extensions.contains(&0x002b) {
            without_grease(&self.supported_versions)
                .into_iter()
                .max()
                .unwrap_or(0)
        } else {
            self.legacy_version
        };
        let transport = match transport {
            Ja4Transport::Tcp => 't',
            Ja4Transport::Quic => 'q',
        };
        let sni = if self.has_sni { 'd' } else { 'i' };
        format!(
            "{transport}{}{sni}{cipher_count:02}{extension_count:02}{}_{cipher_hash}_{extension_hash}",
            ja4_version(version),
            ja4_alpn(&self.alpn)
        )
    }
}

/// Compute the JA3 hash and standard JA4 for TLS over TCP.
///
/// Both TLS records and raw handshake messages default to TCP. Use
/// [`ja3_ja4_with_transport`] for QUIC; framing is not transport evidence.
pub fn ja3_ja4(client_hello: &[u8]) -> Result<(String, String), FingerprintError> {
    ja3_ja4_with_transport(client_hello, Ja4Transport::Tcp)
}

/// Compute the JA3 hash and standard JA4 with explicit transport context.
pub fn ja3_ja4_with_transport(
    client_hello: &[u8],
    transport: Ja4Transport,
) -> Result<(String, String), FingerprintError> {
    let parsed = parse_client_hello(client_hello)?;
    Ok((parsed.ja3_hash(), parsed.ja4_with_transport(transport)))
}

/// Parse visible ClientHello fields from either a TLS record or raw handshake message.
pub fn parse_client_hello(input: &[u8]) -> Result<ClientHelloFingerprint, FingerprintError> {
    let handshake = handshake_bytes(input)?;
    if handshake.len() < 4 || handshake[0] != 0x01 {
        return Err(FingerprintError::InvalidClientHello);
    }
    let declared = read_u24(&handshake[1..4])?;
    if handshake.len() < 4 + declared {
        return Err(FingerprintError::InvalidClientHello);
    }
    let body = &handshake[4..4 + declared];
    parse_client_hello_body(body)
}

/// Build a deterministic ClientHello fixture from a profile.
///
/// This is used by profile tests and early TLS-builder tests; the real TLS
/// crate owns production ClientHello construction.
pub fn build_profile_fixture(profile: &FingerprintProfile) -> Result<Vec<u8>, FingerprintError> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303_u16.to_be_bytes());
    body.extend_from_slice(&[0x11; 32]);
    body.push(32);
    body.extend_from_slice(&[0x22; 32]);

    let mut ciphers = Vec::with_capacity(profile.ciphers.len() * 2);
    for cipher in &profile.ciphers {
        ciphers.extend_from_slice(&cipher.to_be_bytes());
    }
    push_u16_len(ciphers.len(), &mut body)?;
    body.extend_from_slice(&ciphers);
    body.push(1);
    body.push(0);

    let mut extensions = Vec::new();
    for ext in &profile.extension_order {
        extensions.extend_from_slice(&ext.to_be_bytes());
        let data = extension_fixture_data(*ext, profile)?;
        push_u16_len(data.len(), &mut extensions)?;
        extensions.extend_from_slice(&data);
    }
    push_u16_len(extensions.len(), &mut body)?;
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    write_u24(body.len(), &mut handshake)?;
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&0x0301_u16.to_be_bytes());
    push_u16_len(handshake.len(), &mut record)?;
    record.extend_from_slice(&handshake);
    Ok(record)
}

fn parse_client_hello_body(body: &[u8]) -> Result<ClientHelloFingerprint, FingerprintError> {
    let mut offset = 0;
    let legacy_version = read_u16_at(body, &mut offset)?;
    skip(body, &mut offset, 32)?;
    let session_id_len = usize::from(read_u8_at(body, &mut offset)?);
    if session_id_len > 32 {
        return Err(FingerprintError::InvalidClientHello);
    }
    skip(body, &mut offset, session_id_len)?;

    let cipher_len = usize::from(read_u16_at(body, &mut offset)?);
    if cipher_len == 0 || !cipher_len.is_multiple_of(2) {
        return Err(FingerprintError::InvalidClientHello);
    }
    let ciphers = decode_u16_list(take(body, &mut offset, cipher_len)?);
    let compression_len = usize::from(read_u8_at(body, &mut offset)?);
    if compression_len == 0 {
        return Err(FingerprintError::InvalidClientHello);
    }
    skip(body, &mut offset, compression_len)?;

    let mut parsed = ClientHelloFingerprint {
        legacy_version,
        ciphers,
        extensions: Vec::new(),
        supported_groups: Vec::new(),
        ec_point_formats: Vec::new(),
        supported_versions: Vec::new(),
        has_sni: false,
        alpn: Vec::new(),
        signature_algorithms: Vec::new(),
    };
    if offset < body.len() {
        let ext_len = usize::from(read_u16_at(body, &mut offset)?);
        let data = take(body, &mut offset, ext_len)?;
        if offset != body.len() {
            return Err(FingerprintError::InvalidClientHello);
        }
        parse_extensions(data, &mut parsed)?;
    }
    Ok(parsed)
}

fn parse_extensions(
    input: &[u8],
    parsed: &mut ClientHelloFingerprint,
) -> Result<(), FingerprintError> {
    let mut offset = 0;
    let mut seen = std::collections::BTreeSet::new();
    while offset < input.len() {
        let ext_type = read_u16_at(input, &mut offset)?;
        let data_len = usize::from(read_u16_at(input, &mut offset)?);
        let data = take(input, &mut offset, data_len)?;
        if !seen.insert(ext_type) {
            return Err(FingerprintError::InvalidClientHello);
        }
        parsed.extensions.push(ext_type);
        match ext_type {
            0x0000 => {
                validate_sni(data)?;
                parsed.has_sni = true;
            }
            0x000a => parsed.supported_groups = parse_u16_vector(data)?,
            0x000b => parsed.ec_point_formats = parse_ec_point_formats(data)?,
            0x000d => parsed.signature_algorithms = parse_u16_vector(data)?,
            0x0010 => parsed.alpn = parse_alpn(data)?,
            0x002b => parsed.supported_versions = parse_supported_versions(data)?,
            _ => {}
        }
    }
    Ok(())
}

fn handshake_bytes(input: &[u8]) -> Result<&[u8], FingerprintError> {
    if input.first() == Some(&0x16) {
        if input.len() < 5 {
            return Err(FingerprintError::InvalidClientHello);
        }
        let len = usize::from(u16::from_be_bytes([input[3], input[4]]));
        if input.len() < 5 + len {
            return Err(FingerprintError::InvalidClientHello);
        }
        Ok(&input[5..5 + len])
    } else {
        Ok(input)
    }
}

fn parse_u16_vector(data: &[u8]) -> Result<Vec<u16>, FingerprintError> {
    let list = u16_vector_bytes(data)?;
    if list.is_empty() || !list.len().is_multiple_of(2) {
        return Err(FingerprintError::InvalidClientHello);
    }
    Ok(decode_u16_list(list))
}

fn decode_u16_list(data: &[u8]) -> Vec<u16> {
    data.chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect()
}

fn u16_vector_bytes(data: &[u8]) -> Result<&[u8], FingerprintError> {
    let mut offset = 0;
    let len = usize::from(read_u16_at(data, &mut offset)?);
    let list = take(data, &mut offset, len)?;
    if offset != data.len() {
        return Err(FingerprintError::InvalidClientHello);
    }
    Ok(list)
}

fn parse_ec_point_formats(data: &[u8]) -> Result<Vec<u8>, FingerprintError> {
    let Some((&len, rest)) = data.split_first() else {
        return Err(FingerprintError::InvalidClientHello);
    };
    if len == 0 || rest.len() != usize::from(len) {
        return Err(FingerprintError::InvalidClientHello);
    }
    Ok(rest.to_vec())
}

fn parse_supported_versions(data: &[u8]) -> Result<Vec<u16>, FingerprintError> {
    let bytes = parse_ec_point_formats(data)?;
    if !bytes.len().is_multiple_of(2) {
        return Err(FingerprintError::InvalidClientHello);
    }
    Ok(decode_u16_list(&bytes))
}

fn validate_sni(data: &[u8]) -> Result<(), FingerprintError> {
    let list = u16_vector_bytes(data)?;
    let mut offset = 0;
    // host_name (0) is the only defined NameType, and may appear only once.
    if read_u8_at(list, &mut offset)? != 0 {
        return Err(FingerprintError::InvalidClientHello);
    }
    let len = usize::from(read_u16_at(list, &mut offset)?);
    skip(list, &mut offset, len)?;
    if len == 0 || offset != list.len() {
        return Err(FingerprintError::InvalidClientHello);
    }
    Ok(())
}

fn parse_alpn(data: &[u8]) -> Result<Vec<Vec<u8>>, FingerprintError> {
    let list = u16_vector_bytes(data)?;
    if list.is_empty() {
        return Err(FingerprintError::InvalidClientHello);
    }
    let mut offset = 0;
    let mut protocols = Vec::new();
    while offset < list.len() {
        let len = usize::from(read_u8_at(list, &mut offset)?);
        if len == 0 {
            return Err(FingerprintError::InvalidClientHello);
        }
        protocols.push(take(list, &mut offset, len)?.to_vec());
    }
    Ok(protocols)
}

fn extension_fixture_data(
    ext_type: u16,
    profile: &FingerprintProfile,
) -> Result<Vec<u8>, FingerprintError> {
    match ext_type {
        // Synthetic hostname: JA4 records presence only, never the name itself.
        0x0000 => Ok(vec![
            0, 12, 0, 0, 9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't',
        ]),
        0x000a => fixture_u16_vector(&profile.supported_groups),
        0x000b => Ok(vec![1, 0]),
        0x000d => fixture_u16_vector(&profile.signature_algorithms),
        0x0010 => {
            let mut protocols = Vec::new();
            for protocol in &profile.alpn {
                push_u8_len(protocol.len(), &mut protocols)?;
                protocols.extend_from_slice(protocol.as_bytes());
            }
            let mut data = Vec::new();
            push_u16_len(protocols.len(), &mut data)?;
            data.extend_from_slice(&protocols);
            Ok(data)
        }
        0x002b => {
            let mut data = Vec::new();
            push_u8_len(profile.supported_versions.len() * 2, &mut data)?;
            for version in &profile.supported_versions {
                data.extend_from_slice(&version.to_be_bytes());
            }
            Ok(data)
        }
        _ => Ok(Vec::new()),
    }
}

fn fixture_u16_vector(values: &[u16]) -> Result<Vec<u8>, FingerprintError> {
    let mut data = Vec::new();
    push_u16_len(values.len() * 2, &mut data)?;
    for value in values {
        data.extend_from_slice(&value.to_be_bytes());
    }
    Ok(data)
}

fn push_u8_len(value: usize, output: &mut Vec<u8>) -> Result<(), FingerprintError> {
    output.push(
        u8::try_from(value)
            .map_err(|_| FingerprintError::InvalidProfile("fixture length exceeds u8"))?,
    );
    Ok(())
}

fn read_u8_at(input: &[u8], offset: &mut usize) -> Result<u8, FingerprintError> {
    let byte = *input
        .get(*offset)
        .ok_or(FingerprintError::InvalidClientHello)?;
    *offset += 1;
    Ok(byte)
}

fn read_u16_at(input: &[u8], offset: &mut usize) -> Result<u16, FingerprintError> {
    let bytes = take(input, offset, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take<'a>(input: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], FingerprintError> {
    let end = offset
        .checked_add(len)
        .ok_or(FingerprintError::InvalidClientHello)?;
    if end > input.len() {
        return Err(FingerprintError::InvalidClientHello);
    }
    let out = &input[*offset..end];
    *offset = end;
    Ok(out)
}

fn skip(input: &[u8], offset: &mut usize, len: usize) -> Result<(), FingerprintError> {
    take(input, offset, len).map(|_| ())
}

fn read_u24(input: &[u8]) -> Result<usize, FingerprintError> {
    if input.len() != 3 {
        return Err(FingerprintError::InvalidClientHello);
    }
    Ok((usize::from(input[0]) << 16) | (usize::from(input[1]) << 8) | usize::from(input[2]))
}

fn push_u16_len(value: usize, output: &mut Vec<u8>) -> Result<(), FingerprintError> {
    let value = u16::try_from(value)
        .map_err(|_| FingerprintError::InvalidProfile("fixture length exceeds u16"))?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn write_u24(value: usize, output: &mut Vec<u8>) -> Result<(), FingerprintError> {
    if value > 0x00ff_ffff {
        return Err(FingerprintError::InvalidProfile(
            "fixture handshake length exceeds u24",
        ));
    }
    output.push(u8::try_from((value >> 16) & 0xff).map_err(|_| {
        FingerprintError::InvalidProfile("fixture handshake length byte out of range")
    })?);
    output.push(u8::try_from((value >> 8) & 0xff).map_err(|_| {
        FingerprintError::InvalidProfile("fixture handshake length byte out of range")
    })?);
    output.push(u8::try_from(value & 0xff).map_err(|_| {
        FingerprintError::InvalidProfile("fixture handshake length byte out of range")
    })?);
    Ok(())
}

fn join_u16(values: &[u16]) -> String {
    values
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

fn join_u8(values: &[u8]) -> String {
    values
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

fn ja4_version(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

fn ja4_alpn(protocols: &[Vec<u8>]) -> String {
    let Some(protocol) = protocols.first().filter(|protocol| !protocol.is_empty()) else {
        return "00".to_owned();
    };
    let first = protocol[0];
    let last = protocol[protocol.len() - 1];
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        format!("{}{}", char::from(first), char::from(last))
    } else {
        // Use the first and last *hex digit*, not the first/last whole byte.
        format!("{:x}{:x}", first >> 4, last & 0x0f)
    }
}

fn join_hex(values: &[u16]) -> String {
    values
        .iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn ja4_hash(input: &str) -> String {
    if input.is_empty() {
        return "000000000000".to_owned();
    }
    let digest = Sha256::digest(input.as_bytes());
    hex_lower(&digest[..6])
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}
