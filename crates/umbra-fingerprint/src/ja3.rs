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

    /// Build Umbra's deterministic JA4-style self-check identifier.
    #[must_use]
    pub fn ja4(&self) -> String {
        let ciphers = without_grease(&self.ciphers);
        let extensions = without_grease(&self.extensions);
        let groups = without_grease(&self.supported_groups);
        let cipher_hash = truncated_sha256_hex(join_u16(&ciphers).as_bytes(), 12);
        let ext_hash = truncated_sha256_hex(join_u16(&extensions).as_bytes(), 12);
        let group_hash = truncated_sha256_hex(join_u16(&groups).as_bytes(), 12);
        format!(
            "t{}c{}e{}g{}_{}_{}_{}",
            self.legacy_version,
            ciphers.len(),
            extensions.len(),
            groups.len(),
            cipher_hash,
            ext_hash,
            group_hash
        )
    }
}

/// Compute the JA3 hash and JA4-style identifier for ClientHello bytes.
pub fn ja3_ja4(client_hello: &[u8]) -> Result<(String, String), FingerprintError> {
    let parsed = parse_client_hello(client_hello)?;
    Ok((parsed.ja3_hash(), parsed.ja4()))
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
    let session_id_len = read_u8_at(body, &mut offset)? as usize;
    skip(body, &mut offset, session_id_len)?;

    let cipher_len = read_u16_at(body, &mut offset)? as usize;
    if !cipher_len.is_multiple_of(2) {
        return Err(FingerprintError::InvalidClientHello);
    }
    let cipher_bytes = take(body, &mut offset, cipher_len)?;
    let ciphers = cipher_bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect();

    let compression_len = read_u8_at(body, &mut offset)? as usize;
    skip(body, &mut offset, compression_len)?;

    let mut extensions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut ec_point_formats = Vec::new();
    if offset < body.len() {
        let ext_len = read_u16_at(body, &mut offset)? as usize;
        let ext_end = offset
            .checked_add(ext_len)
            .ok_or(FingerprintError::InvalidClientHello)?;
        if ext_end > body.len() {
            return Err(FingerprintError::InvalidClientHello);
        }
        while offset < ext_end {
            let ext_type = read_u16_at(body, &mut offset)?;
            let data_len = read_u16_at(body, &mut offset)? as usize;
            let data = take(body, &mut offset, data_len)?;
            extensions.push(ext_type);
            match ext_type {
                0x000a => supported_groups = parse_supported_groups(data)?,
                0x000b => ec_point_formats = parse_ec_point_formats(data)?,
                _ => {}
            }
        }
        if offset != ext_end {
            return Err(FingerprintError::InvalidClientHello);
        }
    }

    Ok(ClientHelloFingerprint {
        legacy_version,
        ciphers,
        extensions,
        supported_groups,
        ec_point_formats,
    })
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

fn parse_supported_groups(data: &[u8]) -> Result<Vec<u16>, FingerprintError> {
    if data.len() < 2 {
        return Err(FingerprintError::InvalidClientHello);
    }
    let len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    if data.len() != 2 + len || !len.is_multiple_of(2) {
        return Err(FingerprintError::InvalidClientHello);
    }
    Ok(data[2..]
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect())
}

fn parse_ec_point_formats(data: &[u8]) -> Result<Vec<u8>, FingerprintError> {
    let Some((&len, rest)) = data.split_first() else {
        return Err(FingerprintError::InvalidClientHello);
    };
    if rest.len() != usize::from(len) {
        return Err(FingerprintError::InvalidClientHello);
    }
    Ok(rest.to_vec())
}

fn extension_fixture_data(
    ext_type: u16,
    profile: &FingerprintProfile,
) -> Result<Vec<u8>, FingerprintError> {
    match ext_type {
        0x000a => {
            let mut groups = Vec::with_capacity(2 + profile.supported_groups.len() * 2);
            push_u16_len(profile.supported_groups.len() * 2, &mut groups)?;
            for group in &profile.supported_groups {
                groups.extend_from_slice(&group.to_be_bytes());
            }
            Ok(groups)
        }
        0x000b => Ok(vec![1, 0]),
        _ => Ok(Vec::new()),
    }
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

fn truncated_sha256_hex(input: &[u8], chars: usize) -> String {
    let digest = Sha256::digest(input);
    hex_lower(&digest)[..chars].to_owned()
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
