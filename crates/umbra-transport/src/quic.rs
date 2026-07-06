//! QUIC fingerprint, REALITY carrier, fallback, and target stream helpers.

use umbra_fingerprint::FingerprintProfile;
use umbra_proto::addr::TargetAddr;

use crate::TransportError;

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
